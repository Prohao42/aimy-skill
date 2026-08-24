"""业务系统弱口令 / 默认凭据检测。

自动探测登录表单并低频尝试常见弱口令, 用"错误凭据差分"判断是否命中,
避免依赖某个系统的具体响应结构。只对登录口 POST, 不爆破其它接口。

    from tools.weakpass import check
    r = check("http://target.com/login", timeout=8, delay=0.3)
    # -> {url, form, attempts, findings: [{user, pass, reason}]}
"""
import hashlib
import re
import time
from typing import Dict, List, Optional, Tuple

import requests
import urllib3

from tools._session import make_session
from tools.log_utils import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger("weakpass")

# (username, password) -- common default / weak credentials.
DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"), ("admin", "123456"), ("admin", "admin888"),
    ("admin", "admin@123"), ("admin", "123456789"), ("admin", "password"),
    ("admin", "1234"), ("admin", "12345"), ("admin", "abc123"),
    ("admin", "888888"), ("admin", "666666"), ("admin", "12345678"),
    ("admin", "123123"), ("admin", "000000"), ("admin", "1qaz2wsx"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("root", "123456"), ("test", "test"), ("test", "123456"),
    ("administrator", "admin"), ("admin", ""), ("admin", "qwerty"),
    ("admin", "123456a"), ("admin", "admin!@#"), ("admin", "Aa123456"),
]

LOGIN_HINTS = ("login", "auth", "signin", "sign-in", "logon", "account/login")

# Fields that are never credentials.
_SKIP_FIELDS = {"submit", "button", "image", "remember", "rememberme",
                "csrf_token", "_token", "authenticity_token", "utf8",
                "_method", "next", "return_url", "redirect", "_csrf"}


def _parse_form(html: str) -> Optional[Dict]:
    """Extract the first login form (has a password input)."""
    form_re = re.compile(r"<form[^>]*>.*?</form>", re.I | re.S)
    for fm in form_re.finditer(html):
        form_tag = fm.group(0)
        if not re.search(r'type=["\']password["\']', form_tag, re.I):
            continue
        am = re.search(r'action=["\']([^"\']*)["\']', form_tag, re.I)
        mm = re.search(r'method=["\']([^"\']*)["\']', form_tag, re.I)
        fields = []
        for im in re.finditer(
                r'<(?:input|select)[^>]*name=["\']([^"\']+)["\'][^>]*>',
                form_tag, re.I):
            name = im.group(1)
            tag = im.group(0)
            type_m = re.search(r'type=["\']([^"\']*)["\']', tag, re.I)
            val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
            ftype = (type_m.group(1) if type_m else "text").lower()
            fields.append({
                "name": name,
                "type": ftype,
                "value": val_m.group(1) if val_m else "",
            })
        if not fields:
            continue
        return {
            "action": am.group(1) if am else "",
            "method": (mm.group(1) if mm else "get").lower(),
            "fields": fields,
            "password_field": next((f["name"] for f in fields
                                    if f["type"] == "password"), ""),
        }
    return None


def _resolve(base: str, action: str) -> str:
    if not action:
        return base
    if action.startswith("http"):
        return action
    if action.startswith("/"):
        from urllib.parse import urlparse
        p = urlparse(base)
        return "%s://%s%s" % (p.scheme, p.netloc, action)
    return base.rstrip("/") + "/" + action


def _submit(sess: requests.Session, form: Dict, base: str,
            user: str, pwd: str, timeout: float) -> requests.Response:
    url = _resolve(base, form["action"])
    data = {}
    for f in form["fields"]:
        name = f["name"]
        if name == form["password_field"]:
            data[name] = pwd
        elif name.lower() in ("user", "username", "userid", "login",
                              "loginname", "email", "account", "uname",
                              "user_name", "username_text"):
            data[name] = user
        elif f["type"] in ("hidden",):
            data[name] = f["value"]
        elif name not in _SKIP_FIELDS:
            data[name] = f["value"]
    # Ensure a user field is present; fall back to the first text field.
    if not any(k.lower() in ("user", "username", "userid", "login", "loginname",
                             "email", "account", "uname", "user_name") for k in data):
        for f in form["fields"]:
            if f["type"] == "text" and f["name"] not in _SKIP_FIELDS:
                data[f["name"]] = user
                break
    if form["method"] == "post":
        return sess.post(url, data=data, timeout=timeout,
                         allow_redirects=True, verify=False)  # nosec B501
    return sess.get(url, params=data, timeout=timeout,
                    allow_redirects=True, verify=False)  # nosec B501


def _filebrowser_login(base: str, user: str, pwd: str, sess: requests.Session,
                       timeout: float) -> bool:
    """FileBrowser SPA login via /api/login (JSON, no <form> in HTML)."""
    try:
        r = sess.post(base.rstrip("/") + "/api/login",
                      json={"username": user, "password": pwd, "recaptcha": ""},
                      timeout=timeout, allow_redirects=False,
                      verify=False)  # nosec B501
        if r.status_code != 200:
            return False
        try:
            j = r.json()
        except Exception:
            j = {}
        if isinstance(j, dict) and (j.get("token") or j.get("type") == "ok"):
            return True
    except Exception:
        pass
    return False


def _try_api_loginers(base: str, user: str, pwd: str, sess: requests.Session,
                      timeout: float) -> Tuple[bool, str]:
    """Built-in JSON API login handlers for SPA apps without <form> tags."""
    if _filebrowser_login(base, user, pwd, sess, timeout):
        return True, "filebrowser /api/login token"
    return False, ""


def _json_api_login(url: str, user: str, pwd: str, sess: requests.Session,
                    timeout: float, user_field: str = "username",
                    pass_field: str = "password") -> Tuple[bool, str]:
    """Generic JSON API login for SPA/JSON-RPC style endpoints.

    Success heuristic: HTTP 200 and a JSON reply that carries no explicit
    auth-error marker. Findings still need human confirmation.
    """
    try:
        r = sess.post(url, json={user_field: user, pass_field: pwd},
                      timeout=timeout, allow_redirects=False,
                      verify=False)  # nosec B501
    except Exception:
        return False, ""
    if r.status_code != 200:
        return False, ""
    text = r.text or ""
    if not text.strip().startswith("{"):
        return False, ""
    low = text.lower()
    markers = ("unauthorized", "invalid", "login failed", "wrong password",
               "authentication failed", "denied", "incorrect", "not found",
               "missing password", "invalid password")
    if any(m in low for m in markers):
        return False, ""
    return True, "json api 200 no-auth-error"


def _body_sig(resp: requests.Response) -> str:
    return hashlib.md5((resp.text or "").encode(errors="replace")).hexdigest()  # nosec B324 - diff only


def _likely_success(neg: requests.Response, pos: requests.Response) -> Tuple[bool, str]:
    """Differential check: does the candidate response differ from the
    guaranteed-wrong-credentials baseline in a way consistent with login?"""
    if neg.status_code != pos.status_code:
        return True, "status %d -> %d" % (neg.status_code, pos.status_code)
    neg_url, pos_url = neg.url, pos.url
    if neg_url != pos_url:
        neg_hint = any(h in neg_url.lower() for h in ("login", "auth", "signin"))
        pos_hint = any(h in pos_url.lower() for h in ("login", "auth", "signin"))
        if neg_hint and not pos_hint:
            return True, "redirected out of login page"
    neg_body, pos_body = (neg.text or ""), (pos.text or "")
    if len(neg_body) and len(pos_body):
        sig_neg = _body_sig(neg)
        if sig_neg != _body_sig(pos) and len(pos_body) > len(neg_body) * 2:
            return True, "response body grew significantly"
    return False, ""


def check(url: str, creds: Optional[List[Tuple[str, str]]] = None,
          sess: Optional[requests.Session] = None, timeout: float = 8.0,
          delay: float = 0.3, max_attempts: int = 0,
          api_url: str = "", user_field: str = "username",
          pass_field: str = "password") -> Dict:
    """Probe a login form for weak credentials. Low-rate, read-mostly.

    If api_url is set, the JSON login endpoint is used directly (SPA apps,
    Odoo, custom APIs) instead of HTML form parsing.
    """
    sess = sess or make_session()
    creds = creds or DEFAULT_CREDS
    result = {"url": url, "form": None, "attempts": 0, "findings": []}

    if api_url:
        result["form"] = {"kind": "api", "api_url": api_url}
        for user, pwd in creds[:max_attempts or len(creds)]:
            ok, why = _json_api_login(api_url, user, pwd, sess, timeout,
                                      user_field, pass_field)
            result["attempts"] += 1
            if ok:
                result["findings"].append({"user": user, "password": pwd,
                                           "reason": why})
            if delay:
                time.sleep(delay)
        return result

    try:
        r = sess.get(url, timeout=timeout, allow_redirects=True, verify=False)  # nosec B501
    except Exception as e:
        result["error"] = str(e)[:80]
        return result
    form = _parse_form(r.text or "")
    if not form:
        # SPA apps (FileBrowser, etc.) expose a JSON login API with no <form>.
        result["form"] = {"kind": "api", "handler": "builtin"}
        findings = []
        for user, pwd in creds[:max_attempts or len(creds)]:
            ok, why = _try_api_loginers(url, user, pwd, sess, timeout)
            result["attempts"] += 1
            if ok:
                findings.append({"user": user, "password": pwd, "reason": why})
            if delay:
                time.sleep(delay)
        result["findings"] = findings
        return result
    result["form"] = {"action": form["action"], "method": form["method"],
                      "password_field": form["password_field"],
                      "fields": [f["name"] for f in form["fields"]]}

    # Negative baseline: guaranteed-wrong credentials.
    try:
        neg = _submit(sess, form, url, "__aimy_no_such_user__",
                      "__aimy_no_such_pass__", timeout)
    except Exception as e:
        result["error"] = "baseline submit failed: %s" % str(e)[:80]
        return result

    if max_attempts:
        creds = creds[:max_attempts]
    for user, pwd in creds:
        try:
            pos = _submit(sess, form, url, user, pwd, timeout)
        except Exception:
            continue
        result["attempts"] += 1
        ok, reason = _likely_success(neg, pos)
        if ok:
            result["findings"].append({"user": user, "password": pwd,
                                       "reason": reason})
        if delay:
            time.sleep(delay)

    return result
