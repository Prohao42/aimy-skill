import re, pickle, json
from typing import Optional, Dict
import requests

from tools.log_utils import get_logger

logger = get_logger("auth_engine")

CSRF_PATTERNS = [
    r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)',
    r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)',
    r'name=["\']csrf["\'][^>]*value=["\']([^"\']+)',
    r'name=["\']_token["\'][^>]*value=["\']([^"\']+)',
    r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)',
    r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)',
]

FORM_CRED_PATTERNS = [
    r'<input[^>]*type=["\'](?:text|email|hidden)["\'][^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\'](?:text|email|hidden)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
    r'<input[^>]*type=["\']password["\']',
    r'<input[^>]*type=["\']submit["\']',
    r'<form[^>]*action=["\']([^"\']+)["\']',
]


def detect_form_fields(html: str) -> Dict:
    fields = {"action": "", "inputs": {}, "has_password": False}
    for p in CSRF_PATTERNS:
        m = re.search(p, html, re.IGNORECASE)
        if m:
            fields["csrf_token"] = m.group(1)
            fields["csrf_field"] = m.group(0).split("=")[0].strip()
            break
    am = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if am:
        fields["action"] = am.group(1)
    for p in FORM_CRED_PATTERNS:
        for m in re.finditer(p, html, re.IGNORECASE):
            if m.lastindex and m.lastindex >= 1:
                name = m.group(1)
                val = m.group(2) if m.lastindex >= 2 and m.group(2) else ""
                fields["inputs"][name] = val
    if re.search(r'<input[^>]*type=["\']password["\']', html, re.IGNORECASE):
        fields["has_password"] = True
    return fields


class AuthSession:
    def __init__(self, sess: Optional[requests.Session] = None):
        self.sess = sess or requests.Session()
        if "User-Agent" not in self.sess.headers:
            self.sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    def login_form(self, login_url: str, username: str, password: str,
                   user_field: str = "username", pass_field: str = "password") -> bool:
        try:
            html = self.sess.get(login_url, timeout=10, verify=False).text
            fields = detect_form_fields(html)
            data = {user_field: username, pass_field: password}
            if "csrf_token" in fields:
                data[fields.get("csrf_field", "csrf_token")] = fields["csrf_token"]
            for k, v in fields["inputs"].items():
                if k not in data:
                    data[k] = v
            action_url = fields.get("action") or login_url
            r = self.sess.post(action_url, data=data, timeout=10, verify=False)
            return r.status_code == 200 and len(r.text) > 100
        except Exception as e:
            logger.debug("login_form: %s", e)
            return False

    def login_api(self, url: str, username: str, password: str,
                  user_field: str = "username", pass_field: str = "password") -> bool:
        try:
            r = self.sess.post(url, json={user_field: username, pass_field: password},
                               timeout=10, verify=False)
            if r.status_code == 200:
                body = r.text.lower()
                if "token" in body:
                    try:
                        j = r.json()
                        tok = j.get("token") or j.get("access_token") or j.get("data", {}).get("token", "")
                        if tok:
                            self.sess.headers["Authorization"] = "Bearer %s" % tok
                    except Exception as e:
                        logger.debug("login_api parse: %s", e)
                return True
            return False
        except Exception as e:
            logger.debug("login_api: %s", e)
            return False

    def login_basic(self, url: str, username: str, password: str) -> bool:
        from requests.auth import HTTPBasicAuth
        try:
            r = self.sess.get(url, auth=HTTPBasicAuth(username, password),
                              timeout=10, verify=False)
            return r.status_code < 400
        except Exception as e:
            logger.debug("login_basic: %s", e)
            return False

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        for k, v in cookies.items():
            self.sess.cookies.set(k, v)

    def set_header_token(self, token: str, scheme: str = "Bearer") -> None:
        self.sess.headers["Authorization"] = "%s %s" % (scheme, token)

    def save_session(self, path: str) -> None:
        data = {
            "cookies": dict(self.sess.cookies),
            "headers": dict(self.sess.headers),
        }
        with open(path, "wb") as f:
            pickle.dump(data, f)

    def load_session(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)
            for k, v in data.get("cookies", {}).items():
                self.sess.cookies.set(k, v)
            for k, v in data.get("headers", {}).items():
                self.sess.headers[k] = v
            return True
        except Exception as e:
            logger.debug("load_session: %s", e)
            return False


def auth_from_args(args) -> requests.Session:
    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    from tools.kali_executor import init_kali, init_kali_local

    if getattr(args, "kali_local", False):
        init_kali_local()
    else:
        kali_host = getattr(args, "kali_host", None) or ""
        if kali_host:
            init_kali(
                host=kali_host,
                port=getattr(args, "kali_port", 22),
                user=getattr(args, "kali_user", "root") or "root",
                password=getattr(args, "kali_pass", "") or "",
                key_file=getattr(args, "kali_key", "") or "",
            )

    auth_type = getattr(args, "auth_type", None)
    if not auth_type:
        return sess

    engine = AuthSession(sess)
    auth_url = getattr(args, "auth_url", "") or ""
    auth_user = getattr(args, "auth_user", "") or ""
    auth_pass = getattr(args, "auth_pass", "") or ""

    if auth_type == "form":
        engine.login_form(auth_url, auth_user, auth_pass)
    elif auth_type == "api":
        engine.login_api(auth_url, auth_user, auth_pass)
    elif auth_type == "basic":
        engine.login_basic(auth_url, auth_user, auth_pass)

    session_file = getattr(args, "session_file", None)
    if session_file:
        try:
            engine.load_session(session_file)
        except Exception as e:
            logger.debug("session file load: %s", e)

    return sess
