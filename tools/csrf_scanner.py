import re
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("csrf_scanner")

CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "csrfmiddlewaretoken", "_csrf", "_csrf_token",
    "token", "authenticity_token", "csrf-token", "xsrf-token",
    "__RequestVerificationToken", "form_token", "security_token",
    "anticsrf", "anti-csrf", "nonce", "csrftoken",
]

CSRF_HEADER_NAMES = [
    "X-CSRF-TOKEN", "X-CSRFToken", "X-XSRF-TOKEN", "X-XSRFToken",
    "X-Requested-By", "X-Request-ID",
]

SENSITIVE_ACTIONS = [
    r"(create|update|delete|edit|remove|add|change|upload|save)",
    r"(transfer|pay|withdraw|refund|donate)",
    r"(password|email|profile|account|setting)",
    r"(admin|config|user|role|permission)",
]


def _find_csrf_token(html: str) -> List[str]:
    found = []
    for name in CSRF_TOKEN_NAMES:
        patterns = [
            r'name=["\']%s["\'][^>]*value=["\']([^"\']+)["\']' % re.escape(name),
            r'value=["\']([^"\']+)["\'][^>]*name=["\']%s["\']' % re.escape(name),
            r'data-%s=["\']([^"\']+)["\']' % re.escape(name),
            r'<%s[^>]*content=["\']([^"\']+)["\']' % re.escape(name),
        ]
        for pat in patterns:
            m = re.search(pat, html, re.I)
            if m:
                found.append({"name": name, "value": m.group(1)[:30]})
    return found


def _has_csrf_header(response: requests.Response) -> List[str]:
    found = []
    for hdr_name in CSRF_HEADER_NAMES:
        val = response.headers.get(hdr_name) or response.headers.get(hdr_name.lower())
        if val:
            found.append(hdr_name)
    return found


def _find_forms(html: str, base_url: str) -> List[Dict]:
    forms = []
    for match in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', html, re.I | re.S):
        action = match.group(1)
        body = match.group(2)
        if not action:
            action = base_url
        elif not action.startswith("http"):
            action = urljoin(base_url, action)
        method_match = re.search(r'method=["\'](get|post)["\']', match.group(0), re.I)
        method = method_match.group(1).upper() if method_match else "GET"
        inputs = []
        for inp in re.finditer(r'<input[^>]*name=["\']([^"\']+)["\']', body, re.I):
            inputs.append(inp.group(1))
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def _is_sensitive(action: str, method: str) -> bool:
    if method == "GET":
        return False
    for pat in SENSITIVE_ACTIONS:
        if re.search(pat, action, re.I):
            return True
    return False


def check(url: str, param: Optional[str] = None, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = settings.verify_ssl
        sess.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

    result = {
        "vulnerable": False,
        "url": url,
        "findings": [],
        "forms_analyzed": 0,
        "csrf_protected": False,
    }

    try:
        r = sess.get(url, timeout=timeout)
    except Exception as e:
        result["error"] = str(e)
        return result

    html = r.text
    result["csrf_header"] = _has_csrf_header(r)
    result["token_in_page"] = _find_csrf_token(html)

    if result["csrf_header"] or result["token_in_page"]:
        result["csrf_protected"] = True

    forms = _find_forms(html, url)
    result["forms_analyzed"] = len(forms)

    for form in forms:
        action = form["action"]
        method = form["method"]
        if method == "GET":
            continue
        if action.startswith("javascript:"):
            continue
        form_has_token = any(t["name"] for t in result["token_in_page"] if t["name"] in " ".join(form["inputs"]))
        if not form_has_token and len(form["inputs"]) > 0:
            result["findings"].append({
                "type": "missing_csrf_token",
                "action": action,
                "method": method,
                "inputs": form["inputs"],
                "sensitive": _is_sensitive(action, method),
            })

    if not result["csrf_protected"] and result["forms_analyzed"] > 0:
        for form in forms:
            if form["method"] == "POST":
                result["vulnerable"] = True
                break

    if result["findings"]:
        for f in result["findings"]:
            if f.get("sensitive"):
                result["vulnerable"] = True

    return result


def bypass_check(url: str, form_action: str, form_data: Dict,
                 sess: Optional[requests.Session] = None,
                 timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = settings.verify_ssl

    result = {"url": url, "action": form_action, "tests": []}

    test_cases = [
        ("no_referer", {"Referer": ""}),
        ("no_origin", {"Origin": ""}),
        ("wrong_origin", {"Origin": "https://evil.com", "Referer": "https://evil.com/fake"}),
        ("method_override", {}),
        ("json_content_type", {}),
    ]

    for name, extra_headers in test_cases:
        try:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            headers.update(extra_headers)
            if name == "json_content_type":
                headers["Content-Type"] = "application/json"
                r = sess.post(urljoin(url, form_action), json=form_data,
                            headers=headers, timeout=timeout)
            elif name == "method_override":
                r = sess.get(urljoin(url, form_action), params=form_data,
                           headers=headers, timeout=timeout)
            else:
                r = sess.post(urljoin(url, form_action), data=form_data,
                            headers=headers, timeout=timeout)
            if r.status_code in (200, 302, 403):
                result["tests"].append({
                    "test": name,
                    "status": r.status_code,
                    "bypassed": r.status_code in (200, 302),
                    "size": len(r.text),
                })
        except Exception as e:
            result["tests"].append({"test": name, "error": str(e)})

    result["bypassable"] = any(t.get("bypassed") for t in result["tests"])
    return result
