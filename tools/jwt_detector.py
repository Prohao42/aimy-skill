import re, json
from typing import Optional, Dict
import requests

JWT_PATTERNS = [
    r'[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+',
]

JWT_HEADER_KEYS = ["authorization", "x-jwt", "x-auth-token", "token", "bearer"]


def decode_jwt_payload(token: str) -> Optional[Dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded = __import__("base64").urlsafe_b64decode(padded).decode("utf-8")
        return json.loads(decoded)
    except:
        return None


def decode_jwt_header(token: str) -> Optional[Dict]:
    try:
        parts = token.split(".")
        padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
        decoded = __import__("base64").urlsafe_b64decode(padded).decode("utf-8")
        return json.loads(decoded)
    except:
        return None


def check_jwt_none(sess: requests.Session, url: str = None,
                   token_header: str = None) -> Dict:
    result = {"vulnerable": False, "type": None, "evidence": []}
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "admin", "role": "admin", "iat": __import__("time").time()}
    import base64
    hdr_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    pld_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    token = "%s.%s." % (hdr_b64, pld_b64)
    return {"token": token, "header": header, "payload": payload,
            "note": "alg:none token generated - test against target manually"}


def check_jwt_weak_secret(token: str, wordlist: list = None) -> Dict:
    if wordlist is None:
        wordlist = ["secret", "password", "123456", "admin", "key", "jwt_secret",
                     "supersecret", "pass", "changeme", "1234"]
    result = {"vulnerable": False, "found_secret": None}
    try:
        import hmac, hashlib, base64
        parts = token.split(".")
        if len(parts) != 3:
            return result
        message = ("%s.%s" % (parts[0], parts[1])).encode()
        sig_b64 = parts[2] + "=" * (4 - len(parts[2]) % 4)
        target_sig = base64.urlsafe_b64decode(sig_b64)
        for secret in wordlist:
            expected = hmac.new(secret.encode(), message, hashlib.sha256).digest()
            if hmac.compare_digest(expected, target_sig):
                result["vulnerable"] = True
                result["found_secret"] = secret
                break
    except:
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
            for pat in JWT_PATTERNS:
                for m in re.finditer(pat, r.text):
                    token = m.group(0)
                    if len(token.split(".")) == 3:
                        payload = decode_jwt_payload(token)
                        hdr = decode_jwt_header(token)
                        entry = {"token": token[:50] + "...", "header": hdr, "payload": payload}
                        result["tokens_found"].append(entry)
                        if payload:
                            if payload.get("role") == "admin" or payload.get("sub", "").startswith("admin"):
                                result["findings"].append("high-privilege token found")
                            if hdr and hdr.get("alg") == "none":
                                result["findings"].append("alg:none token header detected")
                            ws = check_jwt_weak_secret(token)
                            if ws["vulnerable"]:
                                result["findings"].append("weak secret: %s" % ws["found_secret"])
        except:
            pass

    if result["tokens_found"] or result["findings"]:
        result["vulnerable"] = True

    if not result["tokens_found"]:
        none_token = check_jwt_none(sess, url)
        result["alg_none_test"] = none_token

    return result
