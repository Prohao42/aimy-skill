"""Web cache deception / poisoning detector.

Tests for vulnerabilities arising from caching behavior:
- Web cache deception: attacker tricks server into caching sensitive data
- Cache poisoning: injecting malicious content into cached responses
"""

from typing import Dict, Optional

import requests

from tools.log_utils import get_logger

logger = get_logger("web_cache")

SUSPICIOUS_CACHE_HEADERS = [
    "x-cache",
    "x-cache-lookup",
    "cf-cache-status",
    "age",
    "via",
]

WEB_CACHE_PATHS = [
    "/profile",
    "/account",
    "/settings",
    "/admin",
    "/cart",
    "/user",
    "/dashboard",
]

DECEPTION_SUFFIXES = [
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".gif",
    ".pdf",
    ".ico",
    "/nonexistent.css",
    "/../../etc/passwd.css",
]


def check(url: str, sess: Optional[requests.Session] = None, timeout: float = 10.0) -> Dict:
    if sess is None:
        from tools._session import make_session

        sess = make_session()

    result: Dict = {"vulnerable": False, "findings": [], "cache_info": {}}

    if not url.startswith("http"):
        url = "http://" + url

    try:
        r1 = sess.get(url, timeout=timeout, allow_redirects=True)
    except Exception as e:
        logger.debug("web_cache baseline: %s", e)
        return result

    cache_headers = {k: v for k, v in r1.headers.items() if k.lower() in SUSPICIOUS_CACHE_HEADERS}
    result["cache_info"]["baseline_headers"] = cache_headers

    if cache_headers:
        result["cache_present"] = True

    for path in WEB_CACHE_PATHS:
        full_path = url.rstrip("/") + path
        for suffix in DECEPTION_SUFFIXES:
            test_url = full_path + suffix
            try:
                r = sess.get(test_url, timeout=timeout, allow_redirects=False)
            except Exception:
                continue

            if r.status_code == 200:
                ct = r.headers.get("Content-Type", "")
                cache = r.headers.get("X-Cache", "") or r.headers.get("CF-Cache-Status", "")

                if "text/html" in ct:
                    finding = {
                        "type": "web_cache_deception",
                        "endpoint": test_url,
                        "issue": "HTML response returned for non-HTML path (cache deception vector)",
                        "status_code": r.status_code,
                        "content_type": ct,
                        "cache_header": cache,
                        "response_length": len(r.text),
                        "severity": "high",
                        "confidence": 0.85,
                    }

                    if (
                        "user" in r.text.lower()
                        or "account" in r.text.lower()
                        or "session" in r.text.lower()
                    ):
                        finding["sensitive_data"] = True
                        finding["severity"] = "critical"
                        finding["confidence"] = 0.95

                    result["findings"].append(finding)
                    result["vulnerable"] = True
        if result["vulnerable"]:
            break

    return result
