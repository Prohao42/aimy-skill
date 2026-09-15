"""CRLF (Carriage Return Line Feed) injection detector.

Tests whether user input in URL parameters or headers can inject
CRLF sequences, leading to HTTP response splitting, header injection,
or cookie manipulation.
"""

from typing import Dict, Optional

import requests

from tools.log_utils import get_logger

logger = get_logger("crlf_injection")

CRLF_PAYLOADS = [
    "%0d%0a",
    "%0d%0a%20",
    "%0d%0a%0d%0a",
    "\r\n",
    "\r\nSet-Cookie:%20injected%3dtrue",
    "%0d%0aX-Injected:%20test",
    "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK",
]


def check(
    url: str, param: str = "q", sess: Optional[requests.Session] = None, timeout: float = 10.0
) -> Dict:
    if sess is None:
        from tools._session import make_session

        sess = make_session()

    result: Dict = {"vulnerable": False, "findings": []}

    if not url.startswith("http"):
        url = "http://" + url

    base_param_val = "test"
    parsed_url = url
    if "?" in url:
        parsed_url = url.split("?")[0]
        existing_params = url.split("?", 1)[1]
    else:
        existing_params = ""

    for payload in CRLF_PAYLOADS:
        test_url = (
            f"{parsed_url}?{existing_params}&{param}={payload}{base_param_val}"
            if existing_params
            else f"{parsed_url}?{param}={payload}{base_param_val}"
        )
        try:
            r = sess.get(test_url, timeout=timeout, allow_redirects=False)
        except Exception as e:
            logger.debug("crlf test: %s", e)
            continue

        set_cookie = r.headers.get("Set-Cookie", "")
        x_injected = any(h.startswith("X-Injected") for h in r.headers)

        if set_cookie and "injected" in set_cookie.lower():
            finding = {
                "type": "crlf_injection",
                "endpoint": test_url,
                "parameter": param,
                "payload": payload,
                "issue": f"CRLF payload injected Set-Cookie header: {set_cookie[:100]}",
                "severity": "high",
                "confidence": 0.8,
                "response_headers": dict(r.headers),
            }
            result["findings"].append(finding)
            result["vulnerable"] = True
            break

        if x_injected:
            finding = {
                "type": "crlf_injection",
                "endpoint": test_url,
                "parameter": param,
                "payload": payload,
                "issue": "Injected X-Injected header found in response",
                "severity": "high",
                "confidence": 0.85,
            }
            result["findings"].append(finding)
            result["vulnerable"] = True
            break

    return result
