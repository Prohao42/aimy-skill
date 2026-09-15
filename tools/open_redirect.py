"""Open Redirect vulnerability detector.

Tests whether the application redirects to attacker-controlled URLs
passed via parameters, enabling phishing and SSRF bypass.
"""

from typing import Dict, Optional

import requests

from tools.log_utils import get_logger

logger = get_logger("open_redirect")

REDIRECT_PARAMS = [
    "redirect",
    "next",
    "return",
    "url",
    "r",
    "redirect_uri",
    "redirect_url",
    "continue",
    "dest",
    "destination",
    "forward",
]

REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "/\\/\\evil.com",
    "https:evil.com",
    "//evil.com/",
    "%2f%2fevil.com",
    "https://evil.com#@example.com",
    "/\\evil.com",
    "////evil.com",
    "https://evil.com\\@example.com",
]


def check(
    url: str, param: str = "", sess: Optional[requests.Session] = None, timeout: float = 10.0
) -> Dict:
    if sess is None:
        from tools._session import make_session

        sess = make_session()

    result: Dict = {"vulnerable": False, "findings": []}

    if not url.startswith("http"):
        url = "http://" + url

    if not param:
        params_to_test = REDIRECT_PARAMS
    else:
        params_to_test = [param]

    for redirect_param in params_to_test:
        for payload in REDIRECT_PAYLOADS:
            test_url = url
            if "?" in url:
                test_url = f"{url}&{redirect_param}={payload}"
            else:
                test_url = f"{url}?{redirect_param}={payload}"

            try:
                r = sess.get(test_url, timeout=timeout, allow_redirects=False)
            except Exception as e:
                logger.debug("open_redirect test: %s", e)
                continue

            location = r.headers.get("Location", "")
            if location and "evil.com" in location:
                finding = {
                    "type": "open_redirect",
                    "endpoint": test_url,
                    "parameter": redirect_param,
                    "payload": payload,
                    "redirect_to": location,
                    "issue": f"Redirects to external domain: {location}",
                    "severity": "medium",
                    "confidence": 0.9,
                }
                result["findings"].append(finding)
                result["vulnerable"] = True
                break
        else:
            continue
        break

    return result
