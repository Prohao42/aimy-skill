"""Clickjacking vulnerability detector.

Checks whether a page can be framed (missing or weak
X-Frame-Options / CSP frame-ancestors), enabling UI redress attacks.
"""

from typing import Dict, Optional

import requests

from tools.log_utils import get_logger

logger = get_logger("clickjacking")


def check(url: str, sess: Optional[requests.Session] = None, timeout: float = 10.0) -> Dict:
    if sess is None:
        from tools._session import make_session

        sess = make_session()

    result: Dict = {"vulnerable": False, "findings": []}

    if not url.startswith("http"):
        url = "http://" + url

    try:
        r = sess.get(url, timeout=timeout, allow_redirects=True)
        result["status"] = r.status_code
    except Exception as e:
        logger.debug("clickjacking: %s", e)
        return result

    xfo = r.headers.get("X-Frame-Options", "").lower()
    csp = r.headers.get("Content-Security-Policy", "")

    has_xfo = bool(xfo)
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    finding = {}
    if not has_xfo and not has_frame_ancestors:
        finding = {
            "type": "clickjacking",
            "endpoint": url,
            "issue": "No X-Frame-Options or CSP frame-ancestors header",
            "severity": "medium",
            "confidence": 0.9,
        }
        result["findings"].append(finding)
        result["vulnerable"] = True
    elif xfo and "deny" not in xfo and "sameorigin" not in xfo:
        finding = {
            "type": "clickjacking",
            "endpoint": url,
            "issue": f"Weak X-Frame-Options: {xfo}",
            "severity": "low",
            "confidence": 0.7,
        }
        result["findings"].append(finding)
        result["vulnerable"] = True
    elif has_frame_ancestors:
        if "'none'" in csp.lower() or "frame-ancestors" in csp.lower():
            sources = csp.lower().split("frame-ancestors")[-1].split(";")[0].strip()
            if "'self'" in sources or "'none'" in sources:
                if "'none'" in sources:
                    result["protected"] = True
                elif "'self'" in sources:
                    result["protected"] = True
                else:
                    finding = {
                        "type": "clickjacking",
                        "endpoint": url,
                        "issue": f"CSP frame-ancestors allows: {sources}",
                        "severity": "low",
                        "confidence": 0.6,
                    }
                    result["findings"].append(finding)
                    result["vulnerable"] = True

    return result
