"""HTTP Parameter Pollution (HPP) detector.

Tests whether duplicate query parameters are handled differently by
different layers (WAF, proxy, application), which can bypass filters
or trigger unexpected behavior.
"""

from typing import Dict, Optional

import requests

from tools.log_utils import get_logger

logger = get_logger("hpp")


def check(
    url: str, param: str = "q", sess: Optional[requests.Session] = None, timeout: float = 10.0
) -> Dict:
    if sess is None:
        from tools._session import make_session

        sess = make_session()

    result: Dict = {"vulnerable": False, "findings": [], "parameter_pollution": False}

    if not url.startswith("http"):
        url = "http://" + url

    base_payload = "1"
    polluted_payload = "2"

    single_url = f"{url}?{param}={base_payload}"
    polluted_url = f"{url}?{param}={base_payload}&{param}={polluted_payload}"

    try:
        r1 = sess.get(single_url, timeout=timeout)
        r2 = sess.get(polluted_url, timeout=timeout)
    except Exception as e:
        logger.debug("hpp test: %s", e)
        return result

    if r1.text != r2.text:
        if polluted_payload in r2.text:
            finding = {
                "type": "hpp",
                "endpoint": polluted_url,
                "parameter": param,
                "issue": "Server accepts duplicate parameters (last-wins or first-wins behavior)",
                "severity": "low",
                "confidence": 0.8,
                "single_response_length": len(r1.text),
                "polluted_response_length": len(r2.text),
            }
            result["findings"].append(finding)
            result["vulnerable"] = True
            result["parameter_pollution"] = True

    return result
