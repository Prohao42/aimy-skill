from typing import Optional, Dict
from tools.log_utils import get_logger
from tools.xss_browser_verify import check as browser_verify

logger = get_logger("xss_validator")


def check(url: str, param: str, sess: Optional["requests.Session"] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        import requests
        sess = requests.Session()

    result = browser_verify(url, param, sess, timeout)

    if result.get("playwright_available"):
        logger.info("Playwright XSS verify: confirmed=%s", result.get("confirmed"))
    else:
        logger.info("XSS verify (HTTP fallback): vulnerable=%s", result.get("vulnerable"))

    return result
