from typing import Optional, Dict, List
import requests

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("cors_scanner")

TEST_ORIGINS = [
    "http://evil.com",
    "https://evil.com",
    "null",
    "http://evil.com.evil.com",
    "http://evilevil.com",
    "https://attacker.com",
    "http://evil.com:8080",
    "http://192.168.1.1",
    "http://127.0.0.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://localhost",
    "http://evil.com/",
    "http://evil.com%2F",
    "https://evil.com.evil.com",
    "http://evil.co",
    "http://evil.com.evildomain.com",
    "http://test",
]


def check_single_origin(url: str, origin: str, sess: requests.Session,
                        timeout: float) -> Dict:
    finding = {"origin": origin, "acao": "", "credentialed": False}
    try:
        r = sess.get(url, headers={"Origin": origin}, timeout=timeout)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acc = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == origin or acao == "*":
            finding["acao"] = acao
            finding["status"] = r.status_code
            if acc == "true":
                finding["credentialed"] = True
    except Exception as e:
        logger.debug("cors test %s: %s", origin[:20], e)
    return finding


def check_options_preflight(url: str, sess: requests.Session,
                            timeout: float) -> Dict:
    finding = {"method": "OPTIONS", "acao": "", "allow_methods": "", "expose_headers": ""}
    try:
        r = sess.options(url, timeout=timeout)
        finding["acao"] = r.headers.get("Access-Control-Allow-Origin", "")
        finding["allow_methods"] = r.headers.get("Access-Control-Allow-Methods", "")
        finding["expose_headers"] = r.headers.get("Access-Control-Expose-Headers", "")
    except Exception as e:
        logger.debug("cors options: %s", e)
    return finding


def check(url: str, param: str = None, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "findings": [], "sensitive_headers_exposed": []}

    if not url.startswith("http"):
        url = "http://" + url

    for origin in TEST_ORIGINS:
        finding = check_single_origin(url, origin, sess, timeout)
        if finding["acao"]:
            result["findings"].append(finding)
            result["vulnerable"] = True

    pref = check_options_preflight(url, sess, timeout)
    if pref["acao"]:
        result["findings"].append(pref)

    sensitive_headers = {"access-control-expose-headers"}
    expose_headers = {h.lower() for h in pref.get("expose_headers", "").split(",") if h.strip()}
    if expose_headers & sensitive_headers:
        result["sensitive_headers_exposed"].append(pref["expose_headers"])

    try:
        r = sess.get(url, timeout=timeout)
        vary = r.headers.get("Vary", "")
        if vary and "origin" not in vary.lower():
            result["findings"].append({
                "note": "Vary header missing 'Origin' (caching risk)",
                "vary": vary
            })
    except Exception as e:
        logger.debug("cors vary check: %s", e)

    return result
