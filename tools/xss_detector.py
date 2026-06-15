from typing import Optional
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.payload_engine import generate

logger = get_logger("xss_detector")

REFLECTION_MARKERS = ["XSS_TEST_%d" % i for i in range(100, 160)]


def _is_unescaped(html: str, needle: str) -> bool:
    if needle in html:
        escaped = needle.replace("<", "&lt;").replace(">", "&gt;")
        return escaped not in html or needle in html.replace(escaped, "")
    return False


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, post_body: bool = False, post_data: dict = None,
          context: str = "all", waf_name: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": [], "confirmed": False,
              "vector": None, "needs_browser_verify": False}

    contexts = ["html", "attr", "js", "angular"] if context == "all" else [context]

    for ctx in contexts:
        seeds = generate("xss", ctx, "all", waf_name)
        for i, entry in enumerate(seeds):
            payload = entry["payload"]
            marker = REFLECTION_MARKERS[i % len(REFLECTION_MARKERS)]
            test_payload = marker + payload
            try:
                if post_body and post_data:
                    d = post_data.copy()
                    d[param] = test_payload
                    r = sess.post(url, data=d, timeout=timeout, verify=False)
                else:
                    r = sess.get(build_url(url, param, test_payload),
                                 timeout=timeout, verify=False)
                if marker in r.text:
                    result["vulnerable"] = True
                    result["type"] = "reflected_%s" % ctx
                    result["evidence"].append(
                        "reflected %s in %s (%dB)" % (ctx, param, len(r.text)))
                    result["vector"] = payload[:80]
                    if _is_unescaped(r.text, "alert(1)"):
                        result["confirmed"] = True
                    break
            except Exception as e:
                logger.debug("xss %s payload: %s", ctx, e)
        if result["vulnerable"]:
            break

    if not result["vulnerable"]:
        dom_seeds = [
            {"payload": "javascript:alert(1)"},
            {"payload": "<svg/onload=alert(1)>"},
            {"payload": "';alert(1);//"},
            {"payload": "<img src=x onerror=alert(1)>"},
            {"payload": "'-alert(1)-'"},
            {"payload": "\\';alert(1);//"},
            {"payload": "<script>alert(1)</script>"},
        ]
        for entry in dom_seeds:
            payload = entry["payload"]
            try:
                r = sess.get(build_url(url, param, payload),
                             timeout=timeout, verify=False)
                if _is_unescaped(r.text, "alert(1)"):
                    result["vulnerable"] = True
                    result["type"] = "dom_possible"
                    result["needs_browser_verify"] = True
                    result["evidence"].append("dom_payload_reflected: %s" % payload[:30])
                    result["vector"] = payload[:80]
                    break
            except Exception as e:
                logger.debug("xss dom payload: %s", e)

    return result
