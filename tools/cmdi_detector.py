import re, time
from typing import Optional
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.payload_engine import generate

logger = get_logger("cmdi_detector")

OUTPUT_INDICATORS = [
    r"uid=\d+\([\w]+\)",
    r"gid=\d+\([\w]+\)",
    r"groups?=\d+\([\w]+\)",
    r"Microsoft Windows",
    r"NT AUTHORITY",
    r"root:[^:]+:\d+:\d+",
    r"www-data",
    r"bin/bash",
    r"bin/sh",
    r"cmd\.exe",
    r"command not found",
    r"is not recognized",
    r"TTY|tty",
    r"\d+ bytes from",
    r"time[<=]\d+",
    r"PING |ping statistics",
]


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, waf_name: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": [], "payload": None}

    output_seeds = generate("cmdi", "output", "all", waf_name)
    for entry in output_seeds:
        payload = entry["payload"]
        indicator = entry.get("indicator")
        try:
            r = sess.get(build_url(url, param, payload),
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
        except Exception as e:
            logger.debug("cmdi payload %s: %s", payload[:15], e)
        if result["vulnerable"]:
            break

    if not result["vulnerable"]:
        time_seeds = generate("cmdi", "time", "all", waf_name)
        for entry in time_seeds:
            payload = entry["payload"]
            threshold = entry.get("threshold", 2.5)
            try:
                start = time.time()
                sess.get(build_url(url, param, payload),
                         timeout=timeout + 2, verify=False)
                elapsed = time.time() - start
                if elapsed >= threshold:
                    result["vulnerable"] = True
                    result["type"] = "time"
                    result["evidence"].append("cmdi time: %s => %.1fs" % (payload[:15], elapsed))
                    result["payload"] = payload
                    break
            except Exception as e:
                logger.debug("cmdi time %s: %s", payload[:15], e)

    return result
