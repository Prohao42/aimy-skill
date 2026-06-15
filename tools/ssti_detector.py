import re
from typing import Optional
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.payload_engine import generate

logger = get_logger("ssti_detector")

TEMPLATE_ENGINE_FINGERPRINTS = {
    "jinja2": [r"\{\{999999\*999999\}\}",
               r"\{%\s*if\s*1\s*%\}true\{%\s*endif\s*%\}"],
    "twig": [r"\{\{999999\*999999\}\}", r"\$\{999999\*999999\}"],
    "freemarker": [r"\$\{999999\*999999\}"],
    "velocity": [r"\$\{999999\*999999\}"],
    "smarty": [r"\{999999\*999999\}"],
    "handlebars": [r"\{\{999999\*999999\}\}"],
    "mustache": [r"\{\{999999\*999999\}\}"],
    "mako": [r"\$\{999999\*999999\}"],
    "tornado": [r"\{\{999999\*999999\}\}"],
    "django": [r"\{\{999999\*999999\}\}"],
    "angular": [r"\{\{999999\*999999\}\}"],
}


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, waf_name: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "engine": None, "evidence": [], "payload": None}

    seeds = generate("ssti", "detect", "all", waf_name)
    for entry in seeds:
        payload = entry["payload"]
        indicator = entry["indicator"]
        try:
            r = sess.get(build_url(url, param, payload),
                         timeout=timeout, verify=False)
            if indicator in r.text:
                result["vulnerable"] = True
                result["evidence"].append("ssti: %s => %s" % (payload[:25], indicator))
                result["payload"] = payload
                for engine, patterns in TEMPLATE_ENGINE_FINGERPRINTS.items():
                    for pat in patterns:
                        if re.search(pat, r.text):
                            result["engine"] = engine
                            break
                break
        except Exception as e:
            logger.debug("ssti payload %s: %s", payload[:20], e)

    if not result["vulnerable"]:
        blind_seeds = generate("ssti", "blind", "all", waf_name)
        for entry in blind_seeds:
            payload = entry["payload"]
            indicator = entry["indicator"]
            try:
                r = sess.get(build_url(url, param, payload),
                             timeout=timeout, verify=False)
                if indicator in r.text:
                    result["vulnerable"] = True
                    result["evidence"].append("ssti: %s" % payload[:30])
                    result["payload"] = payload
                    break
            except Exception as e:
                logger.debug("ssti blind %s: %s", payload[:20], e)

    return result
