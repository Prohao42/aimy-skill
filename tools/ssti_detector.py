import re
import statistics
import time
from typing import Optional

import requests

from tools.http_client import build_url
from tools.log_utils import get_logger
from tools.payload_engine import generate
from tools.settings import settings
from tools.verification_oracle import ConfidenceVoter

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
    for _ in range(3):
        try:
            start = time.time()
            sess.get(build_url(url, param, "NOMINAL_TEST"), timeout=timeout)
            samples.append(time.time() - start)
        except Exception:
            pass
    if not samples:
        return 0.3
    return statistics.median(samples) if len(samples) >= 3 else sum(samples) / len(samples)


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, waf_name: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "engine": None, "evidence": [], "payload": None,
              "rce_available": False}

    voter = ConfidenceVoter()

    context = "numeric" if param.lower() in ("id", "uid", "pid", "page") else "string"

    seeds = generate("ssti", "detect", "all", waf_name)
    detect_hits = 0
    for entry in seeds:
        payload = entry["payload"]
        indicator = entry["indicator"]
        try:
            r = sess.get(build_url(url, param, payload), timeout=timeout)
            if indicator in r.text:
                detect_hits += 1
                result["evidence"].append("ssti: %s => %s" % (payload[:25], indicator))
                result["payload"] = payload
                voter.add_vote("detect_%s" % indicator[:10], 0.6)
                for engine, patterns in TEMPLATE_ENGINE_FINGERPRINTS.items():
                    for pat in patterns:
                        if re.search(pat, r.text):
                            result["engine"] = engine
                            voter.add_vote("engine_%s" % engine, 0.4)
                            break
        except Exception as e:
            logger.debug("ssti payload %s: %s", payload[:20], e)

    if not result.get("evidence") and context == "string":
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
                    detect_hits += 1
                    result["evidence"].append("ssti: %s => %s (engine=%s)" % (payload[:25], indicator, engine_hint))
                    result["payload"] = payload
                    result["engine"] = engine_hint
                    voter.add_vote("alt_%s" % engine_hint, 0.5)
                    break
            except Exception as e:
                logger.debug("ssti alt %s: %s", payload[:20], e)

    if detect_hits >= 2:
        voter.add_vote("multi_detect", 0.8)
        result["vulnerable"] = True
    elif detect_hits == 1:
        voter.add_vote("single_detect", 0.5)
        result["vulnerable"] = True

    if not result["vulnerable"]:
        baseline = _measure_baseline(url, param, sess, timeout)
        if baseline < timeout * 0.8:
            threshold = max(2.0, baseline * 1.5 + 1.5)
            time_payloads = [
                "{{ ''.__class__.__mro__[1].__subclasses__() and sleep(3) }}",
                "{% if 1==1 %}{% endif %}",
            ]
            for payload in time_payloads:
                try:
                    start = time.time()
                    sess.get(build_url(url, param, payload), timeout=timeout + 3)
                    elapsed = time.time() - start
                    if elapsed >= threshold:
                        result["evidence"].append("ssti: time-based anomaly detected")
                        result["payload"] = payload
                        voter.add_vote("time_delay", ConfidenceVoter.vote_time_elapsed(
                            elapsed, baseline, threshold))
                        result["vulnerable"] = True
                        break
                except requests.Timeout:
                    voter.add_vote("timeout", 0.7)
                    result["vulnerable"] = True
                    result["evidence"].append("ssti: timeout anomaly detected")
                    break
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
                    voter.add_vote("rce_available", 0.5)
                    break
            except Exception as e:
                logger.debug("ssti blind %s: %s", payload[:20], e)

    result["confidence_score"] = round(voter.score, 2)
    result["confidence"] = voter.level.value
    result["confidence_votes"] = voter.evidence()
    return result
