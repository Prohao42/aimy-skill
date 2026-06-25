import time
from typing import Optional, Dict, List
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.response_profiler import ResponseProfiler, CLEAN_VALUE

logger = get_logger("verification_oracle")


class VerificationOracle:
    def __init__(self, response_profiler: Optional[ResponseProfiler] = None):
        self.profiler = response_profiler or ResponseProfiler()

    def verify(self, detector_type: str, finding: Dict, url: str, param: str,
               sess: requests.Session, timeout: float = 10.0,
               post_body: bool = False, post_data: dict = None) -> Dict:
        if not finding.get("vulnerable"):
            return finding
        if finding.get("confidence") == "high":
            finding["verified"] = True
            return finding

        if detector_type == "sqli":
            return self._verify_sqli(finding, url, param, sess, timeout, post_body, post_data)
        elif detector_type == "cmdi":
            return self._verify_cmdi(finding, url, param, sess, timeout)
        elif detector_type == "xss":
            return self._verify_xss(finding, url, param, sess, timeout, post_body, post_data)
        elif detector_type == "lfi":
            return self._verify_lfi(finding, url, param, sess, timeout)
        elif detector_type == "ssrf":
            return self._verify_ssrf(finding)
        return finding

    def _verify_sqli(self, finding, url, param, sess, timeout, post_body, post_data):
        baseline_sec = self._measure_baseline(url, param, sess, timeout)
        if baseline_sec < timeout * 0.8:
            threshold = max(2.0, baseline_sec * 1.5 + 1.5)
            from tools.payload_engine import generate
            time_payloads = generate("sqli", "time_mysql", "all", max_payloads=3)
            for entry in time_payloads:
                try:
                    start = time.time()
                    sess.get(build_url(url, param, entry["payload"]), timeout=timeout + 3)
                    if time.time() - start >= threshold:
                        finding["verified"] = True
                        finding["confidence"] = "high"
                        return finding
                except requests.Timeout:
                    pass
                except Exception:
                    continue

        profiler = self.profiler
        profiler.profile_endpoint(url, param, sess, timeout)
        from tools.payload_engine import generate_sqli_boolean
        pairs = generate_sqli_boolean(param.lower() in ("id", "uid", "pid"))
        confirmed = 0
        for true_p, false_p in pairs[:3]:
            try:
                r_true = sess.get(build_url(url, param, true_p), timeout=timeout)
                r_false = sess.get(build_url(url, param, false_p), timeout=timeout)
                if profiler.analyze(url, param, r_true).is_anomalous != profiler.analyze(url, param, r_false).is_anomalous:
                    confirmed += 1
            except Exception:
                continue
        if confirmed >= 1:
            finding["verified"] = True
            finding["confidence"] = "high"

        return finding

    def _verify_cmdi(self, finding, url, param, sess, timeout):
        baseline_sec = self._measure_baseline(url, param, sess, timeout)
        threshold = max(2.5, baseline_sec * 1.5 + 2.0)

        from tools.payload_engine import generate
        time_seeds = generate("cmdi", "time", "all", max_payloads=3)
        for entry in time_seeds:
            try:
                start = time.time()
                sess.get(build_url(url, param, entry["payload"]), timeout=timeout + 3)
                if time.time() - start >= threshold:
                    finding["verified"] = True
                    finding["confidence"] = "high"
                    return finding
            except requests.Timeout:
                finding["verified"] = True
                finding["confidence"] = "high"
                return finding
            except Exception:
                continue
        return finding

    def _verify_xss(self, finding, url, param, sess, timeout, post_body, post_data):
        import random
        from tools.payload_engine import generate
        marker = "VFY_XSS_%d" % random.randint(1000, 9999)
        seeds = generate("xss", "html", "all", max_payloads=3)
        for entry in seeds:
            payload = entry["payload"]
            test = marker + payload
            try:
                if post_body and post_data:
                    d = post_data.copy()
                    d[param] = test
                    r = sess.post(url, data=d, timeout=timeout)
                else:
                    r = sess.get(build_url(url, param, test), timeout=timeout)
                if marker in r.text:
                    escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
                    if payload in r.text and escaped not in r.text:
                        finding["verified"] = True
                        finding["confidence"] = "high"
                        return finding
            except Exception:
                continue
        return finding

    def _verify_lfi(self, finding, url, param, sess, timeout):
        from tools.payload_engine import generate
        seeds = generate("lfi", "encoded", "all", max_payloads=3)
        for entry in seeds:
            try:
                r = sess.get(build_url(url, param, entry["payload"]), timeout=timeout)
                if "root:" in r.text or "[fonts]" in r.text:
                    finding["verified"] = True
                    finding["confidence"] = "high"
                    return finding
            except Exception:
                continue
        return finding

    def _verify_ssrf(self, finding):
        if finding.get("type") == "disclosure":
            finding["verified"] = True
            finding["confidence"] = "high"
        elif finding.get("type") == "oob_http_callback" or finding.get("type") == "oob_dns_callback":
            finding["verified"] = True
            finding["confidence"] = "high"
        return finding

    def _measure_baseline(self, url, param, sess, timeout):
        samples = []
        for _ in range(2):
            try:
                start = time.time()
                sess.get(build_url(url, param, CLEAN_VALUE), timeout=timeout)
                samples.append(time.time() - start)
            except Exception:
                pass
        if not samples:
            return 0.3
        return sum(samples) / len(samples)
