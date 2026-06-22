import time
from typing import Optional, Dict, List, Callable
import requests
import hashlib

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.response_profiler import ResponseProfiler, CLEAN_VALUE

logger = get_logger("verification_oracle")

ALT_PAYLOADS: Dict[str, List[Dict]] = {
    "sqli": [
        {"sub_type": "boolean_true", "label": "boolean_true"},
        {"sub_type": "boolean_false", "label": "boolean_false"},
        {"sub_type": "time_mysql", "label": "time_based"},
    ],
    "xss": [
        {"sub_type": "attr", "label": "attr_context"},
        {"sub_type": "js", "label": "js_context"},
    ],
    "cmdi": [
        {"sub_type": "time", "label": "time_based"},
        {"sub_type": "output", "label": "output_based"},
    ],
    "lfi": [
        {"sub_type": "encoded", "label": "encoded_path"},
        {"sub_type": "php_wrappers", "label": "php_wrappers"},
    ],
    "ssrf": [
        {"sub_type": "internal_reachable", "label": "internal_probe"},
    ],
}

ALT_EVIDENCE_CHECKS: Dict[str, List[Callable]] = {
    "sqli": [],
    "lfi": [],
}


class VerificationOracle:
    def __init__(self, response_profiler: Optional[ResponseProfiler] = None):
        self.profiler = response_profiler or ResponseProfiler()

    def verify(
        self,
        detector_type: str,
        finding: Dict,
        url: str,
        param: str,
        sess: requests.Session,
        timeout: float = 10.0,
        post_body: bool = False,
        post_data: dict = None,
    ) -> Dict:
        if not finding.get("vulnerable"):
            return finding

        if finding.get("confidence") == "high":
            finding["verified"] = True
            return finding

        alt_strategies = ALT_PAYLOADS.get(detector_type, [])
        if not alt_strategies:
            finding["verified"] = None
            return finding

        confirmed = 0
        attempts = []

        for strategy in alt_strategies[:2]:
            try:
                result = self._try_alternative(
                    detector_type,
                    strategy["sub_type"],
                    url,
                    param,
                    sess,
                    timeout,
                    post_body,
                    post_data,
                )
                attempts.append({"strategy": strategy["label"], "result": result})
                if result:
                    confirmed += 1
                    if confirmed >= 1:
                        break
            except Exception as e:
                logger.debug(
                    "verify %s/%s: %s", detector_type, strategy["label"], e
                )

        if confirmed >= 1:
            finding["verified"] = True
            finding["confidence"] = "high"
            finding["verification_attempts"] = attempts
            finding["verification_count"] = confirmed + 1
        else:
            finding["verified"] = False
            finding["verification_attempts"] = attempts

        return finding

    def _try_alternative(
        self,
        detector_type: str,
        sub_type: str,
        url: str,
        param: str,
        sess: requests.Session,
        timeout: float,
        post_body: bool,
        post_data: dict,
    ) -> bool:
        from tools.payload_engine import generate

        payloads = generate(detector_type, sub_type, "all", max_payloads=5)
        if not payloads:
            return False

        if detector_type == "sqli" and sub_type in ("boolean_true", "boolean_false"):
            return self._verify_sqli_boolean(
                url, param, sess, timeout, payloads, sub_type == "boolean_true"
            )

        if detector_type == "sqli" and "time" in sub_type:
            return self._verify_time_based(url, param, sess, timeout, payloads, 2.0)

        if detector_type == "cmdi" and sub_type == "time":
            return self._verify_time_based(url, param, sess, timeout, payloads, 2.0)

        if detector_type == "xss":
            return self._verify_xss_reflection(
                url, param, sess, timeout, payloads, post_body, post_data
            )

        return self._verify_any_reflection(
            url, param, sess, timeout, payloads, post_body, post_data
        )

    def _verify_sqli_boolean(
        self,
        url: str,
        param: str,
        sess: requests.Session,
        timeout: float,
        payloads: List[Dict],
        expect_true: bool,
    ) -> bool:
        baseline = self.profiler.get_baseline(url, param)
        if baseline is None:
            return False

        matched = 0
        for entry in payloads[:3]:
            payload = entry["payload"]
            try:
                r = sess.get(
                    build_url(url, param, payload), timeout=timeout
                )
                report = self.profiler.analyze(url, param, r)
                if (expect_true and not report.is_anomalous) or (
                    not expect_true and report.is_anomalous
                ):
                    matched += 1
            except Exception:
                continue

        return matched >= 2

    def _verify_time_based(
        self,
        url: str,
        param: str,
        sess: requests.Session,
        timeout: float,
        payloads: List[Dict],
        threshold: float,
    ) -> bool:
        for entry in payloads[:3]:
            payload = entry["payload"]
            try:
                start = time.time()
                sess.get(
                    build_url(url, param, payload),
                    timeout=timeout + 3,
                    verify=False,
                )
                elapsed = time.time() - start
                if elapsed >= threshold:
                    return True
            except requests.Timeout:
                return True
            except Exception:
                continue
        return False

    def _verify_xss_reflection(
        self,
        url: str,
        param: str,
        sess: requests.Session,
        timeout: float,
        payloads: List[Dict],
        post_body: bool,
        post_data: dict,
    ) -> bool:
        import random
        marker = "VFY_XSS_%d" % random.randint(1000, 9999)

        for entry in payloads[:3]:
            payload = entry["payload"]
            test = marker + payload
            try:
                if post_body and post_data:
                    d = post_data.copy()
                    d[param] = test
                    r = sess.post(url, data=d, timeout=timeout)
                else:
                    r = sess.get(
                        build_url(url, param, test), timeout=timeout
                    )
                if marker in r.text:
                    escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
                    if payload in r.text and escaped not in r.text:
                        return True
            except Exception:
                continue
        return False

    def _verify_any_reflection(
        self,
        url: str,
        param: str,
        sess: requests.Session,
        timeout: float,
        payloads: List[Dict],
        post_body: bool,
        post_data: dict,
    ) -> bool:
        import random
        marker = "VFY_REF_%d" % random.randint(1000, 9999)

        for entry in payloads[:3]:
            payload = entry["payload"]
            test = marker + payload
            try:
                if post_body and post_data:
                    d = post_data.copy()
                    d[param] = test
                    r = sess.post(url, data=d, timeout=timeout)
                else:
                    r = sess.get(
                        build_url(url, param, test), timeout=timeout
                    )
                if marker in r.text:
                    return True
            except Exception:
                continue
        return False
