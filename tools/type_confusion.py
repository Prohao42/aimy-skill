import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("type_confusion")


@dataclass
class TypeConfusionResult:
    param: str
    original_type: str
    confused_type: str
    success: bool
    response_diff: bool = False
    status_changed: bool = False
    length_diff_pct: float = 0.0
    error_leak: bool = False
    evidence: str = ""
    risk_level: str = "low"
    vuln_type: str = ""


TYPE_CONFUSION_PAYLOADS = {
    "array": [
        {"param": "[]"},
        {"param[0]": "test"},
        {"param[a]": "test"},
        {"param[test]": "1"},
    ],
    "object": [
        {"param": '{"__proto__":{"admin":true}}'},
        {"param": '{"constructor":{"prototype":{"admin":true}}}'},
        {"param": '{"__proto__":null}'},
    ],
    "null": [
        {"param": "null"},
        {"param": "\x00"},
        {"param": "%00"},
    ],
    "boolean": [
        {"param": "true"},
        {"param": "false"},
        {"param": "1"},
        {"param": "0"},
        {"param": "yes"},
        {"param": "no"},
    ],
    "integer_overflow": [
        {"param": "99999999999999999999"},
        {"param": "2147483648"},
        {"param": "-1"},
        {"param": "0"},
        {"param": "999999999999999999999999999999"},
    ],
    "string_special": [
        {"param": ""},
        {"param": " "},
        {"param": "\n"},
        {"param": "\r\n"},
        {"param": "\t"},
        {"param": "../../../etc/passwd"},
        {"param": "${7*7}"},
        {"param": "{{7*7}}"},
        {"param": "<script>alert(1)</script>"},
        {"param": "'; DROP TABLE users; --"},
    ],
    "type_coercion": [
        {"param": "undefined"},
        {"param": "NaN"},
        {"param": "Infinity"},
        {"param": "function"},
        {"param": "[object Object]"},
    ],
}

TOCTOU_PARAMS = {
    "balance", "amount", "price", "cost", "total", "credit", "debit",
    "stock", "quantity", "count", "inventory",
    "coupon", "discount", "voucher", "promo",
    "token", "nonce", "csrf", "ticket",
    "role", "admin", "permission", "access", "level",
    "email", "user", "account", "id", "uid",
}

TOCTOU_PATTERNS = [
    (r"(?:balance|余额).*(?:update|change|modify|set)", "balance_modification"),
    (r"(?:coupon|优惠券).*(?:redeem|use|verify)", "coupon_reuse"),
    (r"(?:stock|库存).*(?:decrease|reduce|set)", "inventory_tampering"),
    (r"(?:token|验证码).*(?:verify|check|validate)", "token_reuse"),
    (r"(?:role|角色).*(?:set|change|update|assign)", "privilege_escalation"),
]


class TypeConfusionDetector:
    def __init__(self, sess: requests.Session, timeout: float = 10.0):
        self.sess = sess
        self.timeout = timeout

    def detect(self, url: str, param: str, method: str = "GET",
               post_data: Optional[Dict] = None) -> List[TypeConfusionResult]:
        results = []

        baseline = self._send_request(url, param, "test", method, post_data)
        if not baseline:
            return results

        for type_name, payloads in TYPE_CONFUSION_PAYLOADS.items():
            for payload_dict in payloads:
                value = payload_dict.get("param", "")
                result = self._test_type(url, param, value, type_name, method, post_data, baseline)
                if result and (result.success or result.response_diff or result.error_leak):
                    results.append(result)

        return results

    def detect_toctou(self, url: str, param: str, method: str = "GET",
                      post_data: Optional[Dict] = None) -> List[TypeConfusionResult]:
        results = []

        if param.lower() not in TOCTOU_PARAMS:
            return results

        for pattern, vuln_type in TOCTOU_PATTERNS:
            baseline = self._send_request(url, param, "1", method, post_data)
            if not baseline:
                continue

            for i in range(5):
                r1 = self._send_request(url, param, "1", method, post_data)
                r2 = self._send_request(url, param, "2", method, post_data)
                if r1 and r2 and self._responses_differ(r1, r2):
                    results.append(TypeConfusionResult(
                        param=param,
                        original_type="concurrent_access",
                        confused_type="race_condition",
                        success=True,
                        response_diff=True,
                        evidence="concurrent_request_%d_detected" % i,
                        risk_level="high",
                        vuln_type="race_condition",
                    ))
                    break

        return results

    def _test_type(self, url: str, param: str, value: str, type_name: str,
                   method: str, post_data: Optional[Dict],
                   baseline: requests.Response) -> Optional[TypeConfusionResult]:
        try:
            resp = self._send_request(url, param, value, method, post_data)
            if not resp:
                return None

            result = TypeConfusionResult(
                param=param,
                original_type="normal",
                confused_type=type_name,
                success=False,
            )

            if resp.status_code != baseline.status_code:
                result.status_changed = True
                result.response_diff = True

            baseline_len = len(baseline.text)
            resp_len = len(resp.text)
            if baseline_len > 0:
                diff_pct = abs(resp_len - baseline_len) / baseline_len * 100
                result.length_diff_pct = round(diff_pct, 1)
                if diff_pct > 50:
                    result.response_diff = True

            error_indicators = [
                "exception", "error", "traceback", "stack trace",
                "internal server error", "500", "type error",
                "conversion", "parse error", "json decode",
                " TypeError:", " ValueError:", " AttributeError:",
            ]
            for indicator in error_indicators:
                if indicator.lower() in resp.text.lower():
                    result.error_leak = True
                    result.evidence = "error_indicator: %s" % indicator
                    break

            if type_name == "object" and value.startswith("{"):
                try:
                    obj = json.loads(value)
                    if "__proto__" in str(obj) or "constructor" in str(obj):
                        result.vuln_type = "prototype_pollution"
                        result.risk_level = "high"
                        result.success = True
                except json.JSONDecodeError:
                    pass

            if type_name == "null" and resp.status_code != baseline.status_code:
                result.vuln_type = "null_injection"
                result.risk_level = "medium"
                result.success = True

            if type_name == "integer_overflow" and resp.status_code != baseline.status_code:
                result.vuln_type = "integer_overflow"
                result.risk_level = "medium"
                result.success = True

            if type_name == "string_special":
                if resp.status_code >= 500:
                    result.vuln_type = "input_validation_bypass"
                    result.risk_level = "medium"
                    result.success = True
                elif "sql" in resp.text.lower() or "query" in resp.text.lower():
                    result.vuln_type = "sql_injection_via_type"
                    result.risk_level = "high"
                    result.success = True

            if type_name == "type_coercion":
                if resp.status_code != baseline.status_code:
                    result.vuln_type = "type_coercion_bypass"
                    result.risk_level = "medium"
                    result.success = True

            if result.success or result.error_leak:
                return result

            if result.response_diff and result.length_diff_pct > 100:
                result.success = True
                result.risk_level = "low"
                return result

        except Exception as e:
            logger.debug("type confusion test: %s", e)

        return None

    def _send_request(self, url: str, param: str, value: str,
                      method: str, post_data: Optional[Dict]) -> Optional[requests.Response]:
        try:
            if method.upper() == "POST" and post_data:
                data = post_data.copy()
                data[param] = value
                return self.sess.post(url, data=data, timeout=self.timeout, verify=settings.verify_ssl)
            else:
                test_url = url.replace(param + "=", param + "=" + requests.utils.quote(value, safe=""))
                return self.sess.get(test_url, timeout=self.timeout, verify=settings.verify_ssl)
        except Exception:
            return None

    def _responses_differ(self, r1: requests.Response, r2: requests.Response) -> bool:
        if r1.status_code != r2.status_code:
            return True
        h1 = hashlib.md5(r1.text.encode()).hexdigest()
        h2 = hashlib.md5(r2.text.encode()).hexdigest()
        return h1 != h2

    def toctou_risk_assessment(self, param: str, method: str = "GET",
                               post_data: Optional[Dict] = None) -> Dict:
        param_lower = param.lower()

        risk_score = 0
        risk_factors = []

        for toctou_param in TOCTOU_PARAMS:
            if toctou_param in param_lower:
                risk_score += 30
                risk_factors.append("matches_toctou_param_%s" % toctou_param)

        for pattern, vuln_type in TOCTOU_PATTERNS:
            import re
            test_str = "%s %s" % (param_lower, method.lower())
            if re.search(pattern, test_str):
                risk_score += 20
                risk_factors.append("matches_pattern_%s" % vuln_type)

        if method.upper() == "POST":
            risk_score += 10
            risk_factors.append("post_method")

        if risk_score > 50:
            risk_level = "high"
        elif risk_score > 30:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "param": param,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "recommendation": "测试竞态条件" if risk_score > 30 else "低风险参数",
        }
