import re
from typing import Dict, List, Optional

from tools.log_utils import get_logger
from tools.response_profiler import ResponseProfiler

logger = get_logger("false_positive_filter")


NOISE_KEYWORDS = [
    "test", "example", "demo", "sample", "placeholder",
    "coming soon", "under construction", "default",
    "nginx default", "welcome to", "index of",
    "403 forbidden", "404 not found", "500 internal server error",
    "access denied", "access forbidden",
]

ERROR_PAGE_PATTERNS = [
    r"<title>404 Not Found</title>",
    r"<title>403 Forbidden</title>",
    r"<title>500 Internal Server Error</title>",
    r"<title>Service Unavailable</title>",
    r"<!--\s*404|404\s*-->",
    r"Page not found",
    r"The requested URL was not found",
    r"Object not found",
    r"Error 404",
    r"Error 500",
    r"Apache.*Server at",
    r"cgi-bin",
]


class FalsePositiveFilter:
    def __init__(self, profiler: Optional[ResponseProfiler] = None):
        self.profiler = profiler
        self._min_confidence_threshold = 0.5
        self._min_evidence_count = 2

    def set_threshold(self, min_confidence: float = 0.5, min_evidence: int = 2):
        self._min_confidence_threshold = min_confidence
        self._min_evidence_count = min_evidence

    def filter(self, results: List[Dict]) -> List[Dict]:
        filtered = []
        for r in results:
            if not r.get("vulnerable"):
                r["filtered"] = False
                filtered.append(r)
                continue
            if self._is_false_positive(r):
                r["filtered"] = True
                r["filter_reason"] = self._get_filter_reason(r)
                continue
            r["filtered"] = False
            filtered.append(r)
        return filtered

    def filter_single(self, result: Dict) -> Dict:
        if not result.get("vulnerable"):
            result["filtered"] = False
            return result
        if self._is_false_positive(result):
            result["filtered"] = True
            result["filter_reason"] = self._get_filter_reason(result)
            result["vulnerable"] = False
        else:
            result["filtered"] = False
        return result

    def _is_false_positive(self, result: Dict) -> bool:
        reasons = self._check_all(result)
        if len(reasons) >= 2:
            return True
        if "error_page" in reasons:
            return True
        if "low_confidence" in reasons:
            return True
        if "insufficient_evidence" in reasons:
            return True
        if "noise_keywords" in reasons:
            return True
        if "stale_data" in reasons:
            return True
        return False

    def _get_filter_reason(self, result: Dict) -> str:
        reasons = self._check_all(result)
        return "; ".join(reasons) if reasons else "unknown"

    def _check_all(self, result: Dict) -> List[str]:
        reasons = []

        if self._check_low_confidence(result):
            reasons.append("low_confidence")

        if self._check_insufficient_evidence(result):
            reasons.append("insufficient_evidence")

        if self._check_error_page(result):
            reasons.append("error_page")

        if self._check_noise_keywords(result):
            reasons.append("noise_keywords")

        if self._check_stale_data(result):
            reasons.append("stale_data")

        return reasons

    def _check_low_confidence(self, result: Dict) -> bool:
        score = result.get("confidence_score", 0)
        if isinstance(score, str):
            try:
                score = float(score)
            except (ValueError, TypeError):
                score = 0
        return score < self._min_confidence_threshold

    def _check_insufficient_evidence(self, result: Dict) -> bool:
        evidence = result.get("evidence", [])
        if not isinstance(evidence, list):
            return True
        return len(evidence) < self._min_evidence_count

    def _check_error_page(self, result: Dict) -> bool:
        response_text = ""
        if "response_text" in result:
            response_text = result.get("response_text", "")
        elif "raw_response" in result:
            raw = result.get("raw_response", {})
            if isinstance(raw, dict):
                response_text = raw.get("text", "") or raw.get("body", "") or ""
        if not response_text:
            return False
        for pat in ERROR_PAGE_PATTERNS:
            if re.search(pat, response_text, re.IGNORECASE):
                return True
        if len(response_text) < 50:
            return True
        return False

    def _check_noise_keywords(self, result: Dict) -> bool:
        response_text = ""
        if "response_text" in result:
            response_text = result.get("response_text", "")
        elif "raw_response" in result:
            raw = result.get("raw_response", {})
            if isinstance(raw, dict):
                response_text = raw.get("text", "") or raw.get("body", "") or ""
        if not response_text:
            return False
        text_lower = response_text.lower()
        noise_count = sum(1 for kw in NOISE_KEYWORDS if kw in text_lower)
        return noise_count >= 3

    def _check_stale_data(self, result: Dict) -> bool:
        timestamp = result.get("timestamp", 0)
        if not timestamp:
            return False
        import time
        return (time.time() - timestamp) > 3600


def filter_results(results: List[Dict], min_confidence: float = 0.5,
                   min_evidence: int = 2) -> List[Dict]:
    fpf = FalsePositiveFilter()
    fpf.set_threshold(min_confidence, min_evidence)
    return fpf.filter(results)


def filter_single_result(result: Dict, min_confidence: float = 0.5,
                         min_evidence: int = 2) -> Dict:
    fpf = FalsePositiveFilter()
    fpf.set_threshold(min_confidence, min_evidence)
    return fpf.filter_single(result)
