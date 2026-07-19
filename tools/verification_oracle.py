import time, statistics
from typing import Optional, Dict, List, Tuple
from enum import Enum
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.response_profiler import ResponseProfiler, CLEAN_VALUE

logger = get_logger("verification_oracle")


class ConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class ConfidenceVoter:
    def __init__(self):
        self.votes: List[Tuple[str, float]] = []

    def add_vote(self, source: str, weight: float):
        self.votes.append((source, weight))

    @property
    def score(self) -> float:
        if not self.votes:
            return 0.0
        weights = [w for _, w in self.votes]
        max_weight = max(weights) if weights else 0.0
        avg_weight = sum(weights) / len(weights) if weights else 0.0
        return max_weight * 0.7 + avg_weight * 0.3

    @property
    def level(self) -> ConfidenceLevel:
        s = self.score
        if s >= 0.85:
            return ConfidenceLevel.CONFIRMED
        if s >= 0.65:
            return ConfidenceLevel.HIGH
        if s >= 0.35:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    def evidence(self) -> List[str]:
        return [f"{src}:{w:.2f}" for src, w in self.votes]

    @staticmethod
    def vote_status_code(resp, baseline_status: int) -> float:
        if resp.status_code == baseline_status:
            return 0.0
        if resp.status_code in (500, 502, 503):
            return 0.5
        if baseline_status == 200 and resp.status_code == 200:
            return 0.1
        return 0.3

    @staticmethod
    def vote_length_diff(cur_len: int, baseline_len: int) -> float:
        if baseline_len <= 0:
            return 0.0
        ratio = abs(cur_len - baseline_len) / baseline_len
        if ratio > 0.2:
            return 0.7
        if ratio > 0.08:
            return 0.5
        if ratio > 0.03:
            return 0.3
        return 0.0

    @staticmethod
    def vote_body_hash(cur_hash: str, baseline_hash: str) -> float:
        return 0.6 if cur_hash != baseline_hash else 0.0

    @staticmethod
    def vote_time_elapsed(elapsed: float, baseline: float, threshold: float) -> float:
        if elapsed >= threshold:
            return min(0.9, elapsed / (threshold * 2))
        return 0.0

    @staticmethod
    def vote_evidence_keywords(text: str, keywords: List[str]) -> float:
        matches = sum(1 for kw in keywords if kw in text)
        if matches >= 3:
            return 0.9
        if matches >= 1:
            return 0.5
        return 0.0

    @staticmethod
    def vote_oob_callback(callback_received: bool) -> float:
        return 0.95 if callback_received else 0.0

    @staticmethod
    def vote_multiple_payloads(confirmed_count: int, total_tried: int) -> float:
        if total_tried == 0:
            return 0.0
        rate = confirmed_count / total_tried
        if rate >= 0.5:
            return 0.8
        if rate >= 0.25:
            return 0.5
        return 0.2


class VerificationOracle:
    def __init__(self, response_profiler: Optional[ResponseProfiler] = None):
        self.profiler = response_profiler or ResponseProfiler()

    def verify(self, detector_type: str, finding: Dict, url: str, param: str,
               sess: requests.Session, timeout: float = 10.0,
               post_body: bool = False, post_data: dict = None) -> Dict:
        if not finding.get("vulnerable"):
            finding["confidence_votes"] = []
            finding["confidence_score"] = 0.0
            return finding

        voter = ConfidenceVoter()

        if detector_type == "sqli":
            return self._verify_sqli(finding, url, param, sess, timeout, post_body, post_data, voter)
        elif detector_type == "cmdi":
            return self._verify_cmdi(finding, url, param, sess, timeout, voter)
        elif detector_type == "xss":
            return self._verify_xss(finding, url, param, sess, timeout, post_body, post_data, voter)
        elif detector_type == "lfi":
            return self._verify_lfi(finding, url, param, sess, timeout, voter)
        elif detector_type == "ssrf":
            return self._verify_ssrf(finding, voter)
        return finding

    def _verify_sqli(self, finding, url, param, sess, timeout, post_body, post_data, voter):
        profiler = self.profiler
        baseline = profiler.profile_endpoint(url, param, sess, timeout)
        if baseline is None:
            return finding

        from tools.payload_engine import generate, generate_sqli_boolean
        baseline_sec = baseline.elapsed if baseline.elapsed > 0 else self._measure_baseline(url, param, sess, timeout)

        time_ok = baseline_sec < timeout * 0.8
        if time_ok:
            threshold = max(2.0, baseline_sec * 1.5 + 1.5)
            time_payloads = generate("sqli", "time_mysql", "all", max_payloads=3)
            time_confirmed = 0
            for entry in time_payloads:
                try:
                    start = time.time()
                    sess.get(build_url(url, param, entry["payload"]), timeout=timeout + 3)
                    elapsed = time.time() - start
                    if elapsed >= threshold:
                        time_confirmed += 1
                        voter.add_vote("time_delay", voter.vote_time_elapsed(elapsed, baseline_sec, threshold))
                except requests.Timeout:
                    voter.add_vote("timeout", 0.7)
                    time_confirmed += 1
                except Exception:
                    continue
            if time_confirmed >= 2:
                voter.add_vote("time_confirmed", 0.85)

        ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page", "limit", "offset") else "string"
        pairs = generate_sqli_boolean(ctx)
        confirmed = 0
        for true_p, false_p in pairs[:4]:
            try:
                r_true = sess.get(build_url(url, param, true_p), timeout=timeout)
                r_false = sess.get(build_url(url, param, false_p), timeout=timeout)
                true_report = profiler.analyze(url, param, r_true)
                false_report = profiler.analyze(url, param, r_false)
                if true_report.is_anomalous != false_report.is_anomalous:
                    confirmed += 1
                    voter.add_vote("bool_pair_diff", 0.6)
                diff = abs(len(r_true.text) - len(r_false.text))
                max_len = max(len(r_true.text), len(r_false.text), 1)
                if diff / max_len > 0.03 and diff > 30:
                    voter.add_vote("bool_length_diff", 0.5)
                    confirmed += 1
            except Exception:
                continue

        if confirmed >= 2:
            voter.add_vote("bool_multi_confirmed", 0.75)
        elif confirmed >= 1:
            voter.add_vote("bool_single_confirmed", 0.4)

        finding["confidence"] = voter.level.value
        finding["confidence_score"] = round(voter.score, 2)
        finding["confidence_votes"] = voter.evidence()
        finding["verified"] = voter.level in (ConfidenceLevel.HIGH, ConfidenceLevel.CONFIRMED)
        return finding

    def _verify_cmdi(self, finding, url, param, sess, timeout, voter):
        baseline_sec = self._measure_baseline(url, param, sess, timeout)
        threshold = max(2.5, baseline_sec * 1.5 + 2.0)

        from tools.payload_engine import generate
        time_seeds = generate("cmdi", "time", "all", max_payloads=4)
        confirmed = 0
        for entry in time_seeds:
            try:
                start = time.time()
                sess.get(build_url(url, param, entry["payload"]), timeout=timeout + 3)
                elapsed = time.time() - start
                if elapsed >= threshold:
                    confirmed += 1
                    voter.add_vote("time_delay", voter.vote_time_elapsed(elapsed, baseline_sec, threshold))
            except requests.Timeout:
                voter.add_vote("timeout", 0.7)
                confirmed += 1
            except Exception:
                continue

        output_seeds = generate("cmdi", "output", "all", max_payloads=3)
        for entry in output_seeds:
            indicator = entry.get("indicator", "")
            if indicator:
                try:
                    r = sess.get(build_url(url, param, entry["payload"]), timeout=timeout)
                    if indicator in r.text:
                        voter.add_vote("output_indicator", 0.7)
                        confirmed += 1
                except Exception:
                    continue

        if confirmed >= 2:
            voter.add_vote("multi_confirmed", 0.8)
        finding["confidence"] = voter.level.value
        finding["confidence_score"] = round(voter.score, 2)
        finding["confidence_votes"] = voter.evidence()
        finding["verified"] = voter.level in (ConfidenceLevel.HIGH, ConfidenceLevel.CONFIRMED)
        return finding

    def _verify_xss(self, finding, url, param, sess, timeout, post_body, post_data, voter):
        import random
        from tools.payload_engine import generate
        from tools.html_context_parser import probe_and_detect

        detected_ctx = probe_and_detect(url, param, sess, timeout, post_body, post_data)
        if detected_ctx in ("not_reflected", "unknown"):
            voter.add_vote("context_not_reflected", 0.1)
        else:
            voter.add_vote("context_reflected", 0.3)

        marker = "VFY_XSS_%d" % random.randint(1000, 9999)
        confirmed = 0
        total = 0

        contexts = [detected_ctx] if detected_ctx not in ("not_reflected", "unknown") else ["html", "attr", "js"]
        for ctx in contexts:
            seeds = generate("xss", ctx, "all", max_payloads=3)
            for entry in seeds:
                total += 1
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
                            confirmed += 1
                            voter.add_vote("unescaped_reflection", 0.65)
                            if any(t in r.text for t in ["alert(1)", "onerror=", "onload=", "onfocus="]):
                                voter.add_vote("trigger_fired", 0.85)
                except Exception:
                    continue

        voter.add_vote("payload_ratio", voter.vote_multiple_payloads(confirmed, total))
        finding["confidence"] = voter.level.value
        finding["confidence_score"] = round(voter.score, 2)
        finding["confidence_votes"] = voter.evidence()
        finding["verified"] = voter.level in (ConfidenceLevel.HIGH, ConfidenceLevel.CONFIRMED)
        return finding

    def _verify_lfi(self, finding, url, param, sess, timeout, voter):
        from tools.payload_engine import generate
        seeds = generate("lfi", "encoded", "all", max_payloads=5)
        confirmed = 0
        for entry in seeds:
            try:
                r = sess.get(build_url(url, param, entry["payload"]), timeout=timeout)
                if "root:" in r.text:
                    voter.add_vote("etc_passwd", 0.8)
                    confirmed += 1
                if "[fonts]" in r.text:
                    voter.add_vote("win_ini", 0.8)
                    confirmed += 1
                if len(r.text) > 100 and r.status_code == 200:
                    voter.add_vote("non_empty_response", 0.3)
                    confirmed += 0.5
            except Exception:
                continue
        if confirmed >= 2:
            voter.add_vote("multi_file_confirmed", 0.75)
        finding["confidence"] = voter.level.value
        finding["confidence_score"] = round(voter.score, 2)
        finding["confidence_votes"] = voter.evidence()
        finding["verified"] = voter.level in (ConfidenceLevel.HIGH, ConfidenceLevel.CONFIRMED)
        return finding

    def _verify_ssrf(self, finding, voter):
        ftype = finding.get("type", "")
        if ftype == "disclosure":
            voter.add_vote("disclosure", 0.6)
        elif "oob_http_callback" in ftype or "oob_dns_callback" in ftype:
            voter.add_vote("oob_callback", 0.95)
        if finding.get("oob_type") in ("dns", "http"):
            voter.add_vote(f"oob_{finding['oob_type']}", 0.9)
        finding["confidence"] = voter.level.value
        finding["confidence_score"] = round(voter.score, 2)
        finding["confidence_votes"] = voter.evidence()
        finding["verified"] = voter.level in (ConfidenceLevel.HIGH, ConfidenceLevel.CONFIRMED)
        return finding

    def _measure_baseline(self, url, param, sess, timeout):
        samples = []
        for _ in range(3):
            try:
                start = time.time()
                sess.get(build_url(url, param, CLEAN_VALUE), timeout=timeout)
                samples.append(time.time() - start)
            except Exception:
                pass
        if not samples:
            return 0.3
        return statistics.median(samples) if len(samples) >= 3 else sum(samples) / len(samples)
