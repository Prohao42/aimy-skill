import statistics
import time
from enum import Enum
from typing import Dict, List, Optional, Tuple

import requests

from engine.config import DEFAULT_THRESHOLDS
from engine.cvss import cvss_base_score, cvss_vector_for
from engine.diff import ResponseDiffer
from engine.layering import combine_independent, layer_votes
from engine.reproducibility import reproduction_gate, samples_required
from tools.http_client import build_url
from tools.log_utils import get_logger
from tools.response_profiler import CLEAN_VALUE, ResponseProfiler

logger = get_logger("verification_oracle")


class ConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"

    @classmethod
    def from_score(cls, score: float) -> "ConfidenceLevel":
        if score >= 0.85:
            return cls.CONFIRMED
        if score >= 0.65:
            return cls.HIGH
        if score >= 0.35:
            return cls.MEDIUM
        return cls.LOW


class ConfidenceVoter:
    """证据投票器，基于 engine 分层规则：

    同一证据族 (family) 内取 max，跨独立族以 union 叠加 —— 相关证据绝不叠加。
    """

    def __init__(self):
        self.votes: List[Tuple[str, float, Optional[str]]] = []

    def add_vote(self, source: str, weight: float, family: Optional[str] = None):
        self.votes.append((source, weight, family))

    @property
    def score(self) -> float:
        layered = layer_votes(self.votes)
        return combine_independent([w for _, w in layered])

    @property
    def level(self) -> ConfidenceLevel:
        return ConfidenceLevel.from_score(self.score)

    def evidence(self) -> List[str]:
        return [f"{src}:{w:.2f}" for src, w, _ in self.votes]

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
        self._differ = ResponseDiffer(DEFAULT_THRESHOLDS)

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

    def _emit(self, finding: Dict, voter: ConfidenceVoter, vtype: str,
              observed: Optional[int] = None) -> Dict:
        """产出最终判定：复现性门控 + CVSS 向量推导。"""
        raw = voter.score
        effective, reproduced = reproduction_gate(vtype, observed, raw)
        level = ConfidenceLevel.from_score(effective)
        finding["confidence"] = level.value
        finding["confidence_score"] = round(effective, 2)
        finding["confidence_votes"] = voter.evidence()
        finding["verified"] = (
            level in (ConfidenceLevel.HIGH, ConfidenceLevel.CONFIRMED) and reproduced
        )
        finding["reproduction"] = {
            "samples_required": samples_required(vtype),
            "observed": observed,
            "reproduced": reproduced,
        }
        try:
            vector = cvss_vector_for(vtype)
            finding["cvss_vector"] = vector
            finding["cvss_score"] = cvss_base_score(vector)
        except ValueError:
            pass
        return finding

    def _verify_sqli(self, finding, url, param, sess, timeout, post_body, post_data, voter):
        profiler = self.profiler
        baseline = profiler.profile_endpoint(url, param, sess, timeout)
        if baseline is None:
            return finding

        from tools.payload_engine import generate, generate_sqli_boolean

        th = DEFAULT_THRESHOLDS
        baseline_sec = baseline.elapsed if baseline.elapsed > 0 else self._measure_baseline(url, param, sess, timeout)

        observed = 0
        time_ok = baseline_sec < timeout * 0.8
        if time_ok:
            threshold = max(th.latency_floor_s, baseline_sec * th.latency_ratio + th.latency_margin_s)
            time_payloads = generate("sqli", "time_mysql", "all", max_payloads=3)
            time_confirmed = 0
            for entry in time_payloads:
                try:
                    start = time.time()
                    sess.get(build_url(url, param, entry["payload"]), timeout=timeout + 3)
                    elapsed = time.time() - start
                    if elapsed >= threshold:
                        time_confirmed += 1
                        voter.add_vote("time_delay",
                                       voter.vote_time_elapsed(elapsed, baseline_sec, threshold),
                                       family="time_delay")
                except requests.Timeout:
                    voter.add_vote("timeout", 0.7, family="time_delay")
                    time_confirmed += 1
                except Exception:
                    continue
            observed = time_confirmed
            if time_confirmed >= 2:
                voter.add_vote("time_confirmed", 0.85, family="time_delay")

        ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page", "limit", "offset") else "string"
        pairs = generate_sqli_boolean(ctx)
        bool_confirmed = 0
        for true_p, false_p in pairs[:4]:
            try:
                r_true = sess.get(build_url(url, param, true_p), timeout=timeout)
                r_false = sess.get(build_url(url, param, false_p), timeout=timeout)
                true_report = profiler.analyze(url, param, r_true)
                false_report = profiler.analyze(url, param, r_false)
                if true_report.is_anomalous != false_report.is_anomalous:
                    bool_confirmed += 1
                    voter.add_vote("bool_pair_diff", 0.6, family="boolean_diff")
                sig = self._differ.compare(r_true, baseline)
                dw = self._differ.differential_weight(sig)
                if dw > 0:
                    bool_confirmed += 1
                    voter.add_vote("bool_vs_baseline_diff", dw, family="boolean_diff")
            except Exception:
                continue
        if bool_confirmed >= 2:
            voter.add_vote("bool_multi_confirmed", 0.75, family="boolean_diff")
            observed = max(observed, bool_confirmed)
        elif bool_confirmed >= 1:
            voter.add_vote("bool_single_confirmed", 0.4, family="boolean_diff")
            observed = max(observed, bool_confirmed)

        return self._emit(finding, voter, "sqli", observed=observed)

    def _verify_cmdi(self, finding, url, param, sess, timeout, voter):
        th = DEFAULT_THRESHOLDS
        baseline_sec = self._measure_baseline(url, param, sess, timeout)
        threshold = max(th.latency_floor_s, baseline_sec * th.latency_ratio + th.latency_margin_s)

        from tools.payload_engine import generate
        observed = 0
        time_seeds = generate("cmdi", "time", "all", max_payloads=4)
        for entry in time_seeds:
            try:
                start = time.time()
                sess.get(build_url(url, param, entry["payload"]), timeout=timeout + 3)
                elapsed = time.time() - start
                if elapsed >= threshold:
                    observed += 1
                    voter.add_vote("time_delay",
                                   voter.vote_time_elapsed(elapsed, baseline_sec, threshold),
                                   family="time_delay")
            except requests.Timeout:
                voter.add_vote("timeout", 0.7, family="time_delay")
                observed += 1
            except Exception:
                continue

        output_seeds = generate("cmdi", "output", "all", max_payloads=3)
        for entry in output_seeds:
            indicator = entry.get("indicator", "")
            if indicator:
                try:
                    r = sess.get(build_url(url, param, entry["payload"]), timeout=timeout)
                    if indicator in r.text:
                        voter.add_vote("output_indicator", 0.7, family="output_indicator")
                        observed += 1
                except Exception:
                    continue

        if observed >= 2:
            voter.add_vote("multi_confirmed", 0.8, family="output_indicator")
        return self._emit(finding, voter, "cmdi", observed=observed)

    def _verify_xss(self, finding, url, param, sess, timeout, post_body, post_data, voter):
        import random

        from tools.html_context_parser import probe_and_detect
        from tools.payload_engine import generate

        detected_ctx = probe_and_detect(url, param, sess, timeout, post_body, post_data)
        if detected_ctx in ("not_reflected", "unknown"):
            voter.add_vote("context_not_reflected", 0.1, family="reflection")
        else:
            voter.add_vote("context_reflected", 0.3, family="reflection")

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
                            voter.add_vote("unescaped_reflection", 0.65, family="reflection")
                            if any(t in r.text for t in ["alert(1)", "onerror=", "onload=", "onfocus="]):
                                voter.add_vote("trigger_fired", 0.85, family="reflection")
                except Exception:
                    continue

        voter.add_vote("payload_ratio", voter.vote_multiple_payloads(confirmed, total), family="reflection")
        return self._emit(finding, voter, "xss", observed=confirmed)

    def _verify_lfi(self, finding, url, param, sess, timeout, voter):
        from tools.payload_engine import generate
        seeds = generate("lfi", "encoded", "all", max_payloads=5)
        confirmed = 0
        for entry in seeds:
            try:
                r = sess.get(build_url(url, param, entry["payload"]), timeout=timeout)
                matched = False
                if "root:" in r.text:
                    voter.add_vote("etc_passwd", 0.8, family="content_signature")
                    matched = True
                if "[fonts]" in r.text:
                    voter.add_vote("win_ini", 0.8, family="content_signature")
                    matched = True
                if matched:
                    confirmed += 1
            except Exception:
                continue
        if confirmed >= 2:
            voter.add_vote("multi_file_confirmed", 0.75, family="content_signature")
        return self._emit(finding, voter, "lfi", observed=confirmed)

    def _verify_ssrf(self, finding, voter):
        ftype = finding.get("type", "") or ""
        observed = 0
        if ftype == "disclosure":
            voter.add_vote("disclosure", 0.6, family="oob_callback")
            observed = 1
        if "oob_http_callback" in ftype or "oob_dns_callback" in ftype:
            voter.add_vote("oob_callback", 0.95, family="oob_callback")
            observed = 1
        if finding.get("oob_type") in ("dns", "http"):
            voter.add_vote("oob_%s" % finding["oob_type"], 0.9, family="oob_callback")
            observed = 1
        # 无回调/无内容签名的「可能命中」绝不当独立证据，交由离线判定，不给 0.5。
        return self._emit(finding, voter, "ssrf", observed=observed)

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
