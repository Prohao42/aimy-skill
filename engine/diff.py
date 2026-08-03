"""响应差分核心：所有信号相对基线计算，状态码绝不充当独立证据。

「差分前置」：payload 响应 vs 同源基线 (baseline) 的相对偏差才有意义。
status_delta 只是差分信号的一部分，且只归入 response_diff 单一证据族，
绝不允许作为独立证据叠加。
"""

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Optional

from engine.config import DEFAULT_THRESHOLDS, Thresholds

_MAX_BODY_BYTES = 20000


@dataclass
class DiffSignals:
    status_delta: int = 0
    length_ratio: float = 0.0
    body_changed: bool = False
    latency_ratio: float = 0.0
    elapsed: float = 0.0
    content_similarity: float = 1.0
    baseline_present: bool = False

    @property
    def is_differential(self) -> bool:
        """基线存在且出现长度/内容/状态的相对偏差。"""
        if not self.baseline_present:
            return False
        return (
            abs(self.length_ratio) >= 0.03
            or self.body_changed
            or abs(self.status_delta) != 0
        )


class ResponseDiffer:
    def __init__(self, thresholds: Optional[Thresholds] = None):
        self.thresholds = thresholds or DEFAULT_THRESHOLDS

    def compare(self, resp, baseline, elapsed: float = 0.0) -> DiffSignals:
        """resp: requests.Response；baseline: 具 status/length/body_hash/elapsed 的对象。"""
        sig = DiffSignals(baseline_present=baseline is not None)
        if baseline is None:
            return sig

        sig.status_delta = resp.status_code - baseline.status
        base_len = baseline.length
        cur_len = len(resp.text)
        if base_len > 0:
            sig.length_ratio = abs(cur_len - base_len) / base_len
        if getattr(baseline, "body_hash", ""):
            sig.body_changed = self._hash(resp.text) != baseline.body_hash
        if getattr(baseline, "elapsed", 0) and baseline.elapsed > 0 and elapsed > 0:
            sig.latency_ratio = elapsed / baseline.elapsed
        sig.elapsed = elapsed
        base_text = getattr(baseline, "text", None)
        sig.content_similarity = (
            self._similarity(resp.text, base_text) if base_text else 1.0
        )
        return sig

    def differential_weight(self, sig: DiffSignals) -> float:
        """差分信号 -> 单一相关证据权重。

        只产出一个权重 (response_diff 族)，长度/内容/延迟/状态任一信号
        都只是该族的一部分，绝不拆成多条独立证据叠加。
        """
        th = self.thresholds
        if not sig.baseline_present:
            return 0.0
        w = 0.0
        if sig.length_ratio >= th.length_diff_ratio_strong:
            w = max(w, 0.6)
        elif sig.length_ratio >= th.length_diff_ratio:
            w = max(w, 0.5)
        elif sig.length_ratio >= th.length_diff_ratio_weak:
            w = max(w, 0.3)
        if sig.body_changed and w < 0.5:
            w = max(w, 0.4)
        if sig.latency_ratio >= th.latency_ratio and w < 0.5:
            w = max(w, 0.4)
        if abs(sig.status_delta) != 0 and w < 0.4:
            w = max(w, 0.3)
        return round(w, 2)

    @staticmethod
    def _hash(text: str) -> str:
        import hashlib

        return hashlib.md5(text.encode()).hexdigest()[:16]

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        ta, tb = a[:_MAX_BODY_BYTES], b[:_MAX_BODY_BYTES]
        return SequenceMatcher(None, ta, tb).ratio()
