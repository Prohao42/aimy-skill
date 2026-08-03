"""判定引擎 (Round 1+2)：差分前置 / 证据分层 / 参数化阈值 / 复现性 / 离线OOB / CVSS。

设计原则:
- 差分前置: 所有信号相对基线 (baseline) 计算，状态码绝不当独立证据。
- 证据分层: 相关证据同族取 max，跨独立证据族才叠加 (probabilistic union)。
- 阈值参数化: 零散绝对值全部收归 engine.config。
- 验证思维 > 扫描思维: 按漏洞类型分派复现性采样要求。
"""

from engine.config import DEFAULT_THRESHOLDS, EVIDENCE_FAMILIES, Thresholds
from engine.cvss import cvss_base_score, cvss_vector_for, round_up
from engine.diff import DiffSignals, ResponseDiffer
from engine.layering import classify_family, combine_independent, layer_votes
from engine.oob import OfflineOOBJudge
from engine.reproducibility import (
    DEFAULT_SAMPLES,
    REPRODUCIBILITY,
    reproduction_gate,
    samples_required,
)

__all__ = [
    "DEFAULT_THRESHOLDS",
    "EVIDENCE_FAMILIES",
    "Thresholds",
    "cvss_base_score",
    "cvss_vector_for",
    "round_up",
    "DiffSignals",
    "ResponseDiffer",
    "classify_family",
    "combine_independent",
    "layer_votes",
    "OfflineOOBJudge",
    "REPRODUCIBILITY",
    "DEFAULT_SAMPLES",
    "reproduction_gate",
    "samples_required",
]
