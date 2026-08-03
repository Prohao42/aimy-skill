"""复现性分派：按漏洞类型要求采样次数，不足则封顶置信度。

反射 XSS / SSTI 一次渲染即确认；时间/布尔/NoSQLi/CMDi/反序列化 需多采样复现；
SSRF 在 OOB 回调下一次即确认，离线差分路径则要求多采样。
"""

from typing import Dict, Optional, Tuple

from engine.config import DEFAULT_THRESHOLDS, Thresholds

REPRODUCIBILITY: Dict[str, dict] = {
    "xss": {"samples_required": 1, "note": "反射 XSS 一次渲染即确认"},
    "ssti": {"samples_required": 1, "note": "SSTI 一次渲染即确认"},
    "lfi": {"samples_required": 1, "note": "LFI 内容签名一次命中即确认"},
    "sqli": {"samples_required": 3, "note": "SQLi 时间/布尔需多采样复现"},
    "sql_injection": {"samples_required": 3, "note": "SQLi 时间/布尔需多采样复现"},
    "cmdi": {"samples_required": 3, "note": "CMDi 需多采样复现"},
    "nosqli": {"samples_required": 3, "note": "NoSQLi 需多采样复现"},
    "ssrf": {"samples_required": 1, "note": "OOB 回调一次即确认；离线差分路径需多采样"},
    "deser": {"samples_required": 3, "note": "反序列化需多采样复现"},
    "xxe": {"samples_required": 1, "note": "XXE OOB/内容签名一次即确认"},
    "graphql": {"samples_required": 1, "note": "GraphQL 一次即确认"},
}

DEFAULT_SAMPLES = 3


def samples_required(vtype: str) -> int:
    return REPRODUCIBILITY.get(vtype, {}).get("samples_required", DEFAULT_SAMPLES)


def reproduction_gate(
    vtype: str,
    observed: Optional[int],
    confidence: float,
    thresholds: Optional[Thresholds] = None,
) -> Tuple[float, bool]:
    """返回 (effective_confidence, reproduced)。

    采样不足时置信度封顶于 reproduction_cap，绝不进入 CONFIRMED。
    observed=None 表示未统计采样，不施加封顶。
    """
    th = thresholds or DEFAULT_THRESHOLDS
    if observed is None:
        return confidence, True
    if observed >= samples_required(vtype):
        return confidence, True
    return min(confidence, th.reproduction_cap), False
