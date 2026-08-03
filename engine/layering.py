"""证据分层：相关证据取 max，跨独立证据族才叠加 (probabilistic union)。

同族 (同一机制) 的多条证据是相关的，重复命中不增加独立信息，取最大值；
不同族的证据相互独立，才能以 union 方式叠加，避免把相关证据数乘式放大。
"""

from typing import Dict, Iterable, List, Optional, Tuple

from engine.config import EVIDENCE_FAMILIES

Vote = Tuple[str, float, Optional[str]]


def classify_family(
    source: str,
    family_map: Optional[Dict[str, List[str]]] = None,
) -> str:
    """把证据源名称归类到证据族；未命中则以其自身作为独立族。"""
    if not source:
        return "unknown"
    low = source.lower()
    for family, patterns in (family_map or EVIDENCE_FAMILIES).items():
        for pat in patterns:
            if pat in low:
                return family
    return low


def layer_votes(
    votes: Iterable[Vote],
    family_map: Optional[Dict[str, List[str]]] = None,
) -> List[Tuple[str, float]]:
    """votes: (source, weight, family_or_None) 迭代。

    返回 [(family, max_weight), ...] 按权重降序 —— 每族只保留最强证据。
    """
    best: Dict[str, float] = {}
    for vote in votes:
        if len(vote) >= 3 and vote[2]:
            family = vote[2]
        else:
            family = classify_family(vote[0], family_map)
        best[family] = max(best.get(family, 0.0), float(vote[1]))
    return sorted(best.items(), key=lambda kv: kv[1], reverse=True)


def combine_independent(weights: Iterable[float]) -> float:
    """独立证据叠加：probabilistic union = 1 - prod(1 - w)。

    单条证据返回其自身权重；空集返回 0.0。
    """
    result = 0.0
    for w in weights:
        w = min(max(float(w), 0.0), 1.0)
        result = result + w - result * w
    return round(min(1.0, result), 3)
