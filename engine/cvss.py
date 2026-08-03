"""CVSS:3.1 合法向量推导与评分。

按 FIRST 官方公式与指标权重实现，不编造修正系数。
BaseScore = Roundup(min(Impact + Exploitability, 10))，Roundup 向上取整到 0.1。
"""

import math
from typing import Dict

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

_VALID_VALUES = {
    "AV": set("NALP"),
    "AC": set("LH"),
    "PR": set("NLH"),
    "UI": set("NR"),
    "S": set("UC"),
    "C": set("NLH"),
    "I": set("NLH"),
    "A": set("NLH"),
}

_DEFAULT_VECTORS: Dict[str, str] = {
    "sqli": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "sql_injection": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cmdi": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "xss": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "ssti": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "lfi": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "nosqli": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssrf": "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N",
    "xxe": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "deser": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "graphql": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
}


def cvss_vector_for(vtype: str) -> str:
    return _DEFAULT_VECTORS.get(
        vtype, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )


def _parse(vector: str) -> Dict[str, str]:
    parts: Dict[str, str] = {}
    for chunk in vector.split("/"):
        chunk = chunk.strip()
        if ":" in chunk:
            key, val = chunk.split(":", 1)
            parts[key] = val.upper()
    return parts


def _valid(vector: str) -> bool:
    parts = _parse(vector)
    if set(parts) != set(_VALID_VALUES):
        return False
    for key, values in _VALID_VALUES.items():
        if parts.get(key) not in values:
            return False
    return True


def round_up(value: float) -> float:
    """CVSS v3.1 Roundup：返回不小于输入的最小一位小数。"""
    return math.ceil(value * 10.0) / 10.0


def cvss_base_score(vector: str) -> float:
    """按 CVSS:3.1 官方公式计算 Base Score；非法向量抛 ValueError。"""
    if not _valid(vector):
        raise ValueError("invalid CVSS:3.1 vector: %r" % vector)
    parts = _parse(vector)
    scope_changed = parts["S"] == "C"

    iss = 1.0 - (
        (1.0 - _CIA[parts["C"]])
        * (1.0 - _CIA[parts["I"]])
        * (1.0 - _CIA[parts["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = (
        8.22
        * _AV[parts["AV"]]
        * _AC[parts["AC"]]
        * _PR[parts["S"]][parts["PR"]]
        * _UI[parts["UI"]]
    )

    if impact <= 0:
        return 0.0
    return round_up(min(impact + exploitability, 10.0))
