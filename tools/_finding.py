"""统一 Security Finding 模型。

所有 Detector 返回的结果必须符合此结构。
兼容旧格式检测与适配。

原则：
1. 新检测器直接返回 Finding 实例
2. 旧检测器通过 Adapter 转换
3. _output() 函数统一处理 Finding 列表
4. 序列化/报告均基于此模型
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    """漏洞严重程度枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(str, Enum):
    """漏洞类型枚举 (与 Skill 类目一致)"""
    SQLI = "sqli"
    BLIND_SQLI = "sqli-blind"
    OOB_SQLI = "sqli-oob"
    XSS = "xss"
    DOM_XSS = "dom-xss"
    XSS_VALIDATE = "xss-validate"
    SSTI = "ssti"
    CMDI = "cmdi"
    LFI = "lfi"
    XXE = "xxe"
    NOSQLI = "nosqli"
    JWT = "jwt"
    CSRF = "csrf"
    AUTH_BYPASS = "auth-bypass"
    CORS = "cors"
    PROTO_POLLUTION = "proto-pollution"
    TYPE_CONFUSION = "type-confusion"
    BIZ_LOGIC = "biz-logic"
    RACE_CONDITION = "race"
    WAF_BYPASS = "waf-bypass"
    WAF_HEAVY = "waf-heavy"
    SSRF = "ssrf"
    SSRF_PWN = "ssrf-pwn"
    SSRF_CHAIN = "ssrf-chain"
    SQLI_WEAPONIZE = "sqli-weaponize"
    DESER_WEAPONIZE = "deser-weaponize"
    REVERSE_SHELL = "reverse-shell"
    CLOUD_PWN = "cloud-pwn"
    IDOR = "idor"
    CMS_FINGERPRINT = "cms-fingerprint"
    GRAPHQL = "graphql"
    GRAPHQL_ABUSE = "graphql-abuse"


@dataclass
class Evidence:
    """证据结构（标准化）"""
    request: Optional[Dict] = None  # {method, url, headers, body}
    response: Optional[Dict] = None  # {status, headers, body, time}
    headers: Optional[Dict] = None  # 关键响应头
    payload: Optional[str] = None  # 触发漏洞的 payload
    indicator: Optional[str] = None  # 关键指标 (keyword, pattern, etc)
    timestamp: Optional[float] = None


@dataclass
class Finding:
    """统一 Security Finding 模型。

    所有检测器必须返回此结构（直接或通过 Adapter）。
    """

    # 域标识
    id: str  # 唯一标识 (生成器责任，格式: {detector_name}_{timestamp})
    vuln_type: VulnType  # 漏洞类型
    severity: Severity  # 严重程度
    title: str  # 可读标题

    # 目标信息
    target: str  # 目标 URL/IP
    endpoint: str  # 受影响端点 (含查询参数)
    parameter: str  # 受控参数名

    # 置信度与证据
    confidence: float  # 0.0 - 1.0
    description: str  # 人类可读描述
    evidence: Evidence  # 关键证据 (请求/响应/payload)
    verification: Optional[Dict] = None  # 验证信息

    # 元数据
    risk: int = 5  # 风险等级 (1-10)
    tags: List[str] = field(default_factory=list)  # 标签列表
    detected_at: float = field(default_factory=lambda: __import__("time").time())

    # 参考信息
    references: List[str] = field(default_factory=list)  # CVE/CWE/文档引用

    def to_dict(self) -> Dict:
        """转换为字典 (用于 JSON 序列化/报告)"""
        return {
            "id": self.id,
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "target": self.target,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "confidence": round(self.confidence, 4),
            "description": self.description,
            "evidence": self.evidence.to_dict() if self.evidence else {},
            "verification": self.verification,
            "risk": self.risk,
            "tags": self.tags,
            "detected_at": self.detected_at,
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Finding":
        """从字典创建 (用于报告恢复/反序列化)"""
        evidence_data = data.get("evidence", {})
        evidence = Evidence(
            request=evidence_data.get("request"),
            response=evidence_data.get("response"),
            headers=evidence_data.get("headers"),
            payload=evidence_data.get("payload"),
            indicator=evidence_data.get("indicator"),
            timestamp=evidence_data.get("timestamp"),
        )

        try:
            vuln_type = VulnType(data["vuln_type"])
        except (KeyError, ValueError):
            vuln_type = VulnType.INFO

        try:
            severity = Severity(data["severity"])
        except (KeyError, ValueError):
            severity = Severity.MEDIUM

        return cls(
            id=data.get("id", ""),
            vuln_type=vuln_type,
            severity=severity,
            title=data.get("title", "Unnamed Finding"),
            target=data.get("target", ""),
            endpoint=data.get("endpoint", ""),
            parameter=data.get("parameter", ""),
            confidence=float(data.get("confidence", 0.5)),
            description=data.get("description", ""),
            evidence=evidence,
            verification=data.get("verification"),
            risk=int(data.get("risk", 5)),
            tags=data.get("tags", []),
            detected_at=data.get("detected_at", 0),
            references=data.get("references", []),
        )

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}]{self.vuln_type} @ {self.endpoint}"

    def __repr__(self) -> str:
        return f"Finding(id='{self.id}', vuln_type={self.vuln_type}, severity={self.severity}, target='{self.target}')"[:120]


# 便捷工具函数

def make_finding(
    vuln_type: str,
    endpoint: str,
    parameter: str,
    title: str,
    severity: str = "medium",
    confidence: float = 0.5,
    target: str = "",
    **kwargs,
) -> Finding:
    """快速创建 Finding 实例 (装配器常用)"""
    from ._finding import Severity, VulnType

    try:
        vt = VulnType(vuln_type)
    except (ValueError, KeyError):
        vt = VulnType.INFO

    try:
        sev = Severity(severity)
    except (ValueError, KeyError):
        sev = Severity.MEDIUM

    import time
    finding_id = f"{vt.value}_{endpoint}_{parameter}_{int(kwargs.get('timestamp', time.time()))}"

    evidence = Evidence(
        payload=kwargs.get("payload"),
        indicator=kwargs.get("indicator"),
    )

    return Finding(
        id=finding_id,
        vuln_type=vt,
        severity=sev,
        title=title,
        target=target or endpoint,
        endpoint=endpoint,
        parameter=parameter,
        confidence=confidence,
        description=kwargs.get("description", ""),
        evidence=evidence,
        verification=kwargs.get("verification"),
        risk=kwargs.get("risk", 5),
        tags=kwargs.get("tags", []),
    )


# 旧格式适配器

class OldFormatFinding:
    """兼容旧格式 Finding 的适配器。

    支持检测器返回 dict/旧格式结构的平滑过渡。
    """

    @staticmethod
    def adapt(data: Dict) -> Finding:
        """将旧格式 dict 转换为统一 Finding。

        旧格式可能包含的键:
        - vulnerable: bool
        - type: str
        - url: str
        - param: str
        - evidence: dict
        - description: str
        - severity: str
        - ...
        """
        # 提取基本信息
        vuln_type_str = data.get("type", "info").lower()
        endpoint = data.get("url", "").rsplit("?", 1)[0] or ""
        param = data.get("param", endpoint.split("?")[-1] if "?" in endpoint else "")
        title = data.get("description", "Detection")[:100]
        severity_str = data.get("severity", "medium").lower()
        confidence = data.get("confidence", 0.5)

        # 映射严重程度
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }
        severity = Severity(severity_map.get(severity_str, "medium"))

        # 映射漏洞类型 (简易映射)
        type_map = {
            "sqli": "sqli",
            "xss": "xss",
            "ssrf": "ssrf",
            "ssti": "ssti",
            "cmdi": "cmdi",
            "lfi": "lfi",
            "xxe": "xxe",
            "nosqli": "nosqli",
            "jwt": "jwt",
            "csrf": "csrf",
            "auth-bypass": "auth-bypass",
            "cors": "cors",
            "waf": "waf-bypass",
        }
        vuln_type = VulnType(type_map.get(vuln_type_str, "info"))

        # 构建证据
        evidence_data = data.get("evidence", {})
        evidence = Evidence(
            request=evidence_data.get("request"),
            response=evidence_data.get("response"),
            payload=evidence_data.get("payload"),
            indicator=evidence_data.get("indicator"),
        )

        # 生成 ID
        import time
        finding_id = f"{vuln_type_str}_{endpoint}_{param}_{int(time.time())}"

        return Finding(
            id=finding_id,
            vuln_type=vuln_type,
            severity=severity,
            title=title,
            target=data.get("url", endpoint),
            endpoint=endpoint,
            parameter=param or "",
            confidence=float(confidence),
            description=title,
            evidence=evidence,
            verification=data.get("verification"),
            risk=data.get("risk", 5),
            tags=data.get("tags", []),
        )
