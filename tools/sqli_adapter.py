"""SQLi 检测器适配器 - 统一接口适配。

演示如何将现有的 sql_injection.py 检测器适配到统一 Finding 模型。

适配器模式:
旧检测器函数 -> adapt_old_format() -> Finding 实例
"""

from typing import Dict

from tools._finding import Evidence, Finding, Severity, VulnType


def adapt_sql_injection_old(result_dict: Dict) -> Finding:
    """适配旧格式的 SQLi 检测结果。

    旧格式期望包含的键:
    - vulnerable: bool
    - type: str (如 "sqli", "boolean_blind", "union_blind")
    - url: str
    - param: str
    - description: str
    - severity: str (如 "critical", "high", "medium")
    - evidence: dict (可选)
      - request: dict
      - response: dict
      - payload: str
    """
    vuln_type_str = result_dict.get("type", "sqli").lower()
    endpoint = result_dict.get("url", "").rsplit("?", 1)[0] or ""
    param = result_dict.get("param", endpoint.split("?")[-1] if "?" in endpoint else "")
    title = result_dict.get("description", "SQL Injection Detection")[:120]
    severity_str = result_dict.get("severity", "medium").lower()

    # 映射严重程度
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    severity = Severity(severity_map.get(severity_str, "medium"))

    # 映射漏洞类型
    type_map = {
        "boolean_blind": "sqli-blind",
        "time_blind": "sqli-blind",
        "union_blind": "sqli-blind",
        "error_based": "sqli",
        "union": "sqli",
        "error": "sqli",
    }
    vuln_type = VulnType(type_map.get(vuln_type_str, "sqli"))

    # 构建证据
    evidence_data = result_dict.get("evidence", {})
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
        target=result_dict.get("url", endpoint),
        endpoint=endpoint,
        parameter=param or "",
        confidence=float(result_dict.get("confidence", 0.8)),
        description=title,
        evidence=evidence,
        verification=result_dict.get("verification"),
        risk=int(result_dict.get("risk", 5)),
        tags=result_dict.get("tags", [vuln_type_str]),
    )


def adapt_sql_injection_new(result_dict: Dict) -> Finding:
    """适配新格式的 SQLi 检测结果（直接返回 Finding）。

    新检测器应直接返回 Finding 实例，无需此适配。
    此函数保留为向后兼容过渡期。
    """
    # 新格式直接构建 Finding (示例，实际新检测器应直接返回 Finding)
    vuln_type_str = result_dict.get("vuln_type", "sqli").lower()
    try:
        vuln_type = VulnType(vuln_type_str)
    except (ValueError, KeyError):
        vuln_type = VulnType.SQli

    severity_str = result_dict.get("severity", "medium").lower()
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    severity = Severity(severity_map.get(severity_str, "medium"))

    endpoint = result_dict.get("endpoint", result_dict.get("url", "").rsplit("?", 1)[0] or "")
    param = result_dict.get("parameter", "")

    evidence_data = result_dict.get("evidence", {})
    evidence = Evidence(
        request=evidence_data.get("request"),
        response=evidence_data.get("response"),
        payload=evidence_data.get("payload"),
        indicator=evidence_data.get("indicator"),
    )

    import time
    finding_id = f"{vuln_type_str}_{endpoint}_{param}_{int(time.time())}"

    return Finding(
        id=finding_id,
        vuln_type=vuln_type,
        severity=severity,
        title=result_dict.get("title", "SQL Injection"),
        target=result_dict.get("target", endpoint),
        endpoint=endpoint,
        parameter=param or "",
        confidence=float(result_dict.get("confidence", 0.8)),
        description=result_dict.get("description", ""),
        evidence=evidence,
        verification=result_dict.get("verification"),
        risk=int(result_dict.get("risk", 5)),
        tags=result_dict.get("tags", [vuln_type_str]),
    )


# 统一适配入口
def adapt_sql_injection(result: Dict) -> Finding:
    """SQLi 检测结果统一适配入口。

    自动检测格式版本并调用相应适配器。
    """
    # 检测是否为新格式 (含 vuln_type 字段)
    if "vuln_type" in result and "severity" in result:
        return adapt_sql_injection_new(result)
    else:
        return adapt_sql_injection_old(result)


# 便捷测试
if __name__ == "__main__":
    # 旧格式测试
    old_result = {
        "type": "boolean_blind",
        "url": "http://target.com/page?id=1",
        "param": "id",
        "description": "Boolean-based SQL injection detected",
        "severity": "high",
        "evidence": {
            "payload": "' OR '1'='1",
            "indicator": "Boolean response difference",
        },
    }
    finding = adapt_sql_injection(old_result)
    print("Old format adapted:")
    print(f"  ID: {finding.id}")
    print(f"  Type: {finding.vuln_type}")
    print(f"  Severity: {finding.severity}")
    print(f"  Title: {finding.title}")
    print(f"  Confidence: {finding.confidence}")
    print(f"  Parameter: {finding.parameter}")
    print(f"  Evidence payload: {finding.evidence.payload}")

    # 新格式测试
    new_result = {
        "vuln_type": "sqli",
        "severity": "high",
        "title": "SQL Injection via UNION",
        "endpoint": "/page",
        "parameter": "id",
        "target": "http://target.com/page?id=1",
        "confidence": 0.95,
        "description": "Union-based SQL injection detected",
        "evidence": {
            "payload": "' UNION SELECT NULL--",
            "indicator": "UNION mark in response",
        },
        "verification": {"method": "OOB", "status": "confirmed"},
        "risk": 9,
        "tags": ["sqli", "union", "blind"],
    }
    finding2 = adapt_sql_injection(new_result)
    print("\nNew format adapted:")
    print(f"  ID: {finding2.id}")
    print(f"  Type: {finding2.vuln_type}")
    print(f"  Severity: {finding2.severity}")
    print(f"  Title: {finding2.title}")
    print(f"  Confidence: {finding2.confidence}")
    print(f"  Parameter: {finding2.parameter}")
    print(f"  Evidence payload: {finding2.evidence.payload}")
