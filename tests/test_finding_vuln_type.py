"""回归测试：VulnType 必须包含 INFO（缺失时任何产出 info 级 finding 的路径都会崩）。

历史 bug：`tools/_finding.py` 的 VulnType 枚举没有 INFO 成员，但以下路径都会用到它：
  - `Finding.from_dict()` 的兜底分支（`VulnType(data["vuln_type"])` 失败 → `VulnType.INFO`）
  - `make_finding(vuln_type="info", ...)` / `create_finding(..., vuln_type="info")`（字符串直传）
  - `from_legacy()`（旧格式适配）
于是 `python main.py cms-fingerprint ...` 直接失败：
`Command 'cms-fingerprint' failed: 'info' is not a valid VulnType`
"""

import pytest

from tools._finding import Finding, Severity, VulnType, make_finding


class TestVulnTypeInfo:
    def test_info_member_exists(self):
        assert VulnType.INFO.value == "info"

    def test_info_is_valid_value(self):
        assert VulnType("info") is VulnType.INFO

    def test_severity_info_still_present(self):
        assert Severity.INFO.value == "info"


class TestInfoFindingPaths:
    def test_from_dict_accepts_info_type(self):
        finding = Finding.from_dict(
            {
                "vuln_type": "info",
                "severity": "info",
                "title": "robots.txt",
                "target": "http://t",
                "endpoint": "http://t/robots.txt",
                "evidence": {"indicator": "robots.txt exposed"},
            }
        )
        assert finding.vuln_type is VulnType.INFO
        assert finding.to_dict()["vuln_type"] == "info"

    def test_from_dict_unknown_type_falls_back_to_info(self):
        """未知类型走兜底分支，必须回落到 INFO 而不是抛错。"""
        finding = Finding.from_dict({"vuln_type": "definitely-not-a-real-type", "endpoint": "http://t/x"})
        assert finding.vuln_type is VulnType.INFO

    def test_make_finding_accepts_info_string(self):
        finding = make_finding("info", "http://t/robots.txt", "", "info finding", severity="info")
        assert finding.vuln_type is VulnType.INFO
