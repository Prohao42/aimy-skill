"""Version fingerprint CVE range tests."""

from tools.version_fingerprint import VersionFingerprint


def _header(value):
    return VersionFingerprint().extract_from_headers({"Server": value})


def test_tomcat_affected_version_matches_cve():
    items = _header("Apache Tomcat/9.0.30")
    assert items[0].product == "tomcat"
    assert items[0].version == "9.0.30"
    assert items[0].cve_matches == ["CVE-2020-1938"]
    assert items[0].risk_level == "high"


def test_tomcat_patched_version_has_no_cve():
    items = _header("Apache Tomcat/9.0.31")
    assert items[0].cve_matches == []
    assert items[0].risk_level == "unknown"


def test_spring_affected_and_patched_boundaries():
    assert _header("Spring/5.3.17")[0].cve_matches == ["CVE-2022-22965"]
    assert _header("Spring/5.3.18")[0].cve_matches == []


def test_struts_error_version_uses_explicit_range():
    items = VersionFingerprint().extract_from_body("Apache Struts/2.5.10")
    assert items[0].cve_matches == ["CVE-2017-5638"]


def test_laravel_patched_version_is_not_flagged():
    items = VersionFingerprint().extract_from_body("Laravel Framework 8.4.3")
    assert items[0].cve_matches == []


def test_unknown_product_and_version_do_not_raise():
    items = _header("nginx/1.25.0")
    assert items[0].product == "nginx"
    assert items[0].cve_matches == []
    assert items[0].risk_level == "unknown"


def test_risk_summary_counts_versions_with_cves():
    fp = VersionFingerprint()
    fp.extract_from_headers({"Server": "Apache Tomcat/9.0.30", "X-Powered-By": "PHP/8.2.1"})
    summary = fp.get_risk_summary()
    assert summary["total_versions"] == 2
    assert summary["high"] == 1
    assert any(
        item["product"] == "tomcat" for item in summary["critical_versions"] + summary["versions"]
    )
