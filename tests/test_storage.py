import os

import pytest

from tools import storage
from tools.storage import SessionStore, db_path


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "STORAGE_DIR", str(tmp_path))
    SessionStore._instances.clear()
    s = SessionStore("test_sessions")
    yield s
    s.close()
    SessionStore._instances.clear()


@pytest.fixture
def isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "STORAGE_DIR", str(tmp_path))
    SessionStore._instances.clear()
    yield str(tmp_path)
    SessionStore._instances.clear()


class TestPaths:
    def test_db_path_creates_dir(self, isolated_storage):
        p = db_path("custom")
        assert os.path.exists(os.path.dirname(p))
        assert p.endswith("session_custom.db")

    def test_store_is_singleton(self, isolated_storage):
        a = SessionStore("s1")
        b = SessionStore("s1")
        assert a is b
        a.close()
        SessionStore._instances.clear()


class TestContextKV:
    def test_roundtrip_string(self, store):
        store.save_context("host", "10.0.0.1", source="recon")
        ctx = store.load_all_context()
        assert ctx["host"]["value"] == "10.0.0.1"
        assert ctx["host"]["source"] == "recon"

    def test_roundtrip_dict(self, store):
        store.save_context("meta", {"a": 1}, tags=["x", "y"])
        ctx = store.load_all_context()
        assert ctx["meta"]["value"] == {"a": 1}
        assert ctx["meta"]["tags"] == ["x", "y"]

    def test_overwrite(self, store):
        store.save_context("k", "v1")
        store.save_context("k", "v2")
        ctx = store.load_all_context()
        assert ctx["k"]["value"] == "v2"

    def test_isolated_sessions(self, store):
        s1 = store.session_id()
        store.save_context("k", "a", session_id=s1)
        store.save_context("k", "b", session_id=s1 + 999)
        ctx1 = store.load_all_context(session_id=s1)
        assert ctx1["k"]["value"] == "a"


class TestFindings:
    def test_save_and_load(self, store):
        store.save_finding(
            "f1", "sqli", "http://t/x?id=1", param="id", severity="high", confidence=0.9
        )
        findings = store.load_findings()
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "sqli"
        assert findings[0]["severity"] == "high"

    def test_filter_by_type(self, store):
        store.save_finding("a", "sqli", "http://t/x")
        store.save_finding("b", "xss", "http://t/y")
        assert len(store.load_findings(vuln_type="xss")) == 1
        assert len(store.load_findings()) == 2

    def test_detail_roundtrip(self, store):
        store.save_finding("a", "ssrf", "http://t", detail={"url": "http://169.254.169.254/"})
        f = store.load_findings()[0]
        assert f["detail"] == {"url": "http://169.254.169.254/"}


class TestPhaseState:
    def test_save_load(self, store):
        store.save_phase("crawl", {"pages": 5})
        assert store.load_phase("crawl") == {"pages": 5}

    def test_missing_phase(self, store):
        assert store.load_phase("nope") is None

    def test_all_phases(self, store):
        store.save_phase("a", {"x": 1})
        store.save_phase("b", "plain")
        all_p = store.load_all_phases()
        assert all_p["a"] == {"x": 1}
        assert all_p["b"] == "plain"


class TestVulnContext:
    def test_save_load(self, store):
        store.save_vuln_context({"dbms": "mysql", "count": 3})
        ctx = store.load_vuln_context()
        assert ctx["dbms"] == "mysql"
        assert ctx["count"] == 3

    def test_none_skipped(self, store):
        store.save_vuln_context({"a": None, "b": 1})
        ctx = store.load_vuln_context()
        assert "a" not in ctx
        assert ctx["b"] == 1


class TestSessionMgmt:
    def test_list_sessions(self, store):
        sid = store.session_id()
        store.save_context("k", "v")
        sessions = store.list_sessions()
        assert sessions
        assert sessions[0]["id"] == sid

    def test_report_roundtrip(self, store):
        assert store.load_report() is None
        store.save_vuln_context({"k": "v"})
        assert store.load_report() is None
