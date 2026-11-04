"""session_id 一等公民存储测试: 覆盖 save/load 往返与缺失容错。"""

import requests

import tools.session_store as ss


def test_save_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(ss, "_DIR", str(tmp_path / "sessions"))
    s = requests.Session()
    s.cookies.set("sid", "abc123")
    s.headers["X-Token"] = "t1"
    sid = ss.new_id()
    ss.save(sid, s)

    s2 = requests.Session()
    assert ss.load(sid, s2) is True
    assert s2.cookies.get("sid") == "abc123"
    assert s2.headers.get("X-Token") == "t1"


def test_load_missing_returns_false(tmp_path, monkeypatch):
    monkeypatch.setattr(ss, "_DIR", str(tmp_path / "nope"))
    assert ss.load("missing-id", requests.Session()) is False


def test_new_id_is_hex16():
    sid = ss.new_id()
    assert len(sid) == 16
    int(sid, 16)  # 不抛异常即合法 hex
