"""Offline packet capture mode and dispatch tests."""

from types import SimpleNamespace

import tools.packet_capture as pc


def _args(**overrides):
    values = {
        "proxy": False,
        "capture": False,
        "kali_local": False,
        "kali_host": "",
        "proxy_port": 8080,
        "proxy_host": "127.0.0.1",
        "proxy_duration": 0,
        "capture_iface": "",
        "capture_count": 10,
        "capture_filter": "",
        "capture_timeout": 5,
        "capture_tls": False,
        "capture_http": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_run_capture_without_mode_returns_error():
    result = pc.run_capture(_args())
    assert result["success"] is False
    assert "No capture mode" in result["error"]


def test_proxy_mode_dispatches(monkeypatch):
    monkeypatch.setattr(pc, "_run_proxy", lambda args: {"success": True, "mode": "proxy"})
    assert pc.run_capture(_args(proxy=True))["mode"] == "proxy"


def test_capture_mode_dispatches_local_and_remote(monkeypatch):
    calls = []

    def fake_capture(args, local=False):
        calls.append(local)
        return {"success": True, "local": local}

    monkeypatch.setattr(pc, "_run_kali_capture", fake_capture)
    pc.run_capture(_args(capture=True, kali_local=True))
    pc.run_capture(_args(capture=True, kali_host="10.0.0.2"))
    assert calls == [True, False]


def test_auto_detect_self_kali(monkeypatch):
    checked = []
    monkeypatch.setattr(pc, "_check_self_kali", lambda: checked.append(True))
    assert pc.auto_detect_mode(_args(capture=True)) == "kali-local"
    assert checked == [True]


def test_run_kali_capture_requires_kali(monkeypatch):
    monkeypatch.setattr(pc, "is_available", lambda: False)
    result = pc._run_kali_capture(_args(capture=True))
    assert result["success"] is False
    assert "Kali backend" in result["error"]


class _FakeCapture:
    def __init__(self, local=False):
        self.local = local
        self.calls = []

    def capture(self, **kwargs):
        self.calls.append(("full", kwargs))
        return {"success": True}

    def capture_https(self, **kwargs):
        self.calls.append(("https", kwargs))
        return {"success": True}

    def capture_http(self, **kwargs):
        self.calls.append(("http", kwargs))
        return {"success": True}


def test_run_kali_capture_selects_http_tls_or_full(monkeypatch):
    created = []
    monkeypatch.setattr(pc, "is_available", lambda: True)

    def factory(local=False):
        inst = _FakeCapture(local)
        created.append(inst)
        return inst

    monkeypatch.setattr(pc, "KaliCapture", factory)
    assert pc._run_kali_capture(_args(capture_tls=True), local=True)["success"] is True
    assert pc._run_kali_capture(_args(capture_http=True), local=True)["success"] is True
    assert pc._run_kali_capture(_args(), local=True)["success"] is True
    assert [inst.calls[0][0] for inst in created] == ["https", "http", "full"]


def test_proxy_duration_returns_captured_requests(monkeypatch):
    class FakeProxy:
        def ca_info(self):
            return {"ca_cert": "/tmp/ca.pem"}

        def install_ca_instruction(self):
            return "install"

        def get_captured(self, clear=False):
            return [{"method": "GET"}]

    monkeypatch.setattr(pc, "start_proxy", lambda **kwargs: FakeProxy())
    monkeypatch.setattr(pc, "stop_proxy", lambda: None)
    monkeypatch.setattr(pc.time, "sleep", lambda seconds: None)
    result = pc._run_proxy(_args(proxy_duration=1))
    assert result["success"] is True
    assert result["total_captured"] == 1
    assert result["captured"] == [{"method": "GET"}]


def test_run_realtime_requires_kali(monkeypatch):
    monkeypatch.setattr(pc, "is_available", lambda: False)
    assert pc.run_realtime(_args())["success"] is False
