"""Offline cross-platform internal scan tests."""

from types import SimpleNamespace

import tools.internal_scan as scan


def _run_result(returncode=0, stdout=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


def test_ping_command_on_windows(monkeypatch):
    monkeypatch.setattr(scan.platform, "system", lambda: "Windows")
    assert scan._ping_command("10.0.0.1", 2) == [
        "ping",
        "-n",
        "1",
        "-w",
        "2000",
        "10.0.0.1",
    ]


def test_ping_command_on_linux(monkeypatch):
    monkeypatch.setattr(scan.platform, "system", lambda: "Linux")
    assert scan._ping_command("10.0.0.1", 2) == ["ping", "-c1", "-W", "2", "10.0.0.1"]


def test_ping_sweep_uses_windows_flags(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _run_result(returncode=0 if cmd[-1].endswith(".1") else 1)

    monkeypatch.setattr(scan.platform, "system", lambda: "Windows")
    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    assert scan.ping_sweep("192.168.1.0/30", timeout=1, threads=2) == ["192.168.1.1"]
    assert calls
    assert all(cmd[1] == "-n" for cmd in calls)


def test_arp_scan_parses_windows_and_linux_macs(monkeypatch):
    output = (
        "  192.168.1.10           aa-bb-cc-dd-ee-ff     dynamic\n"
        "? (192.168.1.11) at 11:22:33:44:55:66 [ether] on eth0\n"
    )
    monkeypatch.setattr(scan.subprocess, "run", lambda *a, **k: _run_result(stdout=output))
    entries = scan.arp_scan()
    assert entries == [
        {"ip": "192.168.1.10", "mac": "aa-bb-cc-dd-ee-ff"},
        {"ip": "192.168.1.11", "mac": "11:22:33:44:55:66"},
    ]


def test_get_local_networks_uses_ipconfig_on_windows(monkeypatch):
    monkeypatch.setattr(scan.platform, "system", lambda: "Windows")
    monkeypatch.setattr(scan.socket, "gethostbyname_ex", lambda host: (host, [], []))
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        lambda *a, **k: _run_result(
            stdout="IPv4 Address. . . . . . . . . . . : 192.168.50.7\n"
            "Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
        ),
    )
    assert scan.get_local_networks() == ["192.168.50.0/24"]


def test_scan_host_only_returns_open_ports(monkeypatch):
    def fake_scan(host, port, timeout):
        if port == 443:
            return {"host": host, "port": port, "state": "open"}
        return {"host": host, "port": port, "state": "closed"}

    monkeypatch.setattr(scan, "_scan_port", fake_scan)
    result = scan.scan_host("10.0.0.5", ports=[80, 443], timeout=0.1, threads=2)
    assert result["count"] == 1
    assert result["open_ports"][0]["port"] == 443
