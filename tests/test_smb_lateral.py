"""Offline SMB lateral-movement tests with smbclient mocked."""

from types import SimpleNamespace

import tools.smb_lateral as smb


def _result(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_null_session_parses_shares(monkeypatch):
    output = "Sharename Type Comment\nADMIN$ Disk Remote Admin\nIPC$ IPC Remote IPC\n"
    monkeypatch.setattr(smb.subprocess, "run", lambda *a, **k: _result(stdout=output))
    result = smb.smb_null_session("10.0.0.5")
    assert result["success"] is True
    assert result["shares"] == ["ADMIN$", "IPC$"]


def test_null_session_nt_status_is_failure(monkeypatch):
    output = "session setup failed: NT_STATUS_ACCESS_DENIED"
    monkeypatch.setattr(smb.subprocess, "run", lambda *a, **k: _result(returncode=1, stderr=output))
    result = smb.smb_null_session("10.0.0.5")
    assert result["success"] is False


def test_enum_shares_success(monkeypatch):
    output = "Sharename Type Comment\nC$ Disk Default share\nprint$ Disk Drivers\n"
    monkeypatch.setattr(smb.subprocess, "run", lambda *a, **k: _result(stdout=output))
    result = smb.smb_enum_shares("10.0.0.5", "alice", "secret")
    assert result["success"] is True
    assert result["shares"] == ["C$", "print$"]


def test_enum_shares_auth_error_is_not_success(monkeypatch):
    output = "session setup failed: NT_STATUS_LOGON_FAILURE"
    monkeypatch.setattr(smb.subprocess, "run", lambda *a, **k: _result(returncode=1, stderr=output))
    result = smb.smb_enum_shares("10.0.0.5", "alice", "wrong")
    assert result["success"] is False
    assert "NT_STATUS_LOGON_FAILURE" in result["error"]


def test_get_file_returns_stdout(monkeypatch):
    monkeypatch.setattr(smb.subprocess, "run", lambda *a, **k: _result(stdout="file content"))
    result = smb.smb_get_file("10.0.0.5", "share", "secret.txt")
    assert result["success"] is True
    assert result["content"] == "file content"


def test_get_file_nonzero_exit_is_failure(monkeypatch):
    monkeypatch.setattr(
        smb.subprocess,
        "run",
        lambda *a, **k: _result(returncode=1, stdout="error output", stderr="denied"),
    )
    result = smb.smb_get_file("10.0.0.5", "share", "secret.txt")
    assert result["success"] is False
    assert "denied" in result["error"]


def test_get_file_nt_status_even_with_zero_exit_is_failure(monkeypatch):
    monkeypatch.setattr(
        smb.subprocess,
        "run",
        lambda *a, **k: _result(returncode=0, stdout="", stderr="NT_STATUS_OBJECT_NAME_NOT_FOUND"),
    )
    result = smb.smb_get_file("10.0.0.5", "share", "missing.txt")
    assert result["success"] is False


def test_wmi_and_psexec_require_zero_exit(monkeypatch):
    monkeypatch.setattr(
        smb.subprocess,
        "run",
        lambda *a, **k: _result(returncode=1, stdout="error", stderr="access denied"),
    )
    assert smb.wmi_exec("10.0.0.5", "whoami", "alice", "secret")["success"] is False
    assert smb.psexec("10.0.0.5", "whoami", "alice", "secret")["success"] is False

    monkeypatch.setattr(smb.subprocess, "run", lambda *a, **k: _result(returncode=0, stdout="ok"))
    result = smb.wmi_exec("10.0.0.5", "whoami", "alice", "secret")
    assert result["success"] is True
    assert result["output"] == "ok"


def test_lateral_move_falls_through_to_winrm(monkeypatch):
    monkeypatch.setattr(
        smb, "wmi_exec", lambda *a, **k: {"success": False, "output": "", "method": "wmi_exec"}
    )
    monkeypatch.setattr(
        smb, "psexec", lambda *a, **k: {"success": False, "output": "", "method": "psexec"}
    )
    monkeypatch.setattr(
        smb, "winrm_exec", lambda *a, **k: {"success": True, "output": "ok", "method": "winrm"}
    )
    result = smb.lateral_move("10.0.0.5", "whoami", "alice", "secret")
    assert result["success"] is True
    assert result["method"] == "winrm"
    assert set(result["all_results"]) == {"wmi", "psexec", "winrm"}
