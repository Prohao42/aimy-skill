"""Environment capability report tests (offline, no target access)."""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from tools import capabilities

ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ, NO_PROXY="127.0.0.1,localhost")


def test_capability_report_ready(monkeypatch):
    monkeypatch.setattr(capabilities, "_module_available", lambda name: True)
    monkeypatch.setattr(capabilities, "_writable_dir", lambda path: True)
    monkeypatch.setattr(
        capabilities,
        "_kali_status",
        lambda: {
            "available": True,
            "local": True,
            "remote_configured": False,
            "paramiko": True,
        },
    )
    monkeypatch.setattr(
        capabilities,
        "settings",
        SimpleNamespace(oob_domain="oob.test", oob_callback_url="http://oob.test"),
    )
    report = capabilities.check_capabilities()
    assert report["ready"] is True
    assert report["capabilities"]["web_validation"] is True
    assert report["capabilities"]["mcp_server"] is True
    assert report["capabilities"]["kali_execution"] is True
    assert report["warnings"] == []


def test_capability_report_missing_optional(monkeypatch):
    optional = {"mcp", "playwright", "paramiko"}

    def module_available(name):
        return name not in optional

    monkeypatch.setattr(capabilities, "_module_available", module_available)
    monkeypatch.setattr(capabilities, "_writable_dir", lambda path: True)
    monkeypatch.setattr(
        capabilities,
        "_kali_status",
        lambda: {
            "available": False,
            "local": False,
            "remote_configured": False,
            "paramiko": False,
        },
    )
    monkeypatch.setattr(
        capabilities, "settings", SimpleNamespace(oob_domain="", oob_callback_url="")
    )
    report = capabilities.check_capabilities()
    assert report["ready"] is True
    assert report["capabilities"]["mcp_server"] is False
    assert report["capabilities"]["browser_verification"] is False
    assert any("MCP" in warning for warning in report["warnings"])
    assert any("Playwright" in warning for warning in report["warnings"])


def test_doctor_cli_is_structured():
    proc = subprocess.run(
        [sys.executable, "main.py", "--json", "doctor"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        env=ENV,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["_meta"]["tool"] == "doctor"
    assert payload["_meta"]["status"] == "ok"
    assert {"ready", "dependencies", "capabilities", "warnings"} <= payload.keys()
