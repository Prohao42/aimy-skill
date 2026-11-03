"""End-to-end checks for machine-readable CLI output."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Pin the child process to UTF-8: the harness decodes with encoding="utf-8",
# so a cp936 child (Windows default) would produce undecodable bytes.
ENV = dict(
    os.environ,
    NO_PROXY="127.0.0.1,localhost",
    PYTHONIOENCODING="utf-8",
    PYTHONUTF8="1",
)


def test_json_mode_keeps_stdout_pure():
    proc = subprocess.run(
        [sys.executable, "main.py", "--json", "list"],
        cwd=str(ROOT),
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        env=ENV,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert isinstance(payload, dict) and payload
    # The mode banner/progress must not leak into stdout.
    assert "菜鸟模式" not in proc.stdout
    assert "MODE" not in proc.stdout


def test_quiet_flag_hides_progress():
    proc = subprocess.run(
        [sys.executable, "main.py", "--quiet", "--json", "list"],
        cwd=str(ROOT),
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        env=ENV,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)
