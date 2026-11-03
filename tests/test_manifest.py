"""The CLI manifest is the contract Claude/Agents use to call commands."""

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


def test_manifest_exposes_commands_and_arguments():
    proc = subprocess.run(
        [sys.executable, "main.py", "--json", "manifest"],
        cwd=str(ROOT),
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        env=ENV,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["name"] == "aimy-skill"
    assert payload["command_count"] >= 87
    assert "sqlcheck" in payload["commands"]
    args = {item["dest"]: item for item in payload["commands"]["sqlcheck"]["arguments"]}
    assert args["url"]["required"] is True
    assert args["param"]["required"] is False
    global_options = {
        option for item in payload["global_arguments"] for option in item.get("options", [])
    }
    assert "--json" in global_options
    assert "--quiet" in global_options
