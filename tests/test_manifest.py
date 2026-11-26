"""The CLI manifest is the contract Claude/Agents use to call commands."""

import json
import os
import subprocess
import sys
from pathlib import Path

from tools.manifest import build_manifest

ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ, NO_PROXY="127.0.0.1,localhost")


def test_manifest_exposes_commands_and_arguments():
    proc = subprocess.run(
        [sys.executable, "main.py", "--json", "manifest"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        env=ENV,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload.pop("_meta")["tool"] == "manifest"
    assert payload == build_manifest()

    commands = {item["name"]: item for item in payload["commands"]}
    assert len(commands) == 91
    args = {item["name"]: item for item in commands["sqlcheck"]["parameters"]}
    assert args["url"]["required"] is True
    assert args["param"]["required"] is False
    global_names = {item["name"] for item in payload["global_parameters"]}
    assert {"json", "quiet", "format"} <= global_names
    assert len(payload["nested_commands"]) == 14
