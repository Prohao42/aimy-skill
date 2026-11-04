"""CLI 端到端集成测试: 走 main.main() 全链路，验证信封注入 / 退出码 / jsonl。

这是对 result 信封与退出码约定的真实行为回归，不是纯函数单测。
"""

import json
import sys

import main


def _run_main(argv, capsys):
    old = sys.argv
    sys.argv = ["main.py"] + argv
    try:
        try:
            main.main()
            code = 0
        except SystemExit as e:
            code = e.code
    finally:
        sys.argv = old
    out = capsys.readouterr().out
    return code, out


def test_success_envelope(capsys):
    code, out = _run_main(["payload-mutate", "--payload", "x"], capsys)
    assert code == 0
    d = json.loads(out.strip())
    assert d["_meta"]["status"] == "ok"
    assert d["_meta"]["tool"] == "payload-mutate"
    assert "request_id" in d["_meta"]
    assert "duration_ms" in d["_meta"]


def test_missing_required_exits_nonzero(capsys):
    code, _ = _run_main(["login"], capsys)
    assert code == 1


def test_format_jsonl(capsys):
    code, out = _run_main(["payload-mutate", "--payload", "x", "--format", "jsonl"], capsys)
    assert code == 0
    lines = [l for l in out.splitlines() if l.strip()]
    assert len(lines) >= 1
    assert json.loads(lines[0])["encoded"] is not None


def test_list_includes_poja(capsys):
    code, out = _run_main(["list"], capsys)
    assert code == 0
    d = json.loads(out.strip())
    assert "poja" in d
    assert "sqlcheck" in d
