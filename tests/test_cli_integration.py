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
    code, out = _run_main(["--json", "login"], capsys)
    assert code == 2
    result = json.loads(out)
    assert result["_meta"]["status"] == "error"
    assert result["_meta"]["tool"] == "login"
    assert result["code"] == "invalid_args"


def test_argparse_error_is_structured(capsys):
    code, out = _run_main(["--json", "fuzz"], capsys)
    assert code == 2
    result = json.loads(out)
    assert result["code"] == "invalid_args"
    assert result["_meta"]["tool"] == "fuzz"
    assert "required: url" in result["error"]


def test_validation_error_is_structured(capsys):
    code, out = _run_main(["--json", "fuzz", "not-a-valid-url"], capsys)
    assert code == 2
    result = json.loads(out)
    assert result["code"] == "invalid_args"
    assert result["command"] == "fuzz"
    assert "valid scheme" in result["error"]


def test_format_jsonl(capsys):
    code, out = _run_main(["payload-mutate", "--payload", "x", "--format", "jsonl"], capsys)
    assert code == 0
    lines = [l for l in out.splitlines() if l.strip()]
    assert len(lines) >= 1
    result = json.loads(lines[0])
    assert result["encoded"] is not None
    assert result["_meta"]["tool"] == "payload-mutate"


def test_list_includes_poja(capsys):
    code, out = _run_main(["list"], capsys)
    assert code == 0
    d = json.loads(out.strip())
    assert "poja" in d
    assert "sqlcheck" in d
    assert d["_meta"]["tool"] == "list"


def test_fuzz_executes_custom_payloads(capsys):
    from unittest.mock import MagicMock, patch

    response = MagicMock(status_code=200, text="ok")
    response.elapsed.total_seconds.return_value = 0.1
    sess = MagicMock()
    sess.get.return_value = response
    with patch.object(main, "_sess", return_value=sess):
        code, out = _run_main(
            [
                "--json",
                "fuzz",
                "http://target.test",
                "--param",
                "q",
                "--payloads",
                "one,two",
            ],
            capsys,
        )
    assert code == 0
    result = json.loads(out)
    assert result["payloads_tested"] == 2
    assert [r["payload"] for r in result["results"]] == ["one", "two"]
    assert sess.get.call_count == 3


def test_smuggler_exploit_emits_single_json(capsys):
    from unittest.mock import MagicMock, patch

    detection = {"vulnerable": True, "type": "smuggling", "smuggling_type": "cl_te"}
    with (
        patch.object(main, "_sess", return_value=MagicMock()),
        patch("tools.smuggler.check", return_value=detection),
        patch("tools.smuggler.exploit", return_value={"success": True}),
    ):
        code, out = _run_main(["--json", "smuggler", "http://target.test", "--exploit"], capsys)
    assert code == 0
    assert len([line for line in out.splitlines() if line.strip()]) == 1
    result = json.loads(out)
    assert result["smuggling_exploit"]["success"] is True
    assert result["_meta"]["status"] == "ok"
