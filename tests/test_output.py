"""统一结果信封测试: 覆盖 _meta 注入、列表包装、jsonl 逐行输出。"""

import json

from tools.output import begin_context, output, set_format, to_json


def test_to_json_adds_meta():
    begin_context("poja")
    d = json.loads(to_json({"vulnerable": True}))
    assert d["vulnerable"] is True
    assert d["_meta"]["tool"] == "poja"
    assert d["_meta"]["status"] == "ok"
    assert d["_meta"]["schema_version"] == 1
    assert "request_id" in d["_meta"]


def test_to_json_list_wraps_vulnerabilities():
    begin_context("xsscheck")
    d = json.loads(to_json([{"type": "sqli", "vulnerable": True}]))
    assert d["vulnerabilities"][0]["type"] == "sqli"
    assert "_meta" in d


def test_output_jsonl_streams_findings(capsys):
    set_format("jsonl")
    begin_context("x")
    output({"vulnerabilities": [{"type": "xss"}, {"type": "sqli"}]})
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert len(lines) == 2
    assert json.loads(lines[0])["type"] == "xss"
    assert json.loads(lines[1])["type"] == "sqli"
    set_format("json")  # 复位，避免污染其他测试


def test_output_json_single_line(capsys):
    set_format("json")
    begin_context("y")
    output({"vulnerable": False})
    out = capsys.readouterr().out.strip()
    assert out.count("\n") == 0
    assert json.loads(out)["_meta"]["status"] == "ok"
    set_format("json")
