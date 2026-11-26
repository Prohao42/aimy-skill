"""MCP 接入层测试: 覆盖 list_tools / call_tool 的直接调用 (不经 stdio 传输)。"""

import asyncio

import pytest

pytest.importorskip("mcp", reason="MCP SDK requires Python >= 3.10")

import aimy_mcp.server as srv  # noqa: E402


def test_mcp_lists_only_executable_commands():
    tools = asyncio.run(srv.list_tools())
    names = {t.name for t in tools}
    assert len(tools) == 104
    assert {"sqlcheck", "poja", "waf", "auto", "doctor", "kali-connect"} <= names
    assert "kali" not in names


def test_mcp_tool_schema_marks_required():
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    assert "url" in tools["poja"].inputSchema["required"]


def test_mcp_call_tool_returns_result():
    r = asyncio.run(srv.call_tool("payload-mutate", {"payload": "x", "param": "id"}))
    assert r.isError is False
    assert r.content and r.content[0].text
    assert r.structuredContent is not None
    assert "_meta" in r.structuredContent


def test_mcp_runs_cli_validation(monkeypatch):
    seen = {}

    def validate(ns):
        seen["command"] = ns.command

    monkeypatch.setattr(srv, "validate_args", validate)
    r = asyncio.run(srv.call_tool("payload-mutate", {"payload": "x", "param": "id"}))
    assert r.isError is False
    assert seen == {"command": "payload-mutate"}


def test_mcp_partial_output_does_not_hide_error(monkeypatch):
    import json

    def fail_after_output(ns):
        print('{"partial": true}')
        raise RuntimeError("boom")

    monkeypatch.setitem(srv._funcs, "payload-mutate", fail_after_output)
    r = asyncio.run(srv.call_tool("payload-mutate", {"payload": "x", "param": "id"}))
    assert r.isError is True
    payload = json.loads(r.content[0].text)
    assert payload["_meta"]["status"] == "error"
    assert "RuntimeError: boom" in payload["error"]
    assert payload["partial_output"] == '{"partial": true}'
    assert r.structuredContent == payload


def test_mcp_invalid_argument_is_structured():
    import json

    r = asyncio.run(srv.call_tool("fuzz", {"url": "not-a-valid-url"}))
    assert r.isError is True
    payload = json.loads(r.content[0].text)
    assert payload["code"] == "invalid_args"
    assert payload["_meta"]["status"] == "error"


def test_mcp_execution_is_serialized(monkeypatch):
    import threading
    import time

    active = 0
    peak = 0
    guard = threading.Lock()

    def fake_tool(ns):
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
        time.sleep(0.02)
        with guard:
            active -= 1
        print('{"ok": true}')

    monkeypatch.setitem(srv._funcs, "payload-mutate", fake_tool)

    async def invoke_three():
        return await asyncio.gather(
            *(srv.call_tool("payload-mutate", {"payload": str(i)}) for i in range(3))
        )

    results = asyncio.run(invoke_three())
    assert all(result.isError is False for result in results)
    assert peak == 1


def test_mcp_unknown_tool_is_error():
    r = asyncio.run(srv.call_tool("nope", {}))
    assert r.isError is True
