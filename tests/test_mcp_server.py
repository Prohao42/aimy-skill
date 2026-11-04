"""MCP 接入层测试: 覆盖 list_tools / call_tool 的直接调用 (不经 stdio 传输)。"""

import asyncio

import pytest

pytest.importorskip("mcp", reason="MCP SDK requires Python >= 3.10")

import aimy_mcp.server as srv  # noqa: E402


def test_mcp_lists_all_commands():
    tools = asyncio.run(srv.list_tools())
    names = {t.name for t in tools}
    assert len(tools) >= 80
    assert {"sqlcheck", "poja", "waf", "auto"} <= names


def test_mcp_tool_schema_marks_required():
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    assert "url" in tools["poja"].inputSchema["required"]


def test_mcp_call_tool_returns_result():
    r = asyncio.run(srv.call_tool("payload-mutate", {"payload": "x", "param": "id"}))
    assert r.isError is False
    assert r.content and r.content[0].text
    assert r.structuredContent is not None
    assert "_meta" in r.structuredContent


def test_mcp_unknown_tool_is_error():
    r = asyncio.run(srv.call_tool("nope", {}))
    assert r.isError is True
