"""aimy-skill MCP server: 把 88 条 CLI 命令暴露为 MCP tools (stdio transport)。

接入任意 MCP 客户端 (Claude Code / Cursor / Cline):
    {"mcpServers": {"aimy": {"command": "python", "args": ["-m", "aimy_mcp.server"]}}}

运行: python -m aimy_mcp.server  (工作目录为项目根)
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

import main as _main
from cli.arg_parsers import build_parser
from cli.check_commands import COMMAND_SPECS, build_dispatcher
from tools.manifest import (
    command_funcs,
    global_params,
    list_commands,
    list_nested_commands,
    nested_command_funcs,
)
from tools.output import begin_context, set_format

# 强制 JSON 输出 (MCP 客户端需要机器可解析，不用 jsonl)
set_format("json")

_dispatchers = {name: build_dispatcher(spec, _main._sess, _main._output)
                for name, spec in COMMAND_SPECS.items()}
_parser = build_parser(_dispatchers)
_funcs = command_funcs(_parser)
_funcs.update(nested_command_funcs(_parser))
_commands = list_commands(_parser) + list_nested_commands(_parser)
_global = global_params(_parser)

app = Server("aimy-skill")

_JSON_TYPE = {"string": "string", "integer": "integer", "number": "number", "boolean": "boolean"}


def _tool_schema(cmd: dict) -> dict:
    props: dict = {}
    required: list = []
    # 全局参数合并 (agent 可按需覆盖 timeout / session_id / session_file / mode)
    for p in _global:
        props[p["name"]] = {
            "type": _JSON_TYPE.get(p["type"], "string"),
            "description": p.get("description", ""),
        }
        if "default" in p:
            props[p["name"]]["default"] = p["default"]
    for p in cmd["parameters"]:
        s = {
            "type": _JSON_TYPE.get(p["type"], "string"),
            "description": p.get("description", ""),
        }
        if "choices" in p:
            s["enum"] = p["choices"]
        if "default" in p:
            s["default"] = p["default"]
        props[p["name"]] = s
        if p.get("required"):
            required.append(p["name"])
    return {"type": "object", "properties": props, "required": required}


def _param_default(p: dict):
    if "default" in p:
        return p["default"]
    return {"integer": 0, "number": 0.0, "boolean": False, "string": ""}.get(
        p.get("type", "string"), ""
    )


def _build_namespace(cmd: dict, arguments: dict) -> argparse.Namespace:
    ns: dict = {}
    for p in _global:
        ns[p["name"]] = _param_default(p)
    for p in cmd["parameters"]:
        ns[p["name"]] = _param_default(p)
    ns.update(arguments or {})
    ns["command"] = cmd["name"]
    if "kali_command" in cmd:
        ns["kali_command"] = cmd["kali_command"]
    return argparse.Namespace(**ns)


def _run(cmd: dict, arguments: dict):
    func = _funcs.get(cmd["name"])
    ns = _build_namespace(cmd, arguments)
    buf = io.StringIO()
    err = None
    begin_context(cmd["name"])
    try:
        with contextlib.redirect_stdout(buf):
            func(ns)
    except SystemExit as e:
        err = "command exited: %s" % (e.code,)
    except Exception as e:
        err = "%s: %s" % (type(e).__name__, e)
    return buf.getvalue(), err


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name=cmd["name"],
            description=cmd["description"] or cmd["name"],
            inputSchema=_tool_schema(cmd),
        )
        for cmd in _commands
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> CallToolResult:
    cmd = next((c for c in _commands if c["name"] == name), None)
    if cmd is None:
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps({"error": "unknown tool: %s" % name}))],
            isError=True,
        )
    text, err = await asyncio.to_thread(_run, cmd, arguments or {})
    if err and not text.strip():
        text = json.dumps({"_meta": {"status": "error", "tool": name, "error": err}},
                          ensure_ascii=False)
        return CallToolResult(content=[TextContent(type="text", text=text)], isError=True)

    result = CallToolResult(content=[TextContent(type="text", text=text)])
    try:
        result.structuredContent = json.loads(text)
    except (ValueError, TypeError):
        pass
    return result


async def serve() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main() -> None:
    asyncio.run(serve())


if __name__ == "__main__":
    main()
