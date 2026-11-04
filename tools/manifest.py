"""单一事实源: 从 COMMAND_SPECS + argparse 提取工具清单与参数 schema。

供 export_manifest.py (写 JSON) 与 mcp/server.py (生成 MCP tools) 共用，
保证 CLI / 文档 / MCP 三处参数定义一致，消除手工维护造成的漂移。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from cli.arg_parsers import build_parser
from cli.check_commands import COMMAND_SPECS

_PY_TYPE = {
    int: "integer",
    float: "number",
    bool: "boolean",
    str: "string",
}


def _build_parser():
    dummy = {name: (lambda *a, **k: None) for name in COMMAND_SPECS}
    return build_parser(dummy)


def _arg_type(action) -> str:
    if getattr(action, "nargs", None) == 0 and isinstance(getattr(action, "const", None), bool):
        return "boolean"
    return _PY_TYPE.get(action.type, "string")


def _action_to_param(action) -> Optional[Dict[str, Any]]:
    if action.dest in ("help",):
        return None
    if action.option_strings in (["-h", "--help"], ["-v", "--version"]):
        return None
    name = action.dest
    if not name:
        return None
    param: Dict[str, Any] = {
        "name": name,
        "type": _arg_type(action),
        "required": bool(action.required),
        "description": action.help or "",
    }
    if action.choices:
        param["choices"] = list(action.choices)
    if action.default is not None:
        param["default"] = action.default
    # 位置参数 (url / target) 无默认值且非可选时视为必填
    if not action.option_strings and action.nargs != "?" and action.default is None:
        param["required"] = True
    return param


def _subparser_params(subparser) -> List[Dict[str, Any]]:
    params: List[Dict[str, Any]] = []
    seen = set()
    for action in subparser._actions:
        p = _action_to_param(action)
        if p and p["name"] not in seen:
            seen.add(p["name"])
            params.append(p)
    return params


def global_params(parser) -> List[Dict[str, Any]]:
    params: List[Dict[str, Any]] = []
    for action in parser._actions:
        if action.dest == "command":
            continue
        p = _action_to_param(action)
        if p:
            params.append(p)
    return params


def _command_spec_for(name: str) -> Optional[Dict[str, str]]:
    spec = COMMAND_SPECS.get(name)
    if spec is None:
        return None
    return {"module": spec.module, "func": spec.func}


def _subparsers_action(parser):
    for action in parser._actions:
        if action.__class__.__name__ == "_SubParsersAction":
            return action
    return None


def list_commands(parser=None) -> List[Dict[str, Any]]:
    """返回全部顶层命令的机器可读清单 (name/description/parameters/module/func)。"""
    parser = parser or _build_parser()
    sub = _subparsers_action(parser)
    choices = getattr(sub, "choices", {}) if sub is not None else {}
    commands: List[Dict[str, Any]] = []
    for name, subparser in choices.items():
        spec = _command_spec_for(name)
        entry: Dict[str, Any] = {
            "name": name,
            "description": subparser.description or "",
            "parameters": _subparser_params(subparser),
        }
        if spec:
            entry["module"] = spec["module"]
            entry["func"] = spec["func"]
        commands.append(entry)
    commands.sort(key=lambda c: c["name"])
    return commands


def get_subparsers(parser):
    """返回 {命令名: subparser}，供 MCP 服务读取 func 与参数默认值。"""
    sub = _subparsers_action(parser)
    return dict(getattr(sub, "choices", {})) if sub is not None else {}


def command_funcs(parser):
    """返回 {命令名: callable}，callable 是解析器 set_defaults(func=...) 注册的调用体。"""
    return {name: sp.get_default("func") for name, sp in get_subparsers(parser).items()}


def list_nested_commands(parser):
    """返回嵌套子命令清单 (kali exec/nmap/... → kali-<sub>)。"""
    out: List[Dict[str, Any]] = []
    for parent_name, parent_sp in get_subparsers(parser).items():
        sub_action = _subparsers_action(parent_sp)
        if sub_action is None:
            continue
        for name, sp in getattr(sub_action, "choices", {}).items():
            out.append({
                "name": "%s-%s" % (parent_name, name),
                "description": sp.description or "%s %s" % (parent_name, name),
                "parameters": _subparser_params(sp),
                "parent": parent_name,
                "kali_command": sp.get_default("kali_command") or name,
            })
    out.sort(key=lambda c: c["name"])
    return out


def nested_command_funcs(parser):
    """返回嵌套子命令的 {命令名: callable}。"""
    out: Dict[str, Any] = {}
    for parent_name, parent_sp in get_subparsers(parser).items():
        sub_action = _subparsers_action(parent_sp)
        if sub_action is None:
            continue
        for name, sp in getattr(sub_action, "choices", {}).items():
            out["%s-%s" % (parent_name, name)] = sp.get_default("func")
    return out


def build_manifest() -> Dict[str, Any]:
    parser = _build_parser()
    return {
        "schema_version": 1,
        "project": "aimy-skill",
        "global_parameters": global_params(parser),
        "commands": list_commands(parser),
        "nested_commands": list_nested_commands(parser),
    }
