"""单一事实源清单测试: 覆盖 COMMAND_SPECS + argparse -> 机器可读清单的提取。"""

from cli.arg_parsers import build_parser
from cli.check_commands import COMMAND_SPECS
from tools.manifest import build_manifest, command_funcs, list_commands


def test_manifest_has_all_commands():
    m = build_manifest()
    assert m["schema_version"] == 1
    assert len(m["commands"]) >= 80
    names = {c["name"] for c in m["commands"]}
    for expected in ("sqlcheck", "waf", "poja", "auto", "login", "recon"):
        assert expected in names


def test_manifest_param_schema():
    by_name = {c["name"]: c for c in build_manifest()["commands"]}
    poja_params = {p["name"]: p for p in by_name["poja"]["parameters"]}
    assert poja_params["url"]["required"] is True
    assert poja_params["adaptive"]["type"] == "boolean"
    assert poja_params["vuln_type"]["choices"] == ["sqli", "xss", "lfi", "ssti", "nosqli"]


def test_manifest_module_mapping():
    by_name = {c["name"]: c for c in build_manifest()["commands"]}
    assert by_name["sqlcheck"]["module"] == "tools.sql_injection"
    assert by_name["waf"]["module"] == "tools.waf_bypass"


def test_command_funcs_registered():
    dummy = {n: (lambda *a, **k: None) for n in COMMAND_SPECS}
    parser = build_parser(dummy)
    funcs = command_funcs(parser)
    assert "sqlcheck" in funcs and "poja" in funcs
    assert callable(funcs["sqlcheck"])


def test_list_commands_sorted_and_complete():
    cmds = list_commands()
    names = [c["name"] for c in cmds]
    assert names == sorted(names)
    assert all(c["parameters"] is not None for c in cmds)
