"""CLI 入口层测试: 覆盖 main.py 的 cmd_login / cmd_idor 完整路径 + 数据驱动分发。

重点回归: main.py 曾因顶层缺失 `import requests` 导致 cmd_idor / cmd_login
走到 requests.Session() 时 NameError (F821)。这两个测试确保该路径可执行。
"""

import argparse
import re
import unittest.mock

import pytest
import responses

import main
from cli.check_commands import _SESS, COMMAND_SPECS, CheckSpec, build_dispatcher
from tools.auth_engine import AuthSession


def _base_args(**overrides):
    args = dict(
        auth_type="",
        auth_url="",
        auth_user="",
        auth_pass="",
        session_file="",
        kali_local=False,
        kali_host="",
        kali_port=22,
        kali_user="root",
        kali_pass="",
        kali_key="",
    )
    args.update(overrides)
    return argparse.Namespace(**args)


class TestCmdLogin:
    def test_missing_args_exits(self):
        with pytest.raises(SystemExit) as exc:
            main.cmd_login(_base_args())
        assert exc.value.code == 1

    @responses.activate
    def test_success_saves_session(self, tmp_path, capsys):
        args = _base_args(
            auth_type="form",
            auth_url="http://t/login",
            auth_user="admin",
            auth_pass="secret",
            session_file=str(tmp_path / "s.json"),
        )
        with unittest.mock.patch.object(AuthSession, "login_form", return_value=True):
            main.cmd_login(args)
        out = capsys.readouterr().out
        assert '"success": true' in out
        assert (tmp_path / "s.json").exists()

    @responses.activate
    def test_failure_exits(self):
        args = _base_args(
            auth_type="form",
            auth_url="http://t/login",
            auth_user="a",
            auth_pass="b",
        )
        with unittest.mock.patch.object(AuthSession, "login_form", return_value=False):
            with pytest.raises(SystemExit):
                main.cmd_login(args)


class TestCmdIdor:
    @responses.activate
    def test_no_auth(self, capsys):
        responses.add(
            responses.GET,
            "http://test.com/admin/api/users",
            body='[{"name": "admin"}]',
            status=200,
        )
        args = _base_args(
            url="http://test.com/admin/api/users",
            session_file_b="",
            no_auth=True,
            timeout=5,
        )
        main.cmd_idor(args)
        out = capsys.readouterr().out
        assert '"vulnerable": true' in out

    @responses.activate
    def test_with_session_file_b(self, tmp_path, capsys):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/api/user\?id=(1001|1002)$"),
            body='{"id": 1001, "name": "user1001", "email": "u@x.com"}',
            status=200,
        )
        args = _base_args(
            url="http://test.com/api/user?id={id}",
            param="id",
            my_id="1001",
            other_id="1002",
            method="GET",
            json_param="",
            session_file_b=str(tmp_path / "missing.json"),
            no_auth=False,
            timeout=5,
        )
        main.cmd_idor(args)
        out = capsys.readouterr().out
        assert '"type": "idor"' in out


class TestCheckCommandDispatch:
    """Verify that data-driven check commands dispatch to the right tool."""

    def test_specs_cover_known_commands(self):
        expected = {
            "sqlcheck",
            "xsscheck",
            "cmdi",
            "ssrf",
            "jwt",
            "reverse-shell",
            "weakpass",
            "crawl",
            "race",
            "workflow-trace",
            "constraint",
            "xss-verify",
        }
        assert expected.issubset(COMMAND_SPECS.keys())

    def test_all_specs_have_module_and_func(self):
        for name, spec in COMMAND_SPECS.items():
            assert spec.module.startswith("tools."), f"{name}: bad module"
            assert spec.func, f"{name}: missing func"

    def test_reverse_shell_spec_has_no_session(self):
        spec = COMMAND_SPECS["reverse-shell"]
        assert not any(v is _SESS for v in spec.args)
        assert not any(v is _SESS for v in spec.kwargs.values())

    def test_dispatcher_calls_check(self):
        spec = CheckSpec(
            "tools.sql_injection", "check", args=["url", "param", _SESS, "timeout"], kwargs={}
        )
        args = argparse.Namespace(
            url="http://x",
            param="id",
            timeout=5,
            auth_type="",
            auth_url="",
            auth_user="",
            auth_pass="",
            session_file="",
        )
        with unittest.mock.patch("tools.sql_injection.check") as mock_check:
            mock_check.return_value = {"vulnerable": False}
            dispatcher = build_dispatcher(spec, main._sess, main._output)
            dispatcher(args)
            mock_check.assert_called_once()
            call_args = mock_check.call_args
            assert call_args.args[0] == "http://x"
            assert call_args.args[1] == "id"
            assert call_args.args[3] == 5
