"""回归测试：CLI 参数解析必须能构建成功（修复 --param 冲突前会直接抛错）。

历史 bug：file-upload / saml-sso 子命令里 `_add_url_arg()` 已经注册了 `url` 与 `--param`，
调用方又重复 add_argument("url") / ("--param")，argparse 抛
`argparse.ArgumentError: argument --param: conflicting option string: --param`，
导致任何 `python main.py <cmd>` 都在解析阶段崩溃。
"""

from collections import defaultdict

import pytest

from cli.arg_parsers import build_parser


@pytest.fixture()
def parser():
    return build_parser(defaultdict(lambda: (lambda *a, **k: None)))


class TestParserBuilds:
    def test_build_parser_does_not_raise(self, parser):
        assert parser is not None

    def test_all_subcommands_registered(self, parser):
        # 至少应包含这些关键子命令（不写死总数，避免与上游演进冲突）
        for name in ("portscan", "file-upload", "saml-sso", "leak-scan", "unauth", "cms-fingerprint"):
            assert name in parser._subparsers._group_actions[0].choices


class TestUploadSubcommandsArgs:
    def test_file_upload_accepts_url_and_param(self, parser):
        args = parser.parse_args(["file-upload", "http://t/uploads", "--param", "upload"])
        assert args.url == "http://t/uploads"
        assert args.param == "upload"

    def test_file_upload_param_defaults_to_file(self, parser):
        args = parser.parse_args(["file-upload", "http://t/uploads"])
        assert args.param == "file"

    def test_saml_sso_accepts_url(self, parser):
        args = parser.parse_args(["saml-sso", "http://t/sso"])
        assert args.url == "http://t/sso"
        assert args.param == "SAMLResponse"
