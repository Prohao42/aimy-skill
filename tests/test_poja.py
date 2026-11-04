"""poja 破甲一键命令测试: 覆盖 cmd_poja 的 WAF 指纹 + 绕过生成 + 穿透验证 + 结果合并。

cmd_poja 的网络调用 (fingerprint_waf / adaptive_bypass / test_sqli_bypass) 全部 patch，
纯函数 (generate_bypasses / generate_sqli_payloads) 真实运行，验证结果信封合并逻辑。
"""

import argparse
import json
import unittest.mock

import main


def _base_args(**overrides):
    args = dict(
        url="http://test.com/page",
        param="id",
        payload="1' OR 1=1 -- -",
        waf="",
        vuln_type="sqli",
        adaptive=True,
        test_sqli=True,
        timeout=5,
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


def _last_json(capsys):
    out = capsys.readouterr().out
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise AssertionError("no JSON line in output: %r" % out)


class TestCmdPoja:
    def test_generates_and_merges(self, capsys):
        with unittest.mock.patch(
            "tools.waf_bypass.fingerprint_waf",
            return_value={"detected": True, "name": "cloudflare", "evidence": [], "all_matches": []},
        ), unittest.mock.patch(
            "tools.waf_bypass.adaptive_bypass",
            return_value={"success": True, "payload": "1%2527..."},
        ), unittest.mock.patch(
            "tools.waf_bypass.test_sqli_bypass",
            return_value={"vulnerable": True, "bypasses": [{"payload": "'"}], "best_payload": "'"},
        ):
            main.cmd_poja(_base_args())

        d = _last_json(capsys)
        assert d["vulnerable"] is True
        assert d["waf_name"] == "cloudflare"
        assert d["best_payload"] == "'"
        assert d["bypasses"] == [{"payload": "'"}]
        assert len(d["bypass_payloads"]) > 0
        assert len(d["encoded_variants"]) > 0
        assert d["adaptive"]["success"] is True

    def test_waf_override_wins_over_fingerprint(self, capsys):
        with unittest.mock.patch(
            "tools.waf_bypass.fingerprint_waf",
            return_value={"detected": False, "name": None, "evidence": [], "all_matches": []},
        ), unittest.mock.patch(
            "tools.waf_bypass.adaptive_bypass",
            return_value={"success": False, "strategies_tried": 22},
        ), unittest.mock.patch(
            "tools.waf_bypass.test_sqli_bypass",
            return_value={"vulnerable": False, "bypasses": [], "best_payload": None},
        ):
            main.cmd_poja(_base_args(waf="mod_security"))

        d = _last_json(capsys)
        assert d["waf_name"] == "mod_security"
        assert d["vulnerable"] is False

    def test_disabled_tests_omitted(self, capsys):
        with unittest.mock.patch(
            "tools.waf_bypass.fingerprint_waf",
            return_value={"detected": False, "name": None, "evidence": [], "all_matches": []},
        ):
            main.cmd_poja(_base_args(adaptive=False, test_sqli=False))

        d = _last_json(capsys)
        assert "adaptive" not in d
        assert "sqli_test" not in d
        assert d["vulnerable"] is False
