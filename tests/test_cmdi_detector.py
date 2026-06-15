import re
import pytest
import responses
from tools.cmdi_detector import check


class TestCMDIDetector:
    @responses.activate
    def test_output_detection(self):
        body = "uid=1000(user) gid=1000(user) groups=1000(user)"
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/exec\?.*"),
            body=body,
            status=200,
        )

        result = check("http://test.com/exec", "cmd")
        assert result["vulnerable"] is True
        assert result["type"] == "output"

    @responses.activate
    def test_no_cmdi(self):
        responses.add(
            responses.GET,
            url="http://test.com/exec?cmd=ls",
            body="permission denied",
            status=403,
        )

        result = check("http://test.com/exec", "cmd")
        assert result["vulnerable"] is False
