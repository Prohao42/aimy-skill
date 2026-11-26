import re

import responses

from tools.cmdi_detector import check


class TestCMDIDetector:
    @responses.activate
    def test_output_detection(self):
        def callback(request):
            if "CMDI_NOMINAL" in request.url:
                return (200, {}, "command page")
            return (200, {}, "uid=1000(user) gid=1000(user) groups=1000(user)")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/exec\?.*"),
            callback=callback,
        )

        result = check("http://test.com/exec", "cmd")
        assert result["vulnerable"] is True
        assert result["type"] == "output"

    @responses.activate
    def test_post_body_detection(self):
        def callback(request):
            if "CMDI_NOMINAL" in request.body:
                return (200, {}, "command page")
            return (200, {}, "uid=1000(user) gid=1000(user)")

        responses.add_callback(
            responses.POST,
            "http://test.com/exec",
            callback=callback,
        )

        result = check(
            "http://test.com/exec",
            "cmd",
            post_body=True,
            post_data={"Submit": "Submit"},
        )
        assert result["vulnerable"] is True
        assert result["type"] == "output"

    @responses.activate
    def test_generic_slash_on_error_page_is_not_cmdi(self):
        body = '<html><a href="/login">ERROR: invalid IP</a></html>'
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/exec\?.*"),
            body=body,
            status=200,
        )

        result = check("http://test.com/exec", "cmd")
        assert result["vulnerable"] is False
        assert result["evidence"] == []

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
