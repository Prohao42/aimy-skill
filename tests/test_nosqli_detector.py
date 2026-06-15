import re
import pytest
import responses
from tools.nosqli_detector import check


class TestNoSQLIDetector:
    @responses.activate
    def test_boolean_detection(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/login\?id=1"),
            body="normal response",
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/login\?id=%27.*"),
            body="admin data leaked! " + "x" * 40,
            status=200,
        )

        result = check("http://test.com/login", "id")
        assert result["vulnerable"] is True

    @responses.activate
    def test_no_nosqli(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/login\?.*"),
            body="normal response",
            status=200,
        )

        result = check("http://test.com/login", "id")
        assert result["vulnerable"] is False
