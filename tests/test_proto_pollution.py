import re
import pytest
import responses
from tools.proto_pollution import check, PP_MARKER


class TestProtoPollution:
    @responses.activate
    def test_get_param_pollution(self):
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/page\?.*'),
            body=f'<html>{PP_MARKER}=true</html>', status=200,
        )
        result = check('http://test.com/page', 'data')
        assert result['vulnerable'] is True
        assert result['type'] == 'get'

    @responses.activate
    def test_post_body_pollution(self):
        responses.add(
            responses.POST, 'http://test.com/page',
            body=f'<html>{PP_MARKER} detected</html>', status=200,
        )
        result = check('http://test.com/page', 'data')
        assert result['vulnerable'] is True

    @responses.activate
    def test_no_pollution(self):
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/page\?.*'),
            body='normal response', status=200,
        )
        responses.add(
            responses.POST, 'http://test.com/page',
            body='normal response', status=200,
        )
        result = check('http://test.com/page', 'data')
        assert result['vulnerable'] is False
