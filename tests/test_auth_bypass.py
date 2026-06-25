import pytest
import responses
from tools.auth_bypass import check


class TestAuthBypass:
    @responses.activate
    def test_path_bypass_found(self):
        responses.add(
            responses.GET, 'http://test.com/admin',
            body='login page', status=401,
        )
        responses.add(
            responses.GET, 'http://test.com/ADMIN',
            body='admin content', status=200,
        )
        responses.add(
            responses.GET, re.compile(r'http://test\.com/.*'),
            body='not found', status=404,
        )
        import requests
        sess = requests.Session()
        result = check('http://test.com/admin', sess)
        assert result['vulnerable'] is True

    @responses.activate
    def test_header_injection_bypass(self):
        responses.add(
            responses.GET, 'http://test.com/admin',
            body='admin content', status=200,
            match=[responses.matchers.header_matcher({'X-Forwarded-For': '127.0.0.1'})],
        )
        import requests
        sess = requests.Session()
        result = check('http://test.com/admin', sess)
        assert result is not None

    @responses.activate
    def test_no_bypass(self):
        responses.add(
            responses.GET, re.compile(r'http://test\.com/.*'),
            body='login page', status=401,
        )
        import requests
        sess = requests.Session()
        result = check('http://test.com/admin', sess)
        assert result['vulnerable'] is False


import re
