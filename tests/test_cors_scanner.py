import pytest
import responses
from tools.cors_scanner import check, check_single_origin


class TestCORSScanner:
    @responses.activate
    def test_origin_reflection(self):
        responses.add(
            responses.GET, 'http://test.com/api',
            status=200,
            headers={'Access-Control-Allow-Origin': 'http://evil.com'},
        )
        result = check('http://test.com/api')
        assert result['vulnerable'] is True
        assert len(result['findings']) > 0

    @responses.activate
    def test_wildcard_origin(self):
        responses.add(
            responses.GET, 'http://test.com/api',
            status=200,
            headers={'Access-Control-Allow-Origin': '*'},
        )
        result = check('http://test.com/api')
        assert result['vulnerable'] is True

    @responses.activate
    def test_credentialed_reflection(self):
        responses.add(
            responses.GET, 'http://test.com/api',
            status=200,
            headers={
                'Access-Control-Allow-Origin': 'http://evil.com',
                'Access-Control-Allow-Credentials': 'true',
            },
        )
        result = check('http://test.com/api')
        assert result['vulnerable'] is True
        reflected = [f for f in result['findings'] if f.get('credentialed')]
        assert len(reflected) > 0

    @responses.activate
    def test_no_cors_vuln(self):
        responses.add(
            responses.GET, 'http://test.com/api',
            status=200,
            headers={},
        )
        responses.add(
            responses.OPTIONS, 'http://test.com/api',
            status=200,
            headers={},
        )
        result = check('http://test.com/api')
        assert result['vulnerable'] is False

    def test_check_single_origin_function_exists(self):
        assert callable(check_single_origin)
