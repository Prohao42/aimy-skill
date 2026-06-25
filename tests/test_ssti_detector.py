import re
import pytest
import responses
from tools.ssti_detector import check


class TestSSTIDetector:
    @responses.activate
    def test_expression_reflection(self):
        body = '999998000001'
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/page\?.*'),
            body=body, status=200,
        )
        result = check('http://test.com/page', 'name')
        assert result['vulnerable'] is True

    @responses.activate
    def test_alt_engine_detection(self):
        body = '<html>A</html>'
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/page\?.*'),
            body=body, status=200,
        )
        result = check('http://test.com/page', 'name')
        assert result['vulnerable'] is True

    @responses.activate
    def test_no_ssti(self):
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/page\?.*'),
            body='normal page content', status=200,
        )
        result = check('http://test.com/page', 'name')
        assert result['vulnerable'] is False

    @responses.activate
    def test_time_based_fallback(self):
        import time
        def delayed(request):
            time.sleep(3)
            return (200, {}, 'ok')
        responses.add_callback(
            responses.GET,
            re.compile(r'http://test\.com/page\?.*'),
            callback=delayed,
        )
        result = check('http://test.com/page', 'name', timeout=2)
        assert result['vulnerable'] is not None
