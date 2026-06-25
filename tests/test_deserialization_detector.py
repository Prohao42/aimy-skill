import re
import pytest
import responses
from tools.deserialization_detector import check


class TestDeserializationDetector:
    @responses.activate
    def test_source_code_leak(self):
        body = 'using java.io.Serializable; import org.apache.commons...'
        responses.add(
            responses.GET,
            'http://test.com/app',
            body=body, status=200,
        )
        result = check('http://test.com/app', 'data')
        assert result['vulnerable'] is True
        assert result['type'] == 'source_code_leak'

    @responses.activate
    def test_php_unserialize_post(self):
        body = 'PHP Fatal error:  unserialize()'
        responses.add(
            responses.POST,
            url='http://test.com/app',
            body=body, status=500,
        )
        result = check('http://test.com/app', 'data')
        assert result['vulnerable'] is True

    @responses.activate
    def test_java_deser_post(self):
        body = 'java.io.StreamCorruptedException'
        responses.add(
            responses.POST,
            url='http://test.com/app',
            body=body, status=500,
        )
        result = check('http://test.com/app', 'data')
        assert result['vulnerable'] is True

    @responses.activate
    def test_no_deser(self):
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/app\?.*'),
            body='normal page', status=200,
        )
        responses.add(
            responses.POST,
            url='http://test.com/app',
            body='success', status=200,
        )
        result = check('http://test.com/app', 'data')
        assert result['vulnerable'] is False
