import re
import pytest
import responses
from tools.ssrf_detector import check


class TestSSRFDetector:
    @responses.activate
    def test_cloud_metadata_disclosure(self):
        body = 'ami-id: ami-12345 instance-type: t2.micro'
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/fetch\?.*'),
            body=body, status=200,
        )
        result = check('http://test.com/fetch', 'url')
        assert result['vulnerable'] is True
        assert result['type'] in ('disclosure', 'internal_reachable')

    @responses.activate
    def test_internal_reachable(self):
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/fetch\?.*'),
            body='<!DOCTYPE html><html>...' + 'x' * 50,
            status=200,
        )
        result = check('http://test.com/fetch', 'url')
        assert result['vulnerable'] is not None

    @responses.activate
    def test_no_ssrf(self):
        responses.add(
            responses.GET,
            re.compile(r'http://test\.com/fetch\?.*'),
            body='ok', status=200,
        )
        result = check('http://test.com/fetch', 'url')
        assert result['vulnerable'] is False
