import pytest
import responses
from tools.waf_bypass import (
    fingerprint_waf, check, generate_sqli_payloads,
    ENCODER_CHAINS,
)


class TestFingerprintWaf:
    @responses.activate
    def test_cloudflare_detected(self):
        responses.add(
            responses.GET, 'http://test.com/page',
            body='Attention Required! | Cloudflare', status=403,
            headers={'cf-ray': 'abc123', 'server': 'cloudflare'},
        )
        result = fingerprint_waf('http://test.com/page')
        assert result is not None
        assert 'cloudflare' in result['name'].lower()

    @responses.activate
    def test_aws_waf_detected(self):
        responses.add(
            responses.GET, 'http://test.com/page',
            body='Request blocked by AWS WAF', status=403,
        )
        result = fingerprint_waf('http://test.com/page')
        assert result is not None

    @responses.activate
    def test_no_waf(self):
        responses.add(
            responses.GET, 'http://test.com/page',
            body='normal page', status=200,
        )
        result = fingerprint_waf('http://test.com/page')
        assert result['detected'] is False


class TestGenerateSqliPayloads:
    def test_returns_payloads(self):
        payloads = generate_sqli_payloads("1' OR '1'='1", waf_name=None)
        assert len(payloads) > 0
        assert all(isinstance(p, dict) for p in payloads)
        assert all("payload" in p for p in payloads)

    def test_waf_aware(self):
        payloads = generate_sqli_payloads("1' OR '1'='1", waf_name='cloudflare')
        assert len(payloads) > 0


class TestEncoderChains:
    def test_chains_defined(self):
        assert len(ENCODER_CHAINS) > 0
        for chain in ENCODER_CHAINS:
            assert len(chain) > 0


class TestCheck:
    @responses.activate
    def test_basic_request(self):
        responses.add(
            responses.GET, re.compile(r'http://test\.com/page\?.*'),
            body='ok', status=200,
        )
        result = check('http://test.com/page', 'id')
        assert result is not None


import re
