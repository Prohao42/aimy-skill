import pytest
import responses
from tools.second_order_verifier import SecondOrderVerifier


class TestSecondOrderVerifier:
    def test_verifier_init(self):
        v = SecondOrderVerifier()
        assert v is not None

    @responses.activate
    def test_sqli_verification(self):
        responses.add(
            responses.GET,
            "http://test.com/page?id=1",
            body="normal page",
            status=200,
        )
        responses.add(
            responses.GET,
            "http://test.com/page?id=1'",
            body="sql error near syntax",
            status=200,
        )
        v = SecondOrderVerifier()
        result = v.verify(
            url="http://test.com/page",
            param="id",
            vuln_type="sqli",
            original_evidence={"body": "sql error", "status": 200}
        )
        assert hasattr(result, 'confirmed')

    @responses.activate
    def test_xss_verification(self):
        responses.add(
            responses.GET,
            "http://test.com/search?q=test",
            body="test",
            status=200,
        )
        responses.add(
            responses.GET,
            "http://test.com/search?q=<script>alert(1)</script>",
            body="<script>alert(1)</script>",
            status=200,
        )
        v = SecondOrderVerifier()
        result = v.verify(
            url="http://test.com/search",
            param="q",
            vuln_type="xss",
            original_evidence={"body": "<script>alert(1)</script>", "status": 200}
        )
        assert hasattr(result, 'confirmed')

    def test_unsupported_vuln_type(self):
        v = SecondOrderVerifier()
        result = v.verify(
            url="http://test.com/page",
            param="id",
            vuln_type="unsupported_type",
        )
        assert result.confirmed is False

    @responses.activate
    def test_ssrf_verification(self):
        responses.add(
            responses.GET,
            "http://test.com/proxy?url=http://internal",
            body="internal response",
            status=200,
        )
        v = SecondOrderVerifier()
        result = v.verify(
            url="http://test.com/proxy",
            param="url",
            vuln_type="ssrf",
            original_evidence={"body": "internal response", "status": 200}
        )
        assert hasattr(result, 'confirmed')

    @responses.activate
    def test_lfi_verification(self):
        responses.add(
            responses.GET,
            "http://test.com/view?file=../../../../etc/passwd",
            body="root:x:0:0:root:/root:/bin/bash",
            status=200,
        )
        v = SecondOrderVerifier()
        result = v.verify(
            url="http://test.com/view",
            param="file",
            vuln_type="lfi",
            original_evidence={"body": "root:x:0:0", "status": 200}
        )
        assert hasattr(result, 'confirmed')
