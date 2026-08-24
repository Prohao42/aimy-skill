import re

import requests
import responses

from tools.cms_fingerprint import fingerprint
from tools.payload_engine import WAF_STRATEGIES
from tools.waf_bypass import WAF_BLOCK_SIGNATURES, classify_block


class _Resp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text


class TestCmsFingerprint:
    @responses.activate
    def test_v5_74cms_detected(self):
        responses.add(responses.GET, re.compile(r"http://t\.com/index/safe/index\.html"),
                      body="<html>safe</html>", status=200)
        responses.add(responses.GET, re.compile(r"http://t\.com/plus/ajax_user\.php"),
                      body="x", status=404)
        responses.add(responses.GET, re.compile(r"http://t\.com/.*"),
                      body="", status=404)
        sess = requests.Session()
        r = fingerprint("http://t.com", sess=sess, timeout=5)
        assert r["cms"] == "74cms"
        assert r["version"] == "v5.x"
        assert r["matched_vulns"]

    @responses.activate
    def test_v3_74cms_detected(self):
        responses.add(responses.GET, re.compile(r"http://t\.com/plus/ajax_user\.php"),
                      body="ajax", status=200)
        responses.add(responses.GET, re.compile(r"http://t\.com/index/safe/index\.html"),
                      body="x", status=404)
        responses.add(responses.GET, re.compile(r"http://t\.com/.*"),
                      body="", status=404)
        sess = requests.Session()
        r = fingerprint("http://t.com", sess=sess, timeout=5)
        assert r["cms"] == "74cms"
        assert r["version"] == "v3.x"
        assert any("SQL" in v["name"] for v in r["matched_vulns"])


class TestBaotaSupport:
    def test_baota_strategy_in_payload_engine(self):
        assert "baota" in WAF_STRATEGIES
        assert "btwaf" in WAF_STRATEGIES
        assert "double_url" in WAF_STRATEGIES["baota"]["priority"]

    def test_baota_block_signature(self):
        assert "baota" in WAF_BLOCK_SIGNATURES
        class R:
            status_code = 403
            headers = {}
            text = "您的请求已被拦截 - btwaf"
        assert classify_block(R()) == "baota"

    def test_baota_generation(self):
        from tools.payload_engine import generate_sqli_error
        payloads = generate_sqli_error("string", waf_name="baota")
        assert len(payloads) > 0
