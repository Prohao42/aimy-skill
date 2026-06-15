import pytest
from tools.http_client import build_url


class TestBuildUrl:
    def test_simple(self):
        url = build_url("http://example.com/page", "id", "123")
        assert "id=123" in url
        assert url.startswith("http://example.com/page")

    def test_with_existing_query(self):
        url = build_url("http://example.com/page?foo=bar", "q", "test")
        assert "foo=bar" in url
        assert "q=test" in url

    def test_special_chars_encoded(self):
        url = build_url("http://example.com/", "q", "hello world&test=1")
        assert "hello+world" in url
        assert "%26test%3D1" in url or "&test%3D1" not in url

    def test_quote_in_payload(self):
        url = build_url("http://example.com/page", "id", "1' OR '1'='1")
        assert "%27" in url  # single quote encoded

    def test_empty_param_value(self):
        url = build_url("http://example.com/page", "debug", "")
        assert "debug=" in url
