import re

import responses

from tools.xss_browser_verify import check, _verify_http


class TestXssBrowserVerify:
    @responses.activate
    def test_http_fallback_confirms_reflection(self):
        def callback(request):
            import urllib.parse
            q = urllib.parse.parse_qs(request.url.split("?", 1)[1])["q"][0]
            return (200, {}, "<html>%s</html>" % q)

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/xss\?.*"),
            callback=callback,
        )
        import requests
        sess = requests.Session()
        result = _verify_http("http://test.com/xss", "q", sess, 5)
        assert result["vulnerable"] is True

    @responses.activate
    def test_no_reflection(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/xss\?.*"),
            body="no reflection here",
            status=200,
        )
        import requests
        sess = requests.Session()
        result = _verify_http("http://test.com/xss", "q", sess, 5)
        assert result["vulnerable"] is False

    @responses.activate
    def test_check_returns_playwright_status(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/xss\?.*"),
            body="clean",
            status=200,
        )
        import requests
        sess = requests.Session()
        result = check("http://test.com/xss", "q", sess, 3)
        assert "playwright_available" in result
        assert result["vulnerable"] is False
