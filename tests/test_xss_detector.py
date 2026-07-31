import responses

from tools.xss_detector import check


class TestXSSDetector:
    @responses.activate
    def test_reflected_xss(self):
        def callback(request):
            import urllib.parse
            q = urllib.parse.parse_qs(request.url.split("?", 1)[1])["q"][0]
            return (200, {}, "<html>%s</html>" % q)

        responses.add_callback(
            responses.GET,
            "http://test.com/page",
            callback=callback,
        )

        result = check("http://test.com/page", "q")
        assert result["vulnerable"] is True

    @responses.activate
    def test_no_reflection(self):
        responses.add(
            responses.GET,
            url="http://test.com/search?q=test",
            body="no match here",
            status=200,
        )

        result = check("http://test.com/search", "q")
        assert result["vulnerable"] is False


class TestXSSDetectorPost:
    @responses.activate
    def test_post_xss(self):
        def callback(request):
            import urllib.parse
            body = urllib.parse.parse_qs(request.body)
            payload = body.get("content", [""])[0]
            return (200, {}, f"<html>{payload}</html>")

        responses.add_callback(
            responses.POST,
            url="http://test.com/comment",
            callback=callback,
        )

        result = check(
            "http://test.com/comment", "content",
            post_body=True, post_data={"content": "test"},
        )
        assert result["vulnerable"] is True
