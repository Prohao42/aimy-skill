import re

import requests
import responses

from tools.second_order_sqli import check


class TestSecondOrderSqli:
    @responses.activate
    def test_store_and_fetch_diff(self):
        stored = {}

        def on_post(request):
            body = request.body or ""
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            m = re.search(r"username=([^&]*)", body)
            val = m.group(1) if m else ""
            import urllib.parse
            stored["username"] = urllib.parse.unquote_plus(val)
            return (200, {}, "ok")

        def on_get(request):
            val = stored.get("username", "")
            if "1=1" in val or "1=1" in val.replace("+", " "):
                return (200, {}, "x" * 200 + "admin row")
            if "1=2" in val:
                return (200, {}, "no rows")
            return (200, {}, "profile page")

        responses.add_callback(
            responses.POST,
            re.compile(r"http://test\.com/register$"),
            callback=on_post,
        )
        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/(profile|dashboard|me|account|api/user|api/profile)$"),
            callback=on_get,
        )

        sess = requests.Session()
        result = check("http://test.com/", "username", sess, 5)
        assert result["vulnerable"] is True
        assert result["type"] == "second_order_sqli"
        assert result["store_path"] and result["fetch_path"]
        assert result["evidence"]

    @responses.activate
    def test_no_diff_not_vulnerable(self):
        def on_post(request):
            return (200, {}, "ok")

        def on_get(request):
            return (200, {}, "same page always")

        responses.add_callback(
            responses.POST,
            re.compile(r"http://test\.com/register$"),
            callback=on_post,
        )
        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/(profile|dashboard|me|account|api/user|api/profile)$"),
            callback=on_get,
        )
        sess = requests.Session()
        result = check("http://test.com/", "username", sess, 3)
        assert result["vulnerable"] is False
