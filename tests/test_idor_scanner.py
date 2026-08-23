import re

import requests
import responses

from tools.idor_scanner import check, check_unauthorized, _looks_like_data


class _FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class TestLooksLikeData:
    def test_data(self):
        assert _looks_like_data(_FakeResp(200, '{"name": "alice"}'))
        assert _looks_like_data(_FakeResp(200, "<html>user profile</html>"))

    def test_blocked(self):
        assert not _looks_like_data(_FakeResp(403, "forbidden"))
        assert not _looks_like_data(_FakeResp(401, "unauthorized"))
        assert not _looks_like_data(_FakeResp(404, "not found"))
        assert not _looks_like_data(_FakeResp(200, "null"))
        assert not _looks_like_data(_FakeResp(302, "", {"Location": "/login"}))


class TestIdorCheck:
    @responses.activate
    def test_horizontal_escalation(self):
        def user_cb(request, uid):
            return (200, {}, '{"id": %s, "name": "user%s", "email": "u%s@x.com"}' % (uid, uid, uid))

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/api/user\?id=1001$"),
            callback=lambda r: user_cb(r, 1001),
        )
        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/api/user\?id=1002$"),
            callback=lambda r: user_cb(r, 1002),
        )
        # B's session view of id=1002 also returns user1002 -> A's read matches
        sess_a = requests.Session()
        sess_b = requests.Session()
        result = check("http://test.com/api/user?id={id}", "id",
                       sess_a=sess_a, sess_b=sess_b,
                       my_id="1001", other_id="1002", timeout=5)
        assert result["vulnerable"] is True
        assert "user1002" in result.get("response_preview", "")

    @responses.activate
    def test_no_escalation_when_blocked(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/api/user\?id=1001$"),
            body='{"id": 1001}', status=200,
        )
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/api/user\?id=1002$"),
            body="Forbidden", status=403,
        )
        sess_a = requests.Session()
        result = check("http://test.com/api/user?id={id}", "id",
                       sess_a=sess_a, my_id="1001", other_id="1002", timeout=5)
        assert result["vulnerable"] is False

    @responses.activate
    def test_post_json_idor(self):
        def json_cb(request):
            body = request.body or "{}"
            import json as _json
            try:
                uid = _json.loads(body).get("userId", "")
            except Exception:
                uid = ""
            return (200, {}, '{"id": "%s", "secret": "data-%s"}' % (uid, uid))

        responses.add_callback(
            responses.POST,
            re.compile(r"http://test\.com/api/order$"),
            callback=json_cb,
        )
        sess_a = requests.Session()
        result = check("http://test.com/api/order", "id",
                       sess_a=sess_a, my_id="A1", other_id="B2",
                       method="POST", json_param="userId", timeout=5)
        assert result["vulnerable"] is True
        assert "data-B2" in result.get("response_preview", "")


class TestUnauthorized:
    @responses.activate
    def test_unauth_data_leak(self):
        responses.add(
            responses.GET,
            "http://test.com/admin/api/users",
            body='[{"name": "admin"}]', status=200,
        )
        result = check_unauthorized("http://test.com/admin/api/users")
        assert result["vulnerable"] is True

    @responses.activate
    def test_unauth_blocked(self):
        responses.add(
            responses.GET,
            "http://test.com/admin/api/users",
            body="redirecting", status=302,
            headers={"Location": "/login"},
        )
        result = check_unauthorized("http://test.com/admin/api/users")
        assert result["vulnerable"] is False
