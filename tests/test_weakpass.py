import re
from urllib.parse import parse_qs

import responses

from tools.weakpass import _likely_success, _parse_form, check


def _login_cb(request):
    body = request.body or ""
    data = parse_qs(body)
    user = data.get("user", [""])[0]
    pwd = data.get("pass", [""])[0]
    if user.startswith("__aimy_no_such"):
        return (200, {}, "<form action='/login'><input name='user'>"
                          "<input type='password' name='pass'></form>"
                          "invalid credentials")
    if user == "admin" and pwd == "admin":
        return (302, {"Location": "/dashboard"}, "")
    return (200, {}, "<form action='/login'><input name='user'>"
                      "<input type='password' name='pass'></form>"
                      "invalid credentials")


def _fail_cb(request):
    return (200, {}, "<form action='/login'><input name='user'>"
                      "<input type='password' name='pass'></form>"
                      "invalid credentials")


def _setup_route(cb):
    responses.add_callback(responses.GET, re.compile(r"http://t\.com.*"),
                           callback=lambda r: (200, {}, "<html><body>"
                           "<form action='/login' method='post'>"
                           "<input name='user'><input type='password' name='pass'>"
                           "<input type='submit' name='submit'></form></body></html>"))
    responses.add_callback(responses.POST, re.compile(r"http://t\.com.*"),
                           callback=cb)


class TestParseForm:
    def test_login_form_extracted(self):
        html = ("<form action='/login' method='post'>"
                "<input name='user'><input type='password' name='pass'>"
                "<input type='hidden' name='csrf' value='x'></form>")
        f = _parse_form(html)
        assert f is not None
        assert f["password_field"] == "pass"
        assert f["method"] == "post"

    def test_no_password_form_ignored(self):
        html = "<form action='/search'><input name='q'></form>"
        assert _parse_form(html) is None


class TestWeakpass:
    @responses.activate
    def test_weak_cred_detected(self):
        _setup_route(_login_cb)
        r = check("http://t.com/login", creds=[("admin", "admin")],
                  timeout=5, delay=0)
        assert r["form"] is not None
        assert r["findings"] and r["findings"][0]["user"] == "admin"
        assert r["findings"][0]["password"] == "admin"

    @responses.activate
    def test_no_weak_cred(self):
        _setup_route(_fail_cb)
        r = check("http://t.com/login", creds=[("admin", "admin"),
                                               ("root", "root")],
                  timeout=5, delay=0)
        assert r["findings"] == []

    @responses.activate
    def test_no_form_reports_error(self):
        responses.add_callback(responses.GET, re.compile(r"http://t\.com.*"),
                               callback=lambda r: (200, {}, "<html>hello</html>"))
        r = check("http://t.com/login", timeout=5, delay=0)
        assert r["form"] is not None
        assert r["form"].get("kind") == "api"
        assert r["findings"] == []

    @responses.activate
    def test_filebrowser_api_login(self):
        def api_cb(request):
            import json
            if request.url.endswith("/api/login"):
                body = json.loads(request.body or "{}")
                if body.get("username") == "admin" and body.get("password") == "admin":
                    return (200, {}, '{"token": "abc123", "type": "ok"}')
                return (401, {}, '{"type": "unauthorized"}')
            return (200, {}, "<html>SPA</html>")
        responses.add_callback(responses.GET, re.compile(r"http://t\.com.*"),
                               callback=api_cb)
        responses.add_callback(responses.POST, re.compile(r"http://t\.com.*"),
                               callback=api_cb)
        r = check("http://t.com", creds=[("admin", "admin"), ("admin", "bad")],
                  timeout=5, delay=0)
        assert r["form"]["kind"] == "api"
        assert r["findings"] and r["findings"][0]["user"] == "admin"


    @responses.activate
    def test_custom_api_url(self):
        def api_cb(request):
            import json
            body = json.loads(request.body or "{}")
            if body.get("login") == "root" and body.get("pass") == "root":
                return (200, {}, '{"ok": true, "session": "s1"}')
            return (200, {}, '{"error": "unauthorized"}')
        responses.add_callback(responses.POST, re.compile(r"http://api\.com.*"),
                               callback=api_cb)
        r = check("http://api.com", creds=[("root", "root"), ("admin", "x")],
                  timeout=5, delay=0, api_url="http://api.com/login",
                  user_field="login", pass_field="pass")
        assert r["form"]["kind"] == "api"
        assert r["findings"] and r["findings"][0]["user"] == "root"


class TestLikelySuccess:
    def test_redirect_out_of_login(self):
        class R:
            def __init__(self, status, url, text):
                self.status_code = status
                self.url = url
                self.text = text
        neg = R(200, "http://t.com/login", "login page")
        pos = R(302, "http://t.com/dashboard", "")
        ok, reason = _likely_success(neg, pos)
        assert ok is True
