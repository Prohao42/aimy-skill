import responses

from tools.auth_engine import AuthSession, detect_form_fields


class TestDetectFormFields:
    def test_detects_csrf_token_input(self):
        html = '<input type="hidden" name="csrf_token" value="tok123">'
        fields = detect_form_fields(html)
        assert fields["csrf_token"] == "tok123"

    def test_detects_csrf_token_underscore(self):
        html = '<input name="_csrf" value="tok456">'
        fields = detect_form_fields(html)
        assert fields["csrf_token"] == "tok456"

    def test_detects_csrf_authenticity_token(self):
        html = '<input name="authenticity_token" value="tok789">'
        fields = detect_form_fields(html)
        assert fields["csrf_token"] == "tok789"

    def test_detects_csrf_meta(self):
        html = '<meta name="csrf-token" content="meta_tok">'
        fields = detect_form_fields(html)
        assert fields["csrf_token"] == "meta_tok"

    def test_detects_csrf_token_short(self):
        html = '<input type="hidden" name="csrf" value="short_tok">'
        fields = detect_form_fields(html)
        assert fields["csrf_token"] == "short_tok"

    def test_detects_csrf_token_private(self):
        html = '<input type="hidden" name="_token" value="private_tok">'
        fields = detect_form_fields(html)
        assert fields["csrf_token"] == "private_tok"

    def test_detects_password_field(self):
        html = '<input type="password" name="passwd">'
        fields = detect_form_fields(html)
        assert fields["has_password"] is True

    def test_detects_form_action(self):
        html = '<form action="/login" method="POST">'
        fields = detect_form_fields(html)
        assert fields["action"] == "/login"

    def test_no_form_action_fallback(self):
        html = '<form method="GET"><input type="text" name="q"></form>'
        fields = detect_form_fields(html)
        assert fields["action"] == ""

    def test_text_input_extracted(self):
        html = '<input type="text" name="username" value="admin">'
        fields = detect_form_fields(html)
        assert fields["inputs"].get("username") == "admin"

    def test_email_input_extracted(self):
        html = '<input type="email" name="email" value="a@b.com">'
        fields = detect_form_fields(html)
        assert fields["inputs"].get("email") == "a@b.com"

    def test_hidden_input_without_value(self):
        html = '<input type="hidden" name="step">'
        fields = detect_form_fields(html)
        assert fields["inputs"].get("step") == ""

    def test_input_with_name_before_type(self):
        html = '<input name="user" type="text" value="admin">'
        fields = detect_form_fields(html)
        assert fields["inputs"].get("user") == "admin"

    def test_empty_html_returns_defaults(self):
        fields = detect_form_fields("<html><body></body></html>")
        assert fields == {"action": "", "inputs": {}, "has_password": False}

    def test_hidden_input_with_value(self):
        html = '<input type="hidden" name="redirect" value="/home">'
        fields = detect_form_fields(html)
        assert fields["inputs"].get("redirect") == "/home"


class TestAuthSession:
    def test_default_user_agent_set(self):
        engine = AuthSession()
        assert "User-Agent" in engine.sess.headers

    def test_custom_session_preserves_headers(self):
        import requests
        sess = requests.Session()
        sess.headers["X-Custom"] = "val"
        engine = AuthSession(sess)
        assert engine.sess.headers["X-Custom"] == "val"

    @responses.activate
    def test_login_form_success(self):
        responses.add(
            responses.GET, "http://test.com/login",
            body='<form action="http://test.com/login"><input type="text" name="user">'
                 '<input type="password" name="pass">'
                 '<input type="submit"></form>',
            status=200,
        )
        responses.add(
            responses.POST, "http://test.com/login",
            body="x" * 120, status=200,
        )
        engine = AuthSession()
        result = engine.login_form("http://test.com/login", "admin", "secret",
                                    user_field="user", pass_field="pass")
        assert result is True

    @responses.activate
    def test_login_form_failure_status(self):
        responses.add(
            responses.GET, "http://test.com/login",
            body='<form action="/login"><input type="text" name="user">'
                 '<input type="password" name="pass"></form>',
            status=200,
        )
        responses.add(
            responses.POST, "http://test.com/login",
            body="Unauthorized", status=401,
        )
        engine = AuthSession()
        result = engine.login_form("http://test.com/login", "admin", "secret",
                                    user_field="user", pass_field="pass")
        assert result is False

    @responses.activate
    def test_login_form_short_response(self):
        responses.add(
            responses.GET, "http://test.com/login",
            body='<form><input type="text" name="u">'
                 '<input type="password" name="p"></form>',
            status=200,
        )
        responses.add(
            responses.POST, "http://test.com/login",
            body="OK", status=200,
        )
        engine = AuthSession()
        result = engine.login_form("http://test.com/login", "admin", "secret",
                                    user_field="u", pass_field="p")
        assert result is False

    @responses.activate
    def test_login_form_with_csrf(self):
        responses.add(
            responses.GET, "http://test.com/login",
            body='<form action="http://test.com/login"><input type="hidden" name="csrf_token" value="tok123">'
                 '<input type="text" name="username">'
                 '<input type="password" name="password"></form>',
            status=200,
        )
        responses.add(
            responses.POST, "http://test.com/login",
            body="x" * 120, status=200,
        )
        engine = AuthSession()
        result = engine.login_form("http://test.com/login", "admin", "secret")
        assert result is True

    @responses.activate
    def test_login_form_with_extra_hidden_inputs(self):
        responses.add(
            responses.GET, "http://test.com/login",
            body='<form action="http://test.com/login">'
                 '<input type="hidden" name="csrf_token" value="tok">'
                 '<input type="hidden" name="redirect" value="/home">'
                 '<input type="text" name="username" value="admin">'
                 '<input type="password" name="password"></form>',
            status=200,
        )
        responses.add(
            responses.POST, "http://test.com/login",
            body="x" * 120, status=200,
        )
        engine = AuthSession()
        result = engine.login_form("http://test.com/login", "admin", "secret")
        assert result is True

    @responses.activate
    def test_login_form_network_error_returns_false(self):
        responses.add(
            responses.GET, "http://test.com/login",
            body=Exception("Connection refused"),
        )
        engine = AuthSession()
        result = engine.login_form("http://test.com/login", "admin", "secret")
        assert result is False

    @responses.activate
    def test_login_form_exception_during_post(self):
        responses.add(
            responses.GET, "http://test.com/login",
            body='<form><input type="text" name="u">'
                 '<input type="password" name="p"></form>',
            status=200,
        )
        responses.add(
            responses.POST, "http://test.com/login",
            body=Exception("Timeout"),
        )
        engine = AuthSession()
        result = engine.login_form("http://test.com/login", "admin", "secret",
                                    user_field="u", pass_field="p")
        assert result is False

    @responses.activate
    def test_login_api_success_bearer_token(self):
        responses.add(
            responses.POST, "http://test.com/api/login",
            json={"token": "jwt_val"}, status=200,
        )
        engine = AuthSession()
        result = engine.login_api("http://test.com/api/login", "admin", "secret")
        assert result is True
        assert engine.sess.headers.get("Authorization") == "Bearer jwt_val"

    @responses.activate
    def test_login_api_access_token(self):
        responses.add(
            responses.POST, "http://test.com/api/login",
            json={"access_token": "access_val"}, status=200,
        )
        engine = AuthSession()
        result = engine.login_api("http://test.com/api/login", "admin", "secret")
        assert result is True
        assert engine.sess.headers.get("Authorization") == "Bearer access_val"

    @responses.activate
    def test_login_api_nested_token(self):
        responses.add(
            responses.POST, "http://test.com/api/login",
            json={"data": {"token": "nested_val"}}, status=200,
        )
        engine = AuthSession()
        result = engine.login_api("http://test.com/api/login", "admin", "secret")
        assert result is True
        assert "nested_val" in engine.sess.headers.get("Authorization", "")

    @responses.activate
    def test_login_api_no_token_in_response(self):
        responses.add(
            responses.POST, "http://test.com/api/login",
            json={"message": "ok"}, status=200,
        )
        engine = AuthSession()
        result = engine.login_api("http://test.com/api/login", "admin", "secret")
        assert result is True

    @responses.activate
    def test_login_api_failure_status(self):
        responses.add(
            responses.POST, "http://test.com/api/login",
            body="Unauthorized", status=401,
        )
        engine = AuthSession()
        result = engine.login_api("http://test.com/api/login", "admin", "secret")
        assert result is False

    @responses.activate
    def test_login_api_non_json_response(self):
        responses.add(
            responses.POST, "http://test.com/api/login",
            body="OK plain text", status=200,
        )
        engine = AuthSession()
        result = engine.login_api("http://test.com/api/login", "admin", "secret")
        assert result is True

    @responses.activate
    def test_login_api_network_error_returns_false(self):
        responses.add(
            responses.POST, "http://test.com/api/login",
            body=Exception("Timeout"),
        )
        engine = AuthSession()
        result = engine.login_api("http://test.com/api/login", "admin", "secret")
        assert result is False

    @responses.activate
    def test_login_basic_success(self):
        responses.add(
            responses.GET, "http://test.com/protected",
            body="Authorized", status=200,
        )
        engine = AuthSession()
        result = engine.login_basic("http://test.com/protected", "admin", "secret")
        assert result is True

    @responses.activate
    def test_login_basic_failure(self):
        responses.add(
            responses.GET, "http://test.com/protected",
            body="Unauthorized", status=401,
        )
        engine = AuthSession()
        result = engine.login_basic("http://test.com/protected", "admin", "secret")
        assert result is False

    @responses.activate
    def test_login_basic_redirect(self):
        responses.add(
            responses.GET, "http://test.com/protected",
            body="Redirecting", status=302,
        )
        engine = AuthSession()
        result = engine.login_basic("http://test.com/protected", "admin", "secret")
        assert result is True

    @responses.activate
    def test_login_basic_network_error_returns_false(self):
        responses.add(
            responses.GET, "http://test.com/protected",
            body=Exception("Connection refused"),
        )
        engine = AuthSession()
        result = engine.login_basic("http://test.com/protected", "admin", "secret")
        assert result is False

    def test_set_cookies(self):
        engine = AuthSession()
        engine.set_cookies({"session": "s123", "theme": "dark"})
        assert engine.sess.cookies.get("session") == "s123"
        assert engine.sess.cookies.get("theme") == "dark"

    def test_set_header_token_default(self):
        engine = AuthSession()
        engine.set_header_token("my_token")
        assert engine.sess.headers.get("Authorization") == "Bearer my_token"

    def test_set_header_token_custom_scheme(self):
        engine = AuthSession()
        engine.set_header_token("my_token", scheme="JWT")
        assert engine.sess.headers.get("Authorization") == "JWT my_token"

    def test_login_browser_playwright_not_available(self):
        engine = AuthSession()
        result = engine.login_browser(
            "http://test.com/login", "admin", "secret",
            auth_type="auto", user_field="user", pass_field="pass",
        )
        assert result is False

    def test_save_and_load_session(self, tmp_path):
        engine = AuthSession()
        engine.set_cookies({"session": "abc"})
        engine.set_header_token("tok_val")

        path = str(tmp_path / "session.pkl")
        engine.save_session(path)

        engine2 = AuthSession()
        loaded = engine2.load_session(path)
        assert loaded is True
        assert engine2.sess.cookies.get("session") == "abc"
        assert engine2.sess.headers.get("Authorization") == "Bearer tok_val"

    def test_load_session_file_not_found(self):
        engine = AuthSession()
        result = engine.load_session("/nonexistent/path.pkl")
        assert result is False

    def test_load_session_corrupted(self, tmp_path):
        path = str(tmp_path / "bad.pkl")
        with open(path, "w") as f:
            f.write("not pickle data")
        engine = AuthSession()
        result = engine.load_session(path)
        assert result is False

    def test_save_session_preserves_all_cookies(self, tmp_path):
        engine = AuthSession()
        engine.set_cookies({"a": "1", "b": "2", "c": "3"})
        path = str(tmp_path / "multi.pkl")
        engine.save_session(path)

        engine2 = AuthSession()
        engine2.load_session(path)
        assert engine2.sess.cookies.get("a") == "1"
        assert engine2.sess.cookies.get("b") == "2"
        assert engine2.sess.cookies.get("c") == "3"

    @responses.activate
    def test_login_api_malformed_json_no_exception(self):
        responses.add(
            responses.POST, "http://test.com/api/login",
            body="<html>not json</html>", status=200,
        )
        engine = AuthSession()
        result = engine.login_api("http://test.com/api/login", "admin", "secret")
        assert result is True

    @responses.activate
    def test_login_action_url_from_form(self):
        responses.add(
            responses.GET, "http://test.com/login",
            body='<form action="http://test.com/auth">'
                 '<input type="text" name="username">'
                 '<input type="password" name="password"></form>',
            status=200,
        )
        responses.add(
            responses.POST, "http://test.com/auth",
            body="x" * 120, status=200,
        )
        engine = AuthSession()
        result = engine.login_form("http://test.com/login", "admin", "secret")
        assert result is True

    @responses.activate
    def test_login_form_defaults_user_pass_field_names(self):
        responses.add(
            responses.GET, "http://test.com/login",
            body='<form action="http://test.com/login"><input type="text" name="username">'
                 '<input type="password" name="password"></form>',
            status=200,
        )
        responses.add(
            responses.POST, "http://test.com/login",
            body="x" * 120, status=200,
        )
        engine = AuthSession()
        result = engine.login_form("http://test.com/login", "admin", "secret")
        assert result is True
