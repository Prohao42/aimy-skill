from tools import xss_validator


class TestXSSValidator:
    def test_returns_browser_verify_result(self, monkeypatch):
        fake = {
            "vulnerable": False,
            "confirmed": False,
            "playwright_available": False,
            "note": "no xss",
        }
        monkeypatch.setattr(
            xss_validator, "browser_verify", lambda url, param, sess, timeout: dict(fake)
        )
        r = xss_validator.check("http://t.test/echo", "q")
        assert r == fake

    def test_passes_session_through(self, monkeypatch):
        captured = {}

        def fake(url, param, sess, timeout):
            captured["url"] = url
            captured["param"] = param
            captured["sess"] = sess
            captured["timeout"] = timeout
            return {"playwright_available": False}

        monkeypatch.setattr(xss_validator, "browser_verify", fake)
        import requests

        sess = requests.Session()
        xss_validator.check("http://t.test/echo", "q", sess=sess, timeout=3.0)
        assert captured["url"] == "http://t.test/echo"
        assert captured["param"] == "q"
        assert captured["sess"] is sess
        assert captured["timeout"] == 3.0

    def test_creates_session_when_none(self, monkeypatch):
        seen = {}

        def fake(url, param, sess, timeout):
            seen["sess"] = sess
            return {"playwright_available": False}

        monkeypatch.setattr(xss_validator, "browser_verify", fake)
        xss_validator.check("http://t.test/echo", "q")
        assert seen["sess"] is not None
