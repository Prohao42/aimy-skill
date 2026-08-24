import re

import responses

from tools.leak_scanner import check


class _Cb:
    """routes: path -> (status, body). Everything else 404."""

    def __init__(self, routes):
        self.routes = routes

    def __call__(self, request):
        path = request.url.split("http://t.com", 1)[-1]
        if path in self.routes:
            return (self.routes[path][0], {}, self.routes[path][1])
        return (404, {}, "")


class TestLeakScanner:
    @responses.activate
    def test_git_config_critical(self):
        cb = _Cb({"/.git/config": (200, "[core]\n\trepositoryformatversion = 0\n")})
        responses.add_callback(responses.GET, re.compile(r"http://t\.com.*"), callback=cb)
        r = check("http://t.com", timeout=5)
        assert r["count"] >= 1
        git = [l for l in r["leaks"] if l["label"] == "git_config"]
        assert git and git[0]["severity"] == "critical"

    @responses.activate
    def test_env_detected(self):
        cb = _Cb({"/.env": (200, "DB_PASSWORD=supersecret\nAPP_KEY=abc123\n")})
        responses.add_callback(responses.GET, re.compile(r"http://t\.com.*"), callback=cb)
        r = check("http://t.com", timeout=5)
        env = [l for l in r["leaks"] if l["label"] == "env"]
        assert env and env[0]["severity"] == "critical"
        assert "DB_PASSWORD" in env[0]["snippet"]

    @responses.activate
    def test_no_false_positive_on_404(self):
        cb = _Cb({})
        responses.add_callback(responses.GET, re.compile(r"http://t\.com.*"), callback=cb)
        r = check("http://t.com", timeout=5)
        assert r["count"] == 0

    @responses.activate
    def test_custom_paths_filter(self):
        cb = _Cb({"/.git/HEAD": (200, "ref: refs/heads/master\n")})
        responses.add_callback(responses.GET, re.compile(r"http://t\.com.*"), callback=cb)
        r = check("http://t.com", paths=["/.git/HEAD"], timeout=5)
        assert r["count"] == 1
        assert r["leaks"][0]["label"] == "git_head"

    @responses.activate
    def test_redirect_not_followed(self):
        # A 301 to a catch-all should not be treated as a hit.
        cb = _Cb({})
        responses.add_callback(responses.GET, re.compile(r"http://t\.com.*"), callback=cb)
        r = check("http://t.com", timeout=5)
        assert all(l["status"] != 301 for l in r["leaks"])
