from tools.auth_state_machine import (
    AuthStateMachine,
    _denied,
    _signature,
    auth_replay,
)


class FakeSess:
    def __init__(self, response):
        self._resp = response

    def request(self, method, url, **kwargs):
        r = type("_R", (), {})()
        r.status_code = self._resp["status"]
        r.text = self._resp.get("body", "")
        r.content = self._resp.get("body", "").encode()
        r.url = self._resp.get("url", url)
        r.headers = self._resp.get("headers", {})
        return r


def _roles():
    anon = FakeSess({"status": 403, "body": "Unauthorized"})
    user = FakeSess({"status": 403, "body": "Forbidden"})
    admin = FakeSess({"status": 200, "body": '{"data": 42}'})
    return [
        {"label": "anon", "rank": 0, "sess": anon},
        {"label": "user", "rank": 1, "sess": user},
        {"label": "admin", "rank": 2, "sess": admin},
    ]


def _roles_factory(anon=None, user=None, admin=None):
    roles = _roles()
    if anon is not None:
        roles[0]["sess"] = FakeSess(anon)
    if user is not None:
        roles[1]["sess"] = FakeSess(user)
    if admin is not None:
        roles[2]["sess"] = FakeSess(admin)
    return roles


class TestHelpers:
    def test_denied_status(self):
        assert _denied(401, "") is True
        assert _denied(403, "") is True
        assert _denied(200, "") is False

    def test_denied_body_marker(self):
        assert _denied(200, "Access denied") is True
        assert _denied(200, "welcome") is False

    def test_signature_normalizes_whitespace(self):
        assert _signature("a\n b") == _signature("a  b")

    def test_signature_empty(self):
        assert _signature("") != ""


class TestReplay:
    def test_returns_role_rows(self):
        m = AuthStateMachine(_roles())
        out = m.replay("http://x.test/api/user/1")
        assert len(out["roles"]) == 3
        labels = [r["label"] for r in out["roles"]]
        assert labels == ["anon", "user", "admin"]

    def test_denied_flag_set(self):
        m = AuthStateMachine(_roles())
        out = m.replay("http://x.test/api/user/1")
        assert out["roles"][0]["denied"] is True
        assert out["roles"][2]["denied"] is False

    def test_post_json_supported(self):
        m = AuthStateMachine(_roles())
        out = m.replay("http://x.test/api", method="POST", json_body={"a": 1})
        assert out["method"] == "POST"


class TestFindings:
    def test_authz_inversion(self):
        roles = _roles_factory(anon={"status": 200, "body": "public data"},
                               user={"status": 200, "body": "user data"},
                               admin={"status": 403, "body": "Forbidden"})
        m = AuthStateMachine(roles)
        out = m.replay("http://x.test/api/admin")
        types = {f["type"] for f in out["findings"]}
        assert "authz_inversion" in types
        assert out["vulnerable"] is True

    def test_privilege_gap(self):
        roles = _roles_factory(user={"status": 200, "body": '{"data": 42}'})
        m = AuthStateMachine(roles)
        out = m.replay("http://x.test/api/secret")
        types = {f["type"] for f in out["findings"]}
        assert "privilege_gap" in types

    def test_bola_same_rank_identities(self):
        a = FakeSess({"status": 200, "body": "invoice 7"})
        b = FakeSess({"status": 200, "body": "invoice 7"})
        c = FakeSess({"status": 403, "body": "Forbidden"})
        roles = [
            {"label": "alice", "rank": 1, "sess": a},
            {"label": "bob", "rank": 1, "sess": b},
            {"label": "admin", "rank": 2, "sess": c},
        ]
        m = AuthStateMachine(roles)
        out = m.replay("http://x.test/api/invoice/7")
        types = {f["type"] for f in out["findings"]}
        assert "bola" in types

    def test_anon_access(self):
        roles = _roles_factory(anon={"status": 200, "body": "dashboard data"})
        m = AuthStateMachine(roles)
        out = m.replay("http://x.test/dashboard")
        assert any(f["type"] == "anon_access" for f in out["findings"])
        assert out["vulnerable"] is False

    def test_no_findings_when_properly_gated(self):
        m = AuthStateMachine(_roles())
        out = m.replay("http://x.test/api/user/1")
        assert out["findings"] == []
        assert out["vulnerable"] is False

    def test_redirect_to_login_denied(self):
        sess = FakeSess({"status": 302, "body": "", "url": "http://x.test/login"})
        m = AuthStateMachine([{"label": "anon", "rank": 0, "sess": sess}])
        out = m.replay("http://x.test/private")
        assert out["roles"][0]["denied"] is True


class TestBatch:
    def test_replay_batch_counts(self):
        roles = _roles_factory(user={"status": 200, "body": '{"data": 42}'})
        m = AuthStateMachine(roles)
        out = m.replay_batch([
            {"url": "http://x.test/a"},
            {"url": "http://x.test/b"},
        ])
        assert out["points_replayed"] == 2
        assert out["vulnerable"] == 2

    def test_auth_replay_fn(self):
        roles = _roles_factory(user={"status": 200, "body": '{"data": 42}'})
        out = auth_replay([{"url": "http://x.test/a"}], roles)
        assert out["points_replayed"] == 1
