import random

import pytest
import requests

from tools.opsec_session import OPSECSession, opsec_session


def _fake_sleep():
    calls = []

    def sleep_fn(sec):
        calls.append(sec)

    return calls, sleep_fn


def _make(monkeypatch, **kwargs):
    calls, sleep_fn = _fake_sleep()
    sess = OPSECSession(sleep_fn=sleep_fn, rng=random.Random(1), **kwargs)
    monkeypatch.setattr(
        sess, "send",
        lambda req, **kw: requests.Response(),
    )
    return sess, calls


class TestUA:
    def test_rotates_through_pool(self, monkeypatch):
        sess, _ = _make(monkeypatch, retries=0, jitter_range=(0, 0))
        seen = []
        for _ in range(len(sess._ua_pool) + 2):
            seen.append(sess._next_ua())
        assert len(set(seen[: len(sess._ua_pool)])) == len(sess._ua_pool)
        assert seen[0] == seen[len(sess._ua_pool)]


class TestJitter:
    def test_jitter_before_request(self, monkeypatch):
        sess, calls = _make(monkeypatch, retries=0, jitter_range=(1.0, 1.0))
        assert len(calls) == 0
        sess.get("http://x.test/")
        assert len(calls) == 1
        assert calls[0] == 1.0
        assert sess.stats["jitter_delay"] == 1.0

    def test_zero_jitter_no_sleep(self, monkeypatch):
        sess, calls = _make(monkeypatch, retries=0, jitter_range=(0, 0))
        sess.get("http://x.test/")
        assert calls == []


class TestRetry:
    def _flaky_send(self, attempts, fail_status=503):
        state = {"n": 0}

        def send(req, **kw):
            state["n"] += 1
            r = requests.Response()
            r.status_code = fail_status if state["n"] < attempts else 200
            r._content = b"ok"
            r.url = "http://x.test/"
            r.request = req
            return r

        return state, send

    def test_retries_transient_status(self, monkeypatch):
        state, send = self._flaky_send(attempts=2)
        sess, calls = _make(monkeypatch, retries=3, jitter_range=(0, 0))
        monkeypatch.setattr(sess, "send", send)
        r = sess.get("http://x.test/")
        assert r.status_code == 200
        assert state["n"] == 2
        assert sess.stats["retries"] == 1
        assert len(calls) == 1  # one backoff sleep

    def test_exhausts_retries_then_returns_last_status(self, monkeypatch):
        state, send = self._flaky_send(attempts=99)
        sess, calls = _make(monkeypatch, retries=2, jitter_range=(0, 0))
        monkeypatch.setattr(sess, "send", send)
        r = sess.get("http://x.test/")
        assert r.status_code == 503
        assert state["n"] == 3
        assert sess.stats["retries"] == 2

    def test_retries_on_connection_error(self, monkeypatch):
        state = {"n": 0}

        def send(req, **kw):
            state["n"] += 1
            if state["n"] < 2:
                raise requests.ConnectionError("reset")
            r = requests.Response()
            r.status_code = 200
            r._content = b"ok"
            r.url = "http://x.test/"
            r.request = req
            return r

        sess, _ = _make(monkeypatch, retries=2, jitter_range=(0, 0))
        monkeypatch.setattr(sess, "send", send)
        assert sess.get("http://x.test/").status_code == 200
        assert state["n"] == 2

    def test_raises_after_exhausting_exception_retries(self, monkeypatch):
        def send(req, **kw):
            raise requests.Timeout("slow")

        sess, _ = _make(monkeypatch, retries=2, jitter_range=(0, 0))
        monkeypatch.setattr(sess, "send", send)
        with pytest.raises(requests.Timeout):
            sess.get("http://x.test/")

    def test_backoff_grows_with_attempt(self):
        sess = OPSECSession(retries=3, backoff=1.0, backoff_max=100.0,
                            rng=random.Random(1))
        d0 = sess._backoff_delay(0)
        d2 = sess._backoff_delay(2)
        assert d2 > d0


class TestWrap:
    def test_wrap_copies_cookies_and_headers(self):
        base = requests.Session()
        base.cookies.set("sid", "abc")
        base.headers["X-Custom"] = "v1"
        wrapped = OPSECSession.wrap(base, jitter_range=(0, 0), retries=0)
        assert wrapped.cookies.get("sid") == "abc"
        assert wrapped.headers.get("X-Custom") == "v1"

    def test_wrap_preserves_verify(self):
        base = requests.Session()
        base.verify = False
        wrapped = OPSECSession.wrap(base, retries=0)
        assert wrapped.verify is False


class TestOpsecSessionFn:
    def test_disabled_returns_original(self):
        base = requests.Session()
        assert opsec_session(base, enabled=False) is base

    def test_disabled_none_returns_new(self):
        out = opsec_session(None, enabled=False)
        assert isinstance(out, requests.Session)

    def test_enabled_wraps(self):
        base = requests.Session()
        out = opsec_session(base, enabled=True)
        assert isinstance(out, OPSECSession)
        assert out is not base

    def test_enabled_passthrough_when_already_opsec(self):
        sess = OPSECSession()
        assert opsec_session(sess, enabled=True) is sess


class TestOrchestratorOpsec:
    def test_opsec_flag_wraps_session(self):
        from tools.orchestrator import Orchestrator
        o = Orchestrator("http://target.test", opsec=True)
        assert isinstance(o.sess, OPSECSession)

    def test_default_no_session_stays_none(self):
        from tools.orchestrator import Orchestrator
        o = Orchestrator("http://target.test")
        assert o.sess is None
