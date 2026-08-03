import random
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from tools.proxy_pool import ProxyPool, Throttle, pool_session


class TestProxyPool:
    def test_add_and_next_round_robin(self):
        pool = ProxyPool(["http://p1:8080", "http://p2:8080"])
        got = [pool.next(), pool.next(), pool.next()]
        assert got[0] == "http://p1:8080"
        assert got[1] == "http://p2:8080"
        assert got[2] == "http://p1:8080"

    def test_empty_pool(self):
        pool = ProxyPool()
        assert pool.next() is None
        assert pool.health()["total"] == 0

    def test_report_failure_marks_down(self):
        pool = ProxyPool(["http://p1:8080"], max_failures=2)
        pool.report("http://p1:8080", False)
        assert pool.health()["healthy"] == 1
        pool.report("http://p1:8080", False)
        assert pool.health()["healthy"] == 0

    def test_success_recovers_down_proxy(self):
        pool = ProxyPool(["http://p1:8080"], max_failures=2, success_reset=1)
        pool.report("http://p1:8080", False)
        pool.report("http://p1:8080", False)
        assert pool.health()["healthy"] == 0
        pool.report("http://p1:8080", True)
        assert pool.health()["healthy"] == 1
        assert pool.health()["entries"][0]["failures"] == 0

    def test_round_robin_skips_loaded_proxies(self):
        pool = ProxyPool(["http://a:1", "http://b:1", "http://c:1"])
        pool.report("http://a:1", False)  # one failure, still healthy
        # healthy zero-failure proxies preferred, so b and c rotate first
        first_two = {pool.next(), pool.next()}
        assert first_two == {"http://b:1", "http://c:1"}

    def test_dict_init_with_weights(self):
        pool = ProxyPool({"http://a:1": 2.0, "http://b:1": 1.0})
        assert pool.health()["total"] == 2

    def test_unknown_report_ignored(self):
        pool = ProxyPool(["http://a:1"])
        pool.report("http://nope:9", False)
        assert pool.health()["total"] == 1

    def test_latency_recorded(self):
        pool = ProxyPool(["http://a:1"])
        pool.report("http://a:1", True, latency=0.123)
        assert pool.health()["entries"][0]["latency"] == 0.123


class TestThrottle:
    def test_no_limit_no_wait(self):
        calls, sleep_fn = _fake_sleep()
        t = Throttle(sleep_fn=sleep_fn)
        t.acquire()
        t.release()
        assert calls == []

    def test_rate_limit_enforces_gap(self):
        calls, sleep_fn = _fake_sleep()
        t = Throttle(rate_limit=2.0, sleep_fn=sleep_fn)  # 0.5s gap
        t.acquire()
        t.release()
        t.acquire()
        t.release()
        assert len(calls) == 1
        assert 0.4 <= calls[0] <= 0.6

    def test_concurrency_cap(self):
        calls, sleep_fn = _fake_sleep()
        t = Throttle(max_concurrency=1, sleep_fn=sleep_fn)
        results = []

        def work(i):
            t.acquire()
            results.append(i)
            t.release()
            return i

        with ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(work, range(4)))
        assert sorted(results) == [0, 1, 2, 3]


def _fake_sleep():
    calls = []

    def sleep_fn(sec):
        calls.append(sec)

    return calls, sleep_fn


def _ok_send(req, **kw):
    r = requests.Response()
    r.status_code = 200
    r._content = b"ok"
    r.url = req.url
    r.request = req
    return r


class TestOPSECProxyIntegration:
    def _make(self, monkeypatch, **kwargs):
        calls, sleep_fn = _fake_sleep()
        kwargs.setdefault("sleep_fn", sleep_fn)
        kwargs.setdefault("rng", random.Random(1))
        kwargs.setdefault("jitter_range", (0, 0))
        kwargs.setdefault("retries", 1)
        from tools.opsec_session import OPSECSession
        sess = OPSECSession(**kwargs)
        monkeypatch.setattr(sess, "send", _ok_send)
        return sess, calls

    def test_proxy_rotation_per_request(self, monkeypatch):
        pool = ProxyPool(["http://p1:8080", "http://p2:8080"])
        sess, _ = self._make(monkeypatch, proxy_pool=pool)
        seen = []
        orig = sess.send

        def recording_send(req, **kw):
            seen.append(kw.get("proxies"))
            return orig(req, **kw)

        monkeypatch.setattr(sess, "send", recording_send)
        sess.get("http://t.test/")
        sess.get("http://t.test/")
        assert seen[0] == {"http": "http://p1:8080", "https": "http://p1:8080"}
        assert seen[1] == {"http": "http://p2:8080", "https": "http://p2:8080"}
        assert sess.stats["proxy_used"] == 2

    def test_failed_proxy_reported_down(self, monkeypatch):
        pool = ProxyPool(["http://p1:8080"], max_failures=1)

        def fail_send(req, **kw):
            raise requests.ConnectionError("proxy refused")

        sess, _ = self._make(monkeypatch, proxy_pool=pool)
        monkeypatch.setattr(sess, "send", fail_send)
        with pytest.raises(requests.ConnectionError):
            sess.get("http://t.test/")
        assert pool.health()["healthy"] == 0

    def test_pool_session_factory(self):
        sess = pool_session(["http://p1:8080"], max_concurrency=2, rate_limit=0.0)
        from tools.opsec_session import OPSECSession
        assert isinstance(sess, OPSECSession)
        assert sess.proxy_pool.health()["total"] == 1
        assert sess.throttle is not None
