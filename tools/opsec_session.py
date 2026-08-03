"""Opsec-aware HTTP session: request jitter, User-Agent rotation, backoff retry.

Drop-in replacement for requests.Session so it can be handed to the
Orchestrator (or any detector) without changing call sites. Retry policy is
enforced at the session layer with exponential backoff + full-jitter so scan
traffic stays under a per-request rhythm instead of a rigid fixed delay.

Testability: sleep_fn and a seeded RNG are injectable; with a fake sleep_fn
the fuzzer behaves deterministically and no wall-clock delay is incurred.
"""
import random
import time
from typing import Callable, Iterable, List, Optional, Tuple, Type

import requests

from tools.log_utils import get_logger
from tools.proxy_pool import ProxyPool, Throttle
from tools.settings import settings

logger = get_logger("opsec_session")

DEFAULT_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/119.0.0.0 Safari/537.36 Edg/119.0.2151.97",
]

TRANSIENT_STATUS: Tuple[int, ...] = (429, 500, 502, 503, 504)

_RETRYABLE_EXC: Tuple[Type[BaseException], ...] = (
    requests.ConnectionError,
    requests.Timeout,
    requests.exceptions.ChunkedEncodingError,
)


class OPSECSession(requests.Session):
    """requests.Session with jittered pacing, UA rotation and retry/backoff."""

    def __init__(self, jitter_range: Tuple[float, float] = (0.3, 1.5),
                 ua_pool: Optional[Iterable[str]] = None,
                 retries: int = 3, backoff: float = 1.5, backoff_max: float = 30.0,
                 retry_on_status: Tuple[int, ...] = TRANSIENT_STATUS,
                 retry_on_exc: Tuple[Type[BaseException], ...] = _RETRYABLE_EXC,
                 verify: Optional[bool] = None,
                 sleep_fn: Optional[Callable[[float], None]] = None,
                 rng: Optional[random.Random] = None,
                 proxy_pool: Optional["ProxyPool"] = None,
                 throttle: Optional["Throttle"] = None) -> None:
        super().__init__()
        self._jitter_range = tuple(float(x) for x in jitter_range)
        self._ua_pool = list(ua_pool or DEFAULT_USER_AGENTS)
        self._retries = max(0, int(retries))
        self._backoff = float(backoff)
        self._backoff_max = float(backoff_max)
        self._retry_on_status = tuple(retry_on_status)
        self._retry_on_exc = tuple(retry_on_exc)
        self._sleep = sleep_fn or time.sleep
        self._rng = rng or random.Random()
        self.verify = settings.verify_ssl if verify is None else verify
        self._ua_index = 0
        self.proxy_pool = proxy_pool
        self.throttle = throttle
        self.stats = {"requests": 0, "retries": 0, "jitter_delay": 0.0,
                      "proxy_used": 0}

    @classmethod
    def wrap(cls, sess: Optional[requests.Session] = None,
             **kwargs) -> "OPSECSession":
        """Wrap an existing session (copies cookies + headers) into OPSECSession."""
        wrapped = cls(**kwargs)
        if sess is not None:
            wrapped.cookies.update(sess.cookies)
            merged = dict(sess.headers)
            merged.pop("User-Agent", None)
            wrapped.headers.update(merged)
            if sess.verify is not None:
                wrapped.verify = sess.verify
        return wrapped

    def _next_ua(self) -> str:
        ua = self._ua_pool[self._ua_index % len(self._ua_pool)]
        self._ua_index += 1
        return ua

    def _jitter(self) -> float:
        lo, hi = self._jitter_range
        if hi <= lo:
            return lo
        return self._rng.uniform(lo, hi)

    def _backoff_delay(self, attempt: int) -> float:
        base = min(self._backoff_max, self._backoff * (2.0 ** attempt))
        return base * self._rng.uniform(0.5, 1.5)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        delay = self._jitter()
        if delay > 0:
            self._sleep(delay)
            self.stats["jitter_delay"] += delay

        if self.throttle is not None:
            self.throttle.acquire()
        try:
            return self._request_inner(method, url, **kwargs)
        finally:
            if self.throttle is not None:
                self.throttle.release()

    def _request_inner(self, method: str, url: str, **kwargs) -> requests.Response:
        last_resp: Optional[requests.Response] = None
        last_exc: Optional[BaseException] = None
        for attempt in range(self._retries + 1):
            self.headers["User-Agent"] = self._next_ua()
            proxy_url = None
            if self.proxy_pool is not None:
                proxy_url = self.proxy_pool.next()
                if proxy_url:
                    kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}
                    self.stats["proxy_used"] += 1
            started = time.monotonic()
            try:
                last_resp = super().request(method, url, **kwargs)
                self.stats["requests"] += 1
                if proxy_url:
                    ok = getattr(last_resp, "status_code", 500) < 400
                    self.proxy_pool.report(proxy_url, ok,
                                           time.monotonic() - started)
            except self._retry_on_exc as exc:
                last_exc = exc
                if proxy_url:
                    self.proxy_pool.report(proxy_url, False)
                if attempt < self._retries:
                    self.stats["retries"] += 1
                    self._sleep(self._backoff_delay(attempt))
                    continue
                raise
            if last_resp.status_code in self._retry_on_status and attempt < self._retries:
                self.stats["retries"] += 1
                self._sleep(self._backoff_delay(attempt))
                continue
            return last_resp
        raise last_exc  # type: ignore[misc]


def opsec_session(sess: Optional[requests.Session] = None,
                  enabled: bool = True, **kwargs) -> requests.Session:
    """Return an opsec-wrapped session, or the original when disabled."""
    if not enabled:
        return sess or requests.Session()
    if isinstance(sess, OPSECSession):
        return sess
    return OPSECSession.wrap(sess, **kwargs)
