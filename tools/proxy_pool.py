"""Proxy pool with rotation, failover, health tracking and concurrency throttle.

Subset scope: single-process pool (no real distributed farming). Proxies are
health-scored (consecutive failures mark them down, successes bring them back)
and requests round-robin across the healthy set. A Throttle provides both a
concurrency cap (semaphore) and an optional rate limit (requests/second).

The pool plugs into OPSECSession so jitter + UA rotation + proxy rotation +
failover all happen on the same request path.
"""
import threading
import time
from typing import Callable, Dict, List, Optional, Union

from tools.log_utils import get_logger

logger = get_logger("proxy_pool")


class ProxyPool:
    def __init__(self, proxies: Optional[Union[List[str], Dict[str, float]]] = None,
                 max_failures: int = 3, success_reset: int = 2,
                 rng: Optional[object] = None) -> None:
        self._entries: List[Dict] = []
        self._idx = 0
        self._lock = threading.Lock()
        self.max_failures = max(1, int(max_failures))
        self.success_reset = max(1, int(success_reset))
        self._rng = rng
        if proxies:
            if isinstance(proxies, dict):
                for url, weight in proxies.items():
                    self.add(url, weight=weight)
            else:
                for url in proxies:
                    self.add(url)

    def add(self, url: str, weight: float = 1.0) -> Dict:
        entry = {
            "url": url, "weight": float(weight), "failures": 0,
            "successes": 0, "healthy": True, "latency": None,
        }
        with self._lock:
            self._entries.append(entry)
        return entry

    def _find(self, url: str) -> Optional[Dict]:
        for e in self._entries:
            if e["url"] == url:
                return e
        return None

    def healthy_entries(self) -> List[Dict]:
        return [e for e in self._entries if e["healthy"]]

    def next(self) -> Optional[str]:
        with self._lock:
            if not self._entries:
                return None
            zero_fail = [e for e in self._entries if e["failures"] == 0]
            candidates = zero_fail or self._entries
            entry = candidates[self._idx % len(candidates)]
            self._idx += 1
            return entry["url"]

    def report(self, url: str, ok: bool, latency: Optional[float] = None) -> None:
        with self._lock:
            entry = self._find(url)
            if entry is None:
                return
            if ok:
                entry["successes"] += 1
                if entry["successes"] >= self.success_reset:
                    entry["failures"] = 0
                    entry["successes"] = 0
                    entry["healthy"] = True
            else:
                entry["failures"] += 1
                entry["successes"] = 0
                if entry["failures"] >= self.max_failures:
                    entry["healthy"] = False
            if latency is not None:
                entry["latency"] = round(float(latency), 3)

    def health(self) -> Dict:
        with self._lock:
            return {
                "total": len(self._entries),
                "healthy": len(self.healthy_entries()),
                "down": len(self._entries) - len(self.healthy_entries()),
                "entries": [dict(e) for e in self._entries],
            }

    def reset(self) -> None:
        with self._lock:
            for e in self._entries:
                e["failures"] = 0
                e["successes"] = 0
                e["healthy"] = True


class Throttle:
    """Concurrency cap + optional rate limit. acquire() blocks until allowed."""

    def __init__(self, max_concurrency: int = 0, rate_limit: float = 0.0,
                 sleep_fn: Optional[Callable[[float], None]] = None) -> None:
        self._sem = threading.Semaphore(max_concurrency) if max_concurrency > 0 else None
        self._rate = max(0.0, float(rate_limit))
        self._lock = threading.Lock()
        self._last = 0.0
        self._sleep = sleep_fn or time.sleep
        self.wait_total = 0.0

    def acquire(self) -> None:
        if self._sem is not None:
            self._sem.acquire()
        if self._rate > 0:
            gap = 1.0 / self._rate
            with self._lock:
                now = time.monotonic()
                wait = (self._last + gap) - now
                self._last = max(now, self._last + gap)
            if wait > 0:
                self._sleep(wait)
                self.wait_total += wait

    def release(self) -> None:
        if self._sem is not None:
            self._sem.release()

    def stats(self) -> Dict:
        return {"max_concurrency": self._sem._value if self._sem else 0,
                "rate_limit": self._rate, "wait_total": round(self.wait_total, 3)}


def pool_session(proxies: Optional[Union[List[str], Dict[str, float]]] = None,
                 max_concurrency: int = 0, rate_limit: float = 0.0,
                 **opsec_kwargs):
    """Build an OPSECSession wired to a ProxyPool + Throttle."""
    from tools.opsec_session import OPSECSession

    pool = ProxyPool(proxies=proxies)
    throttle = Throttle(max_concurrency=max_concurrency, rate_limit=rate_limit)
    kwargs = dict(opsec_kwargs)
    kwargs.setdefault("proxy_pool", pool)
    kwargs.setdefault("throttle", throttle)
    return OPSECSession(**kwargs)
