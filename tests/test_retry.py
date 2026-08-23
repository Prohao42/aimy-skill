import asyncio

import pytest

from tools.exceptions import NetworkError, TimeoutError
from tools.retry import is_retryable, retry, retry_async


def _always_fail():
    raise NetworkError("boom")


def _fail_twice():
    calls = _fail_twice.__dict__.setdefault("calls", 0)
    calls += 1
    _fail_twice.__dict__["calls"] = calls
    if calls < 3:
        raise NetworkError("transient")
    return "ok"


def _fail_with_timeout():
    raise TimeoutError("slow")


class TestRetrySync:
    def test_returns_immediately_on_success(self):
        @retry(retries=3, delay=0.01)
        def fn():
            return 42

        assert fn() == 42

    def test_retries_then_succeeds(self):
        _fail_twice.__dict__["calls"] = 0

        @retry(retries=5, delay=0.01)
        def fn():
            return _fail_twice()

        assert fn() == "ok"

    def test_raises_last_exception_after_exhaustion(self):
        @retry(retries=2, delay=0.01)
        def fn():
            _always_fail()

        with pytest.raises(NetworkError):
            fn()

    def test_only_retries_on_configured_error(self):
        @retry(retries=3, delay=0.01, retry_on=TimeoutError)
        def fn():
            _fail_with_timeout()

        with pytest.raises(TimeoutError):
            fn()

    def test_custom_retry_tuple(self):
        @retry(retries=2, delay=0.01, retry_on=(NetworkError, ValueError))
        def fn():
            raise ValueError("nope")

        with pytest.raises(ValueError):
            fn()

    def test_custom_logger_name(self):
        @retry(retries=1, delay=0.01, logger_name="custom")
        def fn():
            _always_fail()

        with pytest.raises(NetworkError):
            fn()


class TestRetryAsync:
    def test_success(self):
        @retry_async(retries=2, delay=0.01)
        async def fn():
            return "done"

        assert asyncio.run(fn()) == "done"

    def test_retry_then_success(self):
        state = {"calls": 0}

        @retry_async(retries=4, delay=0.01)
        async def fn():
            state["calls"] += 1
            if state["calls"] < 2:
                raise NetworkError("again")
            return "ok"

        assert asyncio.run(fn()) == "ok"

    def test_exhaustion(self):
        @retry_async(retries=2, delay=0.01)
        async def fn():
            raise TimeoutError("slow")

        with pytest.raises(TimeoutError):
            asyncio.run(fn())


class TestIsRetryable:
    def test_network_and_timeout(self):
        assert is_retryable(NetworkError("x"))
        assert is_retryable(TimeoutError("x"))

    def test_other_exceptions(self):
        assert not is_retryable(ValueError("x"))
        assert not is_retryable(Exception("x"))
