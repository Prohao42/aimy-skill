"""无第三方依赖的重试装饰器"""

import asyncio
import logging
import time
from functools import wraps
from typing import Any, Callable, Optional, Tuple, Type, Union

from tools.exceptions import NetworkError, TimeoutError

logger = logging.getLogger("retry")

RetryableError = Union[Type[Exception], Tuple[Type[Exception], ...]]


def retry(
    retries: int = 3,
    delay: float = 0.5,
    backoff: float = 2.0,
    max_delay: float = 10.0,
    retry_on: RetryableError = NetworkError,
    logger_name: Optional[str] = None,
):
    """同步函数重试装饰器。

    用法:
        @retry(retries=3, retry_on=(TimeoutError, ConnectionError))
        def fetch(url):
            ...
    """
    _log = logging.getLogger(logger_name or __name__)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            wait = delay
            last_exc: Optional[BaseException] = None
            for attempt in range(1, retries + 1):
                try:
                    return func(*args, **kwargs)
                except retry_on as e:
                    last_exc = e
                    if attempt == retries:
                        break
                    _log.debug(
                        "%s failed (attempt %d/%d): %s, retry in %.2fs",
                        func.__name__, attempt, retries, e, wait,
                    )
                    time.sleep(wait)
                    wait = min(wait * backoff, max_delay)
            raise last_exc  # type: ignore[misc]
        return wrapper
    return decorator


def retry_async(
    retries: int = 3,
    delay: float = 0.5,
    backoff: float = 2.0,
    max_delay: float = 10.0,
    retry_on: RetryableError = NetworkError,
    logger_name: Optional[str] = None,
):
    """异步函数重试装饰器。"""
    _log = logging.getLogger(logger_name or __name__)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            wait = delay
            last_exc: Optional[BaseException] = None
            for attempt in range(1, retries + 1):
                try:
                    return await func(*args, **kwargs)
                except retry_on as e:
                    last_exc = e
                    if attempt == retries:
                        break
                    _log.debug(
                        "%s failed (attempt %d/%d): %s, retry in %.2fs",
                        func.__name__, attempt, retries, e, wait,
                    )
                    await asyncio.sleep(wait)
                    wait = min(wait * backoff, max_delay)
            raise last_exc  # type: ignore[misc]
        return wrapper
    return decorator


def is_retryable(exc: BaseException) -> bool:
    """判断异常是否可重试 (网络类错误)。"""
    return isinstance(exc, NetworkError) or isinstance(exc, TimeoutError)
