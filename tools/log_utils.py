import logging
import os
import time
from functools import wraps
from typing import Any, Callable, Optional

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG_LEVEL = os.environ.get("AIMY_LOG_LEVEL", "WARNING").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.WARNING),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def set_log_level(level: str) -> None:
    """运行时调整日志级别，例如 set_log_level('DEBUG')。"""
    lvl = getattr(logging, str(level).upper(), logging.WARNING)
    logging.getLogger().setLevel(lvl)


def timed(logger: logging.Logger, operation: Optional[str] = None) -> Callable:
    """装饰器：记录函数执行耗时 (DEBUG 级别)。"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - start
                name = operation or f"{func.__module__}.{func.__name__}"
                logger.debug("%s took %.3fs", name, elapsed)
        return wrapper
    return decorator


def timed_async(logger: logging.Logger, operation: Optional[str] = None) -> Callable:
    """装饰器：记录异步函数执行耗时 (DEBUG 级别)。"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                return await func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - start
                name = operation or f"{func.__module__}.{func.__name__}"
                logger.debug("%s took %.3fs", name, elapsed)
        return wrapper
    return decorator


def mode_echo(mode: str, msg: str, rookie_msg: str = None):
    from tools.settings import settings
    prefix = "[Rookie]" if settings.is_rookie() else "[Veteran]"
    if settings.is_veteran() and rookie_msg:
        return
    print("%s %s" % (prefix, msg if settings.is_rookie() else (rookie_msg or msg)))
