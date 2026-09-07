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


def classify_error(error: Exception) -> str:
    """根据错误类型分类错误以便统一处理。"""
    msg = str(error).lower()
    if any(kw in msg for kw in ["timeout", "timed out"]):
        return "timeout"
    if any(kw in msg for kw in ["connection", "refused", "network"]):
        return "network"
    if any(kw in msg for kw in ["permission", "access denied"]):
        return "permission"
    if any(kw in msg for kw in ["not found", "missing"]):
        return "not_found"
    if any(kw in msg for kw in ["unauthorized", "auth", "invalid"]):
        return "authentication"
    if any(kw in msg for kw in ["memory", "heap", "allocation"]):
        return "memory"
    if any(kw in msg for kw in ["file", "path", "io"]):
        return "io"
    return "general"


def safe_try(func: Callable, default: Any = None, log: bool = True) -> Any:
    """安全执行封装：捕获异常，记录错误并返回默认值。"""
    import traceback
    try:
        return func()
    except Exception as e:
        if log:
            logger = logging.getLogger(__name__)
            logger.debug("safe_try caught %s: %s", classify_error(e), e)
            logger.debug(traceback.format_exc())
        return default


def handle_errors(
    operation: str,
    logger: logging.Logger,
    task_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Callable:
    """装饰器：统一错误处理，为操作添加 session_id、task_id 上下文。"""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_type = classify_error(e)
                log_msg = (
                    f"[{operation}] error: {e} "
                    f"(type: {error_type})"
                )
                if task_id:
                    log_msg += f" [task_id: {task_id}]"
                if session_id:
                    log_msg += f" [session_id: {session_id}]"
                logger.error(log_msg)
                raise
        return wrapper
    return decorator
