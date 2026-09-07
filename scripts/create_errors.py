#!/usr/bin/env python
import os

content = """#!/usr/bin/env python
# Unified Error Handling Model
# Follows Principle 28:
# - No: except: pass
# - No: except Exception: return None
# - Must: Capture, Log, Classify, Handle or Re-raise

from typing import TypeVar, Generic, Optional, Callable, Any, Dict
import traceback
import logging

from tools.log_utils import get_logger

logger = get_logger("errors")

T = TypeVar("T", bound=Exception)


class AimyError(Exception, Generic[T]):
    """AIMY base exception class.

    All custom exceptions should inherit from this class.
    """

    def __init__(
        self,
        message: str,
        error_code: str = "",
        context: Optional[Dict] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.cause = cause
        self.stack_trace = traceback.format_exc()

    def __str__(self) -> str:
        return f"{self.__class__.__name__}: {self.message}"

    def with_context(self, **kwargs) -> "AimyError":
        """Add context info and return self."""
        self.context.update(kwargs)
        return self


class ConfigurationError(AimyError):
    """Configuration error (wrong env vars, wrong parameters, etc)."""


class TargetError(AimyError):
    """Target error (invalid URL, unreachable host, etc)."""


class DetectorError(AimyError):
    """Detector error (detector execution failed, timeout, etc)."""


class NetworkError(AimyError):
    """Network error (connection timeout, DNS resolution failure, etc)."""


class SecurityError(AimyError):
    """Security error (command injection risk, credential leakage, etc)."""


class ResourceError(AimyError):
    """Resource error (file not found, port already in use, etc)."""


def classify_error(error: Exception) -> str:
    """Classify error into predefined categories.

    Returns: "configuration", "target", "detector", "network", "security", "resource"
    """
    error_str = str(error).lower()
    error_type = type(error).__name__.lower()
    if isinstance(error, (ConfigurationError,)):
        return "configuration"
    if isinstance(error, (TargetError,)):
        return "target"
    if isinstance(error, (DetectorError,)):
        return "detector"
    if isinstance(error, (NetworkError,)):
        return "network"
    if isinstance(error, (SecurityError,)):
        return "security"
    if isinstance(error, (ResourceError,)):
        return "resource"
    if any(keyword in error_str for keyword in ["config", "environment", "setting"]):
        return "configuration"
    if any(keyword in error_str for keyword in ["target", "url", "host", "connect", "timeout"]):
        return "target"
    if any(keyword in error_str for keyword in ["detector", "scan", "detect", "payload"]):
        return "detector"
    if any(keyword in error_str for keyword in ["network", "connection", "dns", "socket"]):
        return "network"
    if any(keyword in error_str for keyword in ["security", "inject", "command", "credential"]):
        return "security"
    if any(keyword in error_str for keyword in ["file", "path", "exist", "permission"]):
        return "resource"
    return "unknown"


def safe_try(
    func: Callable[[], T],
    error_code: str = "",
    default: Optional[T] = None,
    reraise: bool = False,
) -> Optional[T]:
    """Safe try wrapper.

    Ensures all exceptions are logged and not swallowed.
    Only re-raises if reraise is True.

    Args:
        func: Function to execute
        error_code: Custom error code
        default: Value to return on error (if reraise is False)
        reraise: If True, re-raise after logging

    Returns:
        func return value, or default (if error and not reraise)
    """
    try:
        return func()
    except Exception as e:
        # Classify and log error
        category = classify_error(e)
        logger.error(
            "safe_try error [category=%s] %s: %s",
            category,
            type(e).__name__,
            str(e),
            extra={"stack_trace": traceback.format_exc()},
        )
        # If re-raise requested, do so
        if reraise:
            raise
        # Otherwise return default
        return default


def log_and_reraise(
    error: Exception,
    context: Dict = None,
    message: str = "Unexpected error occurred",
) -> None:
    """Log error and re-raise.

    Ensures errors are never silently swallowed.
    """
    logger.error(
        "%s: %s [%s]",
        message,
        str(error),
        type(error).__name__,
        extra={"context": context or {}, "stack_trace": traceback.format_exc()},
    )
    raise error from None  # Clear original stack, show new


def handle_errors(
    error_code: str = "",
    default: Optional[Any] = None,
    reraise: bool = False,
    log_category: str = "unknown",
):
    """Function error handling decorator.

    Automatically catches exceptions, logs classification,
    and returns default or re-raises per configuration.
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Log with context
                logger.error(
                    "handle_errors [%s] %s in %s:%s",
                    log_category,
                    str(e),
                    func.__name__,
                    f"{args}{kwargs}",
                    extra={"stack_trace": "true"},
                )
                # If re-raise requested, do so
                if reraise:
                    raise
                # Otherwise return default
                return default

        return wrapper

    return decorator


if __name__ == "__main__":
    # Simple test
    print("Error module loaded successfully")