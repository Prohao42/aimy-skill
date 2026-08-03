"""统一异常体系"""

from typing import Optional


class AimyError(Exception):
    """aimy-skill 基础异常"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | {self.details}"
        return self.message


class NetworkError(AimyError):
    """网络相关错误 (超时、连接拒绝、DNS 失败等)"""
    pass


class TimeoutError(NetworkError):
    """请求超时"""
    pass


class ConnectionError(NetworkError):
    """连接失败"""
    pass


class DNSError(NetworkError):
    """DNS 解析失败"""
    pass


class TLSError(NetworkError):
    """TLS/SSL 握手失败"""
    pass


class WAFBlockedError(NetworkError):
    """请求被 WAF 拦截"""
    def __init__(self, message: str, waf_name: str = "", details: Optional[dict] = None):
        super().__init__(message, details)
        self.waf_name = waf_name


class DetectionError(AimyError):
    """漏洞检测错误"""
    pass


class FalsePositiveError(DetectionError):
    """误报过滤拦截"""
    pass


class ConfigurationError(AimyError):
    """配置/验证错误"""
    pass


class ValidationError(AimyError):
    """参数/结果验证失败"""
    pass


class OOBError(AimyError):
    """OOB (Out-of-Band) 交互错误"""
    pass


class ChainError(AimyError):
    """攻击链组合错误"""
    pass


class PayloadError(AimyError):
    """Payload 生成/变异错误"""
    pass
