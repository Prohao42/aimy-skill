import os
from typing import Optional


class _Settings:
    """全局配置 (环境变量可覆盖，接口保持向后兼容)。

    支持环境变量:
        AIMY_VERIFY_SSL  是否验证 SSL 证书 (1/true/yes)
        AIMY_MODE        输出模式 (rookie/veteran)
        AIMY_TIMEOUT     默认请求超时 (秒)
        AIMY_THREADS     默认并发线程数
        AIMY_USER_AGENT  默认 User-Agent
        AIMY_LOG_LEVEL   日志级别
    """

    MODES = {"rookie", "veteran"}

    def __init__(self):
        self._env = os.environ
        self.verify_ssl = self._env.get("AIMY_VERIFY_SSL", "").lower() in ("1", "true", "yes")
        self.mode = self._env.get("AIMY_MODE", "rookie").lower()
        if self.mode not in self.MODES:
            self.mode = "rookie"

    def set_mode(self, mode: str):
        mode = (mode or "").lower()
        if mode in self.MODES:
            self.mode = mode

    def is_rookie(self) -> bool:
        return self.mode == "rookie"

    def is_veteran(self) -> bool:
        return self.mode == "veteran"

    @property
    def timeout(self) -> float:
        try:
            return float(self._env.get("AIMY_TIMEOUT", "10"))
        except ValueError:
            return 10.0

    @property
    def threads(self) -> int:
        try:
            return max(1, int(self._env.get("AIMY_THREADS", "20")))
        except ValueError:
            return 20

    @property
    def user_agent(self) -> str:
        return self._env.get(
            "AIMY_USER_AGENT",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        )

    @property
    def log_level(self) -> str:
        return self._env.get("AIMY_LOG_LEVEL", "WARNING").upper()

    def to_dict(self) -> dict:
        return {
            "verify_ssl": self.verify_ssl,
            "mode": self.mode,
            "timeout": self.timeout,
            "threads": self.threads,
        }

    def __repr__(self):
        return "<Settings verify_ssl=%s mode=%s timeout=%s threads=%s>" % (
            self.verify_ssl, self.mode, self.timeout, self.threads,
        )


settings = _Settings()