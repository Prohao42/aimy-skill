import os


class _Settings:
    MODES = {"rookie", "veteran"}

    def __init__(self):
        self.verify_ssl = os.environ.get("AIMY_VERIFY_SSL", "").lower() in ("1", "true", "yes")
        self.mode = os.environ.get("AIMY_MODE", "rookie").lower()
        if self.mode not in self.MODES:
            self.mode = "rookie"

    def set_mode(self, mode: str):
        mode = mode.lower()
        if mode in self.MODES:
            self.mode = mode

    def is_rookie(self):
        return self.mode == "rookie"

    def is_veteran(self):
        return self.mode == "veteran"

    def __repr__(self):
        return "<Settings verify_ssl=%s mode=%s>" % (self.verify_ssl, self.mode)


settings = _Settings()
