import os


class _Settings:
    def __init__(self):
        self.verify_ssl = os.environ.get("AIMY_VERIFY_SSL", "").lower() in ("1", "true", "yes")

    def __repr__(self):
        return "<Settings verify_ssl=%s>" % self.verify_ssl


settings = _Settings()
