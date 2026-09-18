import ssl

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry as urllib3_Retry

from tools.settings import settings


class TLS12Adapter(HTTPAdapter):
    """强制 TLS1.2 + 指数退避自动重试 (连接/超时/5xx)。"""

    def __init__(self, max_retries=2, **kwargs):
        retries = urllib3_Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            status=max_retries,
            backoff_factor=0.3,
            status_forcelist=(429, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS"]),
            respect_retry_after_header=True,
        )
        super().__init__(max_retries=retries, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if not settings.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(connections, maxsize=max(100, maxsize), block=block, **kwargs)


_ADAPTER_CACHE = None


def get_tls12_adapter() -> TLS12Adapter:
    global _ADAPTER_CACHE
    if _ADAPTER_CACHE is None:
        _ADAPTER_CACHE = TLS12Adapter()
    return _ADAPTER_CACHE
