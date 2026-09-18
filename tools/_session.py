from typing import Optional

import requests

from tools.settings import settings
from tools.tls_adapter import TLS12Adapter


def _build_http_adapter(total: int = 2, backoff_factor: float = 0.3) -> TLS12Adapter:
    """带指数退避的 HTTP 适配器：自动重试连接/超时/部分 5xx。

    注意: 500 不入重试列表 —— 对扫描器而言 500 是注入命中的核心信号，
    重试会拖慢扫描并让 RetryError 吞掉有效证据。
    """
    from urllib3.util.retry import Retry

    retries = Retry(
        total=total,
        connect=total,
        read=total,
        status=total,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS"]),
        respect_retry_after_header=True,
    )
    adapter = TLS12Adapter(max_retries=retries, pool_connections=100, pool_maxsize=100)
    return adapter


def make_session(verify: Optional[bool] = None, retry_total: int = 2) -> requests.Session:
    sess = requests.Session()
    sess.verify = settings.verify_ssl if verify is None else verify
    sess.headers["User-Agent"] = settings.user_agent
    sess.mount("http://", _build_http_adapter(total=retry_total))
    sess.mount("https://", _build_http_adapter(total=retry_total))
    return sess
