from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from tools.settings import settings

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def _build_http_adapter(total: int = 2, backoff_factor: float = 0.3) -> HTTPAdapter:
    """带指数退避的 HTTP 适配器：自动重试连接/超时/5xx 错误。"""
    retries = Retry(
        total=total,
        connect=total,
        read=total,
        status=total,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS"]),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=100, pool_maxsize=100)
    return adapter


def make_session(verify: Optional[bool] = None, retry_total: int = 2) -> requests.Session:
    sess = requests.Session()
    sess.verify = settings.verify_ssl if verify is None else verify
    sess.headers["User-Agent"] = _USER_AGENT
    sess.mount("http://", _build_http_adapter(total=retry_total))
    sess.mount("https://", _build_http_adapter(total=retry_total))
    return sess
