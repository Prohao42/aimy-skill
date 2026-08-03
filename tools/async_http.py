"""异步 HTTP 客户端 (基于 aiohttp)"""

import asyncio
import ssl
from typing import Any, Dict, Optional, Tuple

import aiohttp

from tools.exceptions import DNSError, NetworkError, TimeoutError, TLSError
from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("async_http")

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def _make_connector(max_connections: int, force_tls12: bool) -> aiohttp.TCPConnector:
    ssl_ctx = None
    if force_tls12:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        if not settings.verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
    kwargs: Dict[str, Any] = {"limit": max_connections, "limit_per_host": max_connections}
    if ssl_ctx is not None:
        kwargs["ssl"] = ssl_ctx
    return aiohttp.TCPConnector(**kwargs)


def _map_error(exc: Exception, url: str) -> NetworkError:
    if isinstance(exc, asyncio.TimeoutError):
        return TimeoutError(f"timeout: {url}")
    if isinstance(exc, aiohttp.ClientConnectorSSLError):
        return TLSError(f"TLS handshake failed: {url}")
    if isinstance(exc, (aiohttp.ClientConnectorDNSError, aiohttp.ClientConnectorError)):
        return DNSError(f"connect failed: {url}")
    if isinstance(exc, aiohttp.ClientError):
        return NetworkError(f"http client error: {exc}")
    return NetworkError(f"unexpected error: {exc}")


class AsyncHttpClient:
    """可复用的异步 HTTP 客户端。

    用法:
        client = AsyncHttpClient(timeout=10)
        async with client:
            status, headers, body = await client.get(url)
    """

    def __init__(self, timeout: float = 10.0, max_connections: int = 100,
                 force_tls12: bool = True, follow_redirects: bool = True):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_connections = max_connections
        self.force_tls12 = force_tls12
        self.follow_redirects = follow_redirects
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "AsyncHttpClient":
        connector = _make_connector(self.max_connections, self.force_tls12)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={"User-Agent": _UA},
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("AsyncHttpClient must be used as async context manager")
        return self._session

    async def request(self, method: str, url: str,
                      params: Optional[Dict[str, str]] = None,
                      data: Optional[Dict[str, str]] = None,
                      json_body: Optional[Dict[str, Any]] = None,
                      headers: Optional[Dict[str, str]] = None,
                      cookies: Optional[Dict[str, str]] = None,
                      allow_redirects: Optional[bool] = None) -> Tuple[int, Dict[str, str], str]:
        """发起请求，返回 (status, headers, body)。所有异常统一转换为 NetworkError 子类。"""
        if self._session is None:
            raise RuntimeError("AsyncHttpClient must be used as async context manager")
        try:
            async with self.session.request(
                method, url,
                params=params, data=data, json=json_body,
                headers=headers, cookies=cookies,
                allow_redirects=allow_redirects if allow_redirects is not None else self.follow_redirects,
            ) as resp:
                body = await resp.text(encoding="utf-8", errors="replace")
                return resp.status, dict(resp.headers), body
        except asyncio.TimeoutError as e:
            raise TimeoutError(f"timeout: {url}") from e
        except aiohttp.ClientError as e:
            raise _map_error(e, url) from e
        except ssl.SSLError as e:
            raise TLSError(f"TLS error: {url}") from e

    async def get(self, url: str, **kwargs: Any) -> Tuple[int, Dict[str, str], str]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Tuple[int, Dict[str, str], str]:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Tuple[int, Dict[str, str], str]:
        return await self.request("HEAD", url, **kwargs)


async def concurrent_fetch(urls: list, timeout: float = 10.0,
                           max_concurrency: int = 50,
                           headers: Optional[Dict[str, str]] = None) -> Dict[str, Optional[Tuple[int, str]]]:
    """并发抓取多个 URL，返回 {url: (status, body)}；失败返回 None。

    使用信号量限制并发，避免打爆目标。
    """
    sem = asyncio.Semaphore(max_concurrency)
    results: Dict[str, Optional[Tuple[int, str]]] = {}

    async def _one(client: AsyncHttpClient, url: str) -> None:
        async with sem:
            try:
                status, hdrs, body = await client.get(url, headers=headers)
                results[url] = (status, body)
            except NetworkError as e:
                logger.debug("fetch %s failed: %s", url, e)
                results[url] = None

    async with AsyncHttpClient(timeout=timeout) as client:
        await asyncio.gather(*(_one(client, u) for u in urls))
    return results
