"""Recon Engine: 信息收集阶段。

对应 orchestrator.py 中的：
- fingerprint_tech
- scan_ports
- check_git_leak
- fuzz_directories
- enum_subdomains
"""

import concurrent.futures
import logging
import socket
from typing import Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from tools.settings import settings

logger = logging.getLogger(__name__)

URL_SCHEMES = ("http://", "https://", "file://", "gopher://", "dict://")


class TLS12Adapter(HTTPAdapter):
    """强制 TLS1.2 + 指数退避重试。"""

    def __init__(self, max_retries=2, **kwargs):
        retries = Retry(
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
        import ssl
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if not settings.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(
            connections, maxsize=max(100, maxsize), block=block, **kwargs
        )


_adapter_cache: Optional[TLS12Adapter] = None
def _tls12_adapter() -> TLS12Adapter:
    global _adapter_cache
    if _adapter_cache is None:
        _adapter_cache = TLS12Adapter()
    return _adapter_cache


def _validate_url(url: str) -> bool:
    """验证 URL 格式。"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.scheme in URL_SCHEMES and bool(parsed.netloc)


def fingerprint_tech(target: str, sess, timeout: float) -> Dict:
    """指纹技术检测 (简化版)。

    返回检测到的技术栈信息。
    """
    try:
        adapter = _tls12_adapter()
        s = requests.Session()
        s.mount("https://", adapter)
        s.verify = settings.verify_ssl
        s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        r = s.get(target.rstrip("/"), timeout=timeout)
        tech = {
            "server": r.headers.get("Server", ""),
            "x_powered_by": r.headers.get("X-Powered-By", ""),
            "status": r.status_code,
        }

        # 简单的技术识别
        body = r.text.lower()
        if "php" in body or "<?php" in body:
            tech["language"] = "php"
        elif "asp" in body or "<%" in body:
            tech["language"] = "asp"
        elif "jsp" in body or "<%@" in body:
            tech["language"] = "jsp"
        elif "django" in body:
            tech["language"] = "django"
        elif "flask" in body:
            tech["language"] = "flask"
        else:
            tech["language"] = "unknown"

        return {"tech_fingerprint": tech}
    except Exception as e:
        logger.debug("fingerprint_tech error for %s: %s", target, e)
        return {"tech_fingerprint": {}}


def scan_ports(target: str, fast: bool = True) -> Dict:
    """TCP 端口扫描。

    返回开放端口列表。
    """
    ports = [21, 22, 80, 443, 3306, 6379, 8080, 8443, 9200, 27017]
    if not fast:
        ports = list(range(1, 1025)) + list(range(2000, 65536))

    def _scan(port: int) -> Optional[Dict]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            r = sock.connect_ex((target, port))
            if r == 0:
                return {"port": port, "state": "open"}
        except Exception:
            pass
        finally:
            sock.close()
        return None

    max_workers = min(50, max(1, len(ports)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = [f for f in ex.map(_scan, ports) if f]

    return {"target": target, "open_ports": results, "count": len(results)}


def check_git_leak(target: str, sess, timeout: float, deep: bool = False) -> Dict:
    """检查 Git 泄露。

    检查常见的 Git 配置文件和泄露。
    """
    git_paths = [".git", ".git/config", ".htaccess"]
    if deep:
        git_paths.extend(["logs/HEAD", "objects/pack/", "refs/heads/"])

    found = []
    adapter = _tls12_adapter()
    s = requests.Session()
    s.mount("https://", adapter)
    s.verify = settings.verify_ssl

    for path in git_paths:
        try:
            r = s.get(f"{target.rstrip('/')}/{path}", timeout=timeout)
            if r.status_code == 200:
                found.append({"path": path, "status": r.status_code, "size": len(r.text)})
        except Exception:
            pass

    return {"target": target, "git_leak": found, "count": len(found)}


def fuzz_directories(target: str, sess, timeout: float) -> Dict:
    """目录枚举 (dirfuzz)。

    返回发现的有效目录。
    """
    # 默认路径列表
    default_paths = [
        "admin", "login", "wp-admin", "backup", "api",
        "config", ".git", ".env", "robots.txt", "sitemap.xml",
        "phpmyadmin", "manager", "debug", "test"
    ]

    found = []
    wordlist_paths = ["wordlist.txt", "/usr/share/wordlists/dirb/common.txt"]

    # 尝试加载字典
    paths = []
    for wl_path in wordlist_paths:
        import os
        if os.path.exists(wl_path):
            try:
                with open(wl_path, "r") as f:
                    paths = [line.strip() for line in f if line.strip()]
                break
            except Exception:
                pass

    if not paths:
        paths = default_paths[:20]  # 限制数量

    adapter = _tls12_adapter()
    s = requests.Session()
    s.mount("https://", adapter)
    s.verify = settings.verify_ssl
    s.headers["User-Agent"] = "Mozilla/5.0"

    def _probe(path: str) -> Optional[Dict]:
        try:
            r = s.get(f"{target.rstrip('/')}/{path}", timeout=timeout)
            if r.status_code not in (404, 403):
                return {"path": f"/{path}", "status": r.status_code, "size": len(r.text)}
        except Exception as e:
            logger.debug("dirfuzz %s: %s", path, e)
        return None

    max_workers = min(30, max(1, 20))
    tested = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = [f for f in ex.map(_probe, paths) if f and (tested := tested + 1) or True]

    return {"target": target, "found": results, "count": len(results)}


def enum_subdomains(target: str, sess, timeout: float, deep: bool = False) -> Dict:
    """子域枚举。

    返回发现的子域名列表。
    """
    # 简化的子域枚举实现
    # 实际项目中会使用 subfinder, amass 等工具
    discovered = []

    # 常见子域名前缀
    common_prefixes = [
        "www", "mail", "ftp", "admin", "api", "dev", "test",
        "staging", "internal", "secure", "web", "app", "blog"
    ]

    # 尝试解析目标域名
    from urllib.parse import urlparse
    parsed = urlparse(target.rstrip("/"))
    domain = parsed.netloc or parsed.path

    # 去除端口信息
    if ":" in domain:
        domain = domain.split(":")[0]

    # 尝试探测常见子域名
    for prefix in common_prefixes:
        test_domain = f"{prefix}.{domain}"
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(test_domain, "A")
                for rdata in answers:
                    discovered.append({"subdomain": test_domain, "type": "A", "address": str(rdata)})
            except Exception:
                # 备用: 尝试使用 requests
                import requests
                try:
                    r = requests.get(f"http://{test_domain}", timeout=timeout,
                                     verify=settings.verify_ssl, allow_redirects=False)
                    if r.status_code < 400:
                        discovered.append({"subdomain": test_domain, "type": "http", "status": r.status_code})
                except Exception:
                    pass
        except Exception:
            pass

    return {"target": target, "subdomains": discovered, "count": len(discovered)}
