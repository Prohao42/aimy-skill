import socket
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from tools.log_utils import get_logger

logger = get_logger("recon.subdomain")

COMMON_SUBDOMAINS = [
    "www", "mail", "admin", "api", "dev", "test", "staging", "beta",
    "app", "blog", "cdn", "static", "assets", "img", "css", "js",
    "docs", "help", "support", "status", "monitor", "grafana",
    "jenkins", "gitlab", "jira", "confluence", "wiki", "vpn",
    "remote", "portal", "login", "auth", "sso", "oauth",
    "api", "v1", "v2", "v3", "api-dev", "api-staging",
    "backup", "db", "database", "redis", "mysql", "mongo",
    "elastic", "es", "kibana", "logstash", "grafana",
    "prometheus", "alertmanager", "thanos",
    "swagger", "api-docs", "redoc", "graphql", "graphiql",
    "s3", "storage", "files", "upload", "download",
    "ws", "wss", "socket", "chat", "notification",
    "webhook", "callback", "hook", "event",
    "internal", "corp", "office", "staff", "employee",
    "partner", "vendor", "supplier", "client",
    "report", "analytics", "metrics", "stats",
    "search", "catalog", "shop", "store", "cart",
    "payment", "checkout", "billing", "invoice",
    "account", "profile", "settings", "preferences",
    "cdn", "media", "video", "stream", "live",
    "ns1", "ns2", "ns3", "mx1", "mx2",
    "smtp", "imap", "pop3", "mailgun", "sendgrid",
]


def _resolve(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _check_http(domain: str, timeout: float = 5.0) -> Optional[Dict]:
    result = {"domain": domain, "status": None, "title": None, "server": None, "tech": []}
    for scheme in ("https", "http"):
        try:
            r = requests.get("%s://%s" % (scheme, domain), timeout=timeout,
                             headers={"User-Agent": "Mozilla/5.0"}, verify=False)
            result["status"] = r.status_code
            result["server"] = r.headers.get("Server")
            result["tech"].append(scheme)
            if "<title>" in r.text:
                start = r.text.index("<title>") + 7
                end = r.text.index("</title>", start)
                result["title"] = r.text[start:end].strip()[:100]
            return result
        except requests.RequestException:
            continue
    return result if result.get("status") else None


def enum_subdomains(target: str, threads: int = 20, timeout: float = 5.0,
                    wordlist: Optional[List[str]] = None,
                    check_http: bool = True) -> Dict:
    parsed = urlparse(target)
    root = parsed.netloc or parsed.path.split("/")[0]
    root = root.split(":")[0]

    words = wordlist or COMMON_SUBDOMAINS
    domains = ["%s.%s" % (w, root) for w in words if w != root]

    base_ip = _resolve(root)
    found = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_resolve, d): d for d in domains}
        resolved = []
        for f in as_completed(futures):
            ip = f.result()
            if ip:
                resolved.append((futures[f], ip))

    logger.info("Subdomain resolved: %d/%d", len(resolved), len(domains))

    if check_http and resolved:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures2 = {pool.submit(_check_http, d, timeout): d for d, _ in resolved}
            for f in as_completed(futures2):
                info = f.result()
                if info:
                    found.append(info)

    return {
        "target": target,
        "root_domain": root,
        "root_ip": base_ip,
        "total_tried": len(domains),
        "resolved": [{"domain": d, "ip": ip} for d, ip in resolved],
        "http_reachable": found,
    }
