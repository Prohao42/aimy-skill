"""批量资产发现: TCP 端口存活 -> Web 技术指纹 -> 高价值目标排序。

用于 SRC 资产盘点阶段: 给一个 IP/域名列表, 输出哪些主机有开放端口、
哪些跑 Web、哪些疑似高价值(登录面/数据库端口), 并可联动 unauth_scan
对 Redis/ES/Mongo 等做未授权检测。

    from tools.batch_recon import run
    report = run(["1.2.3.4", "5.6.7.8"])
"""
import concurrent.futures
import re
import socket
from typing import Dict, List

import requests
import urllib3

from tools.log_utils import get_logger
from tools.unauth_scan import check as unauth_check

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger("batch_recon")

DEFAULT_PORTS = "21,22,23,25,53,80,443,3306,3389,5432,6379,8080,8443,9200,27017"

# Ports that signal high-value targets (data stores / admin / middleware).
HIGH_VALUE_PORTS = {3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            9200: "Elasticsearch", 27017: "MongoDB", 3389: "RDP"}
WEB_PORTS = {80, 443, 8080, 8443}

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
GEN_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
PW_RE = re.compile(r'<input[^>]+type=["\']password["\']', re.I)
LOGIN_RE = re.compile(r"(login|signin|sign in|登录|wp-login|user/login|/login/)", re.I)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def _parse_hosts(hosts_file: str) -> List[str]:
    with open(hosts_file, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _scan_ports(ip: str, ports: List[int], timeout: float) -> List[int]:
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            s.close()
    return sorted(open_ports)


def _probe_web(ip: str, ports: List[int], timeout: float) -> List[Dict]:
    out = []
    for port in ports:
        for scheme in ("http", "https"):
            if scheme == "https" and port not in (443, 8443):
                continue
            if scheme == "http" and port in (443, 8443):
                continue
            url = "%s://%s:%d/" % (scheme, ip, port)
            try:
                r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                                 headers={"User-Agent": UA})  # nosec B501 - target TLS is out of our control
                body = r.text[:200000]
                tm = TITLE_RE.search(body)
                gm = GEN_RE.search(body)
                out.append({
                    "url": url,
                    "status": r.status_code,
                    "server": r.headers.get("Server", ""),
                    "title": (tm.group(1).strip()[:80] if tm else ""),
                    "generator": (gm.group(1).strip()[:60] if gm else ""),
                    "has_login": bool(PW_RE.search(body) or LOGIN_RE.search(body)),
                    "final_url": r.url[:100],
                })
            except Exception:
                continue
    return out


def run(hosts_file: str, ports: str = DEFAULT_PORTS, threads: int = 100,
        timeout: float = 3.0, unauth: bool = False) -> Dict:
    """Batch asset discovery over a hosts file."""
    hosts = _parse_hosts(hosts_file)
    port_list = [int(p) for p in (ports or DEFAULT_PORTS).split(",") if p.strip().isdigit()]
    report = {"targets": len(hosts), "alive": [], "web": [], "high_priority": [],
              "honeypots": [], "unauth": []}

    results = []

    def _recon(ip):
        open_ports = _scan_ports(ip, port_list, timeout)
        web = _probe_web(ip, [p for p in open_ports if p in WEB_PORTS], timeout)
        return {"ip": ip, "open_ports": open_ports, "web": web}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(_recon, hosts):
            results.append(r)

    for r in sorted(results, key=lambda x: x["ip"]):
        if not r["open_ports"]:
            continue
        report["alive"].append({"ip": r["ip"], "open_ports": r["open_ports"]})
        for w in r["web"]:
            report["web"].append({"ip": r["ip"], **w})

        db = [DB_PORTS[p] for p in r["open_ports"] if p in DB_PORTS]
        interesting_web = any(w["has_login"] for w in r["web"])
        if db or interesting_web:
            report["high_priority"].append({
                "ip": r["ip"],
                "open_ports": r["open_ports"],
                "db_services": db,
                "has_login_web": interesting_web,
            })

    if unauth:
        db_hosts = []
        for r in results:
            for p in r["open_ports"]:
                if p in DB_PORTS:
                    db_hosts.append("%s:%d" % (r["ip"], p))
        if db_hosts:
            report["unauth"] = unauth_check(db_hosts, timeout=timeout)
            report["honeypots"] = [h for h in report["unauth"].get("honeypots", [])]

    return report
