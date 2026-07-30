import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from tools.log_utils import get_logger
from tools.recon.port_scanner import _scan_port

logger = get_logger("internal_scan")


def ping_sweep(subnet: str, timeout: float = 2.0, threads: int = 50) -> List[str]:
    alive = []
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(h) for h in net.hosts()][:254]

    def _ping(host: str) -> Optional[str]:
        try:
            r = subprocess.run(
                ["ping", "-c1", "-W", str(int(timeout)), host],
                capture_output=True, text=True, timeout=timeout + 1,
            )
            if r.returncode == 0:
                return host
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_ping, h): h for h in hosts}
        for f in as_completed(futures):
            r = f.result()
            if r:
                alive.append(r)
    return sorted(alive, key=lambda x: [int(o) for o in x.split(".")])


def arp_scan(interface: str = "") -> List[Dict]:
    entries = []
    try:
        r = subprocess.run(["arp", "-a", interface] if interface else ["arp", "-a"],
                           capture_output=True, text=True, timeout=10)
        for line in r.stdout.split("\n"):
            m = re.search(r'\(?(\d+\.\d+\.\d+\.\d+)\)?\s+.*?(\S[\w:]{14,}\S)', line)
            if m:
                entries.append({"ip": m.group(1), "mac": m.group(2)})
            m2 = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+.*?(\S[\w:]{14,}\S)', line)
            if m2:
                entries.append({"ip": m2.group(1), "mac": m2.group(2)})
    except Exception as e:
        logger.debug("arp scan: %s", e)
    seen = set()
    unique = []
    for e in entries:
        if e["ip"] not in seen:
            seen.add(e["ip"])
            unique.append(e)
    return unique


def get_local_networks() -> List[str]:
    nets = []
    try:
        if hasattr(socket, "AF_INET"):
            hostname = socket.gethostname()
            for addr in socket.gethostbyname_ex(hostname)[2]:
                if addr.startswith("10.") or addr.startswith("172.") or addr.startswith("192.168."):
                    parts = addr.split(".")
                    nets.append(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
    except Exception:
        pass
    try:
        r = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        for m in re.finditer(r'inet (\d+\.\d+\.\d+)\.', r.stdout):
            net = f"{m.group(1)}.0/24"
            if net not in nets:
                nets.append(net)
    except Exception:
        pass
    return nets or ["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"]


def scan_host(host: str, ports: Optional[List[int]] = None,
              timeout: float = 2.0, threads: int = 100) -> Dict:
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389,
                 443, 445, 993, 995, 1433, 1521, 2049, 2375, 2376, 3306,
                 3389, 5432, 5555, 5900, 5985, 5986, 6379, 6443, 7001,
                 7070, 8000, 8009, 8080, 8161, 8200, 8443, 8500, 8686,
                 8761, 8888, 9000, 9090, 9092, 9100, 9200, 10000, 11211,
                 15672, 16379, 27017, 28017, 50070, 61616]
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_scan_port, host, p, timeout): p for p in ports}
        for f in as_completed(futures):
            r = f.result()
            if r and r["state"] == "open":
                results.append(r)
    results.sort(key=lambda x: x["port"])
    return {"host": host, "open_ports": results, "count": len(results)}


def full_network_scan(subnet: str = "", ports: Optional[List[int]] = None) -> Dict:
    if not subnet:
        nets = get_local_networks()
        if nets:
            subnet = nets[0]
    result = {"subnet": subnet, "alive_hosts": [], "scan_results": []}
    result["alive_hosts"] = ping_sweep(subnet, timeout=1.5)
    result["arp_entries"] = arp_scan()
    arp_ips = {e["ip"] for e in result["arp_entries"]}
    all_hosts = list(dict.fromkeys(result["alive_hosts"] + list(arp_ips)))
    for host in all_hosts:
        scan = scan_host(host, ports, timeout=1.5)
        if scan["count"] > 0:
            result["scan_results"].append(scan)
    result["total_alive"] = len(all_hosts)
    result["total_open_ports"] = sum(s["count"] for s in result["scan_results"])
    return result
