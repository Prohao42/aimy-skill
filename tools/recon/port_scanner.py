import socket
import ssl
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from tools.log_utils import get_logger

logger = get_logger("recon.portscan")

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 500: "IKE", 514: "Syslog",
    587: "SMTP Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2375: "Docker", 2376: "Docker TLS", 2433: "MSSQL", 2483: "Oracle",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4333: "MSSQL",
    4444: "Metasploit", 4848: "GlassFish", 5000: "Flask/UPnP",
    5432: "PostgreSQL", 5555: "Android ADB", 5800: "VNC HTTP",
    5900: "VNC", 5984: "CouchDB", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    6379: "Redis", 6443: "Kubernetes API", 7001: "WebLogic",
    7002: "WebLogic SSL", 7070: "Tomcat", 7199: "Cassandra",
    8000: "HTTP-alt", 8001: "HTTP-alt", 8009: "AJP",
    8080: "HTTP-proxy", 8081: "HTTP-alt", 8082: "HTTP-alt",
    8083: "HTTP-alt", 8084: "HTTP-alt", 8085: "HTTP-alt",
    8086: "InfluxDB", 8087: "HTTP-alt", 8088: "HTTP-alt",
    8089: "Splunk", 8090: "HTTP-alt", 8161: "ActiveMQ",
    8200: "Vault", 8443: "HTTPS-alt", 8448: "Matrix",
    8500: "Consul", 8686: "JMX", 8761: "Eureka",
    8888: "HTTP-alt", 9000: "Hadoop NameNode", 9001: "Hadoop ResourceManager",
    9042: "Cassandra CQL", 9090: "Prometheus", 9092: "Kafka",
    9100: "Node Exporter", 9160: "Cassandra Thrift",
    9200: "Elasticsearch", 9300: "Elasticsearch Transport",
    9418: "Git", 9443: "HTTPS-alt", 9600: "Logstash",
    9876: "HTTP-alt", 9999: "HTTP-alt",
    10000: "Webmin", 11211: "Memcached",
    15672: "RabbitMQ Management", 16010: "HBase",
    16379: "Redis-alt", 17000: "HTTP-alt",
    18080: "HTTP-alt", 19000: "HTTP-alt",
    20000: "HTTP-alt", 23333: "HTTP-alt",
    25565: "Minecraft", 27017: "MongoDB",
    27018: "MongoDB Web", 28017: "MongoDB HTTP",
    30000: "HTTP-alt", 31337: "BackOrifice",
    32764: "Router", 32768: "Statd",
    37777: "Tandberg", 39295: "HTTP-alt",
    49152: "Windows RPC", 50000: "HTTP-alt",
    50070: "HDFS NameNode", 50075: "HDFS DataNode",
    50090: "HDFS Secondary", 50470: "HDFS HTTPS",
    54328: "HTTP-alt", 60000: "HTTP-alt",
    60001: "HTTP-alt", 61616: "ActiveMQ Transport",
    62078: "iPhone Sync", 64738: "Mumble",
    65535: "HTTP-alt",
}


def _scan_port(host: str, port: int, timeout: float = 2.0) -> Optional[Dict]:
    result = {"port": port, "service": COMMON_PORTS.get(port, "unknown"), "state": "filtered"}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((host, port))
        if code == 0:
            result["state"] = "open"
            try:
                sock.settimeout(1.0)
                banner = sock.recv(1024)
                decoded = banner.decode("utf-8", errors="replace").strip()
                if decoded:
                    result["banner"] = decoded[:200]
            except Exception:
                pass
            if port == 443 or port == 8443:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(socket.socket(), server_hostname=host) as ssock:
                        ssock.settimeout(timeout)
                        ssock.connect((host, port))
                        cert = ssock.getpeercert(binary_form=True)
                        if cert:
                            result["tls"] = True
                except Exception:
                    pass
        sock.close()
        return result
    except Exception as e:
        logger.debug("port %d: %s", port, e)
        return None


def scan_ports(target: str, ports: Optional[List[int]] = None,
               threads: int = 50, timeout: float = 2.0,
               fast: bool = True) -> Dict:
    if ports is None:
        if fast:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                     161, 389, 443, 445, 465, 500, 514, 587, 636, 993, 995,
                     1080, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 3690,
                     4444, 4848, 5000, 5432, 5555, 5800, 5900, 5984, 5985,
                     5986, 6379, 6443, 7001, 7002, 7070, 8000, 8009, 8080,
                     8086, 8089, 8161, 8200, 8443, 8448, 8500, 8686, 8761,
                     8888, 9000, 9090, 9092, 9100, 9160, 9200, 9300, 9418,
                     9443, 9876, 9999, 10000, 11211, 15672, 16379, 17000,
                     18080, 19000, 20000, 23333, 25565, 27017, 28017, 31337,
                     32764, 37777, 49152, 50000, 50070, 50075, 50090, 50470,
                     61616, 62078]
        else:
            ports = sorted(set(list(COMMON_PORTS.keys()) + [8080, 8443, 9090, 9200, 15672, 27017]))

    host = target.split(":")[0]
    results = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_port, host, p, timeout): p for p in ports}
        for f in as_completed(futures):
            r = f.result()
            if r:
                results.append(r)

    results.sort(key=lambda x: x["port"])
    open_ports = [r for r in results if r["state"] == "open"]

    return {
        "target": target,
        "total_scanned": len(ports),
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "all_results": results,
    }
