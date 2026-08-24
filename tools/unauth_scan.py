"""未授权中间件检测 (Redis / Elasticsearch / MongoDB / MySQL / PostgreSQL)。

只读验证"无认证可达"这一事实: Redis PING/INFO/DBSIZE, ES 根接口,
Mongo isMaster, MySQL/Postgres 握手 banner。不写、不删、不利用。

蜜罐回显识别: 伪装服务会把请求命令原样回显 (如 Redis 回显 "PING" 而非
"+PONG", Mongo 回显命令字段名)。此类目标标记 `honey: True` 并在结果中排除,
避免浪费时间与误报。

用法:
    from tools.unauth_scan import check
    result = check(["167.235.142.43", "212.132.104.109:6379"], services=["redis"])
"""
import concurrent.futures
import socket
import struct
import threading
from typing import Dict, List

import requests
import urllib3

from tools.log_utils import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger("unauth_scan")

DEFAULT_PORTS = {
    "redis": 6379,
    "es": 9200,
    "mongo": 27017,
    "mysql": 3306,
    "pg": 5432,
}

_lock = threading.Lock()


def _sock_send(ip: str, port: int, data: bytes, timeout: float = 5.0,
               read_size: int = 65536) -> bytes:
    """Send raw bytes and drain the reply until quiet or size bound."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(data)
        chunks = []
        while True:
            try:
                c = s.recv(read_size)
            except socket.timeout:
                break
            if not c:
                break
            chunks.append(c)
            if len(chunks) >= 4:
                break
        return b"".join(chunks)
    except Exception as e:
        return b"ERR: %s" % str(e).encode()
    finally:
        s.close()


def check_redis(ip: str, port: int, timeout: float = 5.0) -> Dict:
    result = {"service": "redis", "ip": ip, "port": port, "unauth": False,
              "honey": False, "version": "", "keyspace": "", "dbsize": None}
    resp = _sock_send(ip, port, b"PING\r\n", timeout=timeout)
    if b"ERR:" in resp[:4]:
        result["note"] = resp.decode(errors="replace").strip()
        return result
    if b"+PONG" not in resp:
        if b"PING" in resp:
            result["honey"] = True
            result["note"] = "echo-back honey (PING reflected, not RESP)"
        else:
            result["note"] = "no +PONG (auth required or not Redis)"
        return result
    result["unauth"] = True
    info = _sock_send(ip, port, b"INFO server\r\nINFO keyspace\r\nINFO replication\r\n",
                      timeout=timeout, read_size=65536)
    for line in info.decode(errors="replace").splitlines():
        if line.startswith("redis_version:"):
            result["version"] = line.split(":", 1)[1].strip()
        elif line.startswith("role:"):
            result["role"] = line.split(":", 1)[1].strip()
        elif line.startswith("db0:"):
            result["keyspace"] = line.split(":", 1)[1].strip()
    db = _sock_send(ip, port, b"DBSIZE\r\n", timeout=timeout)
    val = db.decode(errors="replace").strip()
    if val.startswith(":"):
        result["dbsize"] = int(val[1:])
    return result


def check_es(ip: str, port: int, timeout: float = 5.0) -> Dict:
    result = {"service": "es", "ip": ip, "port": port, "unauth": False,
              "honey": False, "version": "", "cluster": ""}
    for scheme in ("http", "https"):
        try:
            r = requests.get("%s://%s:%d/" % (scheme, ip, port), timeout=timeout,
                             verify=False)  # nosec B501 - target TLS is out of our control
            if r.status_code != 200:
                continue
            j = r.json()
            result["unauth"] = True
            result["cluster"] = j.get("cluster_name", "")
            result["version"] = (j.get("version") or {}).get("number", "")
            return result
        except Exception:
            continue
    return result


def check_mongo(ip: str, port: int, timeout: float = 5.0) -> Dict:
    result = {"service": "mongo", "ip": ip, "port": port, "unauth": False,
              "honey": False, "version": ""}
    # OP_QUERY admin.$cmd isMaster:1 (read-only handshake)
    ns = b"admin.$cmd\x00"
    doc = b"\x10isMaster\x00\x01\x00\x00\x00\x00"
    body = struct.pack("<i", 0) + ns + struct.pack("<ii", 0, 1) + doc
    req = struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body
    resp = _sock_send(ip, port, req, timeout=timeout)
    if not resp or b"ERR:" in resp[:4]:
        result["note"] = resp.decode(errors="replace").strip()
        return result
    if len(resp) < 36:
        result["note"] = "short reply, not MongoDB"
        return result
    opcode = struct.unpack("<i", resp[12:16])[0]
    if opcode == 2004:
        # A server never answers OP_QUERY with OP_QUERY: the request was
        # reflected verbatim -> echo-back honeypot.
        result["honey"] = True
        result["note"] = "echo-back honey (OP_QUERY reflected)"
        return result
    if opcode not in (1, 2013):  # OP_REPLY / OP_MSG
        result["note"] = "unexpected opcode %d" % opcode
        return result
    # Echo-back honeypot: the reply document echoes the sent field name.
    if b"isMaster" in resp[36:]:
        result["honey"] = True
        result["note"] = "echo-back honey (command reflected)"
        return result
    result["unauth"] = True
    result["note"] = "anonymous handshake ok"
    return result


def check_mysql(ip: str, port: int, timeout: float = 5.0) -> Dict:
    result = {"service": "mysql", "ip": ip, "port": port, "unauth": False,
              "honey": False, "version": ""}
    resp = _sock_send(ip, port, b"", timeout=timeout)
    if b"ERR:" in resp[:4]:
        result["note"] = resp.decode(errors="replace").strip()
        return result
    try:
        result["version"] = resp[5:].split(b"\x00")[0].decode(errors="replace")
        result["banner"] = "server handshake received"
    except Exception:
        result["note"] = "unparseable handshake"
    return result


def check_pg(ip: str, port: int, timeout: float = 5.0) -> Dict:
    result = {"service": "pg", "ip": ip, "port": port, "unauth": False,
              "honey": False, "version": ""}
    # Startup: protocol 3.0, empty params (read-only; server replies with
    # auth request or error, never runs anything).
    startup = struct.pack(">i", 8) + struct.pack(">i", 196608)
    resp = _sock_send(ip, port, startup, timeout=timeout)
    if b"ERR:" in resp[:4]:
        result["note"] = resp.decode(errors="replace").strip()
        return result
    if len(resp) >= 5:
        code = resp[4:5]
        result["banner"] = "startup replied (type %s)" % code.decode(errors="replace")
    return result


CHECKERS = {
    "redis": check_redis,
    "es": check_es,
    "mongo": check_mongo,
    "mysql": check_mysql,
    "pg": check_pg,
}


def _parse_host(entry: str) -> List[Dict]:
    entry = entry.strip()
    if not entry:
        return []
    if "://" in entry:
        scheme, rest = entry.split("://", 1)
        svc = scheme.lower()
        if svc not in CHECKERS:
            svc = "redis" if svc == "redis" else None
    else:
        rest = entry
        svc = None
    if ":" in rest:
        ip, _, port = rest.rpartition(":")
        try:
            port = int(port)
        except ValueError:
            return []
    else:
        ip = rest
        port = 0
    return [{"ip": ip, "port": port, "svc": svc}]


def check(hosts: List[str], services: List[str] = None,
          threads: int = 30, timeout: float = 5.0) -> Dict:
    """Batch check for unauthorized middleware access.

    hosts: list of "ip" / "ip:port" / "scheme://ip:port".
    services: subset of CHECKERS keys to probe (all by default).
    """
    if services:
        services = [s for s in services if s in CHECKERS]
    else:
        services = list(CHECKERS)

    jobs = []
    for entry in hosts:
        for spec in _parse_host(entry):
            targets = []
            if spec["svc"]:
                targets = [spec["svc"]]
            else:
                targets = services
            for svc in targets:
                if svc not in CHECKERS:
                    continue
                port = spec["port"] or DEFAULT_PORTS[svc]
                jobs.append((svc, spec["ip"], port))

    results = []

    def _run(job):
        svc, ip, port = job
        try:
            return CHECKERS[svc](ip, port, timeout=timeout)
        except Exception as e:
            return {"service": svc, "ip": ip, "port": port,
                    "unauth": False, "honey": False, "note": str(e)[:60]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(_run, jobs):
            results.append(r)

    vulnerable = [r for r in results if r.get("unauth") and not r.get("honey")]
    honey = [r for r in results if r.get("honey")]
    return {
        "scanned": len(results),
        "vulnerable": len(vulnerable),
        "findings": vulnerable,
        "honeypots": honey,
        "all": results,
    }
