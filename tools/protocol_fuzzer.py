"""Protocol-level fuzzing for non-HTTP services.

Probes open TCP ports with service-aware malicious inputs and flags anomalies
via baseline differential, mirroring the engine-style judgment used for HTTP
fuzzing (FuzzEngine.test_payloads). A sender is injectable so the fuzzer is
fully testable without live sockets.

Judgment (engine-style differential vs a per-service baseline probe):
* connection_dropped  -- baseline connected, payload caused a refused/reset connect
* io_error            -- mid-conversation error after a successful connect
* reply_gone          -- baseline got a reply, payload got EOF/empty (crash candidate)
* oversized_reply     -- reply length ratio > 3x baseline (buffer overwrite candidate)
* slow_response       -- elapsed ratio > 5x baseline and > 3s (blind-logic candidate)
"""
import socket
import time
from typing import Callable, Dict, List, Optional, Sequence
from urllib.parse import urlparse

from tools.log_utils import get_logger

logger = get_logger("protocol_fuzzer")

GENERIC_PAYLOADS: List[bytes] = [
    b"A" * 4096,
    b"\x00" * 64,
    b"%s%s%s%s%n%n%n%n",
    b"\r\n\r\n",
    bytes(range(256)),
    b"A" * 1024 + b"\r\n",
]

BASELINE_PROBES: Dict[str, bytes] = {
    "ftp": b"USER anonymous\r\n",
    "ssh": b"",
    "smtp": b"EHLO fuzz\r\n",
    "pop3": b"CAPA\r\n",
    "imap": b"CAPABILITY\r\n",
    "telnet": b"",
    "dns": b"",
    "ldap": b"",
    "smb": b"",
    "snmp": b"",
    "mysql": b"",
    "mssql": b"",
    "oracle": b"",
    "postgres": b"",
    "redis": b"PING\r\n",
    "memcached": b"version\r\n",
    "mongodb": b"",
    "generic": b"",
}

SERVICE_PAYLOADS: Dict[str, List[bytes]] = {
    "ftp": [
        b"USER admin\r\n", b"PASS x\r\n", b"STAT\r\n", b"CWD ../../../../\r\n",
        b"USER " + b"A" * 2048 + b"\r\n", b"LIST -R\r\n",
    ],
    "ssh": [
        b"SSH-2.0-OpenSSH_9.0\r\n", b"\x00" * 64, b"A" * 2048 + b"\r\n",
    ],
    "smtp": [
        b"EHLO fuzz\r\n", b"VRFY root\r\n",
        b"RCPT TO:<" + b"A" * 2048 + b">\r\n", b"MAIL FROM:<a@b>\r\n",
        b"DATA\r\n" + b"X" * 4096 + b"\r\n.\r\n",
    ],
    "pop3": [
        b"CAPA\r\n", b"USER " + b"A" * 2048 + b"\r\n", b"STAT\r\n",
        b"LIST 999999999\r\n",
    ],
    "imap": [
        b"CAPABILITY\r\n", b"a LOGIN " + b"A" * 2048 + b" x\r\n",
        b"b FETCH 1 BODY[]\r\n",
    ],
    "telnet": [
        b"\xff\xf6", b"\xff\xfb\x01", b"A" * 2048 + b"\r\n",
    ],
    "dns": [
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01",
    ],
    "ldap": [
        b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
    ],
    "smb": [
        b"\x00" * 32, b"\xffSMB" + b"\x00" * 64,
    ],
    "snmp": [
        b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04"
        b"\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b"
        b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    ],
    "mysql": [
        b"\x00" * 64, b"\x0a" * 64,
    ],
    "mssql": [
        b"\x12\x01\x00\x34\x00\x00\x00\x00\x00", b"\x00" * 64,
    ],
    "oracle": [
        b"\x00\x00\x01\x00\x00\x00", b"A" * 2048,
    ],
    "postgres": [
        b"\x00\x00\x00\x08\x04\xd2\x16\x2f", b"\x00" * 64,
    ],
    "redis": [
        b"INFO\r\n", b"CONFIG GET *\r\n", b"EVAL \"return 1\" 0\r\n",
        b"SET k " + b"B" * 4096 + b"\r\n", b"AUTH " + b"Z" * 2048 + b"\r\n",
    ],
    "memcached": [
        b"stats\r\n", b"get " + b"A" * 2048 + b"\r\n",
        b"set k 0 0 4096\r\n" + b"V" * 4096 + b"\r\n",
    ],
    "mongodb": [
        b"\x3f\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x0e\x00\x00\x00"
        b"admin.\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00",
    ],
    "generic": GENERIC_PAYLOADS,
}

SERVICE_ALIASES: Dict[str, Sequence[str]] = {
    "ftp": ["ftp"],
    "ssh": ["ssh"],
    "smtp": ["smtp", "submission"],
    "pop3": ["pop3"],
    "imap": ["imap"],
    "telnet": ["telnet"],
    "dns": ["dns"],
    "ldap": ["ldap"],
    "smb": ["smb", "netbios", "microsoft-ds"],
    "snmp": ["snmp"],
    "mysql": ["mysql"],
    "mssql": ["mssql", "ms-sql"],
    "oracle": ["oracle"],
    "postgres": ["postgres"],
    "redis": ["redis"],
    "memcached": ["memcached"],
    "mongodb": ["mongodb", "mongo"],
}

PORT_FAMILY: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    110: "pop3", 143: "imap", 161: "snmp", 389: "ldap", 445: "smb",
    636: "ldap", 993: "imap", 995: "pop3", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 5432: "postgres", 6379: "redis", 11211: "memcached",
    27017: "mongodb",
}


def _family_of(service: str, port: int = 0) -> str:
    s = (service or "").lower()
    for family, aliases in SERVICE_ALIASES.items():
        if any(a in s for a in aliases):
            return family
    if port in PORT_FAMILY:
        return PORT_FAMILY[port]
    return "generic"


def _repr_payload(payload: bytes) -> str:
    try:
        text = payload[:60].decode("utf-8", errors="replace")
    except Exception:
        text = repr(payload)
    return text


def default_sender(host: str, port: int, payload: bytes,
                   timeout: float = 3.0) -> Dict:
    """Raw TCP probe: connect, send bytes, read until EOF/timeout."""
    start = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        return {"connected": False, "reply": b"", "error": "connect_timeout",
                "elapsed": time.monotonic() - start}
    except OSError as exc:
        return {"connected": False, "reply": b"", "error": str(exc),
                "elapsed": time.monotonic() - start}
    try:
        sock.settimeout(timeout)
        if payload:
            sock.sendall(payload)
        reply = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                reply += chunk
                if len(reply) > 65536:
                    break
        except socket.timeout:
            pass
        return {"connected": True, "reply": reply, "error": None,
                "elapsed": time.monotonic() - start}
    except OSError as exc:
        return {"connected": True, "reply": reply, "error": str(exc),
                "elapsed": time.monotonic() - start}
    finally:
        if sock is not None:
            sock.close()


def _reply_len(res: Dict) -> int:
    return len(res.get("reply") or b"")


class ProtocolFuzzer:
    def __init__(self, sender: Optional[Callable] = None, timeout: float = 3.0):
        self.sender = sender or default_sender
        self.timeout = timeout

    def _send(self, host: str, port: int, payload: bytes) -> Dict:
        try:
            return self.sender(host, port, payload, self.timeout)
        except Exception as exc:
            return {"connected": False, "reply": b"", "error": "sender:%s" % exc,
                    "elapsed": 0.0}

    def _judge(self, payload: bytes, baseline: Dict, res: Dict,
               family: str) -> Dict:
        interesting = False
        reasons: List[str] = []

        base_reply = _reply_len(baseline)
        cur_reply = _reply_len(res)
        base_conn = bool(baseline.get("connected"))
        cur_conn = bool(res.get("connected"))
        error = res.get("error")

        if base_conn and not cur_conn and error:
            interesting = True
            reasons.append("connection_dropped")
        if base_conn and cur_conn and error:
            interesting = True
            reasons.append("io_error")
        if base_reply > 0 and cur_reply == 0 and cur_conn:
            interesting = True
            reasons.append("reply_gone")
        if base_reply > 0:
            ratio = cur_reply / float(base_reply)
            if ratio > 3.0:
                interesting = True
                reasons.append("oversized_reply")

        elapsed = float(res.get("elapsed") or 0.0)
        base_elapsed = float(baseline.get("elapsed") or 0.0)
        if base_elapsed > 0 and elapsed > base_elapsed * 5.0 and elapsed > 3.0:
            interesting = True
            reasons.append("slow_response")

        return {
            "payload": _repr_payload(payload),
            "family": family,
            "connected": cur_conn,
            "reply_len": cur_reply,
            "reply_preview": (res.get("reply") or b"")[:80],
            "elapsed": round(elapsed, 3),
            "error": error,
            "interesting": interesting,
            "reasons": reasons,
        }

    def fuzz_service(self, host: str, port: int, service: str = "",
                     payloads: Optional[List[bytes]] = None) -> Dict:
        family = _family_of(service, port)
        probes = payloads or SERVICE_PAYLOADS.get(family, GENERIC_PAYLOADS)
        baseline = self._send(host, port, BASELINE_PROBES.get(family, b""))
        results = [self._judge(p, baseline, self._send(host, port, p), family)
                   for p in probes]
        interesting = [r for r in results if r["interesting"]]
        return {
            "host": host, "port": port, "service": service, "family": family,
            "baseline_len": _reply_len(baseline),
            "probes": len(results),
            "interesting": len(interesting),
            "results": results,
            "interesting_results": interesting,
        }

    def fuzz_ports(self, host: str, ports: Sequence[int],
                   services: Optional[Dict[int, str]] = None) -> Dict:
        services = services or {}
        out = []
        for port in ports:
            svc = services.get(int(port), "")
            try:
                out.append(self.fuzz_service(host, int(port), svc))
            except Exception as exc:
                logger.debug("fuzz port %d failed: %s", port, exc)
        return {
            "host": host,
            "ports_fuzzed": len(out),
            "total_interesting": sum(r["interesting"] for r in out),
            "results": out,
        }

    def fuzz_state(self, state: Dict, target: str = "",
                   ports: Optional[Sequence[int]] = None) -> Dict:
        recon = (state.get("phases") or {}).get("recon", {})
        data = recon.get("open_ports", {})
        if isinstance(data, dict):
            data = data.get("open_ports", [])
        open_list = [p for p in data if isinstance(p, dict) and p.get("state") == "open"]

        if ports is None:
            ports = [int(p["port"]) for p in open_list if p.get("port")]
        services = {int(p["port"]): str(p.get("service") or "") for p in open_list}

        host = target
        if "://" in host:
            host = urlparse(host).netloc
        host = host.split(":")[0] or "localhost"

        result = self.fuzz_ports(host, list(ports), services=services)
        result["target"] = target
        return result


def fuzz_ports(state: Optional[Dict] = None, target: str = "",
               ports: Optional[Sequence[int]] = None,
               sender: Optional[Callable] = None,
               timeout: float = 3.0) -> Dict:
    fuzzer = ProtocolFuzzer(sender=sender, timeout=timeout)
    if state is None:
        if not ports:
            return {"host": "localhost", "ports_fuzzed": 0,
                    "total_interesting": 0, "results": []}
        host = target
        if "://" in host:
            host = urlparse(host).netloc
        host = host.split(":")[0] or "localhost"
        return fuzzer.fuzz_ports(host, list(ports))
    return fuzzer.fuzz_state(state, target, ports=ports)
