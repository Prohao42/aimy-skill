import threading
import http.server
import socket
import struct
import string
import random
import time
import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from tools.log_utils import get_logger

logger = get_logger("oob_server")


@dataclass
class CallbackRecord:
    path: str
    headers: Dict[str, str]
    client: tuple
    timestamp: float
    raw_data: Optional[bytes] = None


class OOBServer:
    _instance = None
    _lock = threading.Lock()

    def __init__(self, host: str = "0.0.0.0", port: int = 0):
        self.host = host
        self.port = port
        self._httpd = None
        self._thread = None
        self._dns_sock = None
        self._dns_thread = None
        self._running = False
        self._callbacks: Dict[str, List[CallbackRecord]] = {}
        self._cb_lock = threading.Lock()

    @classmethod
    def get_instance(cls, host: str = "0.0.0.0", port: int = 0):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(host, port)
        return cls._instance

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._httpd = http.server.HTTPServer(
                (self.host, self.port), self._make_handler(self)
            )
            self.port = self._httpd.server_address[1]
            self._thread = threading.Thread(
                target=self._httpd.serve_forever, daemon=True
            )
            self._thread.start()
            self._running = True
            logger.info("OOB HTTP listener on 0.0.0.0:%d", self.port)
            return True
        except OSError as e:
            logger.warning("OOB HTTP bind failed: %s", e)
            return False

    def start_dns(self) -> Optional[str]:
        try:
            self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._dns_sock.bind(("0.0.0.0", 0))
            self._dns_sock.settimeout(1.0)
            dns_port = self._dns_sock.getsockname()[1]
            self._dns_thread = threading.Thread(target=self._dns_loop, daemon=True)
            self._dns_thread.start()
            lan_ip = self._get_lan_ip()
            token = "".join(random.choices(string.ascii_lowercase, k=6))
            domain = f"{token}.{lan_ip.replace('.', '-')}.oob"
            logger.info("OOB DNS listener on 0.0.0.0:%d domain=%s", dns_port, domain)
            return domain
        except OSError as e:
            logger.warning("OOB DNS bind failed: %s", e)
            return None

    def _dns_loop(self):
        while self._running:
            try:
                data, addr = self._dns_sock.recvfrom(512)
                domain = self._parse_dns_query(data)
                if domain:
                    with self._cb_lock:
                        self._callbacks.setdefault("dns", []).append(
                            CallbackRecord(
                                path=f"/dns/{domain}",
                                headers={},
                                client=addr,
                                timestamp=time.time(),
                                raw_data=data,
                            )
                        )
            except socket.timeout:
                continue
            except Exception:
                break

    @staticmethod
    def _parse_dns_query(data: bytes) -> Optional[str]:
        try:
            if len(data) < 12:
                return None
            qdcount = struct.unpack("!H", data[4:6])[0]
            if qdcount < 1:
                return None
            pos = 12
            labels = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                if length & 0xC0:
                    pos += 2
                    break
                pos += 1
                if pos + length > len(data):
                    return None
                labels.append(
                    data[pos : pos + length].decode("ascii", errors="replace")
                )
                pos += length
            return ".".join(labels)
        except Exception:
            return None

    def register_callback_id(self, cb_id: str) -> str:
        with self._cb_lock:
            self._callbacks.setdefault(cb_id, [])
        return f"http://{self._get_lan_ip()}:{self.port}/cb/{cb_id}"

    def pop_callbacks(self, cb_id: str) -> List[CallbackRecord]:
        with self._cb_lock:
            return self._callbacks.pop(cb_id, [])

    def has_callback(self, cb_id: str) -> bool:
        with self._cb_lock:
            return len(self._callbacks.get(cb_id, [])) > 0

    def stop(self):
        self._running = False
        if self._httpd:
            self._httpd.shutdown()
        if self._dns_sock:
            try:
                self._dns_sock.close()
            except Exception:
                pass

    @staticmethod
    def _get_lan_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def _make_handler(server):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                match = re.match(r"^/cb/([\w-]+)", self.path)
                if match:
                    cb_id = match.group(1)
                    rec = CallbackRecord(
                        path=self.path,
                        headers=dict(self.headers),
                        client=self.client_address,
                        timestamp=time.time(),
                    )
                    with server._cb_lock:
                        server._callbacks.setdefault(cb_id, []).append(rec)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        return Handler
