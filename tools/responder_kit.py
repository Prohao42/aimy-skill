import socket
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("responder_kit")

LLMNR_MULTICAST = "224.0.0.252"
LLMNR_PORT = 5355
NBT_NS_PORT = 137


class LLMNRPoisoner:
    def __init__(self, listen_ip: str = "0.0.0.0",
                 capture_file: str = "/tmp/llmnr_hashes.txt"):
        self.listen_ip = listen_ip
        self.capture_file = capture_file
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.captured_hashes: List[Dict] = []

    def start(self):
        if self._running:
            return
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            self._sock.bind((self.listen_ip, LLMNR_PORT))
            mreq = socket.inet_aton(LLMNR_MULTICAST) + socket.inet_aton("0.0.0.0")
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self._running = True
            self._thread = threading.Thread(target=self._listen, daemon=True)
            self._thread.start()
            logger.info("LLMNR poisoner listening on port %d", LLMNR_PORT)
        except Exception as e:
            logger.error("LLMNR start: %s", e)

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _listen(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
                self._handle_packet(data, addr)
            except Exception:
                break

    def _handle_packet(self, data: bytes, addr):
        if len(data) < 12:
            return
        try:
            q_count = int.from_bytes(data[4:6], "big")
            if q_count == 0:
                return
            pos = 12
            qname_parts = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                pos += 1
                qname_parts.append(data[pos:pos + length].decode("utf-8", errors="replace"))
                pos += length
            qname = ".".join(qname_parts)
            self.captured_hashes.append({
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": addr[0],
                "source_port": addr[1],
                "query": qname,
                "raw_size": len(data),
            })
            logger.info("[LLMNR] %s queried %s", addr[0], qname)
        except Exception:
            pass

    def get_captured(self) -> List[Dict]:
        return list(self.captured_hashes)


class NBTNSPoisoner:
    def __init__(self, listen_ip: str = "0.0.0.0"):
        self.listen_ip = listen_ip
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.captured: List[Dict] = []

    def start(self):
        if self._running:
            return
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.listen_ip, NBT_NS_PORT))
            self._running = True
            self._thread = threading.Thread(target=self._listen, daemon=True)
            self._thread.start()
            logger.info("NBT-NS poisoner listening on port %d", NBT_NS_PORT)
        except Exception as e:
            logger.error("NBT-NS start: %s", e)

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _listen(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
                self.captured.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "source_ip": addr[0],
                    "type": "nbt_ns",
                    "raw_size": len(data),
                })
                logger.info("[NBT-NS] packet from %s (%d bytes)", addr[0], len(data))
            except Exception:
                break

    def get_captured(self) -> List[Dict]:
        return list(self.captured)


class ResponderKit:
    def __init__(self, listen_ip: str = "0.0.0.0"):
        self.llmnr = LLMNRPoisoner(listen_ip)
        self.nbtns = NBTNSPoisoner(listen_ip)
        self._running = False

    def start(self):
        self.llmnr.start()
        self.nbtns.start()
        self._running = True

    def stop(self):
        self.llmnr.stop()
        self.nbtns.stop()
        self._running = False

    def get_results(self) -> Dict:
        return {
            "llmnr_queries": len(self.llmnr.get_captured()),
            "nbtns_packets": len(self.nbtns.get_captured()),
            "llmnr_details": self.llmnr.get_captured()[-20:],
            "nbtns_details": self.nbtns.get_captured()[-20:],
        }

    def capture_for_duration(self, duration: int = 30) -> Dict:
        self.start()
        time.sleep(duration)
        self.stop()
        return self.get_results()
