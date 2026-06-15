import json, os, time, uuid, subprocess
from typing import Optional, Dict, List
from tools.log_utils import get_logger
from tools.kali_executor import get_kali, is_available, has_tool

logger = get_logger("kali_capture")


def resolve_interface() -> str:
    try:
        r = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        parts = r.stdout.strip().split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.splitlines():
            if "interface" in line:
                return line.split(":")[-1].strip()
    except Exception:
        pass
    return "eth0"


def _install_tshark_json_deps(kali, local: bool) -> bool:
    if local:
        r = subprocess.run(
            ["which", "tshark"], capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0:
            logger.warning("tshark not found, try: apt install -y tshark")
            return False
        return True
    r = kali.run("which tshark && tshark --version 2>&1 | head -1", timeout=10)
    if not r["success"]:
        logger.warning("Kali tshark not found, try: apt install -y tshark")
        return False
    return True


class KaliCapture:
    def __init__(self, local: bool = False):
        self.local = local
        self.kali = get_kali()
        self._tag = uuid.uuid4().hex[:8]

    def capture(self, interface: str = "", count: int = 1000,
                bpf_filter: str = "", timeout: int = 60,
                output: str = "") -> Dict:
        if not interface:
            interface = resolve_interface()
        if not output:
            output = f"/tmp/aimy_cap_{self._tag}.pcap"

        if not _install_tshark_json_deps(self.kali, self.local):
            return {"success": False, "error": "tshark not available on Kali"}

        logger.info("Capture: iface=%s count=%d timeout=%s",
                     interface, count, output)

        cap_cmd = (
            f"timeout {timeout} tcpdump -i {interface} -c {count} "
            f"-w {output} -Z root 2>/dev/null"
        )
        if bpf_filter:
            cap_cmd += f" {bpf_filter}"

        r1 = self.kali.run(cap_cmd, timeout=timeout + 30)
        if not r1["success"]:
            logger.warning("tcpdump may have partial result: %s", r1.get("stderr", "")[:200])

        if not self._check_pcap(output):
            return {"success": False, "error": "pcap file not created or empty"}

        parse_cmd = f"tshark -r {output} -T json 2>/dev/null"
        r2 = self.kali.run(parse_cmd, timeout=120)

        if not r2["success"] or not r2.get("stdout", "").strip():
            logger.warning("tshark parse failed, fallback to pdml")
            parse_cmd = f"tshark -r {output} -T pdml 2>/dev/null"
            r2 = self.kali.run(parse_cmd, timeout=120)

        raw = r2.get("stdout", "")
        packets = self._parse_packets(raw)

        summary = self._summarize(packets)

        return {
            "success": True,
            "pcap": output,
            "total_packets": len(packets),
            "summary": summary,
            "packets": packets[:200],
        }

    def capture_http(self, interface: str = "", count: int = 500,
                     timeout: int = 60) -> Dict:
        return self.capture(
            interface=interface,
            count=count,
            bpf_filter="tcp port 80 or tcp port 8080",
            timeout=timeout,
        )

    def capture_https(self, interface: str = "", count: int = 500,
                      timeout: int = 60) -> Dict:
        return self.capture(
            interface=interface,
            count=count,
            bpf_filter="tcp port 443",
            timeout=timeout,
        )

    def live_http(self, interface: str = "", max_packets: int = 100,
                  timeout: int = 30) -> List[Dict]:
        if not interface:
            interface = resolve_interface()
        if not _install_tshark_json_deps(self.kali, self.local):
            return []
        fields = "frame.time_relative,ip.src,ip.dst,tcp.srcport,tcp.dstport,http.request.method,http.request.uri,http.response.code,http.host"
        cmd = (
            f"timeout {timeout} tshark -i {interface} -c {max_packets} "
            f"'-Y' 'http or tls.handshake.type==1' "
            f"-T fields -E separator=| -E quote=d "
            f"-e frame.time_relative -e ip.src -e ip.dst "
            f"-e tcp.srcport -e tcp.dstport "
            f"-e http.request.method -e http.request.uri "
            f"-e http.response.code -e http.host 2>/dev/null"
        )
        r = self.kali.run(cmd, timeout=timeout + 30)
        if not r["success"]:
            return []
        entries = []
        for line in r.get("stdout", "").splitlines():
            parts = [p.strip().strip('"') for p in line.split("|")]
            if len(parts) >= 5:
                entry = {
                    "time": parts[0],
                    "src": parts[1],
                    "dst": parts[2],
                    "sport": parts[3],
                    "dport": parts[4],
                }
                if len(parts) > 5 and parts[5]:
                    entry["method"] = parts[5]
                if len(parts) > 6 and parts[6]:
                    entry["uri"] = parts[6]
                if len(parts) > 7 and parts[7]:
                    entry["status"] = parts[7]
                if len(parts) > 8 and parts[8]:
                    entry["host"] = parts[8]
                entries.append(entry)
        return entries

    def _check_pcap(self, path: str) -> bool:
        r = self.kali.run(
            f"ls -l {path} 2>/dev/null && wc -c < {path}",
            timeout=10,
        )
        if r["success"]:
            size = r["stdout"].strip().splitlines()[-1].strip()
            try:
                return int(size) > 100
            except ValueError:
                return False
        return False

    def _parse_packets(self, raw: str) -> List[Dict]:
        if not raw.strip():
            return []
        if raw.lstrip().startswith("<"):
            return self._parse_pdml(raw)
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return [self._flatten_packet(p) for p in data]
            return []
        except json.JSONDecodeError:
            return self._parse_fallback(raw)

    def _flatten_packet(self, p: dict) -> Dict:
        flat = {"index": p.get("_index", "")}
        layers = p.get("_source", {}).get("layers", {})
        for key, val in layers.items():
            k = key.replace("_", ".").replace(":", "").strip()
            if isinstance(val, list):
                flat[k] = val[0] if val else ""
            elif isinstance(val, dict):
                flat[k] = json.dumps(val, ensure_ascii=False)
            else:
                flat[k] = val
        return flat

    def _parse_pdml(self, raw: str) -> List[Dict]:
        packets = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw)
            for i, pkt in enumerate(root.findall(".//packet")):
                p = {"index": i}
                for proto in pkt.findall(".//proto"):
                    name = proto.get("name", "")
                    for field in proto.findall(".//field"):
                        fname = field.get("name", "")
                        fvalue = field.get("show", "")
                        if fname and fvalue:
                            p[f"{name}.{fname}"] = fvalue
                packets.append(p)
        except Exception as e:
            logger.debug("PDML parse failed: %s", e)
        return packets

    def _parse_fallback(self, raw: str) -> List[Dict]:
        lines = raw.strip().splitlines()
        packets = []
        for i, line in enumerate(lines[:500]):
            packets.append({"index": i, "raw": line[:300]})
        return packets

    def _summarize(self, packets: List[Dict]) -> Dict:
        proto_count = {}
        src_ips = set()
        dst_ips = set()
        http_reqs = 0
        http_resps = 0
        tls_count = 0

        for p in packets:
            proto = "unknown"
            for key in p:
                k = key.lower()
                if "frame.protocols" in k:
                    proto = p[key][:40]
                elif "http.request.method" in k:
                    http_reqs += 1
                elif "http.response.code" in k:
                    http_resps += 1
                elif "tls" in k and k.endswith("record.content.type"):
                    tls_count += 1
                if "ip.src" in k:
                    src_ips.add(p[key])
                if "ip.dst" in k:
                    dst_ips.add(p[key])
            proto_count[proto] = proto_count.get(proto, 0) + 1

        return {
            "unique_src_ips": list(src_ips),
            "unique_dst_ips": list(dst_ips),
            "http_requests": http_reqs,
            "http_responses": http_resps,
            "tls_handshakes": tls_count,
            "protocols": dict(sorted(proto_count.items(), key=lambda x: -x[1])[:15]),
        }
