import json, os, ssl, sys, tempfile, threading, time, uuid
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, List
from tools.log_utils import get_logger

logger = get_logger("mitm_proxy")

CAPTURED = []
CAPTURE_LOCK = threading.Lock()
MAX_CAPTURED = 10000

CA_DIR = os.path.expanduser("~/.aimy-sikll/mitm-ca")
CA_KEY = os.path.join(CA_DIR, "ca.key")
CA_CERT = os.path.join(CA_DIR, "ca.pem")
CERTS_DIR = os.path.join(CA_DIR, "certs")
CA_SUBJECT = "/C=CN/O=aimy-sikll/OU=SecurityTesting/CN=aimy MITM CA"


def _ensure_ca_dir():
    os.makedirs(CA_DIR, exist_ok=True)
    os.makedirs(CERTS_DIR, exist_ok=True)


def _openssl_available() -> bool:
    try:
        import subprocess
        r = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def generate_ca() -> bool:
    _ensure_ca_dir()
    if os.path.isfile(CA_KEY) and os.path.isfile(CA_CERT):
        return True
    if not _openssl_available():
        logger.error("openssl not found, cannot generate CA cert")
        return False
    import subprocess
    try:
        subprocess.run(
            ["openssl", "genrsa", "-out", CA_KEY, "2048"],
            check=True, capture_output=True, timeout=30
        )
        subprocess.run(
            ["openssl", "req", "-new", "-x509", "-days", "3650", "-key", CA_KEY,
             "-out", CA_CERT, "-subj", CA_SUBJECT],
            check=True, capture_output=True, timeout=30
        )
        logger.info("MITM CA generated: %s", CA_CERT)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("CA generation failed: %s", e.stderr.decode()[:200])
        return False


def _generate_host_cert(hostname: str) -> Optional[str]:
    cert_path = os.path.join(CERTS_DIR, f"{hostname}.pem")
    key_path = os.path.join(CERTS_DIR, f"{hostname}.key")
    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        return cert_path
    import subprocess
    try:
        san = f"DNS:{hostname}"
        if hostname.count(".") >= 2:
            wild = ".".join(hostname.split(".")[-2:])
            san += f",DNS:*.{wild}"
        csr_path = os.path.join(CERTS_DIR, f"{hostname}.csr")
        subprocess.run(
            ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key_path, "-out", csr_path,
             "-subj", f"/CN={hostname}"],
            check=True, capture_output=True, timeout=30
        )
        extfile = os.path.join(CERTS_DIR, f"{hostname}.ext")
        with open(extfile, "w") as f:
            f.write(f"subjectAltName={san}\n")
        subprocess.run(
            ["openssl", "x509", "-req", "-days", "365",
             "-in", csr_path, "-CA", CA_CERT, "-CAkey", CA_KEY,
             "-CAcreateserial", "-out", cert_path,
             "-extfile", extfile],
            check=True, capture_output=True, timeout=30
        )
        for tmp in [csr_path, extfile]:
            try: os.remove(tmp)
            except: pass
        return cert_path
    except subprocess.CalledProcessError as e:
        logger.debug("Cert gen failed for %s: %s", hostname, e.stderr.decode()[:100])
        return None


class _ProxyHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        host, _, port_str = self.path.partition(":")
        port = int(port_str) if port_str else 443
        tag = uuid.uuid4().hex[:6]
        logger.debug("[%s] CONNECT %s:%d", tag, host, port)

        try:
            upstream = self._connect_upstream(host, port)
        except Exception as e:
            self.send_error(502, f"Upstream connect failed: {e}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        cert_path = _generate_host_cert(host)
        if cert_path and os.path.isfile(cert_path):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert_path)
                tls = ctx.wrap_socket(self.connection, server_side=True)
                self.connection = tls
                self.rfile = tls.makefile("rb", buffering=0)
                self.wfile = tls.makefile("wb", buffering=0)
                self._proxy_http(upstream, host, tag)
                return
            except Exception as e:
                logger.debug("[%s] MITM failed for %s: %s", tag, host, e)

        self._tunnel(upstream)

    def do_GET(self):
        self._capture_http_request()

    def do_POST(self):
        self._capture_http_request()

    def do_PUT(self):
        self._capture_http_request()

    def do_DELETE(self):
        self._capture_http_request()

    def do_PATCH(self):
        self._capture_http_request()

    def do_HEAD(self):
        self._capture_http_request()

    def do_OPTIONS(self):
        self._capture_http_request()

    def _connect_upstream(self, host: str, port: int):
        import socket
        sock = socket.create_connection((host, port), timeout=15)
        if port == 443:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx.wrap_socket(sock, server_hostname=host)
        return sock

    def _tunnel(self, upstream):
        self.connection.setblocking(True)
        upstream.setblocking(True)
        import select
        socks = [self.connection, upstream]
        try:
            while True:
                r, _, _ = select.select(socks, [], [], 60)
                if not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    if s is self.connection:
                        upstream.sendall(data)
                    else:
                        self.connection.sendall(data)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try: upstream.close()
            except: pass

    def _proxy_http(self, upstream, host: str, tag: str):
        buf = b""
        try:
            while True:
                chunk = self.connection.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if b"\r\n\r\n" in buf:
                    head, rest = buf.split(b"\r\n\r\n", 1)
                    upstream.sendall(head + b"\r\n\r\n" + rest)
                    break

            if buf:
                req_line = buf.split(b"\r\n")[0].decode("utf-8", errors="replace")
                self._capture(
                    method=req_line.split()[0] if len(req_line.split()) > 0 else "UNKNOWN",
                    uri=req_line.split()[1] if len(req_line.split()) > 1 else "/",
                    host=host,
                    req_headers=self._parse_headers(buf),
                    req_body=self._extract_body(buf),
                )

            resp = b""
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                resp += chunk
                self.connection.sendall(chunk)
                if len(resp) > 1048576:
                    break

        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.debug("[%s] tunnel closed: %s", tag, e)
        finally:
            try: upstream.close()
            except: pass

    def _capture_http_request(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b""

        host = self.headers.get("Host", self.address_string())
        uri = self.path
        scheme = "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
        url = f"{scheme}://{host}{uri}"

        tag = uuid.uuid4().hex[:6]
        logger.debug("[%s] %s %s", tag, self.command, url)

        self._capture(
            method=self.command,
            uri=uri,
            host=host,
            url=url,
            req_headers=dict(self.headers),
            req_body=body.decode("utf-8", errors="replace") if body else "",
        )

        try:
            import urllib.request
            req = urllib.request.Request(
                url, data=body or None,
                headers=dict(self.headers),
                method=self.command,
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp_body)
        except Exception as e:
            self.send_error(502, str(e))

    def _capture(self, method="", uri="", host="", url="",
                 req_headers=None, req_body="",
                 resp_headers=None, resp_body="", status=0):
        global CAPTURED
        entry = {
            "ts": datetime.utcnow().isoformat(),
            "method": method,
            "uri": uri,
            "host": host,
            "url": url or f"http://{host}{uri}",
            "req_headers": req_headers or {},
            "req_body": req_body[:50000] if req_body else "",
            "resp_status": status,
            "resp_headers": resp_headers or {},
            "resp_body": resp_body[:50000] if resp_body else "",
        }
        with CAPTURE_LOCK:
            CAPTURED.append(entry)
            if len(CAPTURED) > MAX_CAPTURED:
                CAPTURED[:MAX_CAPTURED // 2] = []

    def _parse_headers(self, raw: bytes) -> Dict:
        headers = {}
        for line in raw.split(b"\r\n")[1:]:
            if not line or line == b"":
                break
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode("utf-8", errors="replace").strip()] = (
                    v.decode("utf-8", errors="replace").strip()
                )
        return headers

    def _extract_body(self, raw: bytes) -> str:
        if b"\r\n\r\n" in raw:
            body = raw.split(b"\r\n\r\n", 1)[1]
            return body.decode("utf-8", errors="replace")[:50000]
        return ""

    def log_message(self, fmt, *args):
        logger.debug("PROXY %s", fmt % args)


class MITMProxy:
    def __init__(self, port: int = 8080, host: str = "127.0.0.1",
                 threads: int = 10, auto_feed: bool = False):
        self.port = port
        self.host = host
        self.threads = threads
        self.auto_feed = auto_feed
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def ca_info(self) -> Dict:
        return {
            "available": os.path.isfile(CA_CERT) and os.path.isfile(CA_KEY),
            "ca_cert": CA_CERT,
            "ca_key": CA_KEY,
            "certs_dir": CERTS_DIR,
        }

    def install_ca_instruction(self) -> str:
        return (
            f"MITM CA cert: {CA_CERT}\n"
            "Install into your browser:\n"
            "  Firefox: Preferences → Certificates → Import\n"
            "  Chrome:  chrome://settings/security → Manage Certificates → Import\n"
            "  curl:    curl --cacert ~/.aimy-sikll/mitm-ca/ca.pem https://...\n"
        )

    def get_captured(self, clear: bool = False) -> List[Dict]:
        global CAPTURED
        with CAPTURE_LOCK:
            out = list(CAPTURED)
            if clear:
                CAPTURED.clear()
        return out

    def start(self):
        if self._server:
            logger.warning("Proxy already running on %s:%d", self.host, self.port)
            return

        generate_ca()

        class Handler(_ProxyHandler):
            pass

        self._server = HTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
            name="mitm-proxy"
        )
        self._thread.start()
        logger.info("MITM proxy listening on %s:%d", self.host, self.port)
        logger.info("CA cert: %s", CA_CERT)

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None
            self._thread = None
            logger.info("MITM proxy stopped")

    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


_GLOBAL_PROXY: Optional[MITMProxy] = None


def get_proxy() -> Optional[MITMProxy]:
    return _GLOBAL_PROXY


def start_proxy(port: int = 8080, host: str = "127.0.0.1",
                threads: int = 10) -> MITMProxy:
    global _GLOBAL_PROXY
    proxy = MITMProxy(port=port, host=host, threads=threads)
    proxy.start()
    _GLOBAL_PROXY = proxy
    return proxy


def stop_proxy():
    global _GLOBAL_PROXY
    if _GLOBAL_PROXY:
        _GLOBAL_PROXY.stop()
        _GLOBAL_PROXY = None
