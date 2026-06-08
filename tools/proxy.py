import threading, json, time, re, base64
from typing import Dict, Optional, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

CREDENTIAL_PATTERNS = [
    (r'(?i)(password|passwd|pwd)=([^&\s"]+)', "password"),
    (r'(?i)(secret|api_key|apikey)=([^&\s"]+)', "api_key"),
    (r'(?i)authorization:\s*basic\s+([^\s\r\n]+)', "basic_auth"),
    (r'(?i)bearer\s+([a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)', "jwt"),
    (r'(?i)(token|jwt)=([^&\s"]+)', "token"),
    (r'(?i)session[_-]?id=([^&\s"]+)', "session"),
]


class ProxyHandler(BaseHTTPRequestHandler):
    req_body = b""
    resp_body = b""

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            ProxyHandler.req_body = self.rfile.read(length)
        self._handle_request("POST")

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            ProxyHandler.req_body = self.rfile.read(length)
        self._handle_request("PUT")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def do_CONNECT(self):
        self._handle_connect()

    def _handle_connect(self):
        try:
            host, port = self.path.split(":")
            self.send_response(200)
            self.end_headers()
        except:
            self.send_response(502)
            self.end_headers()

    def _handle_request(self, method: str):
        import requests
        target = self.path
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("proxy-connection", "proxy-authorization")}
        body = self.req_body or None
        try:
            resp = requests.request(method, target, headers=headers, data=body,
                                    timeout=10, verify=False)
            ProxyHandler.resp_body = resp.content
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() not in ("transfer-encoding", "content-encoding"):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.content)
        except:
            ProxyHandler.resp_body = b""
            self.send_response(502)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


class ProxyCapture:
    def __init__(self, port: int = 8080):
        self.port = port
        self.server = None
        self.thread = None
        self.running = False
        self.callbacks = []

    def start(self):
        if self.running:
            return
        ProxyHandler.req_body = b""
        ProxyHandler.resp_body = b""
        self.server = HTTPServer(("127.0.0.1", self.port), ProxyHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.running = True

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.running = False

    def extract_credentials(self) -> list:
        raw = ProxyHandler.req_body.decode("utf-8", errors="replace") + "\n"
        raw += "\n".join("%s: %s" % (k, v) for k, v in
                         [("Authorization", "Bearer X")])
        findings = []
        for pattern, label in CREDENTIAL_PATTERNS:
            for m in re.finditer(pattern, raw):
                findings.append({"type": label, "match": m.group(0)[:80],
                                 "value": m.group(2) if m.lastindex >= 2 else m.group(1)})
        return findings

    def extract_session(self) -> Dict:
        data = {"cookies": {}, "headers": {}}
        raw = ProxyHandler.req_body.decode("utf-8", errors="replace")
        for m in re.finditer(r'(?i)(session[_-]?id|token|jwt)=([^&\s"]+)', raw):
            data["cookies"][m.group(1)] = m.group(2)
        return data


def start_proxy(port: int = 8080, capture_time: int = 60) -> Dict:
    p = ProxyCapture(port)
    p.start()
    import time as _t
    _t.sleep(capture_time)
    p.stop()
    return {
        "credentials": p.extract_credentials(),
        "session": p.extract_session(),
    }
