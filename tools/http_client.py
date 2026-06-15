import io
import ssl
import socket
import urllib.parse
import re
import subprocess
import json
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse
from http.client import HTTPResponse

from tools.log_utils import get_logger

logger = get_logger("http_client")

_CHALLENGE_PATTERN = re.compile(
    r'toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)',
    re.DOTALL,
)
_AES_JS_CACHE: Optional[str] = None


def _get_aes_js(base_url: str) -> Optional[str]:
    global _AES_JS_CACHE
    if _AES_JS_CACHE is not None:
        return _AES_JS_CACHE
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    try:
        hc = _RawHttpClient(timeout=10)
        status, headers, body = hc.request("GET", f"{origin}/aes.js")
        if status == 200 and len(body) > 1000:
            _AES_JS_CACHE = body
            return _AES_JS_CACHE
    except Exception as e:
        logger.debug("Failed to fetch aes.js: %s", e)
    return None


def _solve_challenge(html: str, base_url: str) -> Optional[str]:
    m = _CHALLENGE_PATTERN.search(html)
    if not m:
        logger.debug("No challenge pattern found in response")
        return None
    a, b, c = m.group(1), m.group(2), m.group(3)
    aes_js = _get_aes_js(base_url)
    if not aes_js:
        logger.debug("Cannot solve challenge: aes.js not available")
        return None
    js_code = aes_js + f"""
function toNumbers(d){{var e=[];d.replace(/(..)/g,function(d){{e.push(parseInt(d,16))}});return e}}
function toHex(){{for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e='',f=0;f<d.length;f++)e+=(16>d[f]?'0':'')+d[f].toString(16);return e.toLowerCase()}}
try {{ console.log(toHex(slowAES.decrypt(toNumbers("{c}"),2,toNumbers("{a}"),toNumbers("{b}")))); }} catch(e) {{ console.error(e.message); }}
"""
    try:
        result = subprocess.run(
            ["node", "-e", js_code],
            capture_output=True, text=True, timeout=15,
        )
        cookie_val = result.stdout.strip()
        if cookie_val and len(cookie_val) == 32 and all(c in "0123456789abcdef" for c in cookie_val):
            logger.debug("Solved anti-bot challenge: __test=%s", cookie_val)
            return cookie_val
        logger.debug("Challenge solver output invalid: %s", result.stdout.strip()[:50])
    except Exception as e:
        logger.debug("Failed to solve challenge via node: %s", e)
    return None


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _RawHttpClient:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._ctx = _build_ssl_context()

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None,
                body: Optional[str] = None, cookie: Optional[str] = None) -> Tuple[int, Dict[str, str], str]:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        sock = socket.create_connection((hostname, port), timeout=self.timeout)
        if parsed.scheme == "https":
            ssock = self._ctx.wrap_socket(sock, server_hostname=hostname)
        else:
            ssock = sock

        req_headers = {
            "Host": hostname,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            req_headers.update(headers)
        if cookie:
            req_headers["Cookie"] = f"__test={cookie}"

        req_body = body or ""
        header_lines = [f"{method} {path} HTTP/1.1"]
        for k, v in req_headers.items():
            header_lines.append(f"{k}: {v}")
        header_lines.append(f"Content-Length: {len(req_body.encode())}" if req_body else "")
        header_lines.append("")
        header_lines.append(req_body)
        request_bytes = "\r\n".join(header_lines).encode()

        ssock.sendall(request_bytes)
        response_bytes = b""
        while True:
            try:
                chunk = ssock.recv(65536)
                if not chunk:
                    break
                response_bytes += chunk
            except socket.timeout:
                break
            except Exception:
                break
        ssock.close()

        # Parse HTTP response
        response_str = response_bytes.decode("utf-8", errors="replace")
        header_end = response_str.find("\r\n\r\n")
        if header_end == -1:
            return (0, {}, response_str)

        raw_headers = response_str[:header_end]
        response_body = response_str[header_end + 4:]

        header_lines = raw_headers.split("\r\n")
        status_line = header_lines[0]
        status_code = int(status_line.split(" ")[1]) if len(status_line.split(" ")) > 1 else 0

        resp_headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()

        return (status_code, resp_headers, response_body)


class HttpClient:
    def __init__(self, sess: Optional[Any] = None, timeout: float = 10.0):
        self.timeout = timeout
        self._cookie: Optional[str] = None
        self._challenge_solved = False

    def _ensure_session(self):
        if not hasattr(self, "_raw"):
            self._raw = _RawHttpClient(timeout=self.timeout)

    def _auto_solve(self, body: str, url: str) -> Optional[str]:
        if self._challenge_solved:
            return None
        if "slowAES" not in body or "toNumbers" not in body[:2000]:
            return None
        cookie_val = _solve_challenge(body, url)
        if cookie_val:
            self._cookie = cookie_val
            self._challenge_solved = True
            return cookie_val
        return None

    def request(self, method: str, url: str, **kwargs) -> "FakeResponse":
        self._ensure_session()
        headers = kwargs.pop("headers", {})
        body = kwargs.pop("data", None)

        status, resp_headers, resp_body = self._raw.request(
            method, url, headers=headers, body=body, cookie=self._cookie
        )

        if not self._challenge_solved:
            cookie_val = self._auto_solve(resp_body, url)
            if cookie_val:
                # Retry with cookie
                status, resp_headers, resp_body = self._raw.request(
                    method, url, headers=headers, body=body, cookie=self._cookie
                )

        return FakeResponse(status, resp_headers, resp_body, url)

    def get(self, url: str, **kwargs) -> "FakeResponse":
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> "FakeResponse":
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> "FakeResponse":
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> "FakeResponse":
        return self.request("DELETE", url, **kwargs)

    def resolve_url(self, base: str, path: str) -> str:
        base = base.rstrip("/")
        path = path.lstrip("/")
        return "%s/%s" % (base, path)


class FakeResponse:
    def __init__(self, status_code: int, headers: Dict[str, str], text: str, url: str):
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.url = url
        self.content = text.encode("utf-8", errors="replace")
        self.ok = 200 <= status_code < 400

    def __repr__(self):
        return f"<FakeResponse [{self.status_code}]>"


def build_url(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.ParseResult(
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ).geturl()
