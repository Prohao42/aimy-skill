import base64
import hashlib
import hmac
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# Hardened lab: 25 endpoints (DVWA-style + obfuscation/context/POST contracts)
# /sqli_error   : error-based SQLi (MySQL)
# /sqli_bool    : boolean-blind SQLi
# /sqli_union   : union injectable, 3 cols, reflects col2, tables/cols/rows
# /sqli_post    : error-based SQLi in form POST body
# /xss_reflect  : reflected XSS (raw echo)
# /xss_attr     : reflected XSS inside HTML attribute value
# /xss_js       : reflected XSS inside <script> string
# /xss_post     : reflected XSS in form POST body
# /cmdi         : command injection (id output)
# /ssti         : SSTI ({{7*7}} -> 49)
# /ssti_alt     : SSTI only for ${7*7}/#{7*7} (alt engine, {{ }} blocked)
# /lfi          : LFI (etc/passwd)
# /lfi_hardened : plain ../ filtered, only ....// or %2f encoding works
# /nosql        : NoSQLi $where oracle (JSON POST)
# /nosqli_get   : NoSQLi operator injection via GET param
# /ssrf         : server-side fetch simulation returning cloud metadata
# /jwt_weak     : JWT signed with weak secret in page body
# /deser        : PHP unserialize error on POST body
# /clean_sqli   : parameterized query (NOT injectable)
# /clean_xss    : HTML-escaped echo (NOT injectable)
# /clean_attr   : attribute context but escaped (NOT injectable)
# /clean_ssti   : literal echo, never evaluates (NOT injectable)
# /clean_ssrf   : fetch failures only (NOT SSRF)
# /jwt_clean    : JWT signed with a strong secret (NOT vulnerable)
# /clean_deser  : normal response for serialized payloads (NOT vulnerable)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_token(secret: str) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"sub": "admin", "role": "admin"}).encode())
    signature = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return "%s.%s.%s" % (header, payload, _b64(signature))


class H(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query)
        v = q.get(
            "id", q.get("q", q.get("cmd", q.get("name", q.get("file", q.get("url", ["7"])))))
        )[0]

        if p == "/sqli_error":
            if "'" in v:
                return self._send(500, "You have an error in your SQL syntax near '' at line 1")
            if "EXTRACTVALUE" in v:
                return self._send(500, "XPATH syntax error: '~root@localhost'")
            return self._send(200, "Product page")

        if p == "/sqli_bool":
            if re.search(r"1\s*=\s*2|'2'", v):
                return self._send(200, "<html>No products found</html>")
            return self._send(200, "<html>" + "x" * 300 + "Product 7</html>")

        if p == "/sqli_union":
            if "RFLCT_" in v:
                m = re.search(r"'RFLCT_(\d+)'", v)
                return self._send(200, "<html>RFLCT_%s</html>" % m.group(1))
            if "GROUP_CONCAT(COLUMN_NAME)" in v:
                return self._send(200, "<html>id,username,password</html>")
            if "CONCAT_WS" in v:
                return self._send(200, "<html>1|admin|s3cret</html>")
            if "GROUP_CONCAT(TABLE_NAME)" in v:
                return self._send(200, "<html>users,orders</html>")
            if "DATABASE()" in v:
                return self._send(200, "<html>shopdb</html>")
            m = re.search(r"ORDER BY (\d+)", v)
            if m:
                return self._send(
                    500 if int(m.group(1)) > 3 else 200,
                    "Unknown column 'x' in 'order clause'"
                    if int(m.group(1)) > 3
                    else "<html>normal</html>",
                )
            if "UNION SELECT NULL,NULL,NULL" in v:
                return self._send(200, "<html>normal</html>")
            if "UNION SELECT" in v:
                return self._send(
                    500, "The used SELECT statements have a different number of columns"
                )
            return self._send(200, "<html>page</html>")

        if p == "/xss_reflect":
            return self._send(200, "<html><body>Hello " + v + "</body></html>")

        if p == "/xss_attr":
            return self._send(200, '<html><input value="' + v + '"></html>')

        if p == "/xss_js":
            return self._send(200, "<html><script>var a='" + v + "';</script></html>")

        if p == "/cmdi":
            if re.search(r"id|whoami", v):
                return self._send(200, "uid=1000(user) gid=1000(user) groups=1000(user)")
            return self._send(200, "input received")

        if p == "/ssti":
            if "7*7" in v:
                return self._send(200, "Result: 49")
            return self._send(200, "Hello")

        if p == "/ssti_alt":
            if "${7*7}" in v or "#{7*7}" in v:
                return self._send(200, "Result: 49")
            if "{{" in v:
                return self._send(200, "blocked")
            return self._send(200, "Hello")

        if p == "/lfi":
            if "etc/passwd" in v:
                return self._send(200, "root:x:0:0:root:/root:/bin/bash")
            return self._send(200, "not found")

        if p == "/lfi_hardened":
            raw_q = urlparse(self.path).query.lower()
            encoded = "%2f" in raw_q or "%252f" in raw_q
            if "etc/passwd" in v and ("....//" in v or encoded):
                return self._send(200, "root:x:0:0:root:/root:/bin/bash")
            return self._send(200, "not found")

        if p == "/nosql":
            return self._send(200, "normal")

        if p == "/nosqli_get":
            if "$ne" in v or "$gt" in v or "$regex" in v:
                return self._send(200, "x" * 120 + "operator-bypass")
            return self._send(200, "x")

        if p == "/ssrf":
            if any(
                marker in v
                for marker in ("169.254.169.254", "metadata.google.internal", "etc/passwd")
            ):
                return self._send(200, "ami-id: ami-0123456789abcdef0\ninstance-id: i-lab")
            return self._send(200, "fetch failed: connection refused")

        if p == "/clean_ssrf":
            return self._send(200, "fetch failed: connection refused")

        if p == "/jwt_weak":
            return self._send(200, json.dumps({"token": _jwt_token("secret")}))

        if p == "/jwt_clean":
            return self._send(
                200, json.dumps({"token": _jwt_token("v3ry-strong-lab-secret-not-guessable")})
            )

        if p == "/clean_sqli":
            # parameterized: input is data, never SQL
            return self._send(200, "Search results for: " + v[:20])

        if p == "/clean_xss":
            # escaped output
            esc = v.replace("<", "&lt;").replace(">", "&gt;")
            return self._send(200, "<html><body>" + esc + "</body></html>")

        if p == "/clean_attr":
            esc = (
                v.replace("&", "&amp;")
                .replace('"', "&quot;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            return self._send(200, '<html><input value="' + esc + '"></html>')

        if p == "/clean_ssti":
            return self._send(200, "Literal template text: " + v[:40])

        return self._send(200, "ok")

    def do_POST(self):
        p = urlparse(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode(
            "utf-8", errors="replace"
        )

        if p == "/sqli_post":
            q = parse_qs(body)
            v = q.get("id", [""])[0]
            if "'" in v:
                return self._send(500, "You have an error in your SQL syntax near '' at line 1")
            return self._send(200, "Product page")

        if p == "/xss_post":
            q = parse_qs(body)
            v = q.get("q", [""])[0]
            return self._send(200, "<html><body>Hello " + v + "</body></html>")

        if p == "/deser":
            values = " ".join(value for values in parse_qs(body).values() for value in values)
            if "O:" in values or "a:1:" in values:
                return self._send(
                    500,
                    "PHP Fatal error: Uncaught Error: "
                    "unserialize(): Error at offset 0; __PHP_Incomplete_Class",
                )
            return self._send(200, "ok")

        if p == "/clean_deser":
            return self._send(200, "ok")

        if p == "/nosql":
            try:
                payload = json.loads(body or "{}").get("id", {})
            except Exception:
                payload = {}
            if isinstance(payload, dict) and "$where" in payload:
                cond = payload["$where"]
                if cond == "true":
                    return self._send(200, "x" * 100 + "row")
                if cond == "false":
                    return self._send(200, "x")
                mm = re.search(r"charCodeAt\((\d+)\)>(\d+)", cond)
                if mm:
                    pos, gt = int(mm.group(1)), int(mm.group(2))
                    ch = ord("admin"[pos]) if pos < len("admin") else 0
                    if ch > gt:
                        return self._send(200, "x" * 100 + "row")
                return self._send(200, "x")
            return self._send(200, "x" * 100 + "json-op")
        return self._send(200, "ok")

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", 18774), H).serve_forever()
