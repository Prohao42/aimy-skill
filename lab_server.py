import re
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# 10-endpoint vulnerable lab (DVWA-style)
# /sqli_error  : error-based SQLi (MySQL)
# /sqli_bool   : boolean-blind SQLi
# /sqli_union  : union injectable, 3 cols, reflects col2, tables/cols/rows
# /xss_reflect : reflected XSS (raw echo)
# /cmdi        : command injection (id output)
# /ssti        : SSTI ({{7*7}} -> 49)
# /lfi         : LFI (etc/passwd)
# /nosql       : NoSQLi $where oracle
# /clean_sqli  : parameterized query (NOT injectable)
# /clean_xss   : HTML-escaped echo (NOT injectable)

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
        v = q.get("id", q.get("q", q.get("cmd", q.get("name", q.get("file", ["7"])))))[0]

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
                return self._send(500 if int(m.group(1)) > 3 else 200, "Unknown column 'x' in 'order clause'" if int(m.group(1)) > 3 else "<html>normal</html>")
            if "UNION SELECT NULL,NULL,NULL" in v:
                return self._send(200, "<html>normal</html>")
            if "UNION SELECT" in v:
                return self._send(500, "The used SELECT statements have a different number of columns")
            return self._send(200, "<html>page</html>")

        if p == "/xss_reflect":
            return self._send(200, "<html><body>Hello " + v + "</body></html>")

        if p == "/cmdi":
            if re.search(r"id|whoami", v):
                return self._send(200, "uid=1000(user) gid=1000(user) groups=1000(user)")
            return self._send(200, "input received")

        if p == "/ssti":
            if "7*7" in v:
                return self._send(200, "Result: 49")
            return self._send(200, "Hello")

        if p == "/lfi":
            if "etc/passwd" in v:
                return self._send(200, "root:x:0:0:root:/root:/bin/bash")
            return self._send(200, "not found")

        if p == "/nosql":
            return self._send(200, "normal")

        if p == "/clean_sqli":
            # parameterized: input is data, never SQL
            return self._send(200, "Search results for: " + v[:20])

        if p == "/clean_xss":
            # escaped output
            esc = v.replace("<", "&lt;").replace(">", "&gt;")
            return self._send(200, "<html><body>" + esc + "</body></html>")

        return self._send(200, "ok")

    def do_POST(self):
        p = urlparse(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", errors="replace")
        if p == "/nosql":
            try:
                import json
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
