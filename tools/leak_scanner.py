"""信息泄露专项扫描 (.git / .env / 备份文件 / Swagger / actuator 等)。

SRC 零成本出洞主力: 只 GET 常见泄露路径并匹配特征, 不触发漏洞。
命中即返回 {path, label, severity, status, snippet}, 可直接作为提交证据。

    from tools.leak_scanner import check
    r = check("http://target.com", timeout=8)
    # -> {"target", "leaks": [{path, label, severity, status, size, snippet}], "count"}
"""
import hashlib
from typing import Dict, List, Optional

import requests
import urllib3

from tools._session import make_session
from tools.log_utils import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger("leak_scanner")

# path -> (label, severity, [body markers])
LEAK_RULES: List[Dict] = [
    {"path": "/.git/config", "label": "git_config", "sev": "critical",
     "match": [b"repositoryformatversion", b"[core]", b"[remote "], "plain": True},
    {"path": "/.git/HEAD", "label": "git_head", "sev": "critical",
     "match": [b"ref: refs/"], "plain": True},
    {"path": "/.git/index", "label": "git_index", "sev": "high",
     "match": [b"DIRC"], "plain": True},
    {"path": "/.git/packed-refs", "label": "git_packed_refs", "sev": "high",
     "match": [b"ref: ", b"packed-refs"], "plain": True},
    {"path": "/.env", "label": "env", "sev": "critical",
     "match": [b"DB_PASSWORD", b"MYSQL_", b"APP_KEY", b"SECRET", b"PASSWORD=", b"ACCESS_KEY"], "plain": True},
    {"path": "/.env.bak", "label": "env_bak", "sev": "critical",
     "match": [b"DB_PASSWORD", b"MYSQL_", b"APP_KEY", b"SECRET", b"PASSWORD="], "plain": True},
    {"path": "/.env.production", "label": "env_production", "sev": "critical",
     "match": [b"DB_PASSWORD", b"MYSQL_", b"APP_KEY", b"SECRET", b"PASSWORD="], "plain": True},
    {"path": "/.svn/entries", "label": "svn_entries", "sev": "high",
     "match": [b"https://", b"file://", b"dir"], "plain": True},
    {"path": "/.svn/wc.db", "label": "svn_wc_db", "sev": "high",
     "match": [b"SQLite format 3"], "plain": True},
    {"path": "/.DS_Store", "label": "ds_store", "sev": "medium",
     "match": [b"Bud1"], "plain": True},
    {"path": "/phpinfo.php", "label": "phpinfo", "sev": "high",
     "match": [b"phpinfo()", b"PHP Version "]},
    {"path": "/swagger-ui.html", "label": "swagger_ui", "sev": "medium",
     "match": [b"Swagger UI", b"swagger-ui/dist", b"swagger-ui.css"]},
    {"path": "/swagger/index.html", "label": "swagger_ui", "sev": "medium",
     "match": [b"Swagger UI", b"swagger-ui/dist", b"swagger-ui.css"]},
    {"path": "/v2/api-docs", "label": "swagger_json", "sev": "medium",
     "match": [b'"swagger"', b'"info"', b'"paths"']},
    {"path": "/api-docs", "label": "api_docs", "sev": "medium",
     "match": [b'"openapi"', b'"paths"', b'"swagger"']},
    {"path": "/openapi.json", "label": "openapi", "sev": "medium",
     "match": [b'"openapi"', b'"paths"', b'"info"']},
    {"path": "/actuator", "label": "actuator", "sev": "medium",
     "match": [b"_links", b"health", b"status"]},
    {"path": "/actuator/env", "label": "actuator_env", "sev": "critical",
     "match": [b"propertySources", b"spring", b"servletContextInitParams"]},
    {"path": "/actuator/health", "label": "actuator_health", "sev": "low",
     "match": [b"UP", b'"status"']},
    {"path": "/server-status", "label": "server_status", "sev": "medium",
     "match": [b"Apache Server Status", b"Scoreboard", b"IdleServers"]},
    {"path": "/robots.txt", "label": "robots", "sev": "info",
     "match": [b"User-agent", b"Disallow"]},
    {"path": "/sitemap.xml", "label": "sitemap", "sev": "info",
     "match": [b"<urlset", b"<sitemapindex"]},
    {"path": "/wp-config.php.bak", "label": "wp_config_bak", "sev": "critical",
     "match": [b"DB_PASSWORD", b"DB_NAME", b"DB_USER"], "plain": True},
    {"path": "/config.php.bak", "label": "config_php_bak", "sev": "high",
     "match": [b"<?php"], "plain": True},
    {"path": "/config.json", "label": "config_json", "sev": "medium",
     "match": [b'"password"', b'"secret"', b'"api_key"', b'"token"'], "plain": True},
    {"path": "/database.yml", "label": "database_yml", "sev": "high",
     "match": [b"password"], "plain": True},
    {"path": "/backup.zip", "label": "backup_zip", "sev": "high",
     "match": [b"PK\x03\x04"], "plain": True},
    {"path": "/backup.tar.gz", "label": "backup_tar", "sev": "high",
     "match": [b"\x1f\x8b"], "plain": True},
    {"path": "/www.zip", "label": "www_zip", "sev": "high",
     "match": [b"PK\x03\x04"], "plain": True},
    {"path": "/site.zip", "label": "site_zip", "sev": "high",
     "match": [b"PK\x03\x04"], "plain": True},
    {"path": "/1.zip", "label": "root_zip", "sev": "high",
     "match": [b"PK\x03\x04"], "plain": True},
    {"path": "/index.php.bak", "label": "index_php_bak", "sev": "high",
     "match": [b"<?php"], "plain": True},
    {"path": "/.gitignore", "label": "gitignore", "sev": "low",
     "match": [b"env", b"config", b"secret"]},
    {"path": "/crossdomain.xml", "label": "crossdomain", "sev": "low",
     "match": [b"cross-domain-policy"]},
    {"path": "/.npmrc", "label": "npmrc", "sev": "high",
     "match": [b"_authToken", b"_password", b"registry"], "plain": True},
    {"path": "/server-info", "label": "server_info", "sev": "medium",
     "match": [b"Server Settings", b"Apache"]},
]


def _get(sess: requests.Session, base: str, path: str, timeout: float) -> Optional[requests.Response]:
    try:
        return sess.get(base + path, timeout=timeout, allow_redirects=False,
                        verify=False)  # nosec B501 - target TLS is out of our control
    except Exception:
        return None


def _extract_snippet(body: bytes, markers: List[bytes]) -> str:
    for m in markers:
        idx = body.find(m)
        if idx >= 0:
            return body[max(0, idx - 20): idx + 60].decode(errors="replace").strip()
    return body[:80].decode(errors="replace").strip()


def check(url: str, paths: Optional[List[str]] = None,
          sess: Optional[requests.Session] = None, timeout: float = 8.0) -> Dict:
    """Probe common leak paths on one target. Read-only, no exploitation."""
    sess = sess or make_session()
    base = url.rstrip("/")
    rules = LEAK_RULES if not paths else [
        r for r in LEAK_RULES if r["path"] in paths
    ]
    leaks = []
    catchall = 0

    # SPA catch-all detection: many apps answer every unknown path with the
    # same shell page (login SPA, error handler). If a probe returns the exact
    # same body as the root page, treat it as a catch-all, not a leak.
    baseline_hash = None
    base_r = _get(sess, base, "/", timeout)
    if base_r is not None and base_r.status_code == 200 and base_r.content:
        baseline_hash = hashlib.md5(base_r.content).hexdigest()  # nosec B324 - dedup only

    for rule in rules:
        r = _get(sess, base, rule["path"], timeout)
        if r is None or r.status_code != 200:
            continue
        markers = rule.get("match", [])
        body = r.content or b""
        if baseline_hash and hashlib.md5(body).hexdigest() == baseline_hash:  # nosec B324 - dedup only
            catchall += 1
            continue
        if rule.get("plain") and (b"<html" in body.lower() or b"<!doctype" in body.lower()):
            # Config/binary leak paths must not answer with an HTML document;
            # an HTML reply means a catch-all shell page or framework error
            # page (e.g. expecco ALM echoes a dynamic login shell for any path).
            catchall += 1
            continue
        hit = False
        if markers:
            hit = any(m in body for m in markers)
        elif body:
            hit = True
        if not hit:
            continue
        leaks.append({
            "path": rule["path"],
            "label": rule["label"],
            "severity": rule["sev"],
            "status": r.status_code,
            "size": len(body),
            "snippet": _extract_snippet(body, markers) if markers else body[:80].decode(errors="replace").strip(),
        })

    leaks.sort(key=lambda x: 0 if x["severity"] == "critical" else
               1 if x["severity"] == "high" else 2)
    return {"target": url, "leaks": leaks, "count": len(leaks),
            "catchall_skipped": catchall}
