"""产品/CMS 版本指纹 + 已知漏洞映射。

无损探测 (只 GET 公开路径, 不触发漏洞) 识别常见 SRC 目标产品与精确版本,
并映射已知 CVE。支持 74cms (原专项) + SPIP/Cal.com/Odoo/Matomo/Jitsi/
Plesk/FileBrowser/Nextcloud/WordPress/phpMyAdmin。

    from tools.cms_fingerprint import fingerprint
    r = fingerprint("http://target/")
    # -> {cms, version, confidence, matched_vulns[], signals{}}
"""
import json
import os
import re
from typing import Dict, List, Optional

import requests

from tools._session import make_session
from tools.log_utils import get_logger

logger = get_logger("cms_fingerprint")

_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cms_vulns.json")
_DB = None


def _load_db() -> Dict:
    global _DB
    if _DB is None:
        try:
            with open(_DB_PATH, encoding="utf-8") as f:
                _DB = json.load(f)
        except Exception:
            _DB = {}
    return _DB


# ---------------------------------------------------------------------------
# Generic product fingerprints. Each entry:
#   name, paths (probe -> accepted statuses), body_regex, version_regex,
#   vulns (list of {cve, title}).
# ---------------------------------------------------------------------------
_PRODUCTS: List[Dict] = [
    {
        "name": "SPIP",
        "paths": [("/spip.php", (200, 302)), ("/spip.php?page=login", (200, 302))],
        "body_regex": re.compile(r"SPIP[^0-9]*([0-9.]+)", re.I),
        "version_regex": r"SPIP[^0-9]*([0-9.]+)",
        "vulns": [
            {"cve": "CVE-2023-27372", "title": "SPIP RCE (未授权, /spip.php _oups/filtre), <4.2.9/4.1.12/3.2.18 受影响"},
            {"cve": "CVE-2019-19831", "title": "SPIP 反序列化 RCE (未授权)"},
        ],
    },
    {
        "name": "Cal.com",
        "paths": [("/api/trpc/public.settings", (200,))],
        "body_regex": re.compile(r"Cal\.com|Login \| Cal", re.I),
        "version_regex": r"",
        "vulns": [
            {"cve": "N/A", "title": "Cal.com 开源预约系统: 检查 SSRF/邮件炸弹/越权 API (版本化攻击面)"},
        ],
    },
    {
        "name": "Odoo",
        "paths": [("/web/login", (200, 302)), ("/web", (200, 302))],
        "body_regex": re.compile(r"Odoo[^0-9]*([0-9.]+)", re.I),
        "version_regex": r"Odoo[^0-9]*([0-9.]+)",
        "vulns": [
            {"cve": "CVE-2024-23107", "title": "Odoo 未授权敏感数据泄露 (部分 <16.0)"},
            {"cve": "CVE-2024-33094", "title": "Odoo SQLi (部分版本)"},
        ],
    },
    {
        "name": "Matomo",
        "paths": [("/index.php?module=Login", (200, 302)), ("/matomo.js", (200,))],
        "body_regex": re.compile(r"Matomo", re.I),
        "version_regex": r"Matomo\s+([0-9]+\.[0-9]+\.[0-9]+)",
        "vulns": [
            {"cve": "CVE-2020-1147", "title": "Matomo 早期 XSS/SQLi (版本相关)"},
        ],
    },
    {
        "name": "Jitsi Meet",
        "paths": [("/config.js", (200,)), ("/lib-jitsi-meet.min.js", (200,))],
        "body_regex": re.compile(r"Jitsi Meet|interfaceConfig", re.I),
        "version_regex": r"",
        "vulns": [
            {"cve": "N/A", "title": "Jitsi Meet: 检查会议绕过/未授权房间访问"},
        ],
    },
    {
        "name": "Plesk",
        "paths": [("/login_up.php3", (200, 302))],
        "body_regex": re.compile(r"Plesk Obsidian[^0-9]*([0-9.]+)|Plesk", re.I),
        "version_regex": r"Plesk Obsidian\s*([0-9.]+)",
        "vulns": [
            {"cve": "CVE-2023-xxxx", "title": "Plesk 管理面板: 检查弱口令/已知绕过 (版本敏感)"},
        ],
    },
    {
        "name": "FileBrowser",
        "paths": [("/api/version", (200,))],
        "body_regex": re.compile(r"filebrowser|FileBrowser", re.I),
        "version_regex": r"\"version\"\s*:\s*\"?([0-9.]+)",
        "vulns": [
            {"cve": "N/A", "title": "FileBrowser 直装文件管理器: 默认口令 admin/admin 或弱口令"},
        ],
    },
    {
        "name": "Nextcloud",
        "paths": [("/status.php", (200,)), ("/ocs/v1.php/cloud/capabilities", (200, 401))],
        "body_regex": re.compile(r"Nextcloud", re.I),
        "version_regex": r"\"versionstring\"\s*:\s*\"Nextcloud ([0-9.]+)",
        "vulns": [
            {"cve": "CVE-2023-49103", "title": "Nextcloud 信息泄露 (OWA 探针)"},
        ],
    },
    {
        "name": "WordPress",
        "paths": [("/wp-login.php", (200, 302)), ("/wp-json/", (200, 403))],
        "body_regex": re.compile(r"wp-content|WordPress", re.I),
        "version_regex": r"WordPress[^0-9]*([0-9.]+)",
        "vulns": [
            {"cve": "N/A", "title": "WordPress: 检查插件/主题已知漏洞与弱口令"},
        ],
    },
    {
        "name": "phpMyAdmin",
        "paths": [],
        "body_regex": re.compile(r"phpMyAdmin", re.I),
        "version_regex": r"phpMyAdmin[^0-9]*([0-9.]+)",
        "vulns": [
            {"cve": "N/A", "title": "phpMyAdmin: 检查弱口令/未授权与已知版本漏洞"},
        ],
    },
]


def _get(base: str, path: str, sess, timeout: float):
    try:
        return sess.get(base + path, timeout=timeout, allow_redirects=True)
    except Exception:
        return None


def _probe_product(base: str, product: Dict, sess, timeout: float) -> Optional[Dict]:
    """Return {name, version, confidence, signals} if any signal hits."""
    signals = {}
    body = ""
    hit = False
    for path, statuses in product["paths"]:
        r = _get(base, path, sess, timeout)
        if r is None:
            signals[path] = "ERR"
            continue
        signals[path] = r.status_code
        if r.status_code in statuses:
            hit = True
            body = r.text or ""
            break

    if hit and product["body_regex"] and not product["body_regex"].search(body or ""):
        # Status hit but no body signature (e.g. a generic 200 from a PHP
        # front controller). Fall through to the root page before rejecting,
        # so non-specific 200 endpoints do not produce false positives.
        hit = False
        body = ""

    if not hit and product["body_regex"]:
        # Body-only detection on the root page.
        r = _get(base, "/", sess, timeout)
        if r is not None and r.status_code == 200:
            body = r.text or ""
            if product["body_regex"].search(body):
                hit = True
                signals["/"] = 200

    if not hit:
        return None

    version = ""
    if product.get("version_regex"):
        m = re.search(product["version_regex"], body or "")
        if m:
            version = m.group(1)
    confidence = 0.9 if version else 0.6
    return {"name": product["name"], "version": version,
            "confidence": confidence, "signals": signals}


# 74cms 专项 (兼容历史逻辑)
_FP_PATHS = {
    "/plus/ajax_user.php": ("v3.x", "74cms"),
    "/index/safe/index.html": ("v5.x", "74cms"),
    "/Application/": ("v4/v5", "74cms"),
    "/Application/Common/Conf/": ("v4.x", "74cms"),
    "/data/config.php": ("v4.x", "74cms"),
    "/index.php?m=&c=M&a=index&type=default": ("v4/v5", "74cms"),
    "/index.php?m=Admin&c=Login&a=index": ("v4/v5", "74cms"),
    "/install/": ("install", "74cms"),
}


def _detect_74cms(base: str, sess, timeout: float) -> Optional[Dict]:
    signals = {}
    for path in _FP_PATHS:
        r = _get(base, path, sess, timeout)
        signals[path] = None if r is None else r.status_code
    version = ""
    confidence = 0.0
    if signals.get("/plus/ajax_user.php") == 200 and not signals.get("/index/safe/index.html") == 200:
        version, confidence = "v3.x", 0.8
    elif signals.get("/index/safe/index.html") == 200:
        version, confidence = "v5.x", 0.8
    elif signals.get("/Application/Common/Conf/") in (200, 403) or \
            signals.get("/Application/") in (200, 403):
        version, confidence = "v4/v5", 0.6
    elif signals.get("/data/config.php") in (200, 403):
        version, confidence = "v4.x", 0.6
    if not confidence:
        return None
    return {"name": "74cms", "version": version, "confidence": confidence,
            "signals": {p: s for p, s in signals.items() if s is not None}}


def _match_vulns(name: str, version: str) -> List[Dict]:
    for p in _PRODUCTS:
        if p["name"] == name:
            return list(p.get("vulns", []))
    if name == "74cms":
        db = _load_db()
        cms_db = db.get("74cms", {})
        matched = []
        for k in (version, version.replace("/", ".")):
            if k in cms_db.get("versions", {}):
                matched.extend(cms_db["versions"][k].get("vulns", []))
                break
        matched.extend(cms_db.get("generic", []))
        return matched
    return []


def fingerprint(url: str, sess: Optional[requests.Session] = None,
                timeout: float = 8.0) -> Dict:
    """无损探测产品/版本 + 匹配已知漏洞。"""
    sess = sess or make_session()
    base = url.rstrip("/")
    result = {"cms": "", "version": "", "confidence": 0.0,
              "matched_vulns": [], "signals": {}}

    for product in _PRODUCTS:
        hit = _probe_product(base, product, sess, timeout)
        if hit:
            result.update(cms=hit["name"], version=hit["version"],
                          confidence=hit["confidence"], signals=hit["signals"])
            result["matched_vulns"] = _match_vulns(hit["name"], hit["version"])
            return result

    hit = _detect_74cms(base, sess, timeout)
    if hit:
        result.update(cms=hit["name"], version=hit["version"],
                      confidence=hit["confidence"], signals=hit["signals"])
        result["matched_vulns"] = _match_vulns(hit["name"], hit["version"])

    return result


def check_batch(urls: List[str], timeout: float = 8.0, max_workers: int = 10) -> List[Dict]:
    """批量指纹。"""
    import concurrent.futures
    sess_pool = [make_session() for _ in range(max_workers)]
    results = []

    def _one(iu):
        i, u = iu
        try:
            return fingerprint(u, sess=sess_pool[i % max_workers], timeout=timeout)
        except Exception as e:
            return {"cms": "", "version": "", "error": str(e)[:50]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = list(ex.map(_one, list(enumerate(urls))))
    return results
