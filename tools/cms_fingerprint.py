"""CMS 版本精确指纹 + 已知漏洞映射。

对目标做无损特征路径探测，精确识别 CMS 版本，并匹配该版本已知漏洞。
输出: {cms, version, confidence, matched_vulns[]}
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


# 无损特征路径 -> (版本标签, 系统)
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


def _get(base: str, path: str, sess, timeout: float):
    try:
        r = sess.get(base + path, timeout=timeout, allow_redirects=True)
        return r
    except Exception:
        return None


def fingerprint(url: str, sess: Optional[requests.Session] = None,
                timeout: float = 8.0) -> Dict:
    """无损探测 CMS/版本 + 匹配已知漏洞。"""
    sess = sess or make_session()
    base = url.rstrip("/")
    result = {"cms": "", "version": "", "confidence": 0.0,
              "matched_vulns": [], "signals": {}}

    signals = {}
    for path, (ver, cms) in _FP_PATHS.items():
        r = _get(base, path, sess, timeout)
        if r is None:
            signals[path] = "ERR"
            continue
        body = (r.text or "").lower()
        hit = r.status_code == 200 and len(body) > 50
        signals[path] = r.status_code
        if hit:
            result["signals"][path] = r.status_code

    # version classification
    if signals.get("/plus/ajax_user.php") == 200 and not signals.get("/index/safe/index.html") == 200:
        result["cms"], result["version"] = "74cms", "v3.x"
        result["confidence"] = 0.8
    elif signals.get("/index/safe/index.html") == 200:
        result["cms"], result["version"] = "74cms", "v5.x"
        result["confidence"] = 0.8
    elif signals.get("/Application/Common/Conf/") in (200, 403) or \
            signals.get("/Application/") in (200, 403):
        result["cms"], result["version"] = "74cms", "v4/v5"
        result["confidence"] = 0.6
    elif signals.get("/data/config.php") in (200, 403):
        result["cms"], result["version"] = "74cms", "v4.x"
        result["confidence"] = 0.6

    # match vulnerabilities from mapping db
    if result["cms"]:
        db = _load_db()
        cms_db = db.get(result["cms"], {})
        version_key = None
        for k in (result["version"], result["version"].replace("/", ".")):
            if k in cms_db.get("versions", {}):
                version_key = k
                break
        matched = []
        if version_key:
            matched.extend(cms_db["versions"][version_key].get("vulns", []))
        # add generic
        matched.extend(cms_db.get("generic", []))
        result["matched_vulns"] = matched

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
