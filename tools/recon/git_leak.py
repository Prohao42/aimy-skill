import re
from typing import Dict, Optional
import requests

from tools.log_utils import get_logger

logger = get_logger("recon.git_leak")

GIT_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.git/logs/HEAD",
    "/.git/objects/info/packs",
    "/.git/COMMIT_EDITMSG",
    "/.git/description",
    "/.git/index",
    "/.git/packed-refs",
    "/.gitignore",
    "/.gitattributes",
]

SENSITIVE_PATTERNS = [
    (r"password\s*=\s*.+", "password"),
    (r"secret\s*=\s*.+", "secret"),
    (r"api[_-]?key\s*=\s*.+", "API key"),
    (r"aws_access_key_id", "AWS key"),
    (r"aws_secret_access_key", "AWS secret"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"sk_live_[0-9a-zA-Z]+", "Stripe live key"),
    (r"pk_live_[0-9a-zA-Z]+", "Stripe live publishable key"),
    (r"Sensitive\s*=\s*true", "sensitive flag"),
    (r"token\s*=\s*.+", "token"),
    (r"BEGIN RSA PRIVATE KEY", "RSA private key"),
    (r"BEGIN DSA PRIVATE KEY", "DSA private key"),
    (r"BEGIN EC PRIVATE KEY", "EC private key"),
    (r"BEGIN OPENSSH PRIVATE KEY", "OpenSSH private key"),
    (r"-----BEGIN.*PRIVATE KEY-----", "private key"),
]


def _fetch_path(base_url: str, path: str, sess: requests.Session,
                timeout: float) -> Optional[Dict]:
    url = base_url.rstrip("/") + path
    try:
        r = sess.get(url, timeout=timeout)
        if r.status_code == 200 and len(r.text) > 0:
            return {"path": path, "status": r.status_code, "size": len(r.text)}
    except requests.RequestException:
        pass
    return None


def check_git_leak(url: str, sess: Optional[requests.Session] = None,
                   timeout: float = 10.0, deep: bool = False) -> Dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    result = {
        "url": url,
        "git_exposed": False,
        "accessible_paths": [],
        "sensitive_finds": [],
    }

    paths = GIT_PATHS
    if not deep:
        paths = GIT_PATHS[:3]

    for p in paths:
        info = _fetch_path(url, p, sess, timeout)
        if info:
            result["accessible_paths"].append(info)

    if result["accessible_paths"]:
        head_paths = [x for x in result["accessible_paths"]
                      if x["path"].endswith("/HEAD")]
        config_paths = [x for x in result["accessible_paths"]
                        if x["path"].endswith("/config")]

        if head_paths:
            for hp in head_paths:
                try:
                    r = sess.get(url.rstrip("/") + hp["path"], timeout=timeout)
                    if r.status_code == 200:
                        ref = r.text.strip()
                        if ref.startswith("ref:"):
                            result["git_exposed"] = True
                            result["ref"] = ref
                            if config_paths:
                                cr = sess.get(url.rstrip("/") + config_paths[0]["path"],
                                              timeout=timeout)
                                if cr.status_code == 200:
                                    for pat, name in SENSITIVE_PATTERNS:
                                        m = re.search(pat, cr.text, re.I)
                                        if m:
                                            line = m.group(0)
                                            result["sensitive_finds"].append({
                                                "type": name,
                                                "match": line[:100],
                                                "file": ".git/config",
                                            })
                except requests.RequestException:
                    pass

            for ap in result["accessible_paths"]:
                try:
                    r = sess.get(url.rstrip("/") + ap["path"], timeout=timeout)
                    if r.status_code == 200:
                        for pat, name in SENSITIVE_PATTERNS:
                            m = re.search(pat, r.text, re.I)
                            if m:
                                line = m.group(0)
                                if not any(s["match"] == line[:100] for s in result["sensitive_finds"]):
                                    result["sensitive_finds"].append({
                                        "type": name,
                                        "match": line[:100],
                                        "file": ap["path"],
                                    })
                except requests.RequestException:
                    pass

    return result
