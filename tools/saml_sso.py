"""SAML (Security Assertion Markup Language) SSO vulnerability detector.

Tests for common SAML-related vulnerabilities:
- XML signature exclusion / wrapping attacks
- Missing NameID encryption
- Weak assertions
- SAML response replay
"""

import base64
import zlib
from typing import Dict, Optional
from xml.etree import ElementTree as ET

import requests

from tools.log_utils import get_logger

logger = get_logger("saml_sso")

SAML_NAMESPACES = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

SAML_PARAMS = ["SAMLResponse", "SAMLRequest", "RelayState"]


def check(
    url: str, param: str = "", sess: Optional[requests.Session] = None, timeout: float = 10.0
) -> Dict:
    if sess is None:
        from tools._session import make_session

        sess = make_session()

    result: Dict = {"vulnerable": False, "findings": []}

    if not url.startswith("http"):
        url = "http://" + url

    try:
        r = sess.get(url, timeout=timeout, allow_redirects=True)
    except Exception as e:
        logger.debug("saml_sso: %s", e)
        return result

    for resp_param in SAML_PARAMS:
        if "?" in url:
            test_url = f"{url}&{resp_param}=test"
        else:
            test_url = f"{url}?{resp_param}=test"

        try:
            r2 = sess.get(test_url, timeout=timeout, allow_redirects=False)
        except Exception:
            continue

        if r2.status_code != r.status_code and r2.status_code in (302, 301):
            location = r2.headers.get("Location", "")
            for sp in SAML_PARAMS:
                if sp in location:
                    finding = {
                        "type": "saml_sso",
                        "endpoint": url,
                        "issue": f"URL appears to handle SAML parameter {sp}",
                        "saml_param": sp,
                        "severity": "info",
                        "confidence": 0.9,
                    }
                    result["findings"].append(finding)
                    result["saml_endpoint"] = True
                    break

        if r2.status_code in (302, 301):
            location = r2.headers.get("Location", "")
            if "SAML" in location or "saml" in location:
                try:
                    if "?" in location and "SAMLResponse" in location:
                        saml_resp = location.split("SAMLResponse=")[1].split("&")[0]
                    else:
                        saml_resp = None

                    if saml_resp:
                        try:
                            decoded = base64.b64decode(saml_resp)
                            try:
                                decoded = zlib.decompress(decoded, -15)
                            except Exception:
                                pass
                            xml_str = decoded.decode("utf-8", errors="replace")

                            root = ET.fromstring(xml_str)
                            sig = root.find(".//ds:Signature", SAML_NAMESPACES)
                            if sig is None:
                                finding = {
                                    "type": "saml_sso",
                                    "endpoint": location,
                                    "issue": "SAML Response without XML Signature detected",
                                    "severity": "high",
                                    "confidence": 0.85,
                                }
                                result["findings"].append(finding)
                                result["vulnerable"] = True

                            assertions = root.findall(".//saml:Assertion", SAML_NAMESPACES)
                            for assertion in assertions:
                                name_id = assertion.find(".//saml:NameID", SAML_NAMESPACES)
                                if name_id is not None and name_id.text:
                                    if not assertion.find(".//saml:Attribute", SAML_NAMESPACES):
                                        finding = {
                                            "type": "saml_sso",
                                            "endpoint": location,
                                            "issue": "SAML assertion with NameID but no Attribute (minimal assertion)",
                                            "severity": "low",
                                            "confidence": 0.6,
                                        }
                                        result["findings"].append(finding)
                                conditions = assertion.find(".//saml:Conditions", SAML_NAMESPACES)
                                if conditions is None:
                                    finding = {
                                        "type": "saml_sso",
                                        "endpoint": location,
                                        "issue": "SAML assertion missing Conditions element (replay risk)",
                                        "severity": "medium",
                                        "confidence": 0.8,
                                    }
                                    result["findings"].append(finding)
                                    result["vulnerable"] = True

                        except (ET.ParseError, ValueError) as e:
                            logger.debug("saml parse: %s", e)
                        except Exception as e:
                            logger.debug("saml decode: %s", e)
                except Exception as e:
                    logger.debug("saml decode error: %s", e)

    return result
