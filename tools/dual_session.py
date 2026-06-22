from typing import Optional, Dict, List, Tuple
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.settings import settings

logger = get_logger("dual_session")


class DualSessionManager:
    def __init__(
        self,
        low_priv: Optional[requests.Session] = None,
        high_priv: Optional[requests.Session] = None,
    ):
        self.low = low_priv or requests.Session()
        self.high = high_priv

    @classmethod
    def from_credentials(
        cls,
        low_url: str,
        low_creds: Dict[str, str],
        high_url: str = "",
        high_creds: Optional[Dict[str, str]] = None,
        auth_type: str = "form",
    ) -> "DualSessionManager":
        low = requests.Session(); low.verify = settings.verify_ssl
        _do_login(low, low_url, low_creds, auth_type)
        high = None
        if high_creds:
            high = requests.Session(); high.verify = settings.verify_ssl
            _do_login(high, high_url or low_url, high_creds, auth_type)
        return cls(low, high)

    def set_high(self, sess: requests.Session):
        self.high = sess

    def test_point(
        self,
        url: str,
        param: str = "id",
        value: str = "1",
        timeout: float = 10.0,
    ) -> Dict:
        result = {
            "bola_detected": False,
            "info_disclosure": False,
            "access_control_bypass": False,
            "low_status": None,
            "high_status": None,
            "low_length": 0,
            "high_length": 0,
            "evidence": [],
        }

        try:
            low_resp = self.low.get(
                build_url(url, param, value), timeout=timeout
            )
            result["low_status"] = low_resp.status_code
            result["low_length"] = len(low_resp.text)
        except Exception as e:
            result["low_error"] = str(e)
            return result

        if self.high is None:
            return result

        try:
            high_resp = self.high.get(
                build_url(url, param, value), timeout=timeout
            )
            result["high_status"] = high_resp.status_code
            result["high_length"] = len(high_resp.text)
        except Exception as e:
            result["high_error"] = str(e)
            return result

        low_ok = result["low_status"] == 200
        high_ok = result["high_status"] == 200
        length_diff = abs(result["low_length"] - result["high_length"])

        if low_ok and high_ok:
            endpoint_context = self._guess_endpoint_context(url)
            if endpoint_context == "protected":
                result["bola_detected"] = True
                result["evidence"].append(
                    "BOLA: low_priv=%d(%dB) high_priv=%d(%dB) diff=%dB" % (
                        result["low_status"], result["low_length"],
                        result["high_status"], result["high_length"],
                        length_diff,
                    )
                )
            if length_diff < 50 and low_ok and high_ok:
                result["info_disclosure"] = True
                result["evidence"].append(
                    "info_disclosure: identical response (%dB)" % result["low_length"]
                )

        if low_ok and not high_ok:
            result["access_control_bypass"] = True
            result["evidence"].append(
                "AC_bypass: low=200 high=%d" % result["high_status"]
            )

        return result

    def test_batch(
        self,
        points: List[Dict],
        timeout: float = 10.0,
    ) -> Dict:
        bola_results = []
        info_results = []
        bypass_results = []

        for p in points:
            r = self.test_point(
                p["url"], p.get("param", "id"), "1", timeout
            )
            if r["bola_detected"]:
                bola_results.append({**p, **r})
            if r["info_disclosure"]:
                info_results.append({**p, **r})
            if r["access_control_bypass"]:
                bypass_results.append({**p, **r})

        return {
            "bola_count": len(bola_results),
            "bola_findings": bola_results,
            "info_disclosure_count": len(info_results),
            "info_disclosure_findings": info_results,
            "bypass_count": len(bypass_results),
            "bypass_findings": bypass_results,
            "tested": len(points),
        }

    @staticmethod
    def _guess_endpoint_context(url: str) -> str:
        url_lower = url.lower()
        sensitive_keywords = [
            "admin", "dashboard", "manage", "setting", "config",
            "user", "account", "profile", "private", "internal",
            "api/v1/admin", "api/v2/admin", "role", "permission",
            "secret", "token", "billing", "payment", "order",
        ]
        for kw in sensitive_keywords:
            if kw in url_lower:
                return "protected"
        return "generic"


def _do_login(
    sess: requests.Session,
    login_url: str,
    creds: Dict[str, str],
    auth_type: str = "form",
):
    try:
        if auth_type == "form":
            resp = sess.get(login_url, timeout=10)
            import re
            tokens = re.findall(
                r'<input[^>]*name=["\'](csrf_token|_token|authenticity_token)["\'][^>]*value=["\']([^"\']+)["\']',
                resp.text,
                re.I,
            )
            if tokens:
                for name, value in tokens[:1]:
                    creds = {**creds, name: value}
            sess.post(login_url, data=creds, timeout=10)
        elif auth_type == "api":
            sess.post(login_url, json=creds, timeout=10)
        elif auth_type == "basic":
            from requests.auth import HTTPBasicAuth
            sess.auth = HTTPBasicAuth(creds.get("username", ""), creds.get("password", ""))
            sess.get(login_url, timeout=10)
    except Exception as e:
        logger.warning("login to %s failed: %s", login_url, e)
