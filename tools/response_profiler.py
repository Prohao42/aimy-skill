import hashlib
from typing import Optional, Dict, List
from dataclasses import dataclass, field
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url

logger = get_logger("response_profiler")

CLEAN_VALUE = "nominal_healthcheck_000"


@dataclass
class BaselineProfile:
    status: int
    length: int
    headers: Dict[str, str] = field(default_factory=dict)
    body_hash: str = ""
    content_type: str = ""
    elapsed: float = 0.0


@dataclass
class AnomalyReport:
    is_anomalous: bool = False
    reasons: List[str] = field(default_factory=list)
    delta_status: int = 0
    delta_length_pct: float = 0.0
    delta_hash: bool = False


class ResponseProfiler:
    def __init__(self):
        self._baselines: Dict[str, BaselineProfile] = {}
        self._length_tolerance_pct: float = 5.0

    def profile_endpoint(
        self,
        url: str,
        param: str,
        sess: requests.Session,
        timeout: float = 10.0,
        method: str = "GET",
        post_data: Optional[dict] = None,
    ) -> Optional[BaselineProfile]:
        key = self._key(url, param, method)
        if key in self._baselines:
            return self._baselines[key]

        try:
            import time
            start = time.time()
            if method.upper() == "POST" and post_data:
                d = post_data.copy()
                d[param] = CLEAN_VALUE
                resp = sess.post(url, data=d, timeout=timeout)
            else:
                resp = sess.get(
                    build_url(url, param, CLEAN_VALUE),
                    timeout=timeout,
                    verify=False,
                )
            elapsed = time.time() - start

            profile = BaselineProfile(
                status=resp.status_code,
                length=len(resp.text),
                headers=dict(resp.headers),
                body_hash=hashlib.md5(resp.text.encode()).hexdigest()[:16],
                content_type=resp.headers.get("Content-Type", ""),
                elapsed=elapsed,
            )
            self._baselines[key] = profile
            return profile
        except Exception as e:
            logger.debug("profile %s?%s: %s", url, param, e)
            return None

    def profile_batch(
        self,
        points: List[Dict],
        sess: requests.Session,
        timeout: float = 10.0,
    ) -> int:
        count = 0
        for p in points:
            if self.profile_endpoint(
                p["url"], p["param"], sess, timeout, p.get("method", "GET")
            ):
                count += 1
        return count

    def analyze(
        self,
        url: str,
        param: str,
        resp,
        method: str = "GET",
    ) -> AnomalyReport:
        report = AnomalyReport()
        key = self._key(url, param, method)
        baseline = self._baselines.get(key)
        if baseline is None:
            report.is_anomalous = True
            report.reasons.append("no_baseline")
            return report

        status_delta = resp.status_code - baseline.status
        if status_delta != 0:
            report.delta_status = status_delta
            report.reasons.append(f"status:{baseline.status}->{resp.status_code}")
            report.is_anomalous = True

        current_length = len(resp.text)
        if baseline.length > 0:
            delta_pct = (
                abs(current_length - baseline.length) / baseline.length * 100.0
            )
            report.delta_length_pct = round(delta_pct, 1)
            if delta_pct > self._length_tolerance_pct:
                report.reasons.append(
                    f"length:{baseline.length}->{current_length}({delta_pct:.1f}%)"
                )
                report.is_anomalous = True

        current_hash = hashlib.md5(resp.text.encode()).hexdigest()[:16]
        if current_hash != baseline.body_hash:
            report.delta_hash = True
            if not report.reasons:
                report.reasons.append("body_changed")

        return report

    def get_baseline(self, url: str, param: str, method: str = "GET") -> Optional[BaselineProfile]:
        return self._baselines.get(self._key(url, param, method))

    def reset(self):
        self._baselines.clear()

    @staticmethod
    def _key(url: str, param: str, method: str = "GET") -> str:
        return f"{method}|{url}|{param}"
