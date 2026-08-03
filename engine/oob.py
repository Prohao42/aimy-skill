"""离线 OOB 判定：无 dnslog 时只用基线差分 + 响应控制，绝不凭「请求已发出」下结论。

原实现 (robust_verifier.verify_ssrf_oob) 在无回调时给 0.5 的「可能命中」，
这是把扫描命中当验证结果。本判定器只有在出现明确的相对差分时才给疑似，
且置信度封顶 offline_oob_ceiling；否则判定 inconclusive (不报漏洞)。
"""

from typing import Dict, List, Optional

from engine.config import DEFAULT_THRESHOLDS, Thresholds

_BLACKHOLE = "http://192.0.2.1:81/"


class OfflineOOBJudge:
    def __init__(self, thresholds: Optional[Thresholds] = None):
        self.thresholds = thresholds or DEFAULT_THRESHOLDS

    def judge(
        self,
        probes: List[Dict],
        control: Optional[Dict] = None,
    ) -> Dict:
        """probes: [{"label","responded","status","length","elapsed_ms"}...]
        control: 黑洞对照样本 (同一形状)。

        返回 {"status","confidence","evidence","note"}。
        """
        evidence: List[str] = []

        if control is not None and probes:
            open_hits = [p for p in probes if p.get("responded")]
            control_hit = control.get("responded", False)
            if open_hits and not control_hit:
                evidence.append(
                    "offline_diff: reachable probe responded while blackhole control "
                    "hung/errored"
                )
                confidence = min(
                    self.thresholds.offline_oob_ceiling,
                    0.5 + 0.05 * min(len(open_hits), 4),
                )
                status = "suspected_offline"
            elif open_hits and control_hit and any(
                p.get("length", 0) != control.get("length", -1) for p in open_hits
            ):
                evidence.append(
                    "offline_diff: probe response diverges from blackhole control"
                )
                status = "suspected_offline"
                confidence = 0.4
            else:
                status = "inconclusive"
                confidence = 0.0
                evidence.append("no differential vs blackhole control")
        elif probes:
            # 无对照样本的差分可信度不足，一律 inconclusive
            status = "inconclusive"
            confidence = 0.0
            evidence.append("no control sample: offline determination not possible")
        else:
            status = "inconclusive"
            confidence = 0.0
            evidence.append("no probes issued")

        note = {
            "suspected_offline": (
                "offline differential detected; no OOB callback. "
                "Treat as suspected, not confirmed."
            ),
            "inconclusive": "inconclusive without OOB callback.",
        }.get(status, "")

        return {
            "status": status,
            "confidence": round(confidence, 2),
            "evidence": evidence,
            "note": note,
        }

    @staticmethod
    def blackhole_control() -> str:
        """黑洞对照 URL：保留段 TEST-NET-1，正常不可达。"""
        return _BLACKHOLE
