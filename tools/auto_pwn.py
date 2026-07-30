import time
from typing import Dict, List

from tools._enrich import deep_check, enrich_generic, enrich_sqli, enrich_ssrf, enrich_xss
from tools.attack_surface import rank_attack_paths, visualize_attack_paths
from tools.chain_engine import ChainEngine
from tools.internal_scan import full_network_scan
from tools.log_utils import get_logger
from tools.orchestrator import Orchestrator
from tools.reasoning_engine import Hypothesis, ReasoningEngine

logger = get_logger("auto_pwn")


class Belief:
    belief: float
    evidence_for: List[str]
    evidence_against: List[str]

    def __init__(self, initial: float = 0.5):
        self.belief = initial
        self.evidence_for = []
        self.evidence_against = []

    def update(self, result: Dict, weight: float = 0.3):
        if result.get("success") or result.get("vulnerable"):
            self.belief = min(self.belief + weight * (1 - self.belief), 0.99)
            self.evidence_for.append(result.get("evidence", str(result))[:80])
        else:
            self.belief = self.belief * (1 - weight * 0.5)
            self.evidence_against.append("no result")

    def __repr__(self):
        return f"Belief({self.belief:.2f})"


class HypothesisDrivenAgent:
    def __init__(self, target: str, sess, timeout: float = 10.0):
        self.target = target
        self.sess = sess
        self.timeout = timeout
        self.reasoner = ReasoningEngine(target)
        self.chain_engine = ChainEngine(sess, timeout)
        self.beliefs: Dict[str, Belief] = {}
        self.attack_history: List[Dict] = []
        self._iteration = 0

    def gather_intel(self) -> Dict:
        logger.info("[AutoPwn] Phase 1: Intelligence gathering")
        intel = {"target": self.target, "techs": [], "ports": [], "attack_paths": []}
        try:
            orch = Orchestrator(self.target, self.sess, self.timeout, fast_recon=True)
            orch.init_storage()
            recon = orch.phase_recon()
            intel["techs"] = recon.get("technologies", {}).get("technologies", [])
            intel["ports"] = recon.get("open_ports", {}).get("open_ports", [])
            intel["git"] = recon.get("git_leak", {})
            intel["dirs"] = recon.get("directories", {}).get("interesting", [])
        except Exception as e:
            logger.debug("intel gather: %s", e)
        try:
            internal = full_network_scan()
            intel["internal_scan"] = internal
        except Exception as e:
            logger.debug("internal scan: %s", e)
        intel["attack_paths"] = rank_attack_paths(
            intel["techs"], intel["ports"], intel.get("git"))
        return intel

    def form_hypotheses(self, intel: Dict) -> List[Hypothesis]:
        logger.info("[AutoPwn] Phase 2: Forming hypotheses (%d paths available)",
                    len(intel.get("attack_paths", [])))
        context = {
            "technologies": intel.get("techs", []),
            "open_ports": intel.get("ports", []),
            "directories": [{"path": d} for d in intel.get("dirs", [])],
            "git_leak": intel.get("git", {}),
            "vulnerabilities": [],
            "attack_plan": {},
            "crawl_endpoints": {},
        }
        hypotheses = self.reasoner.analyze(context)
        for path in intel.get("attack_paths", [])[:10]:
            if path["type"] == "cve":
                hypotheses.append(Hypothesis(
                    vuln_type=path["impact"].lower(),
                    confidence=min(path["score"] / 10, 0.95),
                    evidence=[f"{path['cve']}: {path['name']}"],
                    priority=0,
                    detail=path,
                ))
        if intel.get("internal_scan", {}).get("total_alive", 0) > 1:
            hypotheses.append(Hypothesis(
                vuln_type="internal_pivot",
                confidence=0.7,
                evidence=[f"{intel['internal_scan']['total_alive']} hosts discovered"],
                priority=1,
            ))
        hypotheses.sort(key=lambda h: (h.priority, -h.confidence))
        return hypotheses

    def execute_hypothesis(self, h: Hypothesis) -> Dict:
        logger.info("[AutoPwn] Testing: %s (confidence=%.2f, priority=%d)",
                    h.vuln_type, h.confidence, h.priority)
        result = {"hypothesis": h.vuln_type, "success": False, "detail": {}}
        vt = h.vuln_type

        if vt == "internal_pivot":
            scan = self.sess.get(f"{self.target}/internal_status", timeout=5)
            result["success"] = scan.status_code == 200
            result["detail"] = {"status": scan.status_code}
            return result

        if h.detail.get("type") == "cve":
            exploit_type = h.detail.get("exploit_type", "")
            if exploit_type in ("http_get", "http_post_xml"):
                try:
                    if exploit_type == "http_get":
                        r = self.sess.get(self.target, timeout=self.timeout)
                    else:
                        r = self.sess.post(self.target,
                                           data="""<?xml version="1.0" encoding="UTF-8"?><root><test/></root>""",
                                           timeout=self.timeout)
                    result["success"] = r.status_code not in (403, 404, 500)
                    result["detail"] = {"status": r.status_code, "cve": h.detail.get("cve")}
                except Exception as e:
                    result["detail"] = {"error": str(e)}
                return result

        param = h.param or "id"
        try:
            if vt in ("sql_injection", "sqli"):
                from tools.sql_injection import check as sqli
                result = deep_check(sqli, self.target, param, self.sess, self.timeout, "sqli")
                result = enrich_sqli(result, self.target, param)
            elif vt == "ssrf":
                from tools.ssrf_detector import check as ssrf
                result = ssrf(self.target, param, self.sess, self.timeout)
                result = enrich_ssrf(result, self.target, param)
            elif vt in ("lfi", "path_traversal"):
                from tools.lfi_scanner import check as lfi
                result = lfi(self.target, param, self.sess, self.timeout)
                result = enrich_generic(result, self.target, param, detector_type="lfi")
            elif vt in ("rce", "cmdi"):
                from tools.cmdi_detector import check as cmdi
                result = cmdi(self.target, param, self.sess, self.timeout)
                result = enrich_generic(result, self.target, param, detector_type="cmdi")
            elif vt == "ssti":
                from tools.ssti_detector import check as ssti
                result = ssti(self.target, param, self.sess, self.timeout)
                result = enrich_generic(result, self.target, param, detector_type="ssti")
            elif vt == "xss":
                from tools.xss_detector import check as xss
                result = xss(self.target, param, self.sess, self.timeout)
                result = enrich_xss(result, self.target, param)
            elif vt in ("auth_bypass", "auth-bypass"):
                from tools.auth_bypass import check as auth
                result = auth(self.target, self.sess, self.timeout)
                result = enrich_generic(result, detector_type="auth")
            elif vt == "jwt":
                from tools.jwt_detector import check as jwt
                result = jwt(self.target, param, self.sess, self.timeout)
                result = enrich_generic(result, self.target, param, detector_type="jwt")
            elif vt == "deser":
                from tools.deserialization_detector import check as deser
                result = deser(self.target, param, self.sess, self.timeout)
                result = enrich_generic(result, self.target, param, detector_type="deser")
            elif vt == "xxe":
                from tools.xxe_detector import check as xxe
                result = xxe(self.target, param, sess=self.sess, timeout=self.timeout)
                result = enrich_generic(result, self.target, param, detector_type="xxe")
            else:
                result = {"vulnerable": False, "note": f"no handler for {vt}"}
        except Exception as e:
            result = {"vulnerable": False, "error": str(e)}

        return result

    def learn(self, hypothesis: Hypothesis, result: Dict):
        vt = hypothesis.vuln_type
        if vt not in self.beliefs:
            self.beliefs[vt] = Belief(initial=hypothesis.confidence)
        self.beliefs[vt].update(result)
        self.attack_history.append({
            "timestamp": time.time(),
            "hypothesis": vt,
            "confidence": hypothesis.confidence,
            "result": result.get("vulnerable", False),
            "detail": result.get("evidence", str(result)[:100]),
        })
        if result.get("vulnerable") or result.get("success"):
            logger.info("[AutoPwn] ** CONFIRMED: %s (belief=%.2f) **",
                        vt, self.beliefs[vt].belief)

    def should_continue(self, max_iterations: int = 30) -> bool:
        if self._iteration >= max_iterations:
            return False
        recent = self.attack_history[-5:] if len(self.attack_history) >= 5 else self.attack_history
        any_new = any(r["result"] for r in recent)
        if not any_new and len(self.attack_history) > 10:
            return False
        return True

    def run(self, max_iterations: int = 30) -> Dict:
        logger.info("=" * 60)
        logger.info("[AutoPwn] Autonomous attack loop started on %s", self.target)
        logger.info("=" * 60)

        intel = self.gather_intel()
        logger.info("\n%s", visualize_attack_paths(intel.get("attack_paths", [])))

        hypotheses = self.form_hypotheses(intel)
        while self._iteration < max_iterations and hypotheses:
            self._iteration += 1
            best = hypotheses.pop(0)
            result = self.execute_hypothesis(best)
            self.learn(best, result)
            if result.get("vulnerable") or result.get("success"):
                chain = self.chain_engine.auto_compose({
                    f"finding_{self._iteration}": {
                        "type": best.vuln_type,
                        "url": self.target,
                        "param": best.param or "id",
                        "evidence": result.get("evidence", []),
                    }
                })
                if chain:
                    logger.info("[AutoPwn] Chain triggered: %s", chain[0]["chain"])
                    for entry in chain:
                        chain_fn = self.chain_engine._chain_map().get(entry["chain"])
                        if chain_fn:
                            try:
                                chain_fn(self.target, entry.get("param", "id"))
                            except Exception:
                                pass
                hypotheses = self.form_hypotheses(intel)
                hypotheses.sort(key=lambda h: (h.priority, -h.confidence))
            if not self.should_continue(max_iterations):
                break

        summary = {
            "target": self.target,
            "iterations": self._iteration,
            "hypotheses_tested": len(self.attack_history),
            "confirmed": [h for h in self.attack_history if h["result"]],
            "beliefs": {k: round(v.belief, 2) for k, v in self.beliefs.items()},
            "history": self.attack_history[-20:],
        }
        confirmed = len(summary["confirmed"])
        logger.info("[AutoPwn] Done. %d/%d hypotheses confirmed, %d iterations",
                    confirmed, summary["hypotheses_tested"], self._iteration)
        return summary


def auto_pwn(target: str, sess=None, timeout: float = 10.0,
             max_iterations: int = 30) -> Dict:
    import requests
    sess = sess or requests.Session()
    agent = HypothesisDrivenAgent(target, sess, timeout)
    return agent.run(max_iterations=max_iterations)
