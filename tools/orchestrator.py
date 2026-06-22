import json, time, sys, os, threading, concurrent.futures
from typing import Dict, List, Optional, Tuple

from tools.log_utils import get_logger

logger = get_logger("orchestrator")

from tools import crawler, param_miner
from tools import sql_injection, xss_detector, ssti_detector, cmdi_detector
from tools import ssrf_detector, nosqli_detector, lfi_scanner, auth_bypass
from tools import sqli_weaponizer, jwt_exploiter, ssrf_pwn as ssrf_lateral
from tools import sqli_blind, sqli_oob, reverse_shell
from tools import race_condition
from tools import jwt_detector, graphql_scanner, cors_scanner
from tools import deserialization_detector, proto_pollution
from tools import waf_bypass, biz_logic_scanner
from tools.oob_server import OOBServer
from tools.response_profiler import ResponseProfiler
from tools.verification_oracle import VerificationOracle
from tools.dual_session import DualSessionManager
from tools.playwright_engine import PlaywrightEngine
from tools.spa_crawler import crawl_spa

SKIP_PARAMS = {"submit", "button", "reset", "image", "file", "action",
               "_method", "_token", "utf8", "commit", "form_id", "form_build_id",
               "form_token", "authenticity_token"}

SIGNATURE_PLACEHOLDER = "__placeholder__"


class Orchestrator:
    def __init__(self, target: str,
                 sess: Optional['requests.Session'] = None, timeout: float = 10.0,
                 threads: int = 10, max_pages: int = 30, max_depth: int = 2,
                 high_priv_sess: Optional['requests.Session'] = None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.sess = sess
        self.high_priv_sess = high_priv_sess
        self.threads = threads
        self.max_pages = max_pages
        self.max_depth = max_depth
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

        return points[:250]

    def _test_single_point(self, point: Dict, waf_name: Optional[str] = None,
                           oob_url: Optional[str] = None,
                           oob_domain: Optional[str] = None) -> List[Dict]:
        url = point["url"]
        param = point["param"]
        sess = self.sess
        results = []

        oob_kw = {}
        if oob_url:
            oob_kw["oob_url"] = oob_url
        if oob_domain:
            oob_kw["oob_domain"] = oob_domain

        detectors = [
            ("sqli", lambda u, p, s, t: sql_injection.check(u, p, s, t, waf_name=waf_name)),
            ("xss", lambda u, p, s, t: xss_detector.check(u, p, s, t, waf_name=waf_name)),
            ("ssti", lambda u, p, s, t: ssti_detector.check(u, p, s, t, waf_name=waf_name)),
            ("cmdi", lambda u, p, s, t: cmdi_detector.check(u, p, s, t, waf_name=waf_name, **oob_kw)),
            ("ssrf", lambda u, p, s, t: ssrf_detector.check(u, p, s, t, oob_server=oob_url)),
            ("nosqli", lambda u, p, s, t: nosqli_detector.check(u, p, s, t, waf_name=waf_name)),
            ("lfi", lambda u, p, s, t: lfi_scanner.check(u, p, s, t, waf_name=waf_name)),
            ("race", lambda u, p, s, t: race_condition.check(u, p, s, t)),
            ("jwt", lambda u, p, s, t: jwt_detector.check(u, p, s, t)),
            ("graphql", lambda u, p, s, t: graphql_scanner.check(u, p, s, t)),
            ("cors", lambda u, p, s, t: cors_scanner.check(u, p, s, t)),
            ("deser", lambda u, p, s, t: deserialization_detector.check(u, p, s, t)),
            ("proto_pollution", lambda u, p, s, t: proto_pollution.check(u, p, s, t)),
            ("bizlogic", lambda u, p, s, t: biz_logic_scanner.check(u, p, s, t)),
            ("waf_heavy", lambda u, p, s, t: waf_bypass.heavy_check(u, p, s, t)),
        ]

        for vtype, fn in detectors:
            try:
                r = fn(url, param, sess, self.timeout)
                if isinstance(r, dict):
                    vuln = r.get("vulnerable") or r.get("total_bypasses", 0) > 0
                    if vuln:
                        verified = self.oracle.verify(
                            vtype, r, url, param, sess, self.timeout
                        )
                        if verified.get("verified") is False:
                            continue
                        results.append({
                            "type": vtype,
                            "url": url,
                            "param": param,
                            "result": verified,
                        })
            except Exception as e:
                logger.debug("detect %s on %s?%s: %s", vtype, url, param, e)
        return results

    def phase_auth_bypass(self) -> Dict:
        result = auth_bypass.check(self.target, self.sess, self.timeout)
        self.state["phases"]["auth_bypass"] = result
        return result

    def phase_detect(self) -> Dict:
        sess = self.sess
        waf_info = waf_bypass.fingerprint_waf(self.target, sess, self.timeout)
        waf_name = waf_info.get("name")
        if waf_name:
            print("  [WAF] %s detected - using bypass strategies" % waf_name)
        self.state["waf"] = waf_info

        points = self._build_test_points()
        print("  -> %d test points across 15 detectors" % (len(points)))

        cb_id = "scan_%d" % id(self)
        oob_url = self.oob_server.register_callback_id(cb_id)
        oob_domain = None
        if self.oob_server.start_dns():
            oob_domain = self.oob_server.start_dns()

        profiled = self.profiler.profile_batch(points, sess, self.timeout)
        if profiled:
            print("  -> %d endpoints profiled for anomaly detection" % profiled)

        all_findings = {}
        lock = threading.Lock()
        done = [0]
        total = len(points)

        def worker(point):
            findings = self._test_single_point(
                point, waf_name, oob_url=oob_url, oob_domain=oob_domain
            )
            with lock:
                for f in findings:
                    key = "%s|%s|%s" % (f["type"], f["url"], f["param"])
                    all_findings[key] = f
                done[0] += 1
                if done[0] % 5 == 0 or done[0] == total:
                    print("    \r    progress: %d/%d (found %d)" % (
                        done[0], total, len(all_findings)), end="", flush=True)

        if self.threads > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                list(ex.map(worker, points))
        else:
            for p in points:
                worker(p)
        print()

        jwt_key = "jwt|%s|%s" % (self.target, SIGNATURE_PLACEHOLDER)
        jwt_finding = all_findings.get(jwt_key)
        if jwt_finding:
            jwt_hint = jwt_finding.get("result", {}).get("tokens_found", [])
            if jwt_hint:
                print("  [*] JWT tokens found -> running automatic exploit chain")

        oob_callbacks = self.oob_server.pop_callbacks(cb_id)
        oob_hits = len(oob_callbacks)
        if oob_hits:
            print("  [OOB] %d blind callbacks received" % oob_hits)
            all_findings["__oob_callbacks__"] = {
                "type": "oob",
                "url": self.target,
                "param": "",
                "result": {
                    "vulnerable": True,
                    "type": "oob_callback",
                    "confidence": "high",
                    "confirmed": True,
                    "evidence": ["%d OOB callbacks" % oob_hits],
                    "callbacks": [
                        {"path": c.path, "client": str(c.client)}
                        for c in oob_callbacks[:10]
                    ],
                },
            }

        self.state["phases"]["detect"] = {
            "test_points": total,
            "findings": all_findings,
        }

        self._run_kali_recon()

        return all_findings

    def _run_kali_recon(self):
        from tools.kali_executor import is_available
        if not is_available():
            return

        print("  [Kali] Running heavy recon tools...")

        from tools import kali_toolset

        tech_result = kali_toolset.whatweb_identify(self.target)
        if tech_result.get("technologies"):
            print("  [Kali] whatweb: %d technologies detected" % len(tech_result["technologies"]))
            self.state["technologies"] = tech_result["technologies"]

        nmap_result = kali_toolset.nmap_scan(self.target, fast=True)
        if nmap_result.get("ports"):
            print("  [Kali] nmap: %d open ports found" % nmap_result["count"])
            self.state["open_ports"] = nmap_result["ports"]

        nuclei_result = kali_toolset.nuclei_scan(self.target)
        if nuclei_result.get("findings"):
            print("  [Kali] nuclei: %d template matches" % nuclei_result["count"])
            existing = self.state["phases"].get("detect", {}).get("findings", {})
            for f in nuclei_result["findings"]:
                key = "nuclei|%s|%s" % (f.get("template", ""), self.target)
                existing[key] = {
                    "type": "nuclei",
                    "url": self.target,
                    "param": "",
                    "result": {"vulnerable": True, "template": f},
                }
            self.state["nuclei_findings"] = nuclei_result["findings"]

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
            bola_key = "bola|%s" % self.target
            findings = self.state["phases"].get("detect", {}).get("findings", {})
            for f in result.get("bola_findings", []):
                key = "bola|%s|%s" % (f.get("url", ""), f.get("param", "id"))
                findings[key] = {
                    "type": "bola",
                    "url": f.get("url", ""),
                    "param": f.get("param", "id"),
                    "result": {
                        "vulnerable": True,
                        "type": "bola",
                        "confidence": "high",
                        "evidence": f.get("evidence", []),
                    },
                }
            for f in result.get("info_disclosure_findings", []):
                key = "info_disclosure|%s|%s" % (f.get("url", ""), f.get("param", "id"))
                findings[key] = {
                    "type": "info_disclosure",
                    "url": f.get("url", ""),
                    "param": f.get("param", "id"),
                    "result": {
                        "vulnerable": True,
                        "type": "info_disclosure",
                        "confidence": "high",
                        "evidence": f.get("evidence", []),
                    },
                }
        self.state["phases"]["dual_session"] = result
        return result

    def phase_weaponize(self) -> Dict:
        findings = self.state["phases"].get("detect", {}).get("findings", {})
        jwt_result = self.state["phases"].get("auth_bypass", {})
        exploits = {}
        raw_sess = self.sess

        def _weaponize_one(key, finding):
            vtype = finding["type"]
            url = finding["url"]
            param = finding["param"]
            result = {}

            if vtype == "sqli":
                for mod_name, mod in [("sqli_weaponizer", sqli_weaponizer),
                                       ("sqli_blind", sqli_blind),
                                       ("sqli_oob", sqli_oob)]:
                    try:
                        if mod_name == "sqli_oob":
                            result[mod_name] = mod.check(url, param, "oob.local", raw_sess, self.timeout)
                        else:
                            result[mod_name] = mod.check(url, param, raw_sess, self.timeout)
                    except Exception as e:
                        logger.debug("sqli weaponize %s: %s", mod_name, e)
                    if result.get(mod_name, {}).get("vulnerable") or \
                       result.get(mod_name, {}).get("data_extracted"):
                        result["exploit_ready"] = True

                from tools.kali_executor import is_available as kali_avail
                if kali_avail():
                    try:
                        dbms = result.get("sqli_blind", {}).get("dbms") or \
                               result.get("sqli_weaponizer", {}).get("dbms")
                        sqlmap_r = kali_toolset.sqlmap_detect(url, param, dbms=dbms)
                        if sqlmap_r.get("vulnerable") or sqlmap_r.get("data"):
                            result["sqlmap"] = sqlmap_r
                            result["exploit_ready"] = True
                            if sqlmap_r.get("data"):
                                result["extracted_data"] = sqlmap_r["data"]
                    except Exception as e:
                        logger.debug("sqlmap weaponize: %s", e)

            if vtype == "ssrf":
                try:
                    result["ssrf_lateral"] = ssrf_lateral.run(url, param, sess=raw_sess, timeout=self.timeout)
                    result["ssrf_pwn"] = ssrf_lateral.check(url, param, sess=raw_sess, timeout=self.timeout)
                except Exception as e:
                    logger.debug("ssrf weaponize: %s", e)

            if vtype == "lfi":
                v = finding.get("result", {})
                if v.get("rce_available"):
                    try:
                        result["rce"] = True
                    except Exception as e:
                        logger.debug("lfi rce: %s", e)

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
                            jwt_r = jwt_exploiter.check(token=token_str, sess=raw_sess, url=url,
                                                        param=param, timeout=self.timeout)
                            result["jwt_exploit"] = jwt_r
                        except Exception as e:
                            logger.debug("jwt exploit: %s", e)
                if not result:
                    try:
                        none_token = jwt_exploiter.check(
                            token=None, sess=raw_sess, url=url, param=param, timeout=self.timeout)
                        result["jwt_none_test"] = none_token
                    except Exception as e:
                        logger.debug("jwt none test: %s", e)

            if result:
                return key, result
            return None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(_weaponize_one, k, f): k for k, f in findings.items()}
            for future in concurrent.futures.as_completed(futures):
                k, r = future.result()
                if k and r:
                    exploits[k] = r

        auth_findings = jwt_result.get("path_bypasses", []) + \
                        jwt_result.get("cookie_bypasses", []) + \
                        jwt_result.get("header_bypasses", [])
        if auth_findings:
            exploits["auth_bypass"] = {
                "total": len(auth_findings),
                "findings": auth_findings,
                "exploit_ready": True,
            }

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
        auth_bypass_data = self.state["phases"].get("auth_bypass", {})

        by_type = {}
        for key, f in findings.items():
            vt = f["type"]
            if vt not in by_type:
                by_type[vt] = []
            by_type[vt].append(f)

        by_url = {}
        for f in findings.values():
            u = f["url"]
            if u not in by_url:
                by_url[u] = []
            by_url[u].append(f["type"])

        report["summary"]["vulnerabilities"] = len(findings)
        report["summary"]["by_type"] = {k: len(v) for k, v in by_type.items()}
        report["summary"]["by_url"] = {k: len(v) for k, v in by_url.items()}
        report["summary"]["exploit_ready"] = len(exploits)

        exploit_ready_details = []
        for k, v in exploits.items():
            if v.get("exploit_ready"):
                exploit_ready_details.append(k)
        auth_total = auth_bypass_data.get("total_bypasses", 0)
        if auth_total > 0:
            exploit_ready_details.append("auth_bypass(%d)" % auth_total)
        report["summary"]["exploit_ready_details"] = exploit_ready_details

        critical_flags = ["rce_available", "rce", "shell", "data_extracted",
                          "credential_access", "exploit_ready"]
        report["summary"]["critical"] = any(
            any(f.get("result", {}).get(k) for k in critical_flags)
            for f in findings.values()
        ) or bool(exploit_ready_details)

        report["summary"]["affected_urls"] = list(by_url.keys())
        report["summary"]["param_hits"] = [
            "%s?%s [%s]" % (f["url"], f["param"], f["type"])
            for f in findings.values()
        ]

        for vt, flist in by_type.items():
            report["details"][vt] = flist
        report["exploits"] = exploits
        report["auth_bypass"] = {
            k: v for k, v in auth_bypass_data.items()
            if k != "vulnerable"
        }

        crawl_summary = self.state["phases"].get("crawl", {}).get("summary", {})
        mine_data = self.state["phases"].get("param_mine", {})
        total_mined = sum(
            len(pd.get("all_params", []))
            for pd in mine_data.values()
            if isinstance(pd, dict)
        )
        waf_info = self.state.get("waf", {})
        report["recon"] = {
            "pages_crawled": crawl_summary.get("pages_crawled", 0),
            "endpoints": crawl_summary.get("endpoints_found", 0),
            "forms": crawl_summary.get("forms_found", 0),
            "params_crawled": crawl_summary.get("unique_params", 0),
            "params_mined": total_mined,
            "test_points": detection.get("test_points", 0),
            "is_spa": crawl_summary.get("is_spa", False),
            "js_api_discovered": crawl_summary.get("js_api_discovered", 0),
            "waf": waf_info.get("name"),
        }
        self.state["phases"]["report"] = report
        return report

    def run(self) -> Dict:
        start = time.time()
        self.oob_server.start()
        print("[*] Phase 1/5: Crawling %s ..." % self.target)
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
                                "methods": ["GET"],
                                "params": [],
                                "spa_api": True,
                            }
            except Exception as e:
                logger.debug("spa crawl: %s", e)

        print("[*] Phase 2/5: Parameter mining ...")
        mine_result = self.phase_mine(crawl_result)
        total_mined = sum(
            len(pd.get("all_params", []))
            for pd in mine_result.values()
            if isinstance(pd, dict)
        )
        print("  -> %d params discovered across %d endpoints" % (
            total_mined, len(mine_result)))

        print("[*] Phase 3/5: Auth bypass probing ...")
        auth_result = self.phase_auth_bypass()
        ab_total = auth_result.get("total_bypasses", 0)
        print("  -> %d bypass vectors found (%d path, %d cookie, %d header, %d method)" % (
            ab_total,
            len(auth_result.get("path_bypasses", [])),
            len(auth_result.get("cookie_bypasses", [])),
            len(auth_result.get("header_bypasses", [])),
            len(auth_result.get("method_bypasses", [])),
        ))

        print("[*] Phase 4/5: Vulnerability detection (%d threads, 15 detectors) ..." % (
            self.threads))
        findings = self.phase_detect()
        by_type = {}
        for f in findings.values():
            by_type.setdefault(f["type"], 0)
            by_type[f["type"]] += 1
        by_type_str = " ".join("[%s:%d]" % (k.upper(), v) for k, v in sorted(by_type.items()))
        print("  -> %d vulnerabilities found: %s" % (len(findings), by_type_str))

        if findings or ab_total > 0:
            if self.high_priv_sess:
                print("[*] Phase 5/6: Dual-session BOLA detection ...")
                self.phase_dual_session()
            phase_label = "6/6" if self.high_priv_sess else "5/5"
            print("[*] Phase %s: Weaponization (%d threads) ..." % (phase_label, self.threads))
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
        high_priv_sess: Optional['requests.Session'] = None) -> Dict:
    o = Orchestrator(target, sess, timeout, threads,
                     high_priv_sess=high_priv_sess)
    return o.run()
