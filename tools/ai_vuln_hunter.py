import re
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("ai_vuln_hunter")


@dataclass
class IntelReport:
    target: str = ""
    timestamp: float = 0.0
    discovered_endpoints: List[Dict] = field(default_factory=list)
    response_samples: List[Dict] = field(default_factory=list)
    error_signatures: List[Dict] = field(default_factory=list)
    technology_stack: List[str] = field(default_factory=list)
    anomaly_observations: List[Dict] = field(default_factory=list)
    parameter_behavior: Dict[str, List[Dict]] = field(default_factory=dict)
    timing_profiles: Dict[str, float] = field(default_factory=dict)

    def brief(self) -> str:
        lines = []
        lines.append("=== TARGET INTELLIGENCE BRIEF ===")
        lines.append("Target: %s" % self.target)
        if self.technology_stack:
            lines.append("Tech: %s" % ", ".join(self.technology_stack))
        if self.discovered_endpoints:
            interesting = [e for e in self.discovered_endpoints
                          if e.get("status") in (200, 401, 403) and e.get("size", 0) > 50]
            if interesting:
                lines.append("Endpoints (%d interesting):" % len(interesting))
                for e in interesting[:8]:
                    lines.append("  [%d] %s (%d bytes)" % (e["status"], e["path"], e["size"]))
        if self.error_signatures:
            lines.append("Error Patterns:")
            for e in self.error_signatures[:5]:
                lines.append("  %s (occurrences: %d)" % (e["pattern"][:80], e["count"]))
        if self.anomaly_observations:
            lines.append("Anomalies:")
            for a in self.anomaly_observations[:3]:
                lines.append("  %s" % a["description"][:120])
        if self.timing_profiles:
            slow = [(k, v) for k, v in self.timing_profiles.items() if v > 2.0]
            if slow:
                lines.append("Slow endpoints:")
                for k, v in slow[:3]:
                    lines.append("  %s: %.1fs" % (k, v))
        para_behavior = [(p, len(b)) for p, b in self.parameter_behavior.items() if len(b) > 0]
        if para_behavior:
            lines.append("Parameters tested: %s" % ", ".join(
                "%s(%d)" % (p, c) for p, c in para_behavior[:6]))
        return "\n".join(lines)


class IntelligenceGatherer:
    def __init__(self, sess, timeout: float = 10.0, context_memory=None, vuln_ctx=None):
        self.sess = sess
        self.timeout = timeout
        self.context_memory = context_memory
        self.vuln_ctx = vuln_ctx
        self.report = IntelReport(target="")
        self._lock = threading.Lock()

    def deep_sample_endpoint(self, url: str, param: str,
                              baseline_payload: str = "1",
                              mutant_payloads: List[str] = None) -> Dict:
        sample = {"url": url, "param": param, "responses": []}
        if mutant_payloads is None:
            mutant_payloads = [
                "1", "'", "\"", "true", "null", "1=1",
                "../", "//", "./",
                "<test>", "{test}", "[test]",
                "${1+1}", "#{1+1}", "{{1+1}}",
                " ", "%00", "\\",
            ]
        try:
            r = self.sess.get(url, params={param: baseline_payload}, timeout=self.timeout)
            baseline = {
                "payload": baseline_payload,
                "status": r.status_code,
                "size": len(r.text),
                "time": r.elapsed.total_seconds(),
                "headers": dict(r.headers),
                "body_preview": r.text[:500],
            }
            sample["baseline"] = baseline
            sample["responses"].append(baseline)
        except Exception as e:
            sample["error"] = str(e)
            return sample

        for payload in mutant_payloads:
            try:
                r = self.sess.get(url, params={param: payload}, timeout=self.timeout)
                resp = {
                    "payload": payload,
                    "status": r.status_code,
                    "size": len(r.text),
                    "time": r.elapsed.total_seconds(),
                    "body_preview": r.text[:300],
                }
                diff = self._compute_diff(baseline, resp)
                if diff["anomaly"]:
                    resp["anomaly"] = True
                    resp["diff_reason"] = diff["reason"]
                    with self._lock:
                        self.report.anomaly_observations.append({
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "description": diff["reason"],
                            "baseline_status": baseline["status"],
                            "response_status": resp["status"],
                        })
                sample["responses"].append(resp)
            except Exception:
                pass
        return sample

    def _compute_diff(self, baseline: Dict, response: Dict) -> Dict:
        reasons = []
        if response["status"] != baseline["status"]:
            reasons.append("status %d -> %d" % (baseline["status"], response["status"]))
        size_ratio = response["size"] / max(baseline["size"], 1)
        if size_ratio > 2.0:
            reasons.append("size %.0f -> %.0f (%.1fx)" % (
                baseline["size"], response["size"], size_ratio))
        elif size_ratio < 0.5 and response["size"] > 50:
            reasons.append("size %.0f -> %.0f (shrunk %.1fx)" % (
                baseline["size"], response["size"], size_ratio))
        time_ratio = response["time"] / max(baseline["time"], 0.01)
        if time_ratio > 3.0 and response["time"] > 2.0:
            reasons.append("slow (%.1fs vs %.1fs baseline)" % (
                response["time"], baseline["time"]))
        if response["status"] in (500, 502, 503):
            reasons.append("server error")
        error_patterns = [
            (r"(?:sql|mysql|postgres|mssql|oracle|sqlite)", "SQL"),
            (r"(?:stack trace|at\s+\w+\.\w+)", "stack_trace"),
            (r"(?:fatal|warning|notice|parse error)", "PHP_error"),
            (r"(?:nullpointer|classcast|arithmetic)", "Java_exception"),
            (r"(?:file_get_contents|include|require)", "PHP_include"),
        ]
        for pat, label in error_patterns:
            if re.search(pat, response.get("body_preview", ""), re.IGNORECASE):
                reasons.append("error_signal:%s" % label)
        return {"anomaly": len(reasons) > 0, "reason": "; ".join(reasons)}

    def probe_mutation_matrix(self, url: str, param: str) -> Dict:
        mutation_matrix = {
            "type_coercion": [
                "1", "true", "false", "null", "undefined",
                "01", "1.0", "1e0", "0x1",
            ],
            "sql_prefix": [
                "'", "\"", "')", "\"))", "`",
                "1'", "1\"", "1`",
            ],
            "path_manipulation": [
                "../", "..\\", "....//", "..;/",
                "%2e%2e/", "%252e%252e%252f",
            ],
            "noop_payloads": [
                "1 AND 1=1", "1' AND '1'='1",
                "1 UNION SELECT 1", "1' UNION SELECT '1",
                "1,2,3", "1;2;3",
            ],
            "special_chars": [
                "\x00", "\r\n", "\t", "\\",
                "' OR '1'='1", "\" OR \"1\"=\"1",
                "${7*7}", "#{7*7}", "{{7*7}}",
                "{{config}}", "${java:os}",
            ],
            "verb_tampering": [
                "", "-1", "0", "*",
                "admin", "root", "true",
            ],
        }
        results = {"url": url, "param": param, "mutations": {}}
        baseline = None
        for group_name, payloads in mutation_matrix.items():
            group_results = []
            for payload in payloads:
                try:
                    r = self.sess.get(url, params={param: payload}, timeout=self.timeout)
                    resp = {
                        "payload": payload[:60],
                        "status": r.status_code,
                        "size": len(r.text),
                        "time": r.elapsed.total_seconds(),
                        "body_preview": r.text[:200],
                    }
                    if baseline is None:
                        baseline = resp
                    diff = self._compute_diff(baseline, resp)
                    if diff["anomaly"]:
                        resp["anomaly"] = True
                        resp["diff_reason"] = diff["reason"]
                        with self._lock:
                            self.report.anomaly_observations.append({
                                "url": url, "param": param, "payload": payload[:60],
                                "description": diff["reason"],
                                "baseline_status": baseline["status"],
                                "response_status": resp["status"],
                            })
                    group_results.append(resp)
                except Exception:
                    pass
            results["mutations"][group_name] = group_results
        return results

    def deep_scan_endpoint(self, url: str, param: str) -> Dict:
        result = {
            "url": url,
            "param": param,
            "deep_sample": self.deep_sample_endpoint(url, param),
            "mutation_matrix": self.probe_mutation_matrix(url, param),
        }
        with self._lock:
            key = "%s?%s" % (url, param)
            if key not in self.report.parameter_behavior:
                self.report.parameter_behavior[key] = []
            self.report.parameter_behavior[key].append(result)
        return result

    def explore(self, base_url: str, findings: Dict[str, Dict],
                recon_data: Optional[Dict] = None) -> Dict:
        self.report.target = base_url
        if recon_data:
            self.report.technology_stack = recon_data.get("technologies", [])

        deep_results = {}
        for key, finding in findings.items():
            if key.startswith("__"):
                continue
            url = finding.get("url", "")
            param = finding.get("param", "")
            if url and param:
                deep_results[key] = self.deep_scan_endpoint(url, param)
        result = {
            "report": self.report,
            "brief": self.report.brief(),
            "deep_results_count": len(deep_results),
            "anomalies_found": len(self.report.anomaly_observations),
        }
        return result


def generate_target_brief(sess, base_url: str, timeout: float = 10.0,
                           findings: Optional[Dict[str, Dict]] = None,
                           recon_data: Optional[Dict] = None,
                           context_memory=None, vuln_ctx=None) -> Dict:
    gatherer = IntelligenceGatherer(sess, timeout, context_memory, vuln_ctx)
    return gatherer.explore(
        base_url, findings or {}, recon_data)
