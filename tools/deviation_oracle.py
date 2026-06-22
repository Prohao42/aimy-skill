import json, re, time, copy
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode

from tools.log_utils import get_logger
from tools.session_matrix import SessionMatrix, SessionComparator
from tools.workflow_tracer import WorkflowTracer, WorkflowDeviator, WorkflowTrace, StepRole
from tools.constraint_graph import ConstraintGraph, ConstraintBreaker
from tools.settings import settings

logger = get_logger("deviation_oracle")


class DeviationOracle:
    def __init__(self, base_url: str, sess=None, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.sess = sess
        self.timeout = timeout
        self.matrix = SessionMatrix(base_url)
        self.tracer = WorkflowTracer(base_url)
        self.constraint_graph = ConstraintGraph()
        self.findings: List[Dict] = []

    def run(self) -> Dict:
        self._test_authz_gaps()
        self._test_idor_chain()
        self._test_state_replay()
        self._test_constraint_breaks()
        self._test_method_tampering()
        self._test_mass_assignment()
        return {
            "vulnerable": len(self.findings) > 0,
            "findings": self.findings,
            "total": len(self.findings),
        }

    def _test_authz_gaps(self):
        identities = self.matrix.list()
        if len(identities) < 2:
            return
        labels = list(identities.keys())
        paths_to_test = self._discover_protected_paths()
        for path in paths_to_test:
            url = f"{self.base_url}{path}"
            for i in range(len(labels)):
                for j in range(i + 1, len(labels)):
                    result = self.matrix.cross_session_test(
                        labels[i], labels[j], url)
                    if result.get("authz_gap"):
                        self.findings.append({
                            "type": "authz_gap",
                            "technique": "cross_user_access",
                            "url": url,
                            "actor": labels[i],
                            "target": labels[j],
                            "severity": "critical",
                            "detail": f"{labels[i]} can access {labels[j]}'s resource at {url}",
                        })

    def _test_idor_chain(self):
        identities = self.matrix.list()
        if len(identities) < 2:
            return
        labels = list(identities.keys())
        for i in range(len(labels)):
            for j in range(i + 1, len(labels)):
                urls_discovered = self._collect_urls_for_identity(labels[i])
                for url_info in urls_discovered[:20]:
                    url = url_info["url"]
                    parts = urlparse(url)
                    qs = parse_qs(parts.query)
                    for param, values in qs.items():
                        for val in values:
                            if val.isdigit():
                                test_val = str(int(val) + 1)
                                new_qs = dict(qs)
                                new_qs[param] = [test_val]
                                test_url = (f"{parts.scheme}://{parts.netloc}"
                                           f"{parts.path}?{urlencode(new_qs, doseq=True)}")
                                result = self.matrix.cross_session_test(
                                    labels[j], labels[i], test_url)
                                if result.get("authz_gap"):
                                    self.findings.append({
                                        "type": "idor",
                                        "technique": "sequential_id_enumerate",
                                        "url": test_url,
                                        "param": param,
                                        "original_value": val,
                                        "test_value": test_val,
                                        "actor": labels[j],
                                        "target": labels[i],
                                        "severity": "critical",
                                        "detail": f"{labels[j]} enumerated resource {param}={test_val}"
                                                  f" belonging to {labels[i]}",
                                    })
                                    break

    def _test_state_replay(self):
        if len(self.tracer.traces) == 0:
            return
        for trace_name, trace in self.tracer.traces.items():
            deviator = WorkflowDeviator(trace)
            for skip_test in deviator.generate_skip_steps(len(trace.steps) - 1):
                try:
                    r = self.sess.get(skip_test["target_url"],
                                      timeout=self.timeout)
                    if r.status_code in (200, 201, 204):
                        body_lower = r.text.lower()
                        skip_indicators = ["login", "sign in", "authenticate",
                                           "unauthorized", "forbidden"]
                        if not any(ind in body_lower for ind in skip_indicators):
                            self.findings.append({
                                "type": "workflow_bypass",
                                "technique": "skip_intermediate",
                                "url": skip_test["target_url"],
                                "severity": "high",
                                "detail": (f"Skipped from step {skip_test['from_step']} "
                                           f"to step {skip_test['target_url']} "
                                           f"returned {r.status_code}"),
                            })
                except Exception:
                    pass

            for replay_test in deviator.generate_replay():
                try:
                    r = self.sess.get(replay_test["old_url"],
                                      timeout=self.timeout)
                    if r.status_code in (200, 201, 204):
                        self.findings.append({
                            "type": "state_replay",
                            "technique": "replay_old_step",
                            "url": replay_test["old_url"],
                            "severity": "high",
                            "detail": (f"Step {replay_test['old_step_index']} "
                                       f"replayed successfully after step "
                                       f"{replay_test['current_step_index']}"),
                        })
                except Exception:
                    pass

    def _test_constraint_breaks(self):
        param_constraints = self.constraint_graph.detect_constraints()
        for c in param_constraints:
            if c.severity in ("high", "critical"):
                for param in c.params:
                    breaker = ConstraintBreaker(self.constraint_graph)
                    tests = breaker.generate_break_tests(self.base_url, param)
                    for test in tests:
                        self.findings.append({
                            "type": "constraint_break",
                            "technique": test.get("technique", test.get("technique")),
                            "url": test.get("url", self.base_url),
                            "severity": "high",
                            "detail": (f"Constraint break: {test.get('param')}"
                                       f"={test.get('value')} "
                                       f"({test.get('variant', '')})"),
                            "suggested_input": {
                                test.get("param", ""): test.get("value", ""),
                            },
                        })

    def _test_method_tampering(self):
        paths = self._discover_protected_paths()
        for path in paths[:10]:
            url = f"{self.base_url}{path}"
            for method in ("PUT", "PATCH", "DELETE", "POST"):
                try:
                    r = self.sess.request(method, url, timeout=self.timeout,
                                          verify=False)
                    if r.status_code in (200, 201, 204):
                        body_lower = r.text.lower()
                        if not any(ind in body_lower for ind in
                                   ("405", "not allowed", "method not allowed")):
                            self.findings.append({
                                "type": "method_tampering",
                                "technique": f"unexpected_{method.lower()}",
                                "url": url,
                                "method": method,
                                "status": r.status_code,
                                "severity": "medium",
                                "detail": f"{method} {url} returned {r.status_code}",
                            })
                except Exception:
                    pass

    def _test_mass_assignment(self):
        proto_fields = ["role", "is_admin", "admin", "group",
                        "access_level", "verified", "active"]
        paths = self._discover_protected_paths()
        for path in paths[:10]:
            url = f"{self.base_url}{path}"
            for field in proto_fields:
                for method in ("POST", "PUT", "PATCH"):
                    try:
                        r = self.sess.request(method, url,
                                              json={field: "admin", "username": "test"},
                                              timeout=self.timeout,
                                              verify=False)
                        if r.status_code in (200, 201, 204):
                            body = r.text.lower()
                            if "admin" in body or "role" in body:
                                self.findings.append({
                                    "type": "mass_assignment",
                                    "technique": "proto_field_injection",
                                    "url": url,
                                    "field": field,
                                    "method": method,
                                    "severity": "critical",
                                    "detail": f"Field '{field}' accepted via {method} at {url}",
                                })
                    except Exception:
                        pass

    def _discover_protected_paths(self) -> List[str]:
        common_paths = ["/admin", "/dashboard", "/profile", "/api/user",
                        "/api/users", "/api/admin", "/settings",
                        "/account", "/api/profile", "/api/account"]
        found = []
        for path in common_paths:
            url = f"{self.base_url}{path}"
            try:
                r = self.sess.get(url, timeout=self.timeout)
                if r.status_code in (401, 403, 302):
                    found.append(path)
            except Exception:
                pass
        return found

    def _collect_urls_for_identity(self, label: str) -> List[Dict]:
        urls = []
        identity = self.matrix.get(label)
        if not identity:
            return urls
        from urllib.parse import urlparse
        if label in self.tracer.traces:
            trace = self.tracer.traces[label]
            for step in trace.steps:
                if step.response_status in (200, 201):
                    urls.append({"url": step.url, "status": step.response_status})
        return urls


class OracleSession:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.matrix = SessionMatrix(base_url)
        self.tracer = WorkflowTracer(base_url)

    def as_user(self, label: str):
        sess = self.matrix.make_session(label)
        if sess:
            self.tracer = WorkflowTracer(self.base_url)
        return sess

    def go(self, method: str, url: str, **kwargs):
        return getattr(self, method.lower())(url, **kwargs)


def check(url: str, param: str = None, sess=None, timeout: float = 10.0) -> Dict:
    import requests
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    oracle = DeviationOracle(url, sess, timeout)
    return oracle.run()
