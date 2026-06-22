import json, time, os, sys
from typing import Dict, List, Optional, Any
from tools.log_utils import get_logger

logger = get_logger("biz_logic_v2")

from tools.session_matrix import SessionMatrix
from tools.workflow_tracer import WorkflowTracer, trace_workflow
from tools.constraint_graph import ConstraintGraph
from tools.deviation_oracle import DeviationOracle
from tools.race_profiler import RaceProfiler
from tools.settings import settings


def run_authz_scan(url: str, identities: List[Dict],
                   auth_url: str = None, sess=None,
                   timeout: float = 10.0) -> Dict:
    from tools.session_matrix import SessionMatrix
    if auth_url is None:
        auth_url = f"{url.rstrip('/')}/login"
    matrix = SessionMatrix(url)
    for ident in identities:
        matrix.register(
            label=ident.get("label", ident.get("username", "unknown")),
            username=ident.get("username", ""),
            password=ident.get("password", ""),
            role=ident.get("role", "user"),
        )
    auth_results = matrix.authenticate_all(auth_url, timeout=timeout)
    oracle = DeviationOracle(url, sess, timeout)
    oracle.matrix = matrix
    result = oracle.run()
    result["auth_results"] = auth_results
    result["identities"] = matrix.list()
    return result


def run_workflow_scan(url: str, workflow_steps: List[Dict],
                      sess=None, timeout: float = 10.0) -> Dict:
    import requests
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    trace = trace_workflow(sess, url, workflow_steps)
    from tools.workflow_tracer import WorkflowDeviator
    deviator = WorkflowDeviator(trace)
    findings = []
    skip_tests = deviator.generate_skip_steps(len(trace.steps) - 1)
    for test in skip_tests[:5]:
        try:
            r = sess.get(test["target_url"], timeout=timeout)
            if r.status_code in (200, 201, 202, 204):
                findings.append({
                    "type": "workflow_bypass",
                    "technique": "skip_step",
                    "detail": test["description"],
                    "url": test["target_url"],
                    "status": r.status_code,
                })
        except Exception:
            pass
    replay_tests = deviator.generate_replay()
    for test in replay_tests[:5]:
        try:
            r = sess.get(test["old_url"], timeout=timeout)
            if r.status_code in (200, 201, 202, 204):
                findings.append({
                    "type": "state_replay",
                    "technique": "replay",
                    "detail": test["description"],
                    "url": test["old_url"],
                    "status": r.status_code,
                })
        except Exception:
            pass
    resource_ids = deviator.find_resource_ids()
    for id_key, id_val, step_idx in resource_ids[:10]:
        findings.append({
            "type": "idor_candidate",
            "technique": "resource_id_found",
            "detail": f"Resource identifier {id_key}={id_val} at step {step_idx}",
            "extracted_key": id_key,
            "extracted_value": id_val,
        })
    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "trace": trace.to_dict(),
        "resource_ids": resource_ids,
    }


def run_race_scan(url: str, param: str = None, concurrency: int = 20,
                  sess=None, timeout: float = 10.0) -> Dict:
    import requests
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    profiler = RaceProfiler(sess, timeout)
    method = "POST"
    body = {param: "1"} if param else {"id": "1"}
    result = profiler.detect_windows(url, param, method, body)
    return {
        "vulnerable": result["window_found"],
        "detail": f"Found {len(result['windows'])} race window(s)"
                  if result["window_found"] else "No race window detected",
        "windows": [
            {
                "concurrency": w.concurrency,
                "elapsed_ms": round(w.elapsed_ms, 1),
                "flags": {
                    "duplicate_success": w.duplicate_success,
                    "state_mismatch": w.state_mismatch,
                    "integrity_violated": w.integrity_violated,
                    "resource_created_twice": w.resource_created_twice,
                },
            }
            for w in result.get("windows", [])
        ],
    }


def run_constraint_scan(url: str, param: str = None,
                        sess=None, timeout: float = 10.0) -> Dict:
    import requests
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    from tools.constraint_graph import ConstraintGraph, ConstraintBreaker
    graph = ConstraintGraph()
    try:
        r = sess.get(url, timeout=timeout)
        graph.ingest_request(url, None)
        graph.ingest_response(r.status_code, r.text)
    except Exception:
        pass
    graph.detect_numerical_relationships()
    constraints = graph.detect_constraints()
    findings = []
    if param:
        breaker = ConstraintBreaker(graph)
        tests = breaker.generate_break_tests(url, param)
        for test in tests:
            findings.append({
                "type": "constraint_break",
                "technique": test.get("technique", ""),
                "param": test.get("param", param),
                "value": test.get("value", ""),
                "variant": test.get("variant", ""),
            })
    return {
        "vulnerable": len(constraints) > 0 or len(findings) > 0,
        "graph": graph.summary(),
        "constraints": [
            {"type": c.type, "desc": c.description,
             "params": c.params, "severity": c.severity}
            for c in constraints
        ],
        "findings": findings,
    }


def check(url: str, param: str = None, sess=None,
          timeout: float = 10.0) -> Dict:
    results = {}
    results["constraints"] = run_constraint_scan(url, param, sess, timeout)
    results["race"] = run_race_scan(url, param, sess=sess, timeout=timeout)
    return {
        "vulnerable": any(r.get("vulnerable", False)
                         for r in results.values()),
        "checks": results,
    }
