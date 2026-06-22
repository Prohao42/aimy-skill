import concurrent.futures, time, json, threading, copy, random
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("race_profiler")


@dataclass
class RaceWindow:
    elapsed_ms: float
    concurrency: int
    responses: List[Dict] = field(default_factory=list)
    state_mismatch: bool = False
    duplicate_success: bool = False
    integrity_violated: bool = False
    resource_created_twice: bool = False


class TransactionProbe:
    def __init__(self, sess, timeout: float = 10.0):
        self.sess = sess
        self.timeout = timeout
        self._state_checkpoints: Dict[str, str] = {}

    def checkpoint(self, label: str, url: str) -> Optional[str]:
        try:
            r = self.sess.get(url, timeout=self.timeout)
            self._state_checkpoints[label] = r.text
            return r.text
        except Exception as e:
            logger.debug("checkpoint %s: %s", label, e)
            return None

    def verify(self, label_a: str, label_b: str) -> Dict:
        before = self._state_checkpoints.get(label_a)
        after = self._state_checkpoints.get(label_b)
        if before is None or after is None:
            return {"error": "missing checkpoint", "changed": False}
        changed = before != after
        return {
            "checkpoint_a": label_a,
            "checkpoint_b": label_b,
            "changed": changed,
            "len_before": len(before),
            "len_after": len(after),
        }


class RaceProfiler:
    def __init__(self, sess, timeout: float = 10.0):
        self.sess = sess
        self.timeout = timeout
        self.probe = TransactionProbe(sess, timeout)

    def detect_windows(self, url: str, param: str = None,
                       method: str = "POST",
                       body: Dict = None) -> Dict:
        result = {"window_found": False, "windows": []}
        baseline_r = self._single_request(url, method, body)
        if baseline_r is None:
            return result
        bl_status = baseline_r["status"]
        bl_body = baseline_r["body"]
        bl_len = baseline_r["length"]

        for concurrency in (5, 10, 20, 50):
            for _ in range(3):
                responses = self._race_round(url, method, body, concurrency)
                window = self._analyze_window(responses, bl_status, bl_len,
                                               bl_body, concurrency)
                if (window.duplicate_success or window.state_mismatch
                        or window.integrity_violated
                        or window.resource_created_twice):
                    result["window_found"] = True
                    result["windows"].append(window)
                    break
        return result

    def _single_request(self, url: str, method: str,
                        body: Dict = None) -> Optional[Dict]:
        try:
            start = time.time()
            r = getattr(self.sess, method.lower())(url, json=body,
                                                    timeout=self.timeout,
                                                    verify=False)
            elapsed = (time.time() - start) * 1000
            return {
                "status": r.status_code,
                "body": r.text,
                "length": len(r.text),
                "elapsed_ms": elapsed,
            }
        except Exception as e:
            logger.debug("baseline: %s", e)
            return None

    def _race_round(self, url: str, method: str, body: Dict,
                    concurrency: int) -> List[Dict]:
        def fire(i):
            try:
                start = time.time()
                r = getattr(self.sess, method.lower())(url, json=body,
                                                        timeout=self.timeout + 5,
                                                        verify=False)
                return {
                    "index": i,
                    "status": r.status_code,
                    "body": r.text,
                    "length": len(r.text),
                    "elapsed_ms": (time.time() - start) * 1000,
                }
            except Exception as e:
                return {"index": i, "status": 0, "body": "", "length": 0,
                        "elapsed_ms": 0, "error": str(e)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = [ex.submit(fire, i) for i in range(concurrency)]
            responses = [f.result() for f in concurrent.futures.as_completed(futures)]
        return responses

    def _analyze_window(self, responses: List[Dict], bl_status: int,
                        bl_body: str, bl_len: int,
                        concurrency: int) -> RaceWindow:
        window = RaceWindow(concurrency=concurrency,
                            elapsed_ms=responses[0].get("elapsed_ms", 0)
                            if responses else 0,
                            responses=responses)

        success_count = sum(1 for r in responses if r["status"] in (200, 201))
        window.duplicate_success = success_count > 1

        bodies = [r["body"] for r in responses if r["body"]]
        if len(bodies) >= 2:
            unique_bodies = set(tuple(b) for b in bodies)
            window.state_mismatch = len(unique_bodies) > 1
            all_equal = all(b == bodies[0] for b in bodies)
            if not all_equal and bl_body and bl_body != bodies[0]:
                window.integrity_violated = True

        if len(responses) >= 2:
            created_ids = []
            for r in responses:
                if r["status"] in (200, 201):
                    try:
                        data = json.loads(r["body"])
                        if isinstance(data, dict):
                            for id_key in ("id", "uuid", "order_id", "ref"):
                                if id_key in data:
                                    created_ids.append(data[id_key])
                    except (json.JSONDecodeError, ValueError):
                        pass
            if len(set(created_ids)) > 1 and len(created_ids) > len(set(created_ids)):
                window.resource_created_twice = True

        return window


class StateIntegrityChecker:
    def __init__(self, sess, timeout: float = 10.0):
        self.sess = sess
        self.timeout = timeout
        self._snapshots: Dict[str, str] = {}

    def snapshot(self, label: str, url: str) -> Optional[str]:
        try:
            r = self.sess.get(url, timeout=self.timeout)
            self._snapshots[label] = r.text
            return r.text
        except Exception:
            return None

    def assert_integrity(self, *labels: str) -> Dict:
        results = {}
        for label in labels:
            current = self._snapshots.get(label)
            if current is None:
                results[label] = {"status": "no_baseline"}
                continue
            try:
                r = self.sess.get(label if label.startswith("http")
                                  else label, timeout=self.timeout,
                                  verify=False)
                unchanged = r.text == current
                results[label] = {
                    "unchanged": unchanged,
                    "status": "ok" if unchanged else "modified",
                    "len_before": len(current),
                    "len_after": len(r.text),
                }
            except Exception as e:
                results[label] = {"status": "error", "error": str(e)}
        return results


def check(url: str, param: str = None, sess=None, timeout: float = 10.0) -> Dict:
    import requests
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    profiler = RaceProfiler(sess, timeout)
    write_keywords = ["create", "order", "checkout", "redeem", "claim",
                       "submit", "transfer", "vote", "like"]
    method = "POST" if param and any(k in url.lower() for k in write_keywords) else "GET"
    body = {param: "1"} if param else None
    result = profiler.detect_windows(url, param, method, body)
    return {
        "vulnerable": result["window_found"],
        "race_windows": result["windows"],
        "windows_found": len(result["windows"]),
    }
