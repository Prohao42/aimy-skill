import concurrent.futures, time, json, copy
from typing import Optional, Dict, List, Callable
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url

logger = get_logger("race_condition")

RACE_SCENARIOS = {
    "coupon": {
        "desc": "Coupon/gift-card reuse: send N parallel redemptions",
        "key_patterns": ["coupon", "discount", "promo", "redeem"],
    },
    "vote": {
        "desc": "Vote/like inflation: send N parallel votes",
        "key_patterns": ["vote", "like", "upvote"],
    },
    "wallet": {
        "desc": "Wallet/credit double-spend: send N parallel claims",
        "key_patterns": ["wallet", "credit", "point", "claim"],
    },
    "transfer": {
        "desc": "Transfer TOCTOU: send N parallel transfers",
        "key_patterns": ["transfer", "send", "withdraw"],
    },
    "generic": {
        "desc": "Generic race: parallel request with same data",
        "key_patterns": [],
    },
}

SUCCESS_KEYWORDS = ["true", "success", "claimed", "applied", "ok", "accepted"]


class RaceConditionTester:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0):
        self.sess = sess or requests.Session()
        self.timeout = timeout

    def _run_round(self, url: str, param: str, method: str,
                   concurrency: int, data: dict) -> List[Dict]:
        def race_request(i):
            try:
                if method == "POST":
                    r = self.sess.post(url, data=data,
                                       timeout=self.timeout, verify=False)
                else:
                    r = self.sess.get(build_url(url, param, param),
                                      timeout=self.timeout, verify=False)
                return {"i": i, "status": r.status_code, "len": len(r.text),
                        "body": r.text[:500]}
            except Exception as e:
                logger.debug("race request %d: %s", i, e)
                return {"i": i, "status": 0, "len": 0, "body": ""}

        start = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = [ex.submit(race_request, i) for i in range(concurrency)]
            responses = [f.result() for f in concurrent.futures.as_completed(futures)]
        elapsed_ms = (time.time() - start) * 1000
        for r in responses:
            r["elapsed_ms"] = elapsed_ms
        return responses

    def _analyze_round(self, responses: List[Dict], bl_status: int,
                       bl_len: int, bl_body: str) -> Dict:
        round_result = {"vulnerable": False, "type": None, "evidence": []}

        statuses = [r["status"] for r in responses if r["status"] > 0]
        unique_statuses = set(statuses)

        for s in unique_statuses:
            if s != bl_status and s in (200, 201, 202, 204):
                count = statuses.count(s)
                if count > 1:
                    round_result["vulnerable"] = True
                    round_result["type"] = "status_differential"
                    round_result["evidence"].append(
                        "%dx status %d (baseline: %d)" % (count, s, bl_status))
                    break

        if not round_result["vulnerable"]:
            lengths = [r["len"] for r in responses if r["len"] > 0]
            if lengths:
                avg_len = sum(lengths) / len(lengths)
                variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
                if variance > 100 and any(abs(l - bl_len) > 50 for l in lengths):
                    round_result["vulnerable"] = True
                    round_result["type"] = "length_variance"
                    round_result["evidence"].append(
                        "body-length variance=%.0f (baseline=%d)" % (variance, bl_len))

        if not round_result["vulnerable"]:
            success_bodies = [r["body"] for r in responses if r["status"] in (200, 201)]
            if len(success_bodies) >= 2 and len(set(tuple(b) for b in success_bodies)) > 1:
                round_result["vulnerable"] = True
                round_result["type"] = "body_differential"
                round_result["evidence"].append(
                    "race responses differ: %dB vs %dB" % (
                        len(success_bodies[0]), len(success_bodies[1])))

        for r in responses:
            if r["body"] and bl_body and r["body"] != bl_body:
                for kw in SUCCESS_KEYWORDS:
                    if kw in r["body"].lower():
                        round_result["vulnerable"] = True
                        round_result["type"] = "duplicate_success"
                        round_result["evidence"].append(
                            "duplicate '%s' at %.0fms" % (kw, r.get("elapsed_ms", 0)))
                        break
                if round_result["vulnerable"]:
                    break

        return round_result

    def test_endpoint(self, url: str, param: str, method: str = "GET",
                      concurrency: int = 20, rounds: int = 3) -> Dict:
        result = {"vulnerable": False, "type": None, "evidence": [],
                  "race_window_ms": [], "responses": [], "rounds_tested": 0}

        param_lower = param.lower()
        scenario = "generic"
        for sname, sdata in RACE_SCENARIOS.items():
            if any(k in param_lower for k in sdata["key_patterns"]):
                scenario = sname
                break

        data = {param: "1"}

        baseline = None
        try:
            if method == "POST":
                baseline = self.sess.post(url, data=data, timeout=self.timeout, verify=False)
            else:
                baseline = self.sess.get(build_url(url, param, "1"),
                                         timeout=self.timeout, verify=False)
        except Exception as e:
            logger.debug("race baseline: %s", e)
            return result

        bl_status = baseline.status_code if baseline else 0
        bl_len = len(baseline.text) if baseline else 0
        bl_body = baseline.text if baseline else ""

        for round_idx in range(rounds):
            responses = self._run_round(url, param, method, concurrency, data)
            result["race_window_ms"].append(responses[0].get("elapsed_ms", 0) if responses else 0)
            analysis = self._analyze_round(responses, bl_status, bl_len, bl_body)
            if analysis["vulnerable"]:
                result["vulnerable"] = True
                result["type"] = analysis["type"]
                result["evidence"].append("round %d: %s" % (round_idx + 1, analysis["evidence"][0]))
                result["responses"] = [
                    {"i": r["i"], "status": r["status"], "len": r["len"]}
                    for r in responses[:5]
                ]
                result["rounds_tested"] = round_idx + 1
                return result

        result["rounds_tested"] = rounds
        result["responses"] = [
            {"i": r["i"], "status": r["status"], "len": r["len"]}
            for r in (responses or [])[:5]
        ]
        return result


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    tester = RaceConditionTester(sess, timeout)
    method = "POST" if any(k in url.lower() for k in ["login", "register", "create", "submit", "order", "checkout"]) else "GET"
    return tester.test_endpoint(url, param, method=method)
