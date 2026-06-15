import re, time, json as _json
from typing import Optional
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.payload_engine import generate

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
]


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, waf_name: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": [], "payload": None}

    try:
        r_base = sess.get(build_url(url, param, "1"),
                          timeout=timeout, verify=False)
        base_len = len(r_base.text)
        base_status = r_base.status_code
    except Exception as e:
        logger.debug("nosqli baseline: %s", e)
        base_len = 0
        base_status = 0

    seeds = generate("nosqli", "boolean", "string", waf_name)
    for entry in seeds:
        payload = entry["payload"]
        try:
            r = sess.get(build_url(url, param, payload),
                         timeout=timeout, verify=False)
            diff = abs(len(r.text) - base_len)
            if diff > 30 or r.status_code != base_status:
                result["vulnerable"] = True
                result["type"] = "boolean"
                result["evidence"].append("nosqli: %s (%d diff)" % (payload[:25], diff))
                result["payload"] = payload
                break
            for pat in NOSQLI_ERROR_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["type"] = "error"
                    result["evidence"].append("nosqli error: %s" % pat[:25])
                    result["payload"] = payload
                    break
        except Exception as e:
            logger.debug("nosqli payload %s: %s", payload[:20], e)
        if result["vulnerable"]:
            break

    if not result["vulnerable"]:
        time_seeds = generate("nosqli", "where_time", "string", waf_name)
        for entry in time_seeds:
            payload = entry["payload"]
            threshold = entry.get("threshold", 2.5)
            try:
                start_t = time.time()
                r = sess.get(build_url(url, param, payload),
                             timeout=timeout + 2, verify=False)
                elapsed = time.time() - start_t
                if elapsed >= threshold:
                    result["vulnerable"] = True
                    result["type"] = "time"
                    result["evidence"].append("nosqli time: %s (%.1fs)" % (payload[:25], elapsed))
                    result["payload"] = payload
                    break
            except Exception as e:
                logger.debug("nosqli time %s: %s", payload[:20], e)

    if not result["vulnerable"]:
        json_seeds = generate("nosqli", "json", "json", waf_name)
        for entry in json_seeds:
            payload_raw = entry["payload"]
            try:
                r = sess.post(url, json={param: _json.loads(payload_raw)},
                              timeout=timeout, verify=False)
                if r.status_code == 200 and len(r.text) > base_len + 10:
                    result["vulnerable"] = True
                    result["type"] = "json"
                    result["evidence"].append("nosqli json: %s" % payload_raw[:25])
                    result["payload"] = payload_raw
                    break
            except Exception as e:
                logger.debug("nosqli json: %s", e)

    return result
