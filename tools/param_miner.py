import urllib.parse, re, time, threading, concurrent.futures
from typing import Dict, List, Optional

from tools.log_utils import get_logger
from tools.http_client import build_url

logger = get_logger("param_miner")

COMMON_GET_PARAMS = [
    "id", "page", "file", "url", "cmd", "q", "search", "name", "user",
    "type", "category", "sort", "order", "limit", "offset", "filter",
    "action", "method", "token", "lang", "locale", "debug", "test",
    "template", "view", "include", "path", "dir", "download", "read",
    "show", "edit", "delete", "do", "exec", "run", "pid", "uid",
    "gid", "role", "admin", "config", "setting", "mode", "tab",
    "section", "step", "state", "status", "format", "output", "callback",
    "redirect", "next", "return", "referer", "source", "target",
]

COMMON_POST_PARAMS = [
    "username", "password", "pass", "email", "user", "login",
    "token", "csrf", "csrf_token", "_token", "authenticity_token",
    "name", "first_name", "last_name", "phone", "address",
    "message", "comment", "content", "title", "description",
    "command", "cmd", "code", "data",
    "file", "image", "document", "attachment", "id", "type",
    "category", "status", "role", "permission", "setting",
    "config", "option", "value", "key", "api_key", "secret",
]


class ParamMiner:
    def __init__(self, target_url: str,
                 sess: Optional['requests.Session'] = None, timeout: float = 10.0,
                 threads: int = 1, delay: float = 0.0):
        self.base_url = target_url.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.delay = delay
        self._http = None
        self._http_raw = sess

    def _get_http(self):
        if self._http is None:
            import requests
            self._http = self._http_raw or requests.Session()
            self._http.headers["User-Agent"] = "Mozilla/5.0"
        return self._http

    def _baseline(self, url: str) -> Dict:
        http = self._get_http()
        try:
            start = time.time()
            r = http.get(url, timeout=self.timeout, verify=False)
            elapsed = time.time() - start
            return {"status": r.status_code, "length": len(r.text),
                    "body": r.text[:500], "time": elapsed, "url": r.url}
        except Exception as e:
            logger.debug("baseline %s: %s", url, e)
            return {"status": 0, "length": 0, "body": "", "time": 0, "url": url}

    def _test_param(self, base_url: str, param: str, method: str = "GET") -> Dict:
        http = self._get_http()
        test_value = "test_%d_%s" % (int(time.time() * 1000) % 10000, param)
        try:
            if method == "GET":
                test_url = build_url(base_url, param, test_value)
                start = time.time()
                r = http.get(test_url, timeout=self.timeout, verify=False)
                elapsed = time.time() - start
            else:
                start = time.time()
                r = http.post(base_url, data={param: test_value},
                              timeout=self.timeout, verify=False)
                elapsed = time.time() - start
            result = {
                "param": param,
                "method": method,
                "status": r.status_code,
                "length": len(r.text),
                "time": round(elapsed, 3),
                "url": r.url,
            }
            if r.status_code != 0 and r.text:
                if test_value in r.text[:2000]:
                    result["reflected"] = True
                    result["preview"] = r.text[:200]
                elif len(r.text) > 10:
                    result["reflected"] = False
                    result["preview"] = r.text[:200]
                else:
                    result["reflected"] = False
            return result
        except Exception as e:
            logger.debug("test param %s on %s: %s", param, base_url, e)
            return {"param": param, "method": method, "error": "request failed",
                    "status": 0, "length": 0, "time": 0}

    def _batch_test(self, base_url: str, params: List[str], method: str) -> List[Dict]:
        baseline = self._baseline(base_url)
        results = []
        lock = threading.Lock()

        def _test(p):
            r = self._test_param(base_url, p, method)
            if r["status"] != baseline["status"] or abs(r["length"] - baseline["length"]) > 10:
                r["different"] = True
            else:
                r["different"] = False
            if r.get("reflected") or r.get("different") or r["status"] not in (404, 400, 0):
                with lock:
                    results.append(r)
            if self.delay > 0:
                time.sleep(self.delay)

        n = min(self.threads, len(params))
        if n > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
                list(ex.map(_test, params))
        else:
            for p in params:
                _test(p)
        return results

    def mine_get(self, base_url: str, params: List[str] = None) -> List[Dict]:
        if params is None:
            params = COMMON_GET_PARAMS
        return self._batch_test(base_url, params, "GET")

    def mine_post(self, base_url: str, params: List[str] = None) -> List[Dict]:
        if params is None:
            params = COMMON_POST_PARAMS
        return self._batch_test(base_url, params, "POST")

    def mine_endpoint(self, endpoint_url: str, discovered_params: List[str] = None) -> Dict:
        result = {"url": endpoint_url}
        known = set(discovered_params or [])
        get_params = self.mine_get(endpoint_url)
        post_params = self.mine_post(endpoint_url)
        combined = {g["param"] for g in get_params} | {p["param"] for p in post_params}
        combined.update(known)
        result["get_params"] = get_params
        result["post_params"] = post_params
        result["total_found"] = len(combined)
        result["all_params"] = sorted(combined)
        return result

    def mine_all(self, endpoints: Dict[str, Dict]) -> Dict:
        results = {}
        lock = threading.Lock()
        items = list(endpoints.items())

        def _mine_one(path_info):
            path, info = path_info
            url = info.get("url", "%s%s" % (self.base_url, path))
            known = info.get("params", [])
            r = self.mine_endpoint(url, known)
            with lock:
                results[path] = r

        n = min(self.threads, len(items))
        if n > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
                list(ex.map(_mine_one, items))
        else:
            for item in items:
                _mine_one(item)
        return results

    def run(self, endpoints: Dict[str, Dict] = None) -> Dict:
        if not endpoints:
            endpoints = {"/": {"url": self.base_url, "methods": ["GET"], "params": []}}
        return self.mine_all(endpoints)


def mine(target_url: str, endpoints: Dict[str, Dict] = None,
         sess: Optional['requests.Session'] = None, timeout: float = 10.0,
         threads: int = 1, delay: float = 0.0) -> Dict:
    m = ParamMiner(target_url, sess, timeout, threads, delay)
    return m.run(endpoints)
