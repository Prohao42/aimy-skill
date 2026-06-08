import requests
from typing import Optional, Dict, Any

class HttpClient:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0):
        self.sess = sess or requests.Session()
        self.timeout = timeout
        if "User-Agent" not in self.sess.headers:
            self.sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.sess.get(url, timeout=self.timeout, verify=False, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.sess.post(url, timeout=self.timeout, verify=False, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response:
        return self.sess.put(url, timeout=self.timeout, verify=False, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response:
        return self.sess.delete(url, timeout=self.timeout, verify=False, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        return self.sess.request(method, url, timeout=self.timeout, verify=False, **kwargs)

    def resolve_url(self, base: str, path: str) -> str:
        base = base.rstrip("/")
        path = path.lstrip("/")
        return "%s/%s" % (base, path)
