import concurrent.futures
import re
import threading
import time
import urllib.parse
from typing import Dict, List, Optional, Set

import requests

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("crawler")


def _flatten_dict(d: dict, prefix: str = "") -> dict:
    items = {}
    for k, v in d.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            items.update(_flatten_dict(v, path))
        else:
            items[path] = v
    return items


IGNORE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}

SPA_INDICATORS = [
    r'id=["\']root["\']',
    r'id=["\']app["\']',
    r'id=["\']__nuxt["\']',
    r'id=["\']__next["\']',
    r'__vite_is_modern_browser',
    r'createApp\(',
    r'ReactDOM\.createRoot',
    r'Vue\.createApp',
]

COMMON_API_PATHS = [
    "/api/health", "/api/status", "/api/v1/health", "/api/ping",
    "/api/users", "/api/user", "/api/login", "/api/auth",
    "/api/config", "/api/settings", "/api/info", "/api/version",
    "/api/v1/users", "/api/v1/user", "/api/v1/login", "/api/v1/auth",
    "/api/v1/config", "/api/v1/version", "/api/v1/models",
    "/api/v1/chat/completions", "/api/v1/completions",
    "/graphql", "/api/graphql", "/api/openapi.json",
    "/swagger-resources", "/api/swagger-resources",
    "/api/docs", "/api/v1/docs",
    "/.env", "/api/.env",
    "/actuator", "/api/actuator", "/actuator/health",
    "/sitemap.xml", "/robots.txt",
]

HAS_BS4 = False
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    pass


class Crawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 50,
                 sess: Optional['requests.Session'] = None, timeout: float = 10.0,
                 delay: float = 0.0):
        self.base_url = base_url.rstrip("/")
        self.base_netloc = urllib.parse.urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.delay = delay
        self.sess = sess
        self.visited: Set[str] = set()
        self.endpoints: Dict[str, Dict] = {}
        self.forms: List[Dict] = []
        self.api_endpoints: Set[str] = set()
        self.all_params: Set[str] = set()
        self.pages_crawled = 0
        self.js_api_endpoints: Set[str] = set()
        self.is_spa = False
        self._http = None

    def _get_http(self) -> 'requests.Session':
        if self._http is None:
            import requests
            self._http = self.sess or requests.Session()
            self._http.verify = settings.verify_ssl
            self._http.headers.setdefault("User-Agent",
                                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        return self._http

    def _normalize(self, href: str, current: str) -> Optional[str]:
        parsed = urllib.parse.urlparse(href)
        if parsed.scheme and parsed.scheme not in ("http", "https"):
            return None
        full = urllib.parse.urljoin(current, href)
        frag = urllib.parse.urlparse(full)
        normalized = "%s://%s%s" % (frag.scheme, frag.netloc, frag.path.rstrip("/") or "/")
        if frag.query:
            normalized += "?" + frag.query
        return normalized

    def _should_crawl(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc != self.base_netloc:
            return False
        path = parsed.path.lower()
        for ext in IGNORE_EXTENSIONS:
            if path.endswith(ext):
                return False
        return True

    def _detect_spa(self, html: str) -> bool:
        for pat in SPA_INDICATORS:
            if re.search(pat, html):
                return True
        return False

    def _extract_js_bundles(self, html: str) -> List[str]:
        bundles = []
        for m in re.finditer(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE):
            src = m.group(1)
            if src not in bundles:
                bundles.append(src)
        return bundles

    def _analyze_js_for_api(self, js_content: str) -> Set[str]:
        apis = set()
        patterns = [
            r'["\'](/api/[\w/]+)["\']',
            r'["\'](/v1/[\w/]+)["\']',
            r'["\'](/v2/[\w/]+)["\']',
            r'["\'](/v3/[\w/]+)["\']',
            r'baseURL["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'(?:get|post|put|delete|request)\s*\(\s*["\']([\w/]+)["\']',
            r'url:\s*["\']([\w/]+)["\']',
            r'path:\s*["\']([\w/]+)["\']',
            r'route:\s*["\']([\w/]+)["\']',
        ]
        for pat in patterns:
            for m in re.finditer(pat, js_content, re.IGNORECASE):
                url = m.group(1).rstrip("/")
                if url and len(url) > 4:
                    apis.add(url)
        route_patterns = [
            r'path:\s*["\'](/\w+)["\']',
            r'route:\s*["\'](/\w+)["\']',
            r'["\'](/[\w/-]+)["\']\s*[:\]]\s*\{[^}]*component',
        ]
        for pat in route_patterns:
            for m in re.finditer(pat, js_content):
                route = m.group(1)
                if route and len(route) > 1 and "/" in route:
                    apis.add(route)
        return apis

    def _hit_common_api(self) -> Set[str]:
        found = set()
        http = self._get_http()
        for path in COMMON_API_PATHS:
            try:
                r = http.get("%s%s" % (self.base_url, path), timeout=max(3, self.timeout * 0.5),
                             verify=settings.verify_ssl)
                ct = r.headers.get("Content-Type", "")
                if r.status_code not in (404, 0) and (len(r.text) < 7000 or "text/html" not in ct):
                    "%s [%d] %s" % (path, r.status_code, ct.split(";")[0])
                    found.add((path, r.status_code, ct, r.text[:200]))
            except Exception as e:
                logger.debug("common api %s: %s", path, e)
        return found

    def _extract_forms(self, html: str, current: str):
        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, "html.parser")
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    if action:
                        action_url = self._normalize(action, current) or current
                    else:
                        action_url = current
                    inputs = []
                    for inp in form.find_all("input"):
                        name = inp.get("name")
                        if name:
                            inputs.append({
                                "name": name,
                                "type": inp.get("type", "text"),
                                "value": inp.get("value", ""),
                            })
                            self.all_params.add(name)
                    self.forms.append({
                        "action": action_url,
                        "method": form.get("method", "get").upper(),
                        "inputs": inputs,
                    })
            except Exception as e:
                logger.debug("extract forms: %s", e)
        else:
            for m in re.finditer(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.IGNORECASE):
                action = self._normalize(m.group(1), current) or current
                inputs = []
                for im in re.finditer(r'<input[^>]*name=["\']([^"\']+)["\']', html[m.end():m.end()+500], re.IGNORECASE):
                    inputs.append({"name": im.group(1), "type": "text"})
                    self.all_params.add(im.group(1))
                self.forms.append({"action": action, "method": "GET", "inputs": inputs})

    def _extract_endpoints(self, html: str, current: str):
        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, "html.parser")
                for tag in soup.find_all("a"):
                    href = tag.get("href")
                    if href:
                        next_url = self._normalize(href, current)
                        if next_url and self._should_crawl(next_url):
                            path = urllib.parse.urlparse(next_url).path.rstrip("/") or "/"
                            if path not in self.endpoints:
                                params = []
                                q = urllib.parse.urlparse(next_url).query
                                if q:
                                    for kv in q.split("&"):
                                        if "=" in kv:
                                            k = kv.split("=")[0]
                                            params.append(k)
                                            self.all_params.add(k)
                                self.endpoints[path] = {
                                    "url": next_url,
                                    "methods": ["GET"],
                                    "params": params,
                                }
            except Exception as e:
                logger.debug("extract endpoints: %s", e)
        api_pattern = re.compile(r'["\'](/api/[\w/]+)["\']', re.IGNORECASE)
        for m in api_pattern.finditer(html):
            api_path = m.group(1)
            self.api_endpoints.add(api_path)
            full = self._normalize(api_path, current)
            path = urllib.parse.urlparse(full or api_path).path.rstrip("/") or "/"
            if path not in self.endpoints:
                self.endpoints[path] = {"url": full or api_path, "methods": ["GET"], "params": []}

    def _extract_embedded_params(self, html: str):
        patterns = [
            r'["\']([a-z_]+)["\']\s*:\s*["\']',
            r'var\s+(\w+)\s*=\s*["\']?',
            r'let\s+(\w+)\s*=\s*["\']?',
            r'const\s+(\w+)\s*=\s*["\']?',
        ]
        for pat in patterns:
            for m in re.finditer(pat, html):
                name = m.group(1)
                if len(name) > 1 and name.isidentifier():
                    self.all_params.add(name)

    def _fetch_page(self, url: str) -> Optional[tuple]:
        http = self._get_http()
        try:
            r = http.get(url, timeout=self.timeout)
            return (url, r)
        except Exception as e:
            logger.debug("crawl %s: %s", url, e)
            return None

    def _extract_ssr_data(self, html: str, base: str):
        next_data = re.search(r'<script[^>]*id="__NEXT_DATA__"[^>]*type="application/json"[^>]*>(.*?)</script>', html, re.DOTALL)
        if next_data:
            try:
                import json
                data = json.loads(next_data.group(1))
                props = data.get("props", {}).get("pageProps", {})
                for k, v in _flatten_dict(props).items():
                    if isinstance(v, str) and v.startswith("/"):
                        self.api_endpoints.add(v)
            except Exception:
                pass
        init_state = re.search(r'window\.__INITIAL_STATE__\s*=\s*({.*?});', html, re.DOTALL)
        if init_state:
            try:
                import json
                data = json.loads(init_state.group(1))
                for k, v in _flatten_dict(data).items():
                    if isinstance(v, str) and v.startswith("/api/"):
                        self.api_endpoints.add(v)
                        p = urllib.parse.urlparse(v).path.rstrip("/") or "/"
                        if p not in self.endpoints:
                            self.endpoints[p] = {"url": v, "methods": ["GET"], "params": [], "source": "ssr"}
                    if isinstance(v, str) and v.startswith("http"):
                        self.api_endpoints.add(v)
            except Exception:
                pass
        nuxt_data = re.search(r'<script[^>]*>window\.__NUXT__\s*=\s*({.*?})</script>', html, re.DOTALL)
        if nuxt_data:
            try:
                import json
                data = json.loads(nuxt_data.group(1))
                for k, v in _flatten_dict(data).items():
                    if isinstance(v, str) and v.startswith("/"):
                        self.api_endpoints.add(v)
            except Exception:
                pass

    def _process_page(self, url: str, r) -> List[tuple]:
        html = r.text
        new_urls = []

        self._extract_forms(html, url)
        self._extract_endpoints(html, url)
        self._extract_ssr_data(html, url)
        self._extract_embedded_params(html)

        if r.url != url and self._should_crawl(r.url):
            new_urls.append((r.url, 0))

        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, "html.parser")
                for tag in soup.find_all("a"):
                    href = tag.get("href")
                    if href:
                        next_url = self._normalize(href, url)
                        if next_url and self._should_crawl(next_url):
                            new_urls.append((next_url, 0))
            except Exception:
                pass
        else:
            for m in re.finditer(r'<a[^>]*href=["\']([^"\'>]+)["\']', html, re.IGNORECASE):
                href = m.group(1)
                next_url = self._normalize(href, url)
                if next_url and self._should_crawl(next_url):
                    new_urls.append((next_url, 0))

        return new_urls

    def crawl(self) -> Dict:
        http = self._get_http()
        queue = [(self.base_url, 0)]
        visited_lock = threading.Lock()
        state_lock = threading.Lock()
        crawl_workers = min(8, self.max_pages) if self.max_pages > 1 else 1

        while queue and self.pages_crawled < self.max_pages:
            batch = []
            while queue and len(batch) < crawl_workers * 2:
                url, depth = queue.pop(0)
                with visited_lock:
                    if url in self.visited:
                        continue
                    self.visited.add(url)
                batch.append((url, depth))

            if not batch:
                break

            if crawl_workers > 1 and len(batch) > 1:
                with concurrent.futures.ThreadPoolExecutor(max_workers=crawl_workers) as ex:
                    futures = {ex.submit(self._fetch_page, url): (url, depth) for url, depth in batch}
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        if not result:
                            continue
                        url, r = result
                        with state_lock:
                            self.pages_crawled += 1
                            cur_depth = futures[future][1]
                        new_urls = self._process_page(url, r)
                        with state_lock:
                            if cur_depth < self.max_depth:
                                for nu, nd in new_urls:
                                    queue.append((nu, cur_depth + 1))
            else:
                for url, depth in batch:
                    result = self._fetch_page(url)
                    if not result:
                        continue
                    url, r = result
                    self.pages_crawled += 1
                    new_urls = self._process_page(url, r)
                    if depth < self.max_depth:
                        for nu, nd in new_urls:
                            queue.append((nu, depth + 1))

            if self.delay > 0:
                time.sleep(self.delay)

        if self.pages_crawled >= 1 and not self.is_spa:
            try:
                r = http.get(self.base_url, timeout=self.timeout)
                self.is_spa = self._detect_spa(r.text)
            except Exception:
                pass

        if self.is_spa:
            try:
                r = http.get(self.base_url, timeout=self.timeout)
                bundles = self._extract_js_bundles(r.text)
                for js_url in bundles[:5]:
                    try:
                        js_r = http.get(js_url if js_url.startswith("http") else
                                        "%s/%s" % (self.base_url, js_url.lstrip("/")),
                                        timeout=self.timeout)
                        if js_r.status_code == 200:
                            apis = self._analyze_js_for_api(js_r.text)
                            for a in apis:
                                self.api_endpoints.add(a)
                                self.js_api_endpoints.add(a)
                    except Exception as e:
                        logger.debug("js bundle %s: %s", js_url, e)
                fallback = self._hit_common_api()
                for path, status, ct, preview in fallback:
                    p = "/" + path.lstrip("/")
                    if p not in self.endpoints:
                        self.endpoints[p] = {"url": "%s%s" % (self.base_url, p),
                                             "methods": ["GET"], "params": [],
                                             "status": status, "content_type": ct,
                                             "preview": preview[:100]}
            except Exception:
                pass

        return {
            "urls": list(self.visited),
            "endpoints": self.endpoints,
            "forms": self.forms,
            "api_endpoints": list(self.api_endpoints),
            "parameters": list(self.all_params),
            "is_spa": self.is_spa,
            "js_api_endpoints": list(self.js_api_endpoints)[:50],
            "summary": {
                "pages_crawled": self.pages_crawled,
                "endpoints_found": len(self.endpoints),
                "forms_found": len(self.forms),
                "unique_params": len(self.all_params),
                "api_endpoints": len(self.api_endpoints),
                "is_spa": self.is_spa,
                "js_api_discovered": len(self.js_api_endpoints),
            },
        }


def crawl(target: str, max_depth: int = 3, max_pages: int = 50,
          sess: Optional['requests.Session'] = None, timeout: float = 10.0,
          delay: float = 0.0) -> Dict:
    c = Crawler(target, max_depth, max_pages, sess, timeout, delay)
    return c.crawl()
