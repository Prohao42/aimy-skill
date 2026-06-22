import re
import json
import time
import urllib.parse
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin

from tools.log_utils import get_logger
from tools.playwright_engine import PlaywrightEngine, CapturedRequest

logger = get_logger("spa_crawler")

API_ROUTE_PATTERNS = [
    re.compile(rb'["\'](/api/[\w/]+)["\']'),
    re.compile(rb'["\'](/v\d+/[\w/]+)["\']'),
    re.compile(rb'["\'](/[\w-]+/[\w-]+/[\w-]+)["\']'),
    re.compile(rb'["\'](/graphql)["\']'),
    re.compile(rb'["\'](/actuator/[\w/]*)["\']'),
    re.compile(rb'["\'](/swagger[\w/.-]*)["\']'),
    re.compile(rb'["\'](/\w+\.json)["\']'),
]

ROUTE_PATTERNS_JS = [
    re.compile(rb'path:\s*["\'](/?[\w/-]+)["\']'),
    re.compile(rb'route:\s*["\'](/?[\w/-]+)["\']'),
    re.compile(rb'["\'](/?[\w/-]+)["\']\s*[:\]]\s*\{[^}]*component'),
    re.compile(rb'(?:get|post|put|delete|request)\s*\(\s*["\']([\w/{}:-]+)["\']'),
    re.compile(rb'baseURL["\']?\s*[:=]\s*["\']([^"\']+)["\']'),
    re.compile(rb'url:\s*["\']([\w/{}]+)["\']'),
]


class SpaCrawler:
    def __init__(
        self,
        base_url: str,
        max_clicks: int = 20,
        max_depth: int = 2,
        timeout: int = 30000,
        engine: Optional[PlaywrightEngine] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_netloc = urlparse(self.base_url).netloc
        self.max_clicks = max_clicks
        self.max_depth = max_depth
        self.timeout = timeout
        self.engine = engine

        self.discovered_endpoints: Dict[str, Dict] = {}
        self.api_routes: Set[str] = set()
        self.js_api_routes: Set[str] = set()
        self.clickable_texts: List[str] = []
        self.internal_links: Set[str] = set()

    def crawl(self) -> Dict:
        close_engine = False
        if self.engine is None:
            if not PlaywrightEngine.is_available():
                return self._empty_result("Playwright not available")
            self.engine = PlaywrightEngine()
            close_engine = True

        try:
            if close_engine:
                self.engine.start()

            self._crawl_internal()
        except Exception as e:
            logger.error("spa crawl failed: %s", e, exc_info=True)
            return self._empty_result(str(e)[:80])
        finally:
            if close_engine and self.engine:
                try:
                    self.engine.stop()
                except Exception:
                    pass

        return {
            "endpoints": self.discovered_endpoints,
            "api_routes": list(self.api_routes)[:100],
            "js_api_routes": list(self.js_api_routes)[:100],
            "internal_links": list(self.internal_links)[:100],
            "urls_crawled": len(self.internal_links),
            "api_discovered": len(self.api_routes),
        }

    def _crawl_internal(self):
        page = self.engine.new_page(capture_api=True)

        self.engine.navigate_and_wait(
            page, self.base_url, timeout=self.timeout
        )
        time.sleep(1)

        self._extract_from_page(page)
        self._analyze_scripts()

        depth = 0
        clicks = 0
        visited_texts = set()

        while clicks < self.max_clicks and depth < self.max_depth:
            links = self._get_internal_links(page)
            found_new = False
            for href in links:
                if href not in self.internal_links and clicks < self.max_clicks:
                    self.internal_links.add(href)
                    found_new = True
                    try:
                        page.goto(href, wait_until="domcontentloaded",
                                  timeout=self.timeout)
                        time.sleep(0.5)
                        self._extract_from_page(page)
                        clicks += 1
                    except Exception as e:
                        logger.debug("spa goto %s: %s", href[:50], e)

            if not found_new:
                clickable = self._get_clickable_elements(page)
                for text in clickable:
                    if text not in visited_texts and clicks < self.max_clicks:
                        visited_texts.add(text)
                        try:
                            link = page.get_by_text(text, exact=True)
                            if link.count() > 0:
                                link.first.click(timeout=5000)
                                time.sleep(0.5)
                                self._extract_from_page(page)
                                clicks += 1
                        except Exception as e:
                            logger.debug("spa click %s: %s", text[:30], e)

            depth += 1

        page.close()

    def _extract_from_page(self, page):
        try:
            html = page.content()

            url = page.url
            path = urlparse(url).path.rstrip("/") or "/"
            if path not in self.discovered_endpoints:
                self.discovered_endpoints[path] = {
                    "url": url, "methods": ["GET"], "params": [], "spa": True,
                }

            scripts = page.query_selector_all("script[src]")
            for s in scripts:
                src = s.get_attribute("src")
                if src:
                    full_url = urljoin(self.base_url, src)
                    path2 = urlparse(full_url).path
                    self.js_api_routes.add(path2)

            for a in page.query_selector_all("a[href]"):
                href = a.get_attribute("href")
                if href and not href.startswith("#") and not href.startswith("javascript:"):
                    full = urljoin(url, href)
                    if urlparse(full).netloc == self.base_netloc:
                        self.internal_links.add(full)

        except Exception as e:
            logger.debug("extract page: %s", e)

        api_calls = self.engine.get_api_calls()
        for req in api_calls:
            path = urlparse(req.url).path
            if path and len(path) > 3:
                self.api_routes.add(path)
                if req.response_body:
                    self._parse_json_response(req.response_body, req.url)
                ep = {
                    "url": req.url,
                    "methods": [req.method],
                    "status": req.status,
                    "spa_api": True,
                }
                if path not in self.discovered_endpoints:
                    self.discovered_endpoints[path] = ep
                else:
                    existing = self.discovered_endpoints[path]
                    if req.method not in existing.get("methods", []):
                        existing["methods"].append(req.method)

    def _analyze_scripts(self):
        for script in self.engine.get_scripts():
            body = script.response_body
            if not body:
                continue
            body_bytes = body.encode("utf-8", errors="replace")
            for pat in API_ROUTE_PATTERNS:
                for m in pat.finditer(body_bytes):
                    route = m.group(1).decode("ascii", errors="replace")
                    if len(route) > 3:
                        self.js_api_routes.add(route)
            for pat in ROUTE_PATTERNS_JS:
                for m in pat.finditer(body_bytes):
                    route = m.group(1).decode("ascii", errors="replace")
                    if len(route) > 2:
                        self.js_api_routes.add(route)

    def _parse_json_response(self, body: str, url: str):
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for key in ("endpoints", "routes", "apis", "links"):
                    if key in data and isinstance(data[key], list):
                        for item in data[key]:
                            if isinstance(item, str) and item.startswith("/"):
                                self.api_routes.add(item)
        except (json.JSONDecodeError, TypeError):
            pass

    def _get_internal_links(self, page) -> List[str]:
        links = []
        try:
            for a in page.query_selector_all("a[href]"):
                href = a.get_attribute("href")
                if href and not href.startswith("#") and not href.startswith("javascript:"):
                    full = urljoin(self.base_url, href)
                    if urlparse(full).netloc == self.base_netloc:
                        links.append(full)
        except Exception as e:
            logger.debug("get links: %s", e)
        return links

    def _get_clickable_elements(self, page) -> List[str]:
        texts = []
        try:
            for selector in ("button", "a", '[role="button"]', '[onclick]'):
                elements = page.query_selector_all(selector)
                for el in elements:
                    text = el.text_content()
                    if text and text.strip() and len(text.strip()) < 30:
                        texts.append(text.strip())
        except Exception as e:
            logger.debug("get clickable: %s", e)
        return list(set(texts))

    def _empty_result(self, reason: str) -> Dict:
        return {
            "endpoints": {},
            "api_routes": [],
            "js_api_routes": [],
            "internal_links": [],
            "urls_crawled": 0,
            "api_discovered": 0,
            "error": reason,
        }


def crawl_spa(
    target: str,
    max_clicks: int = 20,
    max_depth: int = 2,
    timeout: int = 30000,
    engine: Optional[PlaywrightEngine] = None,
) -> Dict:
    c = SpaCrawler(target, max_clicks, max_depth, timeout, engine)
    return c.crawl()
