import os
import json
import time
import base64
from typing import Optional, Dict, List, Any, Callable, TYPE_CHECKING
from dataclasses import dataclass, field
from urllib.parse import urlparse

from tools.log_utils import get_logger

logger = get_logger("playwright_engine")

HAS_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext
    HAS_PLAYWRIGHT = True
except ImportError:
    Page = Any
    Browser = Any
    BrowserContext = Any


@dataclass
class CapturedRequest:
    method: str
    url: str
    resource_type: str
    headers: Dict[str, str]
    status: Optional[int] = None
    response_body: Optional[str] = None
    timestamp: float = 0.0


class PlaywrightEngine:
    def __init__(
        self,
        headless: bool = True,
        user_agent: Optional[str] = None,
        viewport: Dict[str, int] = None,
        ignore_https_errors: bool = True,
        proxy: Optional[str] = None,
    ):
        if not HAS_PLAYWRIGHT:
            raise ImportError(
                "playwright not installed. Run: pip install playwright && python -m playwright install chromium"
            )
        self._headless = headless
        self._user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self._viewport = viewport or {"width": 1280, "height": 720}
        self._ignore_https_errors = ignore_https_errors
        self._proxy = proxy
        self._pw = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._captured_requests: List[CapturedRequest] = []
        self._api_patterns: List[str] = []

    def start(self):
        self._pw = sync_playwright().start()
        launch_kw = {
            "headless": self._headless,
            "args": [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-web-security",
            ],
        }
        if self._proxy:
            launch_kw["proxy"] = {"server": self._proxy}
        self._browser = self._pw.chromium.launch(**launch_kw)
        self._context = self._browser.new_context(
            user_agent=self._user_agent,
            viewport=self._viewport,
            ignore_https_errors=self._ignore_https_errors,
        )
        logger.info(
            "Playwright started (headless=%s, browser=%s)",
            self._headless, self._browser.version,
        )

    def stop(self):
        if self._context:
            try:
                self._context.close()
            except Exception:
                pass
        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass
        if self._pw:
            try:
                self._pw.stop()
            except Exception:
                pass
        logger.info("Playwright stopped")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def new_page(self, capture_api: bool = False) -> Page:
        page = self._context.new_page()
        if capture_api:
            self._captured_requests.clear()
            page.on("response", self._on_response)
        return page

    def _on_response(self, response):
        url = response.url
        req = response.request
        captured = CapturedRequest(
            method=req.method,
            url=url,
            resource_type=req.resource_type,
            headers=dict(response.headers),
            status=response.status,
            timestamp=time.time(),
        )
        resource_type = req.resource_type
        if resource_type in ("xhr", "fetch") or (
            resource_type == "document" and "api" in urlparse(url).path
        ):
            try:
                body = response.text()
                if body and len(body) < 50000:
                    captured.response_body = body[:10000]
            except Exception:
                pass
            self._captured_requests.append(captured)
        elif resource_type == "script":
            try:
                body = response.text()
                if body and len(body) < 200000:
                    captured.response_body = body[:20000]
            except Exception:
                pass
            self._captured_requests.append(captured)

    def get_api_calls(self) -> List[CapturedRequest]:
        return [
            r for r in self._captured_requests
            if r.resource_type in ("xhr", "fetch")
            or ("api" in urlparse(r.url).path)
        ]

    def get_scripts(self) -> List[CapturedRequest]:
        return [
            r for r in self._captured_requests if r.resource_type == "script"
        ]

    def navigate_and_wait(
        self,
        page: Page,
        url: str,
        wait_until: str = "networkidle",
        timeout: int = 30000,
    ):
        page.goto(url, wait_until=wait_until, timeout=timeout)

    def screenshot(self, page: Page, path: str) -> Optional[str]:
        try:
            page.screenshot(path=path, full_page=True)
            return path
        except Exception as e:
            logger.debug("screenshot failed: %s", e)
            return None

    def get_cookies(self) -> Dict[str, str]:
        if not self._context:
            return {}
        return {c["name"]: c["value"] for c in self._context.cookies()}

    def inject_session(
        self,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        storage_state: Optional[Dict] = None,
    ):
        if cookies:
            self._context.add_cookies(
                [{"name": k, "value": v, "domain": "", "path": "/"}
                 for k, v in cookies.items()]
            )
        if headers:
            self._context.set_extra_http_headers(headers)
        if storage_state:
            self._context.add_init_script(
                "() => { %s }" % json.dumps(storage_state)
            )

    def set_api_patterns(self, patterns: List[str]):
        self._api_patterns = patterns

    @staticmethod
    def is_available() -> bool:
        return HAS_PLAYWRIGHT
