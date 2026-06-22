import re
import json
import time
from typing import Optional, Dict, List
from urllib.parse import urlparse, urljoin

import requests

from tools.log_utils import get_logger
from tools.playwright_engine import PlaywrightEngine

logger = get_logger("playwright_auth")

LOGIN_FORM_SELECTORS = [
    'input[type="email"]',
    'input[type="text"][name*="user"]',
    'input[type="text"][name*="login"]',
    'input[type="text"][name*="email"]',
    'input[name="username"]',
    'input[name="user"]',
    'input[name="login"]',
    'input[name="email"]',
    'input[id*="user"]',
    'input[id*="login"]',
    'input[id*="email"]',
    'input[placeholder*="user"]',
    'input[placeholder*="email"]',
    'input[placeholder*="login"]',
]

PASSWORD_SELECTORS = [
    'input[type="password"]',
    'input[name="password"]',
    'input[name="pass"]',
    'input[name="passwd"]',
    'input[id*="password"]',
    'input[id*="pass"]',
    'input[placeholder*="password"]',
]

SUBMIT_SELECTORS = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button:has-text("login")',
    'button:has-text("sign in")',
    'button:has-text("log in")',
    'button:has-text("continue")',
    'button:has-text("signin")',
    '[value="Login"]',
    '[value="Sign In"]',
]


class PlaywrightAuth:
    def __init__(self, engine: Optional[PlaywrightEngine] = None):
        self.engine = engine
        self._close_engine = False

    def login(
        self,
        login_url: str,
        username: str,
        password: str,
        auth_type: str = "auto",
        user_field: str = "username",
        pass_field: str = "password",
        timeout: int = 30000,
        success_indicator: Optional[str] = None,
        two_factor_callback: Optional[callable] = None,
    ) -> Dict:
        result = {
            "success": False,
            "cookies": {},
            "headers": {},
            "local_storage": {},
            "redirect_chain": [],
            "error": None,
            "screenshot_path": None,
        }

        close_engine = False
        if self.engine is None:
            if not PlaywrightEngine.is_available():
                result["error"] = "Playwright not available"
                return result
            self.engine = PlaywrightEngine()
            close_engine = True

        try:
            if close_engine:
                self.engine.start()

            page = self.engine.new_page(capture_api=True)
            page.goto(login_url, wait_until="networkidle", timeout=timeout)
            time.sleep(1)

            result["redirect_chain"] = self._capture_redirects(page)
            current_url = page.url
            result["final_url"] = current_url

            if auth_type == "auto":
                filled = self._auto_fill(page, username, password, user_field, pass_field)
            elif auth_type == "form":
                filled = self._fill_fields(page, username, password, user_field, pass_field)
            elif auth_type == "api":
                return self._api_login(login_url, username, password, result)
            elif auth_type == "oauth":
                filled = self._handle_oauth(page, username, password)
            else:
                filled = self._auto_fill(page, username, password, user_field, pass_field)

            if not filled:
                result["error"] = "Could not find login form fields"
                return result

            for selector in SUBMIT_SELECTORS:
                try:
                    btn = page.query_selector(selector)
                    if btn:
                        btn.click()
                        break
                except Exception:
                    continue

            page.wait_for_load_state("networkidle", timeout=timeout)
            time.sleep(1)

            if success_indicator:
                if success_indicator in page.content():
                    result["success"] = True
            elif "error" not in page.url.lower() and "login" not in page.url.lower():
                result["success"] = True
            elif page.url != login_url and page.url != current_url:
                result["success"] = True

            result["cookies"] = self.engine.get_cookies()
            result["local_storage"] = self._get_local_storage(page)
            result["final_url"] = page.url

            if result["success"] and two_factor_callback:
                try:
                    two_factor_callback(page)
                    time.sleep(1)
                    result["success"] = "2fa" in page.url.lower() or len(self.engine.get_cookies()) > len(result.get("cookies", {}))
                except Exception as e:
                    logger.debug("2fa callback: %s", e)

            page.close()

        except Exception as e:
            logger.error("playwright login failed: %s", e, exc_info=True)
            result["error"] = str(e)[:200]
        finally:
            if close_engine and self.engine:
                try:
                    self.engine.stop()
                except Exception:
                    pass

        return result

    def _auto_fill(
        self, page, username: str, password: str,
        user_field: str, pass_field: str,
    ) -> bool:
        user_filled = False
        pass_filled = False

        for selector in LOGIN_FORM_SELECTORS:
            try:
                el = page.query_selector(selector)
                if el:
                    el.fill(username)
                    user_filled = True
                    break
            except Exception:
                continue

        if not user_filled:
            try:
                el = page.query_selector(f'[name="{user_field}"]')
                if el:
                    el.fill(username)
                    user_filled = True
            except Exception:
                pass

        for selector in PASSWORD_SELECTORS:
            try:
                el = page.query_selector(selector)
                if el:
                    el.fill(password)
                    pass_filled = True
                    break
            except Exception:
                continue

        if not pass_filled:
            try:
                el = page.query_selector(f'[name="{pass_field}"]')
                if el:
                    el.fill(password)
                    pass_filled = True
            except Exception:
                pass

        return user_filled and pass_filled

    def _fill_fields(
        self, page, username: str, password: str,
        user_field: str, pass_field: str,
    ) -> bool:
        try:
            el_user = page.query_selector(f'[name="{user_field}"]')
            if not el_user:
                el_user = page.query_selector(f'[id="{user_field}"]')
            if el_user:
                el_user.fill(username)

            el_pass = page.query_selector(f'[name="{pass_field}"]')
            if not el_pass:
                el_pass = page.query_selector(f'[id="{pass_field}"]')
            if el_pass:
                el_pass.fill(password)

            return bool(el_user and el_pass)
        except Exception as e:
            logger.debug("fill fields: %s", e)
            return False

    def _handle_oauth(self, page, username: str, password: str) -> bool:
        try:
            for provider_selector in [
                'button:has-text("sign in with")',
                'button:has-text("log in with")',
                'button:has-text("continue with")',
                'a:has-text("sign in with")',
                'a:has-text("log in with")',
                'a:has-text("continue with")',
            ]:
                el = page.query_selector(provider_selector)
                if el:
                    el.click()
                    page.wait_for_load_state("networkidle", timeout=15000)
                    break

            page.wait_for_selector('input[type="email"], input[type="text"]', timeout=10000)
            return self._auto_fill(page, username, password, "login", "password")
        except Exception as e:
            logger.debug("oauth handler: %s", e)
            return False

    def _api_login(self, url: str, username: str, password: str,
                   result: Dict) -> Dict:
        try:
            resp = requests.post(
                url,
                json={"username": username, "password": password},
                timeout=15,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                token = (
                    data.get("token")
                    or data.get("access_token")
                    or data.get("data", {}).get("token", "")
                )
                if token:
                    result["headers"] = {"Authorization": f"Bearer {token}"}
                    result["success"] = True
        except Exception as e:
            result["error"] = str(e)[:100]
        return result

    def _capture_redirects(self, page) -> List[str]:
        redirects = []
        try:
            redirects.append(page.url)
        except Exception:
            pass
        return redirects

    def _get_local_storage(self, page) -> Dict:
        try:
            return json.loads(
                page.evaluate("JSON.stringify(window.localStorage)")
            )
        except Exception:
            return {}

    @staticmethod
    def cookies_to_session(
        cookies: Dict[str, str], session: requests.Session,
    ) -> requests.Session:
        for k, v in cookies.items():
            session.cookies.set(k, v)
        return session

    @staticmethod
    def is_available() -> bool:
        return PlaywrightEngine.is_available()


def browser_login(
    login_url: str,
    username: str,
    password: str,
    auth_type: str = "auto",
    timeout: int = 30000,
) -> Dict:
    return PlaywrightAuth().login(
        login_url, username, password,
        auth_type=auth_type, timeout=timeout,
    )
