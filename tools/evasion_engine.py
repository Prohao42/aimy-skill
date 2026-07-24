import random
import string
import time

from tools.log_utils import get_logger

logger = get_logger("evasion_engine")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "curl/8.4.0",
    "Wget/1.21.4",
    "Python-urllib/3.11",
]

REFERERS = [
    "https://www.google.com/search?q=",
    "https://www.baidu.com/s?wd=",
    "https://www.bing.com/search?q=",
    "https://t.co/",
    "https://l.facebook.com/l.php?u=",
    "",
]

ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "ko-KR,ko;q=0.9,en;q=0.8",
    "en-GB,en;q=0.8",
]


class EvasionEngine:
    def __init__(self):
        self._agent_pool = list(USER_AGENTS)
        self._referer_pool = list(REFERERS)
        self._lang_pool = list(ACCEPT_LANGS)
        self._min_delay = 0.5
        self._max_delay = 2.5
        self._jitter = 0.3
        self._last_request = 0.0
        self._consecutive_count = 0
        self._rotate_after = random.randint(5, 15)

    def _pace_request(self):
        now = time.time()
        elapsed = now - self._last_request
        base_delay = random.uniform(self._min_delay, self._max_delay)
        jitter_amount = base_delay * random.uniform(-self._jitter, self._jitter)
        delay = max(0.1, base_delay + jitter_amount)
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request = time.time()
        self._consecutive_count += 1

    def headers(self, purpose: str = "recon") -> dict:
        self._pace_request()
        ua = random.choice(self._agent_pool)
        h = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(self._lang_pool),
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        referer = random.choice(self._referer_pool)
        if referer:
            h["Referer"] = referer + "".join(random.choices(string.ascii_lowercase, k=random.randint(3, 10)))

        if self._consecutive_count >= self._rotate_after:
            self._agent_pool = list(USER_AGENTS)
            random.shuffle(self._agent_pool)
            self._consecutive_count = 0
            self._rotate_after = random.randint(5, 15)

        return h

    def stealth_params(self, orig_url: str) -> str:
        if random.random() < 0.3:
            noise = "&_=%d" % int(time.time() * 1000)
            return orig_url + noise
        if random.random() < 0.1:
            noise = "&__cf_chl_tk=%s" % "".join(random.choices(string.hexdigits, k=32))
            return orig_url + noise
        return orig_url

    def request_with_evasion(self, sess, method: str, url: str,
                              purpose: str = "recon", **kwargs) -> "requests.Response":
        h = kwargs.pop("headers", {})
        ev_h = self.headers(purpose)
        ev_h.update(h)
        url = self.stealth_params(url)
        return sess.request(method, url, headers=ev_h, **kwargs)

    def set_pacing(self, min_delay: float = 0.5, max_delay: float = 2.5, jitter: float = 0.3):
        self._min_delay = min_delay
        self._max_delay = max_delay
        self._jitter = jitter

    def fingerprint(self) -> dict:
        return {
            "user_agent_pool_size": len(self._agent_pool),
            "pacing": {"min": self._min_delay, "max": self._max_delay, "jitter": self._jitter},
            "rotate_after": self._rotate_after,
            "consecutive_count": self._consecutive_count,
        }
