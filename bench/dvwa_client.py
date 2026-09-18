"""DVWA 会话管理: 登录 (CSRF token)、安全级别设置、数据库初始化。

DVWA 所有表单都带 user_token 防伪, 登录/切级别前必须先 GET 页面取 token。
"""

import re
from typing import Optional

import requests

_TOKEN_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]{32})['\"]")


class DvwaSession:
    def __init__(self, base_url: str, username: str = "admin",
                 password: str = "password", verify_ssl: bool = False):
        self.base = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.sess = requests.Session()
        self.sess.verify = verify_ssl
        self.sess.headers["User-Agent"] = "aimy-bench/1.0"
        self._level: Optional[str] = None

    def _token(self, path: str) -> str:
        r = self.sess.get(self.base + path, timeout=10)
        m = _TOKEN_RE.search(r.text)
        if not m:
            raise RuntimeError("user_token not found on %s (status %s)" % (path, r.status_code))
        return m.group(1)

    def ensure_db(self) -> bool:
        """访问 setup.php 并点击 Create/Reset Database (幂等)。"""
        try:
            token = self._token("/setup.php")
            r = self.sess.post(self.base + "/setup.php", data={
                "create_db": "Create / Reset Database",
                "user_token": token,
            }, timeout=15)
            return r.status_code in (200, 302)
        except Exception:
            return False

    def login(self) -> bool:
        token = self._token("/login.php")
        r = self.sess.post(self.base + "/login.php", data={
            "username": self.username,
            "password": self.password,
            "Login": "Login",
            "user_token": token,
        }, timeout=10, allow_redirects=True)
        ok = "login.php" not in r.url and ("PHPSESSID" in self.sess.cookies)
        if not ok:
            raise RuntimeError("DVWA login failed (check credentials / setup.php)")
        return True

    def set_security(self, level: str) -> bool:
        """切换 DVWA 安全级别: low / medium / high / impossible。"""
        token = self._token("/security.php")
        self.sess.post(self.base + "/security.php", data={
            "security": level,
            "seclev_submit": "Submit",
            "user_token": token,
        }, timeout=10)
        # cookie 是权威来源, 强制兜底
        self.sess.cookies.set("security", level)
        self._level = level
        return True


def connect(base_url: str, username: str = "admin",
            password: str = "password", verify_ssl: bool = False) -> DvwaSession:
    """一键: 建库(幂等) -> 登录。返回就绪的 DvwaSession。"""
    dvwa = DvwaSession(base_url, username, password, verify_ssl)
    dvwa.ensure_db()   # 已初始化时无害
    dvwa.login()
    return dvwa
