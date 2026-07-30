from typing import Optional

import requests

from tools.settings import settings

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def make_session(verify: Optional[bool] = None) -> requests.Session:
    sess = requests.Session()
    sess.verify = settings.verify_ssl if verify is None else verify
    sess.headers["User-Agent"] = _USER_AGENT
    return sess
