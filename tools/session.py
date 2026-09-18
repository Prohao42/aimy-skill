import requests

from tools.challenge import detect_challenge, solve_with_node
from tools.log_utils import get_logger
from tools.settings import settings
from tools.tls_adapter import get_tls12_adapter

logger = get_logger("session")


def build_session(args=None) -> requests.Session:
    from tools.auth_engine import auth_from_args

    sess = auth_from_args(args) if args else requests.Session()
    # http/https 统一挂 TLS1.2+重试适配器 (否则 http 目标无重试, 行为不一致)
    sess.mount("https://", get_tls12_adapter())
    sess.mount("http://", get_tls12_adapter())
    sess.verify = settings.verify_ssl
    if "User-Agent" not in sess.headers:
        sess.headers["User-Agent"] = settings.user_agent

    _challenge_solved = [False]

    def _patched_send(req, **kwargs):
        resp = _orig_send(req, **kwargs)
        if not _challenge_solved[0]:
            body = resp.text[:2000]
            if "slowAES" in body:
                m = detect_challenge(body)
                if m:
                    cookie_val = solve_with_node(m, req.url)
                    if cookie_val:
                        logger.info("Anti-bot challenge solved, retrying %s %s", req.method, req.url)
                        _challenge_solved[0] = True
                        existing = req.headers.get("Cookie", "")
                        req.headers["Cookie"] = ("%s; __test=%s" % (existing, cookie_val)).strip("; ")
                        resp = _orig_send(req, **kwargs)
        return resp

    _orig_send = sess.send
    sess.send = _patched_send
    return sess
