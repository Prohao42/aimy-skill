#!/usr/bin/env python3
"""Run orchestrator auto scan with full traceback capturing."""

import sys, traceback
sys.path.insert(0, ".")

from tools.orchestrator import run
from tools.settings import settings
import requests
from requests.adapters import HTTPAdapter
import ssl

class _TLS12Adapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        if not settings.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            kwargs["assert_hostname"] = False
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(connections, maxsize=max(100, maxsize), block=block, **kwargs)
    def send(self, request, **kwargs):
        request.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        return super().send(request, **kwargs)

sess = requests.Session()
sess.mount("https://", _TLS12Adapter())
sess.mount("http://", _TLS12Adapter())
sess.verify = settings.verify_ssl

import tools.http_client
_original_send = sess.send
_challenge_solved = [False]

def _patched_send(req, **kwargs):
    global _challenge_solved
    resp = _original_send(req, **kwargs)

    if not _challenge_solved[0] and resp.status_code == 200:
        body = resp.text[:3000]
        if "slowAES" in body and "toNumbers" in body:
            import re
            from tools.http_client import _solve_challenge
            cookie_val = _solve_challenge(body, req.url)
            if cookie_val:
                _challenge_solved[0] = True
                req.headers["Cookie"] = f"__test={cookie_val}"
                resp = _original_send(req, **kwargs)
    return resp

sess.send = _patched_send

if len(sys.argv) > 1:
    target = sys.argv[1]
else:
    print("Usage: python run_scan.py <target_url>", file=sys.stderr)
    sys.exit(1)

try:
    result = run(target, sess=sess, timeout=15, threads=10)
    print("\n=== RESULT ===")
    import json
    print(json.dumps(result, indent=2, default=str))
except SystemExit:
    raise
except:
    traceback.print_exc()
