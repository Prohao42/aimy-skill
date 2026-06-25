import sys, traceback
sys.path.insert(0, ".")

import requests
from tools.orchestrator import run
from tools.http_client import _solve_challenge
from tools.settings import settings

sess = requests.Session()
sess.verify = settings.verify_ssl

_solved = [False]
_original_send = sess.send
def _patched_send(req, **kwargs):
    resp = _original_send(req, **kwargs)
    if not _solved[0] and resp.status_code == 200:
        body = resp.text[:3000]
        if "slowAES" in body and "toNumbers" in body:
            cookie_val = _solve_challenge(body, req.url)
            if cookie_val:
                _solved[0] = True
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
