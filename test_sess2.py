import ssl, re, sys
import requests
from requests.adapters import HTTPAdapter

class _TLS12Adapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = ctx
        kwargs["assert_hostname"] = False
        return super().init_poolmanager(*args, **kwargs)

# Build the same function as main.py
def _sess(args):
    sess = requests.Session()
    sess.mount("https://", _TLS12Adapter())
    sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    
    orig_send = sess.send
    chal_solved = [False]
    
    def patched_send(req, **kwargs):
        resp = orig_send(req, **kwargs)
        if not chal_solved[0]:
            body = resp.text[:2000]
            if "slowAES" in body:
                m = re.search(r'toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)', body, re.DOTALL)
                if m:
                    print("Challenge detected!")
                    chal_solved[0] = True
                    # Test if it works without solving
        return resp
    
    sess.send = patched_send
    return sess

class Args:
    timeout = 10
    auth_type = ""
    auth_url = "" 
    auth_user = ""
    auth_pass = ""
    session_file = ""

sess = _sess(Args())
r = sess.get("https://idcard.kesug.com/", timeout=10, verify=False)
print("Status:", r.status_code)
print("Has challenge:", "slowAES" in r.text[:2000])
print("Body len:", len(r.text))
