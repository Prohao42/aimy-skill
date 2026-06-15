from main import _sess, _TLS12Adapter
import argparse

class FakeArgs:
    timeout = 10
    auth_type = ""
    auth_url = ""
    auth_user = ""
    auth_pass = ""
    session_file = ""

args = FakeArgs()
sess = _sess(args)

r = sess.get("https://idcard.kesug.com/", timeout=10, verify=False)
print("Status:", r.status_code)
print("Has challenge:", "slowAES" in r.text[:2000])
print("Body length:", len(r.text))
