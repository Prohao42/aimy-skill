import requests, ssl, urllib3, socket
from urllib3.util.ssl_ import create_urllib3_context

# Try with custom SSL context
ctx = create_urllib3_context()
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Monkey-patch the adapter
from requests.adapters import HTTPAdapter
class FixedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = ctx
        kwargs["assert_hostname"] = False
        return super().init_poolmanager(*args, **kwargs)

s = requests.Session()
s.mount("https://", FixedAdapter())
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

try:
    r = s.get("https://idcard.kesug.com/", timeout=10, verify=False)
    print("Status:", r.status_code)
    print("Body:", r.text[:300])
except Exception as e:
    print(f"FixedAdapter failed: {e}")
    # Try urllib3 directly
    try:
        http = urllib3.PoolManager(
            cert_reqs='CERT_NONE',
            assert_hostname=False,
            ssl_minimum_version=sll.TLSVersion.TLSv1_2,
            ssl_maximum_version=sll.TLSVersion.TLSv1_2,
        )
        r = http.request("GET", "https://idcard.kesug.com/", headers={"User-Agent": "Mozilla/5.0"})
        print("urllib3 status:", r.status)
        print("urllib3 body:", r.data[:300].decode())
    except Exception as e2:
        print(f"urllib3 failed: {e2}")
