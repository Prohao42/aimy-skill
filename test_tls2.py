import ssl
import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

class TLS12Adapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = ctx
        kwargs["assert_hostname"] = False
        return super().init_poolmanager(*args, **kwargs)

s = requests.Session()
s.mount("https://", TLS12Adapter())
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

try:
    r = s.get("https://idcard.kesug.com/", timeout=10, verify=False)
    print("Status:", r.status_code)
    print("Body:", r.text[:300])
except Exception as e:
    print(f"Error: {e}")
