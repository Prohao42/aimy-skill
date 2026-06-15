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

# Test via the module import
from tools.http_client import HttpClient

hc = HttpClient(timeout=15)
# Now override the adapter
hc.sess.mount("https://", TLS12Adapter())

r = hc.get("https://idcard.kesug.com/")
print("Status:", r.status_code)
print("Has challenge:", "slowAES" in r.text[:2000])
print("Response size:", len(r.text))
