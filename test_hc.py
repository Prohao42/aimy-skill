from tools.http_client import HttpClient
hc = HttpClient(timeout=15)
r = hc.get("https://idcard.kesug.com/")
print("Status:", r.status_code)
print("Has challenge:", "slowAES" in r.text[:2000])
print('Has app div:', '<div id="app"' in r.text)
print("Response size:", len(r.text))

# Second request should not trigger challenge
r2 = hc.get("https://idcard.kesug.com/robots.txt")
print("\nrobots.txt:", r2.status_code, r2.text[:100])
