from tools.http_client import HttpClient
hc = HttpClient(timeout=15)
r = hc.get("https://idcard.kesug.com/")
print("Status:", r.status_code)
print("Challenge present:", "slowAES" in r.text[:2000])
print("Response size:", len(r.text))
print('Has app div:', '<div id="app"' in r.text)
print()

# Second request should not need solving
r2 = hc.get("https://idcard.kesug.com/robots.txt")
print("robots.txt:", r2.status_code, r2.text[:100])
