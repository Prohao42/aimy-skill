import requests, urllib3, re, json
urllib3.disable_warnings()

s = requests.Session()
s.cookies.set('__test', 'dde09b5cbd6693a64e2351ca015467fb')

r = s.get('https://idcard.kesug.com/assets/index-CApTIDIg.js', timeout=10, verify=False)

# Find all strings that look like API endpoints
endpoints = set(re.findall(r'["\x27](/(?:api|v1|v2|upload|render|image|photo|card|generate|save|create|preview)[a-zA-Z0-9_/.-]*?)["\x27]', r.text))
print("=== API Endpoints ===")
for ep in sorted(endpoints):
    print(f"  {ep}")

# Find all fetch/ajax/axios/url assignments
urls = set(re.findall(r'''(?:fetch|axios|url|src)["']?\s*[:=]\s*["']([a-zA-Z0-9_/.?&=%:-]+)["']''', r.text, re.I))
print("\n=== URL references ===")
for u in sorted(urls):
    print(f"  {u}")

# Check for form data / post parameters
params = set(re.findall(r'"([a-z_]+(?:name|id|data|text|value|type|src|image|file))"\s*[:=]', r.text, re.I))
print("\n=== Parameter names ===")
for p in sorted(params):
    print(f"  {p}")

# Look for the word "proxy" or "gateway"
if 'proxy' in r.text.lower():
    print("\n*** Contains 'proxy' ***")
if 'gateway' in r.text.lower():
    print("\n*** Contains 'gateway' ***")
