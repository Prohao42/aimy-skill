import requests, urllib3, re
urllib3.disable_warnings()

s = requests.Session()
s.cookies.set('__test', 'dde09b5cbd6693a64e2351ca015467fb')

r = s.get('https://idcard.kesug.com/', timeout=10)
scripts = re.findall(r'<script[^>]+src="([^"]+)"', r.text)
print('Scripts:', scripts)

for url in scripts:
    js_url = 'https://idcard.kesug.com' + url if url.startswith('/') else 'https://idcard.kesug.com/' + url
    r2 = s.get(js_url, timeout=10)
    print(f'JS {url}: status={r2.status_code} size={len(r2.text)}')
    eps = re.findall(r'["\x27](/[a-zA-Z][a-zA-Z0-9/_-]{2,60})["\x27]', r2.text)
    print('  Endpoints:', sorted(set(eps))[:30])
