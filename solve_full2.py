import requests, urllib3, subprocess, re, time
urllib3.disable_warnings()

s = requests.Session()

# Try fetching with a fresh approach - get challenge, solve, 
# then make a NEW request to the same endpoint with cookie
r1 = s.get('https://idcard.kesug.com/', timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
m = re.search(r'toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)', r1.text, re.DOTALL)
a, b, c = m.group(1), m.group(2), m.group(3) if m else (None, None, None)
print(f"Challenge: a={a} b={b} c={c}")

node_script = f'''
const https = require('https');
function toNumbers(d){{var e=[];d.replace(/(..)/g,function(d){{e.push(parseInt(d,16))}});return e}}
function toHex(){{for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e='',f=0;f<d.length;f++)e+=(16>d[f]?'0':'')+d[f].toString(16);return e.toLowerCase()}}
https.get('https://idcard.kesug.com/aes.js', (res) => {{
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {{
        eval(data);
        var key=toNumbers('{a}'),iv=toNumbers('{b}'),ct=toNumbers('{c}');
        console.log('__test='+toHex(slowAES.decrypt(ct,2,key,iv)));
    }});
}});
'''
result = subprocess.run(['node', '-e', node_script], capture_output=True, text=True, timeout=15)
cookie_val = result.stdout.strip()
print(f"Cookie: {cookie_val}")

# Several approaches:

# 1. Direct request with cookie
print("\n--- Approach 1: Direct GET with cookie ---")
r2 = requests.get('https://idcard.kesug.com/', timeout=10, 
    headers={'User-Agent': 'Mozilla/5.0', 'Cookie': f'__test={cookie_val}'})
print(f"Status: {r2.status_code}, Blocked: {'slowAES' in r2.text}")

# 2. Approach: fetch /?i=1 directly with cookie
print("\n--- Approach 2: GET /?i=1 with cookie ---")
r3 = requests.get('https://idcard.kesug.com/?i=1', timeout=10, 
    headers={'User-Agent': 'Mozilla/5.0', 'Cookie': f'__test={cookie_val}'})
print(f"Status: {r3.status_code}, Blocked: {'slowAES' in r3.text}")

# 3. Approach: keep session and follow redirects
print("\n--- Approach 3: Session with cookie + redirect ---")
s2 = requests.Session()
s2.cookies.set('__test', cookie_val)
r4 = s2.get('https://idcard.kesug.com/', timeout=10, 
    headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
print(f"Status: {r4.status_code}, Blocked: {'slowAES' in r4.text}")
print(f"Final URL: {r4.url}")
if 'slowAES' not in r4.text:
    print("SUCCESS! Page content:")
    print(r4.text[:1000])

# 4. Approach: multiple attempts
print("\n--- Approach 4: Multiple requests with session ---")
s3 = requests.Session()
s3.cookies.set('__test', cookie_val, domain='idcard.kesug.com', path='/')
for i in range(3):
    r5 = s3.get('https://idcard.kesug.com/', timeout=10,
        headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
    print(f"Attempt {i+1}: Status={r5.status_code} Blocked={'slowAES' in r5.text}")
