import requests, urllib3, subprocess, json, re
urllib3.disable_warnings()

# Step 1: Get the challenge
s = requests.Session()
r = s.get('https://idcard.kesug.com/', timeout=10, headers={'User-Agent': 'Mozilla/5.0'})

# Extract the toNumbers values
m = re.search(r'toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)', r.text, re.DOTALL)
if not m:
    print("Could not extract challenge values")
    exit(1)

a, b, c = m.group(1), m.group(2), m.group(3)
print(f"Challenge: a={a} b={b} c={c}")

# Step 2: Solve with Node.js
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

# Step 3: Set cookie and request the actual page
s.cookies.clear()
s.cookies.set('__test', cookie_val)
r = s.get('https://idcard.kesug.com/?i=1', timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
print(f"Status: {r.status_code}")
print(f"Challenge present: {'slowAES' in r.text or 'aes.js' in r.text}")

if 'slowAES' not in r.text and 'aes.js' not in r.text:
    print("=== BYPASS SUCCESS ===")
    print(r.text[:2000])
    # Find all scripts
    scripts = re.findall(r'<script[^>]+src="([^"]+)"', r.text)
    print(f"\nScripts: {scripts}")
    # Save response
    with open('bypassed.html', 'w', encoding='utf-8') as f:
        f.write(r.text)
else:
    print("=== STILL BLOCKED ===")
    print(r.text[:500])
