const https = require('https');

function toNumbers(d) {
    var e = [];
    d.replace(/(..)/g, function(d) { e.push(parseInt(d, 16)); });
    return e;
}
function toHex() {
    for (var d = [], d = 1 == arguments.length && arguments[0].constructor == Array ? arguments[0] : arguments, e = '', f = 0; f < d.length; f++)
        e += (16 > d[f] ? '0' : '') + d[f].toString(16);
    return e.toLowerCase();
}

const agent = new https.Agent({ keepAlive: true });

function fetch(url, cookie) {
    return new Promise((resolve, reject) => {
        const opts = {
            hostname: 'idcard.kesug.com',
            path: url,
            method: 'GET',
            agent: agent,
            headers: { 'User-Agent': 'Mozilla/5.0' }
        };
        if (cookie) opts.headers['Cookie'] = '__test=' + cookie;
        const req = https.get(opts, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        req.on('error', reject);
        req.end();
    });
}

async function main() {
    // Get AES lib
    const aesRes = await fetch('/aes.js', null);
    eval(aesRes.body);
    
    // Get challenge
    const challengeRes = await fetch('/', null);
    const html = challengeRes.body;
    const m = html.match(/toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)/s);
    if (!m) { console.log('No challenge'); return; }
    const a = toNumbers(m[1]), b = toNumbers(m[2]), c = toNumbers(m[3]);
    var result = slowAES.decrypt(c, 2, a, b);
    var cookieVal = toHex(result);
    
    // Get JS bundle
    const jsRes = await fetch('/assets/index-CApTIDIg.js', cookieVal);
    console.log('=== JS Bundle ===');
    console.log('Status:', jsRes.status);
    console.log('Size:', jsRes.body.length);
    
    // Extract API endpoints
    const endpoints = new Set();
    const re = /["'](\/[a-zA-Z][a-zA-Z0-9_\/-]{2,60})["']/g;
    let match;
    while ((match = re.exec(jsRes.body)) !== null) {
        const ep = match[1];
        if (!ep.includes('..') && !ep.includes('//')) {
            endpoints.add(ep);
        }
    }
    console.log('\n=== API Endpoints ===');
    endpoints.forEach(ep => console.log(' ', ep));
    
    // Also look for fetch calls
    const fetchCalls = jsRes.body.match(/fetch\(["'][^"']+["']\)/g) || [];
    console.log('\n=== Fetch calls ===');
    fetchCalls.forEach(f => console.log(' ', f));
    
    // Look for axios
    if (jsRes.body.includes('axios')) {
        console.log('\n*** Uses axios ***');
    }
    
    // Save JS for analysis
    require('fs').writeFileSync('bundle.js', jsRes.body);
    console.log('\nSaved to bundle.js');
}

main().catch(err => console.error(err));
