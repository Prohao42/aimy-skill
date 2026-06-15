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

function fetch(url, cookie) {
    return new Promise((resolve, reject) => {
        const opts = {
            hostname: 'idcard.kesug.com',
            path: url,
            method: 'GET',
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

// First, get the AES library
fetch('/aes.js', null).then(aesRes => {
    eval(aesRes.body);
    // Now get the challenge page
    return fetch('/', null).then(challengeRes => {
        const html = challengeRes.body;
        const m = html.match(/toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)/s);
        if (!m) { console.log('No challenge found'); return; }
        const a = toNumbers(m[1]), b = toNumbers(m[2]), c = toNumbers(m[3]);
        console.log('a:', m[1], 'b:', m[2], 'c:', m[3]);
        var result = slowAES.decrypt(c, 2, a, b);
        var cookieVal = toHex(result);
        console.log('Cookie:', cookieVal);
        // Now fetch with cookie
        return fetch('/?i=1', cookieVal).then(pageRes => {
            console.log('Status after cookie:', pageRes.status);
            const blocked = pageRes.body.includes('slowAES') || pageRes.body.includes('aes.js');
            console.log('Blocked:', blocked);
            if (!blocked) {
                console.log('=== BYPASS SUCCESS ===');
                console.log(pageRes.body.substring(0, 2000));
                // Find scripts
                const scripts = pageRes.body.match(/<script[^>]+src="([^"]+)"/g) || [];
                console.log('\nScripts:', scripts);
            } else {
                console.log('Still blocked:', pageRes.body.substring(0, 300));
            }
        });
    });
}).catch(err => console.error(err));
