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

function fetch(url, cookie) {
    return new Promise((resolve) => {
        const opts = {
            hostname: 'idcard.kesug.com',
            path: url,
            method: 'GET',
            agent: agent,
            headers: { 'User-Agent': 'Mozilla/5.0' }
        };
        if (cookie) opts.headers['Cookie'] = '__test=' + cookie;
        const req = https.get(opts, (res) => {
            let d = '';
            res.on('data', c => d += c);
            res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers }));
        });
        req.on('error', (e) => resolve({ status: 0, body: e.message, headers: {} }));
        req.end();
    });
}

async function main() {
    // Get AES library
    const aesRes = await fetch('/aes.js');
    eval(aesRes.body);

    // Get challenge
    const chRes = await fetch('/');
    // Fix: body uses double quotes
    const m = chRes.body.match(/toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)/s);
    if (!m) {
        console.log('No challenge found in body (first 500 chars):');
        console.log(chRes.body.substring(0, 500));
        return;
    }
    const cookieVal = toHex(slowAES.decrypt(toNumbers(m[3]), 2, toNumbers(m[1]), toNumbers(m[2])));
    console.log('Cookie:', cookieVal);

    // Verify bypass works
    const verify = await fetch('/?i=1', cookieVal);
    const blocked = verify.body.includes('slowAES') || verify.body.includes('aes.js');
    console.log('Verify blocked:', blocked);
    if (blocked) {
        console.log('Bypass failed, body:', verify.body.substring(0, 300));
        return;
    }
    console.log('=== BYPASS VERIFIED ===\n');

    // Scan paths
    const paths = [
        '/robots.txt', '/sitemap.xml', '/.env', '/phpinfo.php',
        '/api', '/admin', '/config.php', '/backup', '/.git/config',
        '/crossdomain.xml', '/test.php', '/info.php', '/wp-admin',
        '/.htaccess', '/db.php', '/database.php', '/dump.sql',
        '/login.php', '/manage.php', '/admin.php', '/.ds_store',
        '/server-status', '/cgi-bin/', '/xmlrpc.php',
        '/wp-content/', '/wp-includes/', '/vendor/',
        '/composer.json', '/package.json', '/package-lock.json',
        '/Dockerfile', '/docker-compose.yml', '/.dockerignore',
        '/.gitignore', '/README.md', '/LICENSE',
        '/nginx.conf', '/.well-known/security.txt',
        '/favicon.ico', '/manifest.json', '/sw.js',
        '/assets/', '/fonts/', '/images/', '/img/',
        '/css/', '/js/', '/lib/', '/dist/', '/src/',
        '/api/v1/', '/api/v2/', '/graphql', '/rest/',
        '/health', '/status', '/info', '/debug',
        '/upload.php', '/file.php', '/download.php',
        '/register.php', '/signup.php', '/user.php',
        '/index.php', '/home.php', '/main.php',
        '/api/user', '/api/config', '/api/upload',
        '/api/render', '/api/generate', '/api/image',
    ];

    for (const p of paths) {
        const r = await fetch(p, cookieVal);
        const status = r.status;
        const len = r.body.length;
        const snippet = r.body.substring(0, 120).replace(/\n/g, '\\n').replace(/<[^>]+>/g, '').trim();
        const server = r.headers['server'] || '';
        const ct = r.headers['content-type'] || '';
        if (status >= 200 && status < 400 && len > 10 && !r.body.includes('slowAES')) {
            console.log(`[${status}] ${p} (${len}b, ${ct})`);
            if (status === 200 && len < 5000) {
                console.log('  ->', snippet.substring(0, 150));
            }
        } else if (status >= 200 && status < 400) {
            console.log(`[${status}] ${p} (${len}b) [challenge page]`);
        } else {
            console.log(`[${status}] ${p}`);
        }
    }
}

main();
