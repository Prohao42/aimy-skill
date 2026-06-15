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

https.get('https://idcard.kesug.com/aes.js', (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
        eval(data);
        var a = toNumbers('f655ba9d09a112d4968c63579db590b4');
        var b = toNumbers('98344c2eee86c3994890592585b49f80');
        var c = toNumbers('07bad8f3af74864bdc05857b0a325431');
        var result = slowAES.decrypt(c, 2, a, b);
        var cookieVal = toHex(result);
        console.log('__test=' + cookieVal);
    });
});
