# HACK.SKILLS - Hacker Arsenal for Agents

<p align="right">English | <a href="./README_CN.md">中文</a></p>

<p align="center">
    <img src="./assets/readme-hero-banner.jpg" alt="HackSkills Hero Banner" width="100%" />
</p>

<p align="center">
    <strong>Master Entry → Category Entries → Deep Topic Skills</strong><br/>
    One master entry, six stable category entries, and 47 deep topic skills drilled down on demand.
</p>

An Agent Skills knowledge base for bug bounty, web security, API security, and authorized testing.

The current branch has converged to a standard directory structure: every skill lives in its own directory, uniformly using `skills/{semantic-identifier}/SKILL.md`. The design goal is not to expose every minor tip as an entry point, but to compress what the loader truly needs to see into one master entry, six category entries, and deep topic skills drilled down on demand.

The objective is straightforward: organize security knowledge that is genuinely useful in real engagements and easy to audit and maintain into a set of installable, searchable, and composable HackSkills.

## Knowledge Sources & Distillation Boundaries

This repository is not a mirror of external materials — it is a distillation layer aimed at Agents.

Primary reference sources (all publicly available, used strictly for educational distillation):

| Source | What It Provides | How We Use It |
|---|---|---|
| `swisskyrepo/PayloadsAllTheThings` | 64 vulnerability categories, payload families, bypass techniques, exploit chains | Distilled into scenario-based indices, method matrices, per-engine/per-database payload sections |
| `PentesterSpecialDict` | OS-specific payload dictionaries, Java middleware path fuzzing lists, file extension databases | Distilled into parameter naming patterns, endpoint frequency tables, middleware fingerprint matrices |
| `Dictionary-Of-Pentesting` | BugBounty bypass techniques (12 topics), cloud metadata endpoints, XXE payload collections, one-liner toolchains | Distilled into bypass pattern matrices, cloud metadata endpoint tables, WAF vendor bypass sections |
| `Hello-CTF` | CTF web security tutorials with hands-on tricks for PHP/Python/Java challenges | Distilled into CTF-specific technique sections (handler bypass, filter chain tricks, Flask PIN) |
| Public security research papers and CVE advisories | Methodology frameworks, vulnerability pattern taxonomies, statistical distributions | Distilled into attack pattern matrices, systematic testing checklists, decision trees |

Processing principles:

- No direct copying of large dictionaries or full payload lists.
- Prioritize distilling into routable, composable, and auditable security skills.
- Use small, stable samples, taxonomies, and cross-references to improve Agent stability in real security scenarios.
- No customer-specific information, no vendor-identifiable case details, purely educational methodology.

## Quick Start

The preferred entry point is `hack`:

```bash
npx skills add yaklang/hack-skills
```

If your tooling supports pulling a single SKILL.md directly, you can also use:

- frontmatter name: `hack`
- raw URL: `https://raw.githubusercontent.com/yaklang/hack-skills/main/skills/hack/SKILL.md`

After installing, the recommended order is simple: start from the master entry, then move into category entries, and only then drill into deep topic skills.

## Loader Priority

| Layer | Role | Recommended Exposure | Representative Skill |
|---|---|---|---|
| Master Entry | Global routing, test sequencing, cross-category switching | Expose first | [hack](./skills/hack/SKILL.md) |
| Category Entry | Route by attack surface to stable topic families | Expose first | [recon-for-sec](./skills/recon-for-sec/SKILL.md), [api-sec](./skills/api-sec/SKILL.md), [auth-sec](./skills/auth-sec/SKILL.md) |
| Deep Topic | Provide complete attack playbooks and execution details | Load on demand | [xss-cross-site-scripting](./skills/xss-cross-site-scripting/SKILL.md), [sqli-sql-injection](./skills/sqli-sql-injection/SKILL.md) |

## Main Entry Points

| Type | Skill | Purpose | When to Use First |
|---|---|---|---|
| Master Entry | [hack](./skills/hack/SKILL.md) | Global routing, phase assessment, cross-category switching | New target, unknown attack surface |
| Category Entry | [recon-for-sec](./skills/recon-for-sec/SKILL.md) | Asset discovery, technology identification | Just received the target |
| Category Entry | [api-sec](./skills/api-sec/SKILL.md) | REST, GraphQL, mobile backend routing | Observed API interfaces |
| Category Entry | [auth-sec](./skills/auth-sec/SKILL.md) | Authentication, sessions, OAuth, JWT, authorization | Login, tokens, object IDs |
| Category Entry | [injection-checking](./skills/injection-checking/SKILL.md) | XSS, SQLi, SSRF, XXE, SSTI, CMDi, NoSQL routing | Input enters interpreter |
| Category Entry | [file-access-vuln](./skills/file-access-vuln/SKILL.md) | Upload, download, LFI, path control | File operations |
| Category Entry | [business-logic-vuln](./skills/business-logic-vuln/SKILL.md) | Race conditions, pricing, workflow, state machines | Business process testing |

## Complete Skill Index (47 Skills)

### Reconnaissance & Methodology

| Skill | SKILL.md | SCENARIOS.md | Key Content |
|---|---|---|---|
| [hack](./skills/hack/SKILL.md) | 161 lines | - | Master router, phenomenon-to-skill mapping, expert intuitions |
| [recon-for-sec](./skills/recon-for-sec/SKILL.md) | 28 lines | - | Category router for reconnaissance phase |
| [recon-and-methodology](./skills/recon-and-methodology/SKILL.md) | 389 lines | - | Methodology framework, Java middleware fingerprint matrix, leak detection checklist |

### API Security

| Skill | SKILL.md | SCENARIOS.md | Key Content |
|---|---|---|---|
| [api-sec](./skills/api-sec/SKILL.md) | 48 lines | - | Category router for API testing |
| [api-recon-and-docs](./skills/api-recon-and-docs/SKILL.md) | 60 lines | - | API discovery, OpenAPI/Swagger, hidden endpoints |
| [api-authorization-and-bola](./skills/api-authorization-and-bola/SKILL.md) | 47 lines | - | BOLA/BFLA, mass assignment, object-level authz |
| [api-auth-and-jwt-abuse](./skills/api-auth-and-jwt-abuse/SKILL.md) | 75 lines | - | JWT attacks, API key abuse, token manipulation |
| [graphql-and-hidden-parameters](./skills/graphql-and-hidden-parameters/SKILL.md) | 49 lines | - | GraphQL introspection, batching, hidden param discovery |

### Authentication & Authorization

| Skill | SKILL.md | SCENARIOS.md | Key Content |
|---|---|---|---|
| [auth-sec](./skills/auth-sec/SKILL.md) | 40 lines | - | Category router for auth testing |
| [authbypass-authentication-flaws](./skills/authbypass-authentication-flaws/SKILL.md) | 441 lines | - | Password reset 22-pattern matrix, captcha bypass 20 methods, insecure randomness (UUID v1/mt_rand/ObjectId) |
| [jwt-oauth-token-attacks](./skills/jwt-oauth-token-attacks/SKILL.md) | 301 lines | - | JWT alg confusion, key confusion, claim tampering, JWKS abuse |
| [oauth-oidc-misconfiguration](./skills/oauth-oidc-misconfiguration/SKILL.md) | 45 lines | - | OAuth flow hijacking, OIDC misconfiguration |
| [saml-sso-assertion-attacks](./skills/saml-sso-assertion-attacks/SKILL.md) | 40 lines | - | SAML assertion manipulation, SSO bypass |
| [idor-broken-object-authorization](./skills/idor-broken-object-authorization/SKILL.md) | 336 lines | - | 8-category systematic IDOR testing, ORM filter chain leaks (Django/Prisma/Ransack) |

### Injection Attacks

| Skill | SKILL.md | SCENARIOS.md | Key Content |
|---|---|---|---|
| [injection-checking](./skills/injection-checking/SKILL.md) | 49 lines | - | Category router for injection testing |
| [xss-cross-site-scripting](./skills/xss-cross-site-scripting/SKILL.md) | 368 lines | 278 lines | Polyglot payloads, WAF bypass by vendor (Cloudflare/Akamai/Incapsula/WordFence), CSP bypass, DOM clobbering, CSS injection data exfiltration |
| [sqli-sql-injection](./skills/sqli-sql-injection/SKILL.md) | 475 lines | 575 lines | DB2/Cassandra/BigQuery/SQLite specifics, SQLite RCE, WAF bypass matrix, CTF techniques (handler/prepare/innodb) |
| [ssrf-server-side-request-forgery](./skills/ssrf-server-side-request-forgery/SKILL.md) | 314 lines | 226 lines | Cloud metadata 6-platform matrix, DNS rebinding, headless browser attacks, Gopher/Redis RCE chain |
| [ssti-server-side-template-injection](./skills/ssti-server-side-template-injection/SKILL.md) | 340 lines | 319 lines | 15+ engine coverage (Jinja2/Twig/Pug/Handlebars/EJS/Razor/EEx/Smarty), blind SSTI, Flask PIN calculation |
| [cmdi-command-injection](./skills/cmdi-command-injection/SKILL.md) | 494 lines | - | WAF bypass (wildcards/xor/base64), PHP disable_functions 6 bypass paths, component RCE (ImageMagick/FFmpeg/ES) |
| [nosql-injection](./skills/nosql-injection/SKILL.md) | 341 lines | - | Blind extraction automation scripts, duplicate key bypass, aggregation pipeline injection, $where JS execution |
| [xxe-xml-external-entity](./skills/xxe-xml-external-entity/SKILL.md) | 326 lines | 112 lines | Local DTD injection (17+ paths for Windows/Linux/JAR), blind XXE, Gopher/FTP OOB |
| [deserialization-insecure](./skills/deserialization-insecure/SKILL.md) | 714 lines | - | Java/PHP/Python + Ruby Marshal/YAML chains, .NET BinaryFormatter/ViewState/JSON.NET, Node.js node-serialize/funcster |
| [expression-language-injection](./skills/expression-language-injection/SKILL.md) | 243 lines | - | SpEL, OGNL, Java EL injection with RCE chains |
| [jndi-injection](./skills/jndi-injection/SKILL.md) | 265 lines | - | JNDI/LDAP/RMI exploitation, Log4Shell patterns |
| [crlf-injection](./skills/crlf-injection/SKILL.md) | 175 lines | - | Header injection, HTTP response splitting |
| [request-smuggling](./skills/request-smuggling/SKILL.md) | 298 lines | - | CL.TE/TE.CL/TE.TE with 8 obfuscation variants, HTTP/2 downgrade, client-side desync |
| [prototype-pollution](./skills/prototype-pollution/SKILL.md) | 190 lines | - | Express black-box probing keys, EJS/Kibana gadget chains, CVE-2019-7609 |
| [type-juggling](./skills/type-juggling/SKILL.md) | 291 lines | - | PHP loose comparison table, magic hash (MD5/SHA1/SHA256), HMAC 0e brute-force, CTF patterns |
| [http-parameter-pollution](./skills/http-parameter-pollution/SKILL.md) | 208 lines | - | Server behavior matrix (9 platforms), HPP+WAF bypass combos |
| [xslt-injection](./skills/xslt-injection/SKILL.md) | 281 lines | - | Three RCE chains (PHP/Java/.NET), EXSLT file write, vendor detection |
| [csv-formula-injection](./skills/csv-formula-injection/SKILL.md) | 144 lines | - | DDE/rundll32 payloads, Google Sheets IMPORT* exfiltration |

### File & Path Attacks

| Skill | SKILL.md | SCENARIOS.md | Key Content |
|---|---|---|---|
| [file-access-vuln](./skills/file-access-vuln/SKILL.md) | 32 lines | - | Category router for file access testing |
| [path-traversal-lfi](./skills/path-traversal-lfi/SKILL.md) | 603 lines | - | LFI-to-RCE 7 paths, PHP wrapper matrix (filter chains/oracle/phar), pearcmd 4 methods, parameter naming dictionary |
| [upload-insecure-files](./skills/upload-insecure-files/SKILL.md) | 287 lines | 158 lines | Success rate formula, editor path matrix, validation defect 5-dimension taxonomy, IIS/Apache/Nginx parsing tricks |

### Business Logic & Session

| Skill | SKILL.md | SCENARIOS.md | Key Content |
|---|---|---|---|
| [business-logic-vuln](./skills/business-logic-vuln/SKILL.md) | 32 lines | - | Category router for business logic testing |
| [business-logic-vulnerabilities](./skills/business-logic-vulnerabilities/SKILL.md) | 339 lines | 298 lines | Payment manipulation matrix (10 attacks), state machine bypass methodology, coupon/stock race |
| [race-condition](./skills/race-condition/SKILL.md) | 286 lines | - | TOCTOU model, HTTP/1.1 last-byte sync, HTTP/2 single-packet attack, Turbo Intruder templates, CVE-2022-4037 |
| [csrf-cross-site-request-forgery](./skills/csrf-cross-site-request-forgery/SKILL.md) | 324 lines | - | JSON CSRF 3 techniques, multipart upload CSRF, CSPT2CSRF modern variant |
| [clickjacking](./skills/clickjacking/SKILL.md) | 163 lines | - | Frame-based attacks, X-Frame-Options/CSP bypass |
| [cors-cross-origin-misconfiguration](./skills/cors-cross-origin-misconfiguration/SKILL.md) | 50 lines | 152 lines | Origin reflection, null origin, subdomain trust abuse |
| [open-redirect](./skills/open-redirect/SKILL.md) | 184 lines | - | Redirect chain abuse, tabnabbing (reverse tabnabbing) |
| [web-cache-deception](./skills/web-cache-deception/SKILL.md) | 211 lines | - | Path confusion, cache key manipulation |

### Infrastructure & Supply Chain

| Skill | SKILL.md | SCENARIOS.md | Key Content |
|---|---|---|---|
| [unauthorized-access-common-services](./skills/unauthorized-access-common-services/SKILL.md) | 380 lines | - | Service exposure checklist, reverse proxy misconfiguration (Nginx off-by-slash, X-Forwarded-For trust, Caddy template injection) |
| [insecure-source-code-management](./skills/insecure-source-code-management/SKILL.md) | 161 lines | - | .git/.svn/.hg/.bzr recovery, 403 vs 404 detection, backup file patterns |
| [dependency-confusion](./skills/dependency-confusion/SKILL.md) | 178 lines | - | npm/pip/gem public registry hijacking, manifest identification, scope/namespace defense |
| [websocket-security](./skills/websocket-security/SKILL.md) | 146 lines | - | CSWSH, Origin validation, wsrepl/ws-harness tooling |

### Total: 47 SKILL.md files + 8 SCENARIOS.md files = 55 documents, ~14,000 lines

## Skill Selection Guide

| Symptom | Recommended Entry | Notes |
|---|---|---|
| New target, insufficient information | [recon-for-sec](./skills/recon-for-sec/SKILL.md) | Start with methodology and asset understanding |
| REST API, GraphQL, mobile backend | [api-sec](./skills/api-sec/SKILL.md) | Route to recon, authz, token, or GraphQL |
| Login, password reset, 2FA, JWT, OAuth | [auth-sec](./skills/auth-sec/SKILL.md) | Distinguish auth, authz, and protocol config |
| HTML/JS reflection, template expressions | [injection-checking](./skills/injection-checking/SKILL.md) | Determine XSS, SQLi, SSRF, XXE, SSTI first |
| File paths, downloads, uploads | [file-access-vuln](./skills/file-access-vuln/SKILL.md) | Distinguish LFI/Traversal from Upload |
| Coupons, payments, state machines | [business-logic-vuln](./skills/business-logic-vuln/SKILL.md) | Model by business rules and race conditions |
| HTTP parsing anomalies | [request-smuggling](./skills/request-smuggling/SKILL.md) | Front/back-end framing disagreement |
| Node.js `__proto__` controllable | [prototype-pollution](./skills/prototype-pollution/SKILL.md) | Client-side PP→XSS, Server-side PP→RCE |
| PHP weak comparison, 0e hash | [type-juggling](./skills/type-juggling/SKILL.md) | Loose comparison auth bypass |
| .git/.svn/.env path accessible | [insecure-source-code-management](./skills/insecure-source-code-management/SKILL.md) | Source code recovery |
| Internal package names in manifests | [dependency-confusion](./skills/dependency-confusion/SKILL.md) | Supply chain hijacking |
| WebSocket protocol upgrade | [websocket-security](./skills/websocket-security/SKILL.md) | CSWSH and WS injection |
| CSV/Excel export functionality | [csv-formula-injection](./skills/csv-formula-injection/SKILL.md) | DDE injection in exports |
| One-time operations (coupons, rewards) | [race-condition](./skills/race-condition/SKILL.md) | Limit-overrun via concurrent requests |

## Installation

### General Installation

```bash
npx skills add yaklang/hack-skills
```

### Raw URL Installation

```bash
curl -fsSL https://raw.githubusercontent.com/yaklang/hack-skills/main/skills/hack/SKILL.md
```

### Local Use as a Knowledge Base

```bash
git clone https://github.com/yaklang/hack-skills.git
cd hack-skills
```

## Design Principles

- Security knowledge takes priority over fancy packaging.
- Content auditability takes priority over quantity expansion.
- Prioritize authorized testing, legitimate research, and defensive verification scenarios.
- Directory names should convey security semantics at a glance.
- No customer-specific information; all content is generic methodology for educational use.

## Contributing

PRs are welcome. Key areas include:

- New vulnerability categories and high-value cases
- Better bug bounty methodologies
- Edge conditions that Agents easily overlook
- Risk annotations, terminology consistency, and content denoising

Contributions should ideally be verifiable, auditable, and helpful for Agents to reason and execute more robustly in real tasks.
