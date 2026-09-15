# Aimy-Skill Security Toolkit - Skill Guide

Penetration testing helper toolkit with 49 vulnerability scanners and exploitation modules.

## Quick Start

```bash
python main.py --help
python main.py sqlcheck --url http://target.com --param id -v 2
```

## Command Categories (49 data-driven commands)

### Injection Scanners
| Command | Tool | Vulnerabilities |
|---------|------|-----------------|
| `sqlcheck` | sql_injection | SQLi (UNION/blind/error/time) |
| `sqli-blind` | sqli_blind | Blind SQLi |
| `sqli-oob` | sqli_oob | OOB SQLi |
| `sqli-weaponize` | sqli_weaponizer | SQLi exploitation |
| `sqli-second-order` | second_order_sqli | Second-order SQLi |
| `cmdi` | cmdi_detector | Command Injection |
| `ssti` | ssti_detector | SSTI |
| `nosqli` | nosqli_detector | NoSQL Injection |

### XSS & Client-Side
| Command | Tool | Vulnerabilities |
|---------|------|-----------------|
| `xsscheck` | xss_detector | Reflected/Stored/DOM XSS |
| `xss-validate` | xss_validator | XSS payload validation |
| `xss-verify` | xss_browser_verify | Browser-level XSS verification |
| `dom-xss` | dom_xss | DOM-based XSS |
| `csrf` | csrf_scanner | CSRF + bypass |

### Server-Side Issues
| Command | Tool | Vulnerabilities |
|---------|------|-----------------|
| `ssrf` | ssrf_detector | SSRF (internal/cloud metadata) |
| `ssrf-pwn` | ssrf_pwn | SSRF exploitation |
| `ssrf-lateral` | ssrf_pwn | SSRF lateral movement |
| `lfi` | lfi_scanner | Local File Inclusion |
| `xxe` | xxe_detector | XML External Entity |
| `deser` | deserialization_detector | Insecure Deserialization |
| `deser-weaponize` | deser_weaponizer | Deserialization RCE |
| `cors` | cors_scanner | CORS misconfiguration |
| `jwt` | jwt_detector | JWT vulnerabilities |
| `jwt-attack` | jwt_attacker | JWT algorithm bypass |
| `jwt-exploit` | jwt_exploiter | JWT exploitation |
| `proto-pollution` | proto_pollution | Prototype Pollution |
| `waf` | waf_bypass | WAF detection |
| `waf-heavy` | waf_bypass | Advanced WAF fuzzing |

### Race Conditions & Business Logic
| Command | Tool | Vulnerabilities |
|---------|------|-----------------|
| `race` | race_condition | Race condition / TOCTOU |
| `race-profile` | race_profiler | Auto race condition analysis |
| `bizlogic` | biz_logic_scanner | Business logic flaws |
| `bizlogic-v2` | biz_logic_v2 | Deep state machine analysis |
| `constraint` | constraint_graph | Constraint graph analysis |
| `deviation` | deviation_oracle | Response deviation detection |
| `workflow-trace` | workflow_tracer | Workflow/business flow tracing |
| `verify` | second_order_verifier | Second-order cross-verification |
| `graphql-abuse` | graphql_abuser | GraphQL intro/abuse |
| `graphql` | graphql_scanner | GraphQL scanning |

### Authentication & Authorization
| Command | Tool | Check |
|---------|------|-------|
| `auth-bypass` | auth_bypass | Auth bypass detection |
| `auth-default-creds` | auth_bypass | Default credentials |
| `auth-cookie-tamper` | auth_bypass | Cookie tampering |
| `auth-header-injection` | auth_bypass | HTTP header injection |
| `auth-method-bypass` | auth_bypass | HTTP method bypass |
| `auth-mass-assignment` | auth_bypass | Mass assignment |
| `idor` | idor_scanner | IDOR / BOLA |
| `weakpass` | weakpass | Weak password auditing |
| `login` | AuthSession | Session authentication |

### Vulnerability Chaining (Cross-Validation)
| Command | Tool | Purpose |
|---------|------|---------|
| `chain-sqli-lfi` | cross_validator | SQLi → LFI verification |
| `chain-sqli-auth` | cross_validator | SQLi → Auth bypass |
| `chain-ssrf-lfi` | cross_validator | SSRF → LFI |

### HTTP Protocol & Smuggling
| Command | Tool | Vulnerabilities |
|---------|------|-----------------|
| `smuggle` | smuggler | HTTP request smuggling |

### Infrastructure & Recon
| Command | Tool | Purpose |
|---------|------|---------|
| `recon` | Orchestrator | Full recon (fingerprints/ports/git/dirs) |
| `deepscan` | Orchestrator | Crawler + scanning + reporting |
| `quickscan` | Orchestrator | Fast high-risk discovery |
| `autohunt` | Orchestrator | AI-powered hunt |
| `auto` | Orchestrator | Full pipeline audit |
| `crawl` | crawler | Web crawling |
| `portscan` | N/A | TCP port scanning |
| `dirfuzz` | Built-in | Directory brute-forcing |
| `batch-recon` | batch_recon | Batch host recon |
| `unauth` | unauth_scan | Unauth service scan |

### Exploitation & Post-Exploitation
| Command | Tool | Purpose |
|---------|------|---------|
| `reverse-shell` | reverse_shell | Shell payload generation |
| `webshell` | reverse_shell | Webshell gen + deployment |
| `kali` | kali_toolset | Kali tool orchestration |
| `chain` | chain_engine | Vulnerability chain assembly |
| `cloud-pwn` | cloud_pwn | Cloud misconfiguration |
| `capture` | packet_capture | Packet capture |
| `fuzz` | fuzz_engine | Generic fuzzing |
| `payload-mutate` | payload_mutator | Payload mutation |
| `code-audit` | code_audit | Static analysis |
| `binary-scan` | binary_analyzer | Binary analysis |
| `mobile-scan` | mobile_scanner | Android/iOS scanning |
| `cms-fingerprint` | cms_fingerprint | CMS fingerprinting |
| `param-mine` | param_miner | Parameter mining |

## Usage

```bash
# Basic scan
python main.py sqlcheck --url http://target.com --param id

# Race condition detection
python main.py race --url http://target.com/login --param otp

# Auth bypass - default creds
python main.py auth-default-creds --url http://target.com/admin

# Chain validation
python main.py chain-sqli-lfi --url http://target.com/page --param id

# Request smuggling
python main.py smuggle --url http://target.com --param input

# Login + authenticated scanning
python main.py login --auth-url http://target.com/login --auth-user admin --auth-pass pass123
python main.py xsscheck --url http://target.com/page --param q

# Kali integration
python main.py --kali-host 10.0.0.5 --kali-user root --kali-pass pass kali connect
python main.py --kali-local kali sqlmap http://target.com --param id

# Full recon
python main.py recon --target http://target.com --deep --full-ports
```

## Architecture

### Data-Driven Dispatch System

```
cli/check_commands.py  →  CheckSpec dataclass + COMMAND_SPECS table (49 entries)
cli/arg_parsers.py     →  build_parser() + validate_args()
main.py                →  main() orchestrates: build dispatchers → build parser → dispatch
```

- 33 one-liner `cmd_*` functions eliminated from `main.py` (reduced 1567 → 820 lines)
- Sentinel values: `_SESS` → session, `"attr"` → `getattr(args, attr)`, `None` → literal

### Security Skills Coverage: 21/28 skill categories

**Covered**: SQLi | XSS | SSTI | CmdI | SSRF | LFI/Path Traversal | XXE | Deserialization | JWT | CORS | CSRF | GraphQL | Prototype Pollution | Race Condition | IDOR/BOLA | Auth Bypass | Business Logic | WAF | Request Smuggling

**Not yet covered** (no tool module): Clickjacking | CRLF Injection | Open Redirect | HTTP Parameter Pollution | Web Cache | File Upload | SAML SSO | OIDC/OAuth | Expression Language | XSLT Injection | Dependency Confusion | Source Code Management
