---
name: cors-cross-origin-misconfiguration
description: >-
  CORS misconfiguration testing playbook. Use when analyzing cross-origin trust, credentialed browser reads, origin reflection, preflight policy bugs, and browser-based access to authenticated APIs.
---

# SKILL: CORS Misconfiguration — Credentialed Origins, Reflection, and Trust Boundary Errors

> **AI LOAD INSTRUCTION**: Use this skill when browsers can access authenticated APIs cross-origin. Focus on reflected origins, credentialed requests, wildcard trust, parser mistakes, and origin allowlist bypasses. For JSONP hijacking deep dives, same-origin policy internals, honeypot de-anonymization, and CORS vs JSONP comparison, load the companion [SCENARIOS.md](./SCENARIOS.md).

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- JSONP hijacking complete attack scenario — watering hole + `<script>` cross-origin data theft
- Honeypot de-anonymization via JSONP — use social platform JSONP endpoints to identify anonymous visitors
- Same-origin policy deep dive — protocol/hostname/port definition, `document.domain` subdomain relaxation and its security risks
- CORS vs JSONP technical comparison — methods, error handling, credential behavior, migration path
- CORS exploitation payloads — reflected origin with `credentials: include`, null origin via sandboxed iframe
- Dual-site attack lab pattern — localhost:8981 (target) + localhost:8982 (attacker) testing setup

## 1. WHEN TO LOAD THIS SKILL

Load when:

- Responses contain `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, or preflight headers
- A browser-based attack path might read authenticated API responses
- JSON endpoints appear protected from CSRF but are readable cross-origin

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| wildcard with credentials | `Access-Control-Allow-Origin: *` plus credential support or equivalent broken behavior |
| reflected origin | server echoes arbitrary `Origin` |
| weak allowlist | suffix, prefix, substring, regex, or mixed-case matching errors |
| `null` origin | acceptance of sandboxed, file, or serialized origins |
| preflight trust | overbroad methods and headers |
| internal API exposure | admin or tenant data readable cross-origin |

## 3. QUICK TRIAGE

1. Send crafted `Origin` headers and inspect reflection.
2. Test with and without credentials.
3. Probe allowlist bypasses using attacker subdomains and parser edge cases.
4. If readable data is sensitive, chain to account or tenant impact.

## 4. RELATED ROUTES

- Session or JSON action abuse: [csrf cross site request forgery](../csrf-cross-site-request-forgery/SKILL.md)
- OAuth token leakage and callback binding: [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md)
- API auth context: [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md)