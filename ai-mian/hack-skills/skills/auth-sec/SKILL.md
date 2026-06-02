---
name: auth-sec
description: >-
  Entry P1 category router for authentication and authorization. Use when
  testing login flows, sessions, object authorization, JWT, OAuth, CORS, CSRF,
  and enterprise SSO weaknesses before any deeper auth topic skill.
---

# Authentication and Authorization Router

这是认证、会话和授权边界的分类入口。

它适合先判断问题更偏向登录机制、对象级授权、浏览器信任边界，还是 OAuth、JWT、SAML 这一类身份协议，再进入具体专题。

## When to Use

- 目标包含登录、注册、找回密码、2FA、Session、JWT、OAuth、SSO
- 你怀疑是对象授权、跨租户访问、跨域读取、CSRF 或协议配置错误
- 你需要决定应该先测认证还是先测授权

## Skill Map

- [Authentication Bypass](../authbypass-authentication-flaws/SKILL.md): 登录绕过、找回密码、2FA、枚举、爆破防护
- [IDOR Broken Object Authorization](../idor-broken-object-authorization/SKILL.md): IDOR、BOLA、BFLA、对象权限缺失
- [JWT OAuth Token Attacks](../jwt-oauth-token-attacks/SKILL.md): 算法混淆、密钥信任、Claim 滥用、Token 伪造
- [OAuth OIDC Misconfiguration](../oauth-oidc-misconfiguration/SKILL.md): redirect URI、state、nonce、PKCE、账号绑定
- [CSRF Cross Site Request Forgery](../csrf-cross-site-request-forgery/SKILL.md): CSRF token、SameSite、JSON CSRF、登录 CSRF
- [CORS Cross Origin Misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md): 反射 Origin、凭证化跨域读取、Allowlist 绕过
- [SAML SSO Assertion Attacks](../saml-sso-assertion-attacks/SKILL.md): assertion wrapping、签名验证、Audience、ACS 边界

## Recommended Flow

1. 先确认认证模型和会话边界
2. 再确认对象级和功能级授权
3. 然后进入 Token、跨域与协议细节
4. 有企业身份联邦时，再进入 OAuth、OIDC 或 SAML 专题

## Related Categories

- [api-sec](../api-sec/SKILL.md)
- 默认凭证、用户名变体、字典规模与端口聚焦已并入 [authbypass-authentication-flaws](../authbypass-authentication-flaws/SKILL.md)