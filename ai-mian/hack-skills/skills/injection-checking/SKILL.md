---
name: injection-checking
description: >-
  Entry P1 category router for injection testing. Use when routing between XSS,
  SQLi, SSRF, XXE, SSTI, command injection, and NoSQL injection workflows based
  on how attacker-controlled input is consumed.
---

# Injection Testing Router

这是输入进入危险解释器或执行环境时的分类入口。

它适合在确认“这是注入类问题”之后，继续判断更偏向浏览器上下文、数据库、模板引擎、服务端请求、XML 解析器还是系统命令。

## When to Use

- 输入会进入 HTML、JS、SQL、模板、URL 提取器、XML 解析器或 shell
- 你还没决定应该先走 XSS、SQLi、SSRF、XXE、SSTI、CMDi 还是 NoSQL
- 你需要按输入流向选择正确的深度专题 skill

## Skill Map

- [XSS Cross Site Scripting](../xss-cross-site-scripting/SKILL.md)
- [SQLi SQL Injection](../sqli-sql-injection/SKILL.md)
- [SSRF Server Side Request Forgery](../ssrf-server-side-request-forgery/SKILL.md)
- [XXE XML External Entity](../xxe-xml-external-entity/SKILL.md)
- [SSTI Server Side Template Injection](../ssti-server-side-template-injection/SKILL.md)
- [CMDi Command Injection](../cmdi-command-injection/SKILL.md)
- [NoSQL Injection](../nosql-injection/SKILL.md)
- [Deserialization Insecure](../deserialization-insecure/SKILL.md)
- [JNDI Injection](../jndi-injection/SKILL.md)
- [Expression Language Injection](../expression-language-injection/SKILL.md)
- [CRLF Injection](../crlf-injection/SKILL.md)
- [Extra Injection Types (SSI, LDAP, XPath)](./EXTRA_INJECTION_TYPES.md)
- [Request Smuggling](../request-smuggling/SKILL.md)
- [Prototype Pollution](../prototype-pollution/SKILL.md)
- [Type Juggling](../type-juggling/SKILL.md)
- [HTTP Parameter Pollution](../http-parameter-pollution/SKILL.md)
- [XSLT Injection](../xslt-injection/SKILL.md)
- [CSV Formula Injection](../csv-formula-injection/SKILL.md)

## Recommended Flow

1. 先识别输入最终落点
2. 再选与该解释器最匹配的专题 skill
3. 小样本 payload 与 quick triage 已并入各主 skill，不再额外走 payload router

## Related Categories

- [file-access-vuln](../file-access-vuln/SKILL.md)