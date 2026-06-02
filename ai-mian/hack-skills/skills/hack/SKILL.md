---
name: hack
description: >-
  Entry P0 primary router for HackSkills. Use when the task involves web
  application testing, API security assessment, recon, vulnerability triage,
  exploit path planning, or choosing the right next category skill before any
  deep topic skill.
---

# HACKING SKILLS / HackSkills

## Overview

这是一个面向 **漏洞赏金、Web 安全、API 安全、授权渗透测试** 的总入口技能。

它的核心作用不是替代所有专题技巧，而是帮助 Agent：

1. 先确定测试阶段（Recon / 验证 / 提权 / 组合链）
2. 再选择正确的漏洞类别
3. 避免只依赖基础训练数据，优先使用结构化方法论
4. 优先关注 AI 容易忽略但在实战里很重要的边界条件

## Trust Model

- 本知识库强调内容安全与可审查性。
- 使用时应限定在 **授权目标**、**合法研究**、**防御验证**、**漏洞赏金规则允许** 的范围内。
- 不要把这里的技巧用于未授权攻击。

## When to Use This Skill

在以下场景优先使用本技能：

- 你刚接手一个新的漏洞赏金目标，不知道先测什么
- 你需要决定应该加载 XSS / SQLi / SSRF / IDOR / JWT / API 等哪类思路
- 你想让 Agent 按更稳定的方法论进行 Web/API 安全测试
- 你需要把零散的现象路由到合适的攻击面
- 你希望 AI 在安全领域少漏掉关键测试点

## Operating Model

### Step 1: 先做 Recon 和上下文确认

优先收集：

- 目标类型：传统 Web、REST API、移动端后端、管理后台、支付流程、文件上传、GraphQL
- 身份与权限模型：匿名、普通用户、管理员、多租户
- 输入位置：URL、查询参数、JSON、Header、Cookie、文件名、导入文件、模板、回显点
- 输出位置：HTML、属性、JS、PDF、邮件、日志、后台任务、移动端接口

### Step 2: 按观察到的现象路由

| 现象 | 优先方向 |
|---|---|
| 输入反射到 HTML / JS | XSS / SSTI |
| 服务端会主动访问 URL / 主机名 | SSRF |
| 接收 XML / Office / SVG | XXE |
| 路径、文件名、下载接口可控 | Path Traversal / LFI |
| API 中大量对象 ID | IDOR / BOLA / BFLA |
| 登录、找回密码、2FA、Session | Auth Bypass / JWT / OAuth |
| 多步骤交易、优惠券、价格、库存 | Business Logic |
| MongoDB / JSON 查询语法暴露 | NoSQL Injection |
| 命令行工具、图像处理、导入器 | Command Injection |
| HTTP 请求解析异常 / 前后端分帧不一致 | Request Smuggling |
| Node.js JSON 处理 / `__proto__` 可控 | Prototype Pollution |
| PHP 弱比较 / 0e hash / 松散条件 | Type Juggling |
| 同名参数重复 / WAF 与应用解析不一致 | HTTP Parameter Pollution |
| 一次性操作（优惠券/库存/重置） | Race Condition |
| XML/XSLT 模板处理 | XSLT Injection |
| .git/.svn/.env 路径可访问 | Insecure SCM |
| 导出 CSV/Excel 功能 | CSV Formula Injection |
| WebSocket 协议升级 | WebSocket Security |
| 内部包名 / 供应链清单 | Dependency Confusion |

### Step 3: 使用最可能命中的测试顺序

1. Recon / Methodology
2. API Security / Auth / IDOR
3. XSS / SQLi / SSRF / SSTI / XXE
4. Business Logic / Race Condition
5. 组合链与提权路径

## Core Skill Map

如果你拥有完整仓库，优先结合这些专题文档一起使用：

- [Recon and Methodology](../recon-and-methodology/SKILL.md)
- [XSS Cross Site Scripting](../xss-cross-site-scripting/SKILL.md)
- [SQLi SQL Injection](../sqli-sql-injection/SKILL.md)
- [SSRF Server Side Request Forgery](../ssrf-server-side-request-forgery/SKILL.md)
- [XXE XML External Entity](../xxe-xml-external-entity/SKILL.md)
- [SSTI Server Side Template Injection](../ssti-server-side-template-injection/SKILL.md)
- [IDOR Broken Object Authorization](../idor-broken-object-authorization/SKILL.md)
- [CMDi Command Injection](../cmdi-command-injection/SKILL.md)
- [Path Traversal LFI](../path-traversal-lfi/SKILL.md)
- [CSRF Cross Site Request Forgery](../csrf-cross-site-request-forgery/SKILL.md)
- [API Security Router](../api-sec/SKILL.md)
- [JWT OAuth Token Attacks](../jwt-oauth-token-attacks/SKILL.md)
- [OAuth OIDC Misconfiguration](../oauth-oidc-misconfiguration/SKILL.md)
- [CORS Cross Origin Misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md)
- [SAML SSO Assertion Attacks](../saml-sso-assertion-attacks/SKILL.md)
- [Authentication Bypass](../authbypass-authentication-flaws/SKILL.md)
- [Business Logic Vulnerabilities](../business-logic-vulnerabilities/SKILL.md)
- [Upload Insecure Files](../upload-insecure-files/SKILL.md)
- [NoSQL Injection](../nosql-injection/SKILL.md)
- [Request Smuggling](../request-smuggling/SKILL.md)
- [Prototype Pollution](../prototype-pollution/SKILL.md)
- [Type Juggling (PHP)](../type-juggling/SKILL.md)
- [HTTP Parameter Pollution](../http-parameter-pollution/SKILL.md)
- [Race Condition](../race-condition/SKILL.md)
- [XSLT Injection](../xslt-injection/SKILL.md)
- [Insecure Source Code Management](../insecure-source-code-management/SKILL.md)
- [CSV Formula Injection](../csv-formula-injection/SKILL.md)
- [WebSocket Security](../websocket-security/SKILL.md)
- [Dependency Confusion](../dependency-confusion/SKILL.md)

原先单独拆出的 payload-selection、brute-selection 一类小 skill 已并回对应主 skill，避免入口过多导致 loader 负担和选择噪音。

## High-Value Expert Intuitions

这些点是很多基础模型容易忽略，但在真实漏洞赏金里经常有效：

1. **同一套过滤逻辑往往复用在多个页面**：一个点可绕过，类似页面通常也能绕过。
2. **参数名本身也是攻击面**：WAF 经常只盯参数值，不盯参数名。
3. **二阶漏洞非常常见**：存储时安全，不代表读取后进入危险上下文时也安全。
4. **BOLA 的本质是“有认证、无授权”**：A/B 账号切换重放非常关键。
5. **老版本接口最容易漏补丁**：v2 修了不代表 v1 下线了。
6. **业务逻辑漏洞往往回报最高**：它们难以被扫描器发现，也更容易长期存在。
7. **Race Condition 应优先测试“一次性”操作**：优惠券、领取、重置、邀请、试用、库存扣减。
8. **JWT 攻击先看密钥与算法上下文**：不要盲目试 payload，要先确认 `alg`、`kid`、JWKS、密钥来源。

## Suggested Prompts

可把本技能当作路由器来用，先让 Agent 明确阶段和目标：

- “先按漏洞赏金方法论帮我做这个目标的测试路线规划。”
- “这是一个 REST API，请优先从 BOLA、BFLA、Mass Assignment、JWT 角度审视。”
- “这个参数会触发服务端请求，请按 SSRF 思路列出关键验证点。”
- “这个功能是支付/优惠券/库存流程，请优先考虑业务逻辑和竞态。”
- “我只看到登录和找回密码流程，请按 Auth Bypass + OAuth/JWT + CSRF 路线分析。”

## Installation Notes

推荐 skill 名称：

- `hack`

推荐检索关键词：

- `HackSkills`
- `HACKING SKILLS`
- `bug bounty`
- `赏金猎人`

## Guidelines

- 优先按目标类型与现象路由，而不是随机枚举 payload。
- 需要 payload 时，优先使用对应主 skill 里的 quick start / first-pass 样本，而不是再跳一个中间入口。
- 优先寻找可复用的过滤器、共享组件和跨页面复现路径。
- 先确认认证边界、授权边界、版本边界，再深入利用。
- 优先保留可解释、可审查、可复现的测试过程。
- 当完整仓库可用时，优先回到专题文档获取更细的攻击细节。
