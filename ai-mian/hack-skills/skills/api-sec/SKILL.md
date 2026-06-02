---
name: api-sec
description: >-
  Entry P1 category router for API security. Use when choosing between API
  recon, authorization, token abuse, and hidden-parameter workflows before any
  deeper API topic skill.
---

# API Security Router

这是 API 安全测试的分类入口。

先用这个 skill 判断当前 API 更像是文档和资产发现、对象授权、令牌信任问题，还是 GraphQL 与隐藏参数问题，再进入更细的专题 skill。

## When to Use

- 目标暴露 REST API、移动端后端或 GraphQL 接口
- 你需要先确定 API 测试顺序，再进入具体专题
- 你想把对象授权、JWT、GraphQL、隐藏字段这些方向分开处理

## Skill Map

- [API Recon and Docs](../api-recon-and-docs/SKILL.md): OpenAPI、Swagger、版本漂移、隐藏文档
- [API Authorization and BOLA](../api-authorization-and-bola/SKILL.md): BOLA、BFLA、方法滥用、隐藏可写字段
- [API Auth and JWT Abuse](../api-auth-and-jwt-abuse/SKILL.md): Bearer token、Header 信任、Claim 滥用、限流绕过
- [GraphQL and Hidden Parameters](../graphql-and-hidden-parameters/SKILL.md): introspection、batching、未公开字段、隐藏参数

## Quick Triage

| Observation | Route |
|---|---|
| Swagger 或 OpenAPI 存在 | [api-recon-and-docs](../api-recon-and-docs/SKILL.md) |
| IDs 出现在 URL、JSON、Header 或 GraphQL args | [api-authorization-and-bola](../api-authorization-and-bola/SKILL.md) |
| JWT token visible in traffic | [api-auth-and-jwt-abuse](../api-auth-and-jwt-abuse/SKILL.md) |
| `/graphql` 或 batched JSON arrays 存在 | [graphql-and-hidden-parameters](../graphql-and-hidden-parameters/SKILL.md) |
| 注册、登录、资料更新接受额外字段 | [api-authorization-and-bola](../api-authorization-and-bola/SKILL.md) 然后 [api-auth-and-jwt-abuse](../api-auth-and-jwt-abuse/SKILL.md) |

## Recommended Flow

1. 先看接口暴露面和文档资产
2. 再看对象级和功能级授权
3. 再看令牌、Header、签名与限流边界
4. 如果有 GraphQL 或复杂 JSON，再进入隐藏字段和 schema 滥用

## Related Categories

- [auth-sec](../auth-sec/SKILL.md)
- [business-logic-vuln](../business-logic-vuln/SKILL.md)
- [recon-for-sec](../recon-for-sec/SKILL.md)