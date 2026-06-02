---
name: recon-for-sec
description: >-
  Entry P1 category router for reconnaissance and methodology. Use when mapping
  scope, discovering assets, fingerprinting technology, building endpoint
  inventory, and choosing the first high-value security testing path.
---

# Recon and Methodology Router

这是新目标和未知攻击面的起始入口。

## When to Use

- 你刚接一个新的目标，还不知道先测什么
- 你需要先做资产发现、技术识别、接口清点和测试路线规划
- 你想把后续测试建立在结构化方法论上，而不是随机枚举 payload

## Skill Map

- [Recon and Methodology](../recon-and-methodology/SKILL.md)
- [Insecure Source Code Management](../insecure-source-code-management/SKILL.md) — .git/.svn/.hg exposure detection
- [Dependency Confusion](../dependency-confusion/SKILL.md) — Supply chain reconnaissance for internal package names

## Recommended Flow

1. 先确认 in-scope 资产和目标类型
2. 再做资产发现、端口与服务识别、技术指纹与端点收集
3. 按收集到的现象再路由到 [api-sec](../api-sec/SKILL.md)、[auth-sec](../auth-sec/SKILL.md)、[injection-checking](../injection-checking/SKILL.md) 或 [business-logic-vuln](../business-logic-vuln/SKILL.md)