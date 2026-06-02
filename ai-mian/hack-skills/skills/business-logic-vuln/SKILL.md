---
name: business-logic-vuln
description: >-
  Entry P1 category router for business logic testing. Use when workflow abuse,
  race conditions, pricing flaws, or multi-step state attacks matter more than
  parser-level input injection.
---

# Business Logic Router

这是业务逻辑和状态机问题的分类入口。

## When to Use

- 目标涉及优惠券、库存、支付、审批、配额、邀请、试用或状态流转
- 问题不在解析器，而在“什么时候检查”和“检查了什么业务条件”
- 你怀疑是竞态、流程绕过、价格篡改、负值、叠加优惠或多步骤缺陷

## Skill Map

- [Business Logic Vulnerabilities](../business-logic-vulnerabilities/SKILL.md)

## Recommended Flow

1. 先画出关键业务状态和一次性动作
2. 再判断是否存在 check-then-act 窗口、顺序依赖或跨步骤授权缺失
3. 若业务链路依赖 API、上传或对象权限，再回到对应分类 skill 补链路

## Related Categories

- [api-sec](../api-sec/SKILL.md)
- [auth-sec](../auth-sec/SKILL.md)
- [file-access-vuln](../file-access-vuln/SKILL.md)