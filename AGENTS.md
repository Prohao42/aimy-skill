# AGENTS.md — aimy-skill 跨智能体接入指南

> 本文件是给所有 AI 智能体（Claude Code / Cursor / Cline / Aider / OpenCode 等）的通用入口。
> aimy-skill 是**验证判定层**：人工/爬虫发现可疑点后，由它快速确认、取证据、出报告，不做全站盲扫。

## 运行方式（任意 agent 通用）

```bash
python main.py <command> [args]      # 所有命令输出结构化 JSON（含 _meta 信封）
python main.py list                  # 列出全部 88 条命令
python -m tools.export_manifest      # 导出单一事实源 data/tools.json
python -m aimy_mcp.server            # MCP 接入（88 命令 + 14 kali 子命令 = 102 工具）
```

## 六步工作流

1. **信息收集** `python main.py recon TARGET --deep` / `waf TARGET` / `portscan` / `dirfuzz`
2. **攻击面** `crawl` / `param-mine` / `graphql`
3. **登录保活** `login --auth-url URL --auth-type form --auth-user U --auth-pass P` → 返回 `session_id`
4. **定向检测** 按下方路由表选命令，追加 `--session-id <id>` 保持登录态
5. **验证穿透** 工具自带负对照/误报过滤，报告前人工复测一次
6. **报告** 要素 = 接口 + 参数 + payload + 响应差异 + 影响面 + 复现步骤

## 路由表（可疑点 → 命令 → 技能文件）

| 可疑点 | 命令 | 技能文件 `ai-mian/hack-skills/skills/` |
|---|---|---|
| 数字 id 参数 | `sqlcheck` / `sqli-weaponize` | `sqli-sql-injection/SKILL.md` |
| 输出/回显点 | `xsscheck` / `xss-validate` | `xss-cross-site-scripting/SKILL.md` |
| ping 等命令执行点 | `cmdi` | `cmdi-command-injection/SKILL.md` |
| 模板渲染点 | `ssti` | `ssti-server-side-template-injection/SKILL.md` |
| 文件下载/路径参数 | `lfi` | `path-traversal-lfi/SKILL.md` |
| 请求 URL 参数外联 | `ssrf` / `ssrf-pwn` | `ssrf-server-side-request-forgery/SKILL.md` |
| 双账号越权对比 | `idor` | `idor-broken-object-authorization/SKILL.md` |
| JWT/Token | `jwt` / `jwt-exploit` | `jwt-oauth-token-attacks/SKILL.md` |
| 有 WAF 拦截 | `waf` / `waf-heavy` / `poja` | `waf-bypass-techniques/SKILL.md` + `aimy-armor-break/SKILL.md` |
| 请求走私 | `smuggler` | `request-smuggling/SKILL.md` |
| 云凭据泄露 | `cloud-pwn` | `cloud_pwn` 模块 |

## 破甲（防御绕过）一键

```bash
python main.py poja URL --param id --payload "1' OR 1=1 -- -" [--waf cloudflare] [--session-id <id>]
```

## 技能库

104 个攻击技能在 `ai-mian/hack-skills/skills/*/SKILL.md`，**纯 Markdown，任意 agent 可直接读取**
（frontmatter 的 `name`/`description` 是 Claude 专用字段，其他 agent 忽略即可）。
技能索引：`ai-mian/hack-skills/site/data/skills.json`。

## 全局参数（所有命令通用）

`--timeout SEC` `--delay SEC` `--mode rookie|veteran` `--format json|jsonl`
`--session-id ID`（login 后复用登录态）`--session-file PATH`（文件方式）
`--ssl-verify` `--auth-type form|api|basic` `--auth-url/--auth-user/--auth-pass`

## 文档

- `docs/tool_guide.md` 命令全量参考 · `docs/vuln_playbooks.md` 8 类漏洞打法 · `docs/report_writing.md` 报告写作
