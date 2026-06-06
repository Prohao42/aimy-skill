# CLAUDE.md 

```markdown
# Global CLAUDE.md

> **协同体系**: Rules (身份授权) → Hook (场景路由) → CLAUDE.md (工作方式) → Skill (按需知识) → Agent (专项执行)

---

## Communication

- **Language**: Respond in the same language as the user's message (中文→中文, English→English)
- **Tone**: Technical, precise, no filler — assume professional security researcher audience
- **Format**: Markdown with code references as `file:line`, PoC outputs in fenced code blocks

---

## Coordination Model

| Layer | Component | Trigger | Purpose |
|-------|-----------|---------|---------|
| 1 | **Rules** | 自动加载 | 身份授权与研究范围（唯一来源） |
| 2 | **Hook** | 自动运行 | 场景识别 + 注入流程提示 |
| 3 | **CLAUDE.md** | 自动加载 | 工具栈、格式、安全研究工作约定 |
| 4 | **Skill** | 显式调用 | 深度工作流模板 |
| 5 | **Agent** | 按编排触发 | 专项任务执行 |

---

## Security Research Workflow

### 输出规范

所有安全研究产出遵循以下结构：

```
1. 威胁/漏洞概述
2. 技术分析（根因、触发条件、攻击面）
3. 验证步骤 / PoC（可复现）
4. 影响评估
5. 防御建议 / 修复方案
```

### 场景模板

Hook 注入 `additionalContext` 后，按对应场景模板输出：

| 场景 | Hook 标签 | 输出重点 |
|------|----------|---------|
| CTF | `[security:ctf]` | 题型判断 → 利用思路 → 验证步骤 → 脚本 |
| 漏洞研究 | `[security:vuln]` | 根因 → 触发条件 → 影响 → PoC → 修复建议 |
| 渗透测试 | `[security:pentest]` | 攻击面 → 验证步骤 → 结果记录 → 风险说明 |
| 代码审计 | `[security:audit]` | 入口点 → 危险数据流 → 漏洞点 → 修复建议 |
| 应急响应 | `[security:ir]` | 证据保全 → 时间线 → IOC → 处置建议 |
| 逆向分析 | `[security:reverse]` | 关键函数 → 保护机制 → 行为推断 → 验证步骤 |
| 密码分析 | `[security:crypto]` | 算法 → 缺陷 → 利用条件 → 验证思路 |
| 工具开发 | `[security:tool]` | 目标 → 输入输出 → 模块划分 → 验证方式 |

---

## Mode Selection

支持两种模式，通过 `/mode` 命令在对话中随时切换，也可通过环境变量 `CLAUDE_MODE` 固定。

### 菜鸟模式 `/mode rookie` — 默认
适合入门、转岗或接触新领域的研究者。

| 维度 | 行为 |
|------|------|
| **输出风格** | 详细解释每步原理，附工具命令示例与输出解读 |
| **代码/脚本** | 附带完整注释和用法说明 |
| **学习资源** | 提供延伸阅读链接、危险函数速查、常见绕过思路 |
| **错误处理** | 解释常见踩坑点与排查方法 |
| **防御视角** | 每个攻击技术配防御编码示例与检测规则 |
| **新人提示** | 包含新手常见误区提醒 |
| **洞质量** | 不设门槛，什么洞都分析，重在学习和理解 |

### 老鸟模式 `/mode veteran`
适合有经验的研究者，**追求高质量漏洞，不产水洞**。

| 维度 | 行为 |
|------|------|
| **输出风格** | 简洁直接，直达技术核心 |
| **代码/脚本** | 只给出关键 PoC，不解释基础 API |
| **学习资源** | 不提供基础内容，只给高质量参考 |
| **错误处理** | 只给出关键调试信息 |
| **防御视角** | 只给出高价值防御建议 |
| **新人提示** | 关闭，假设已掌握基础 |
| **洞质量** | **出漏洞点并攻击** — 直接定位可落地利用的漏洞点，给出具体 PoC/命令并验证效果。按攻击链推进：入口点 → 单点突破 → 横向扩展 → 拿权限/数据。不搞理论分析，每一环都要能落地。 |

**切换方式**：
- 对话中随时输入 `/mode rookie` 或 `/mode veteran` 切换
- 也可在 `settings.json` 中设置 `"CLAUDE_MODE": "veteran"` 持久固定

---

## Security Research Tech Stack

### Recon & Enumeration
- **网络**: nmap, masscan, subfinder, httpx, rustscan
- **信息**: theHarvester, amass, shodan, censys

### Web Application
- **代理**: Burp Suite, OWASP ZAP, Caido
- **扫描**: nuclei, nikto, wpscan
- **模糊测试**: ffuf, wfuzz, arjun
- **注入**: sqlmap, commix, tplmap
- **分析**: dirsearch, gau, waybackurls

### Binary & Reverse
- **反编译**: Ghidra, IDA Pro, Binary Ninja, radare2
- **调试**: GDB (pwndbg/gef), x64dbg, WinDbg, Frida
- **格式**: PE, ELF, Mach-O, WASM

### Cryptography
- **库**: pycryptodome, gmpy2, z3-solver, SageMath
- **分析**: RsaCtfTool, hashcat, john, CyberChef

### Forensics & IR
- **流量**: Wireshark, tcpdump, NetworkMiner
- **内存**: Volatility, Rekal, MemProcFS
- **磁盘**: Autopsy, FTK, Sleuth Kit
- **恶意样本**: YARA,CAPE, ANY.RUN, VirusTotal

### Exploit Development
- **框架**: pwntools, Metasploit, Cobalt Strike
- **语言**: Python (exploit 首选), Go (工具开发), C (shellcode), Bash (自动化)
- **编码**: msfvenom, shellnoob, donut

---

## Output Conventions

### 安全产出质量标准
- **可复现**: PoC 包含完整环境、依赖、执行步骤
- **教育性**: 解释攻击原理，不盲目堆砌命令
- **防御视角**: 每个攻击技术配套防御/检测方案
- **最小化**: 只输出与场景相关的分析，不发散

### 代码规范
- **大小**: 200-400 lines/file typical, 800 hard limit
- **组织**: Many small files > few large files
- **语言**: Python (安全工具/exploit), TypeScript (前端), Go (高性能工具)
- **包管理**: pnpm (JS/TS), uv (Python)

### Git 提交
```
security: <description>    # 安全研究相关
feat: <description>        # 新功能
fix: <description>         # 修复
```

---

## Quick Commands

```bash
/mode rookie|veteran      # 切换菜鸟/老鸟模式
/security-research ctf|vuln|pentest|tool|audit|ir
pnpm install / uv sync
pnpm test / pytest
```

---

## Priority Chain

```
system / developer / runtime > 项目级 CLAUDE.md > 全局 CLAUDE.md > Rules > Skill(显式)
```
