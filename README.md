<div align="center">

  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=36&pause=1000&color=00FF88&center=true&vCenter=true&width=700&lines=aimy-skill+v2.2.0;AI-Ready+Penetration+Test+Kit;65+Modules+%C2%B7+35%2B+CLI+Commands">
    <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=36&pause=1000&color=00A67E&center=true&vCenter=true&width=700&lines=aimy-skill+v2.2.0;AI-Ready+Penetration+Test+Kit;65+Modules+%C2%B7+35%2B+CLI+Commands" alt="aimy-skill typing banner">
  </picture>

  <h1 align="center">🚀 aimy-skill</h1>

  <p align="center">
    <b>让 AI 替你挖洞</b> — 下一代 AI 嵌入式渗透测试工具包
    <br>
    <i>Next-generation AI-native penetration testing toolkit</i>
  </p>

  <div align="center">
    <a href="https://aimywz.edgeone.dev/"><b>🌐 官网</b></a> •
    <a href="#-核心优势"><b>✨ 优势</b></a> •
    <a href="#-快速上手"><b>⚡ 快速上手</b></a> •
    <a href="#-命令速查"><b>📖 命令</b></a> •
    <a href="#-架构"><b>🏗 架构</b></a> •
    <a href="#-法律声明"><b>⚖️ 声明</b></a>
  </div>

  <br>

  <div align="center">
    <img src="https://img.shields.io/badge/version-2.2.0-00A67E?style=for-the-badge&logo=semver&logoColor=white" alt="version">
    <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="python">
    <img src="https://img.shields.io/badge/modules-65-orange?style=for-the-badge" alt="modules">
    <img src="https://img.shields.io/badge/skills-80%2B-8B5CF6?style=for-the-badge" alt="skills">
    <img src="https://img.shields.io/badge/license-MIT-red?style=for-the-badge" alt="license">
    <img src="https://img.shields.io/badge/tests-220%2B-22C55E?style=for-the-badge" alt="tests">
    <img src="https://img.shields.io/badge/OS-Windows%20%7C%20Linux%20%7C%20macOS-64748B?style=for-the-badge" alt="os">
  </div>

</div>

---

## ✨ 核心优势

### 🧠 AI Agent 原生，开箱即用

专为 **Claude Code**、**AutoGPT**、**Cursor** 等 AI Agent 设计 —— 统一 `check()` 接口 + 结构化 JSON 输出，AI 直接解析，零二次开发。

```python
from tools.sql_injection import SQLInjectionChecker

checker = SQLInjectionChecker()
result = checker.check(
    url="http://target.com/page?id=1",
    param="id",
    sess=session,
    timeout=10,
)
# → {"vulnerable": true, "type": "boolean_blind", "dbms": "MySQL", "confidence": 0.95}
```

### 🔫 全攻击链覆盖，一站打通

| 阶段 | 能力 |
|------|------|
| 🔍 **侦察** | 端口扫描 · 目录枚举 · 网页爬虫 · SPA 动态爬取 · 参数挖掘 · **版本指纹** · **CVE 匹配** |
| 💉 **注入检测** | SQL · XSS · SSRF · 命令注入 · SSTI · NoSQL · LFI · GraphQL · **类型混淆** |
| 🔐 **认证突破** | 认证绕过 · JWT 检测/破解 · CORS · 双会话 BOLA · SAML |
| 🧠 **业务逻辑** | 价格篡改 · 条件竞争 · 工作流绕过 · Mass Assignment · **TOCTOU 竞态** |
| ⚔️ **武器化** | SQL 数据提取 · SSRF 云元数据 · JWT 伪造 · 反序列化 · 反弹 Shell · **多跳 SSRF 链** |
| 🛡️ **WAF 绕过** | 14 种 WAF 指纹 · 11 编码器 · HTTP 协议绕过 |
| ✅ **验证** | **5+ payload 交叉验证** · Oracle 验证 · 误报过滤 · 鲁棒验证 |

### 🚀 三行命令，从零到报告

```bash
# 全自动渗透（爬虫 → 检测 → 武器化 → 报告）
python main.py auto -u http://target.com

# 带认证的深度扫描
python main.py deepscan -u http://target.com/admin \
  --auth-type form --auth-user admin --auth-pass secret

# 单点快速检测
python main.py sqlcheck -u "http://target.com/page?id=1"
```

---

## ⚡ 快速上手

### 1️⃣ 安装

```bash
pip install -r requirements.txt
playwright install chromium        # 可选：SPA 爬虫 & XSS 浏览器验证
```

### 2️⃣ 安装 AI Agent 提示词

```bash
# 80+ Attack Skill，即插即用
https://github.com/Prohao42/aimy-skill
```

### 3️⃣ 跑一个全自动扫描

```bash
python main.py auto -u http://target.com
```

### 4️⃣ 极速模式（跳过验证层）

```bash
# 跳过所有验证层，极速扫描
python main.py auto -u http://target.com --skip-verify
```

### 环境要求

| 依赖 | 说明 |
|------|------|
| **Python 3.8+** | 核心运行环境 |
| **OS** | Windows / Linux / macOS |
| **Playwright** *(可选)* | SPA 爬虫 & XSS 浏览器验证 |
| **Kali 工具集** *(可选)* | 扩展高级功能 |

---

## 📖 命令速查

### 🔍 发现

```
portscan        TCP 端口扫描
dirfuzz         目录枚举
crawl           网页爬虫
param-mine      参数挖掘
```

### 💉 注入检测

```
sqlcheck        SQL 注入检测
sqli-blind      SQL 盲注利用（4 种 DBMS）
sqli-oob        OOB SQL 注入
xsscheck        XSS 检测（7+ 上下文）
xss-validate    XSS 浏览器验证（Playwright）
cmdi            命令注入检测
ssti            模板注入检测
ssrf            SSRF 检测（9 种 scheme）
nosqli          NoSQL 注入检测
lfi             本地文件包含
```

### 🔐 认证 & 授权

```
auth-bypass     认证绕过（6 种技术）
jwt             JWT 检测分析
jwt-exploit     JWT 破解/伪造
cors            CORS 跨域检测
```

### 🧠 业务逻辑

```
bizlogic        业务逻辑漏洞检测（9 种场景）
race            条件竞争检测
workflow        工作流执行
chain           利用链组合
```

### ⚔️ 武器化

```
sqli-weaponize  SQL 注入数据提取
ssrf-pwn        SSRF 云元数据 + 文件读取
ssrf-lateral    SSRF 横向移动
deser-weaponize 反序列化 payload 生成
reverse-shell   反弹 Shell 生成器
```

### 🛡️ WAF 绕过

```
waf             WAF 指纹识别（14 种）
waf-heavy       WAF 严格绕过注入检测
```

### 🔬 深度检测

```
graphql         GraphQL 扫描
deser           反序列化检测
proto-pollution 原型链污染检测
```

### 🤖 全自动流程

```
deepscan        深度扫描 → 爬虫 + 检测 + 报告
autohunt        自动狩猎 → + 参数挖掘 + 武器化
auto            全自动渗透 → 增强版
proxy           MITM 代理 → 凭据捕获
capture         数据包捕获
```

### 🛠 工具

```
fuzz            模糊测试
payload-mutate  Payload 变异
list            列出所有工具
```

### 🌐 全局选项

```
--timeout SEC       请求超时（默认: 10s）
--delay SEC         请求间隔
--mode MODE         输出模式: rookie / veteran
--skip-verify       跳过所有验证层（极速模式）
--auth-type TYPE    认证类型: form / api / basic
--auth-url URL      认证地址
--auth-user USER    用户名
--auth-pass PASS    密码
--session-file      会话持久化
--ssl-verify        启用 SSL 验证
```

---

## 🏗 架构

```
                    ┌──────────────┐
                    │   AI Agent   │   ← Claude Code / AutoGPT / Cursor
                    │  (ai-mian/)  │   ← 80+ Attack Skill 文件
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   CLI 入口    │   ← 35+ 命令 · argparse
                    │  (main.py)   │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  自动编排引擎  │   ← 6 阶段流水线
                    │ (orchestrator)│   ← ThreadPool 并行
                    └──────┬───────┘
                           │
    ┌──────────────────────┼──────────────────────┐
    │          │          │          │            │
 ┌──▼──┐  ┌───▼───┐  ┌───▼───┐  ┌──▼───┐  ┌────▼────┐
 │ 基础设施│  │  侦查  │  │ 注入检测│  │认证/  │  │ 业务逻辑  │
 │http_cli│  │crawler│  │sql_inj│  │访问控制│  │biz_logic│
 │payload │  │spa_crw│  │xss_det│  │jwt    │  │deviation│
 │oob_svr │  │dirfuzz│  │ssrf   │  │cors   │  │race_cond│
 │mitm    │  │portscan│  │cmdi   │  │dual_ses│  │workflow │
 └────────┘  └───────┘  └───────┘  └───────┘  └─────────┘
    ┌──────────────────────┬─────────────────────────┐
    │       武器化层        │        辅助分析层         │
    │  sqli_weaponizer     │  resp_profiler          │
    │  ssrf_pwn            │  verification_oracle    │
    │  ssrf_chain          │  enhanced_verify        │
    │  jwt_exploiter       │  false_positive_filter  │
    │  chain_engine        │  cross_validator        │
    └──────────────────────┴─────────────────────────┘
    ┌──────────────────────┬─────────────────────────┐
    │      智能分析层       │       新增能力模块        │
    │  reasoning_engine    │  version_fingerprint    │
    │  knowledge_graph     │  ssrf_chain (多跳)      │
    │  attack_graph        │  type_confusion         │
    │  attack_surface      │  enhanced_verify        │
    └──────────────────────┴─────────────────────────┘
```

### 🧩 核心引擎

| 模块 | 亮点 |
|------|------|
| **sqli_blind** | 4 种 DBMS 盲注 · 并行二分法 · OOB 通道 · 4 级 fallback |
| **ssrf_pwn** | AWS / GCP / Azure / 阿里云元数据 · IMDSv2 · k8s 发现 |
| **ssrf_chain** | 多跳内网穿透 · Redis / SQL / Docker / K8s 协议转换 |
| **waf_bypass** | 14 种 WAF 指纹 · 11 编码器 · HTTP 协议绕过 |
| **dual_session** | 双会话 BOLA 差分 · JSON 字段级比对 |
| **session_matrix** | 多身份矩阵 · 跨会话持久化 |
| **payload_engine** | YAML 种子 · 上下文感知变异 · 编码链 |
| **reasoning_engine** | 30+ 规则假设驱动 · 自动推断攻击路径 |
| **chain_engine** | SSRF→RCE · LFI→RCE · 链式利用组合 |
| **version_fingerprint** | 响应头/错误页版本提取 · 25+ 产品 CVE 匹配 |
| **type_confusion** | 7 种类型测试 · TOCTOU 竞态检测 |
| **enhanced_verify** | 5+ payload 交叉验证 · 降低误报率 |

---

## 🎯 适合谁用

| 角色 | 价值 |
|------|------|
| **渗透测试工程师** | 35+ 命令覆盖全攻击链，自动化报告 |
| **AI Agent 开发者** | 统一接口 + JSON 输出 + 80+ Skill，即插即用 |
| **安全研究员** | 深度武器化模块 + WAF 绕过引擎 |
| **CTF 选手** | 全链路工具包，快速验证漏洞 |
| **企业安全团队** | 自动化流水线 + 持续集成 |

---

## 🧪 测试

```bash
pytest                    # 全部测试
pytest --cov=tools        # 覆盖率报告
```

---

## 🌐 项目宣传网站

[aimywz.edgeone.dev](https://aimywz.edgeone.dev/)

---

## ⚖️ 法律声明

> **⚠️ 重要提醒**
>
> 本工具仅限 **已获得明确授权** 的环境中进行安全测试、CTF 竞赛或漏洞研究使用。未经授权使用可能违反法律法规。**使用者自行承担所有责任。**

---

<div align="center">
  <sub>
    Built with ❤️ for the security research community ·
    <a href="https://github.com/Prohao42/aimy-skill">GitHub</a>
  </sub>
</div>
