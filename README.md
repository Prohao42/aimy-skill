<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&pause=1000&color=00FF00&center=true&vCenter=true&width=600&lines=aimy-sikll+v2.1.0;AI-Ready+Penetration+Test+Kit;65+Modules+%C2%B7+35%2B+CLI+Commands" alt="Typing SVG" />
</div>

<h1 align="center">🚀 aimy-sikll</h1>
<p align="center"><b>让 AI 替你挖洞 — 下一代 AI 嵌入式渗透测试工具包</b></p>

<div align="center">
  <a href="https://aimy-sikll.netlify.app/">🌐 官网</a> •
  <a href="#-核心优势">✨ 优势</a> •
  <a href="#-快速上手">⚡ 快速上手</a> •
  <a href="#-命令速查">📖 命令</a> •
  <a href="#-架构">🏗 架构</a>
</div>

<br>

<div align="center">
  <img src="https://img.shields.io/badge/version-2.1.0-brightgreen" alt="version">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="python">
  <img src="https://img.shields.io/badge/modules-65-orange" alt="modules">
  <img src="https://img.shields.io/badge/skills-80%2B-purple" alt="skills">
  <img src="https://img.shields.io/badge/license-MIT-red" alt="license">
</div>

---

## ✨ 核心优势

### 🧠 AI Agent 原生，开箱即用

专为 Claude Code、AutoGPT、Cursor 等 AI Agent 设计——统一 `check()` 接口 + JSON 输出，AI 直接解析，无需二次开发。

```
from tools.sql_injection import SQLInjectionChecker
result = checker.check(url="http://target.com/page?id=1", param="id", sess=session, timeout=10)
# → {"vulnerable": true, "type": "boolean_blind", "dbms": "MySQL", "confidence": 0.95}
```

### 🔫 全攻击链覆盖，一站打通

| 阶段 | 能力 |
|------|------|
| 🔍 侦察 | 端口扫描 · 目录枚举 · 网页爬虫 · SPA动态爬取 · 参数挖掘 |
| 💉 注入检测 | SQL · XSS · SSRF · 命令注入 · SSTI · NoSQL · LFI · GraphQL |
| 🔐 认证突破 | 认证绕过 · JWT检测/破解 · CORS · 双会话BOLA · SAML |
| 🧠 业务逻辑 | 价格篡改 · 条件竞争 · 工作流绕过 · Mass Assignment · 优惠券滥用 |
| ⚔️ 武器化 | SQL数据提取 · SSRF云元数据 · JWT伪造 · 反序列化 · 反弹Shell |
| 🛡️ WAF 绕过 | 14种WAF指纹 · 11编码器 · HTTP协议绕过 |

### 🚀 三行命令，从零到报告

```bash
# 全自动渗透（爬虫 → 检测 → 武器化 → 报告）
python main.py auto -u http://target.com

# 带认证的深度扫描
python main.py deepscan -u http://target.com/admin --auth-type form --auth-user admin --auth-pass secret

# 单点快速检测
python main.py sqlcheck -u "http://target.com/page?id=1"
```

---

## ⚡ 快速上手

### 1. 安装

```bash
pip install -r requirements.txt && playwright install chromium
```
### 1. 智能体提示词安装
```bash智能体安装提示词
https://github.com/Prohao42/aimy-skill  安装这个
```
### 2. 跑一个全自动扫描

```bash
python main.py auto -u http://target.com
```

### 3. 看结果

输出是结构化 JSON，AI Agent 和人人都能看懂。

### 环境要求

- Python 3.8+
- 操作系统：Windows / Linux / macOS
- 可选：Playwright（SPA爬虫 & XSS浏览器验证）
- 可选：Kali Linux 工具集（扩展功能）

---

## 📖 命令速查

### 🔍 发现

```
portscan       TCP端口扫描
dirfuzz        目录枚举
crawl          网页爬虫
param-mine     参数挖掘
```

### 💉 注入检测

```
sqlcheck       SQL注入检测
sqli-blind     SQL盲注利用（4种DBMS）
sqli-oob       OOB SQL注入
xsscheck       XSS检测（7+上下文）
xss-validate   XSS浏览器验证（Playwright）
cmdi           命令注入检测
ssti           模板注入检测
ssrf           SSRF检测（9种scheme）
nosqli         NoSQL注入检测
lfi            本地文件包含
```

### 🔐 认证 & 授权

```
auth-bypass    认证绕过（6种技术）
jwt            JWT检测分析
jwt-exploit    JWT破解/伪造
cors           CORS跨域检测
```

### 🧠 业务逻辑

```
bizlogic       业务逻辑漏洞检测（9种场景）
race           条件竞争检测
workflow       工作流执行
chain          利用链组合
```

### ⚔️ 武器化

```
sqli-weaponize  SQL注入数据提取
ssrf-pwn        SSRF云元数据+文件读取
ssrf-lateral    SSRF横向移动
deser-weaponize 反序列化payload生成
reverse-shell   反弹Shell生成器
```

### 🛡️ WAF 绕过

```
waf             WAF指纹识别（14种）
waf-heavy       WAF严格绕过注入检测
```

### 🔬 深度检测

```
graphql         GraphQL扫描
deser           反序列化检测
proto-pollution 原型链污染检测
```

### 🤖 全自动流程

```
deepscan        深度扫描 → 爬虫+检测+报告
autohunt        自动狩猎 → +参数挖掘+武器化
auto            全自动渗透 → 增强版
proxy           MITM代理 → 凭据捕获
capture         数据包捕获
```

### 🛠 工具

```
fuzz            模糊测试
payload-mutate  Payload变异
list            列出所有工具
```

### 全局选项

```
--timeout SEC      请求超时（默认: 10s）
--delay SEC        请求间隔
--mode MODE        输出模式: rookie / veteran
--auth-type TYPE   认证类型: form / api / basic
--auth-url URL     认证地址
--auth-user USER   用户名
--auth-pass PASS   密码
--session-file     会话持久化
--ssl-verify       启用SSL验证
```

---

## 🏗 架构

```
                    ┌──────────────┐
                    │   AI Agent   │  ← Claude Code / AutoGPT / Cursor
                    │  (ai-mian/)  │  ← 80+ Attack Skill 文件
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   CLI 入口    │  ← 35+ 命令 · argparse
                    │  (main.py)   │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  自动编排引擎  │  ← 6阶段流水线
                    │ (orchestrator)│  ← ThreadPool 并行
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
    │  jwt_exploiter       │  semantic_diff          │
    │  chain_engine        │  reporter               │
    └──────────────────────┴─────────────────────────┘
```

### 核心引擎

| 模块 | 亮点 |
|------|------|
| **sqli_blind** | 4种DBMS盲注 · 并行二分法 · OOB通道 · 4级fallback |
| **ssrf_pwn** | AWS/GCP/Azure/阿里云元数据 · IMDSv2 · k8s发现 |
| **waf_bypass** | 14种WAF指纹 · 11编码器 · HTTP协议绕过 |
| **dual_session** | 双会话BOLA差分 · JSON字段级比对 |
| **session_matrix** | 多身份矩阵 · 跨会话持久化 |
| **payload_engine** | YAML种子 · 上下文感知变异 · 编码链 |

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

https://aimy-sikll.netlify.app/

---

## ⚠️ 法律声明

本工具仅限 **已获得明确授权** 的环境中进行安全测试、CTF 竞赛或漏洞研究使用。未经授权使用可能违反法律法规。使用者自行承担所有责任。

---

<div align="center">
  <sub>Built with ❤️ for the security research community</sub>
</div>
