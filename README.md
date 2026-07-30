<div align="center">
  <h1>aimy-sikll</h1>
  <p><strong>AI Agent 原生渗透测试技能库</strong><br>
  <em>111 模块 · 33,314 行 · 零 lint 错误</em></p>
</div>

<div align="center">

[![version](https://img.shields.io/badge/version-2.3.1-brightgreen)]()
[![python](https://img.shields.io/badge/python-3.8+-blue)]()
[![modules](https://img.shields.io/badge/modules-111-orange)]()
[![tests](https://img.shields.io/badge/tests-77-green)]()
[![ruff](https://img.shields.io/badge/ruff-0-brightgreen)]()
[![license](https://img.shields.io/badge/license-MIT-red)]()

</div>

---

## 概述

一套结构化的技能库，为 AI Agent 赋予自主渗透测试能力。每个模块暴露统一的 `check()` 接口，专供语言模型直接消费。

```python
from tools import check_sqli

result = check_sqli("http://target.com/page?id=1", "id")
# → {"vulnerable": true, "type": "boolean_blind", "confidence": 0.95}
```

---

## 攻击面

| 层面 | 覆盖 |
|-------|----------|
| 侦察 | 技术栈指纹(80+特征)、端口扫描(130+端口)、目录枚举、Git泄露检测、SSR数据提取、参数挖掘 |
| 注入检测 | SQLi(5方法)、XSS(8上下文)、SSRF(9协议)、SSTI(11引擎)、CMDI(3通道)、LFI、XXE、NoSQL、GraphQL |
| WAF绕过 | 14种WAF指纹、**22种自适应编码策略**、检测到拦截自动升级 |
| 认证突破 | JWT检测/破解/伪造、CORS、CSRF、SAML、OAuth、6种认证绕过技术 |
| 内网渗透 | ICMP/ARP存活发现、SMB空会话、WMI/PsExec/WinRM横向移动、LLMNR哈希捕获、SOCKS级联代理 |
| 数据库横向 | MSSQL xp_cmdshell、linked server枚举、MySQL OUTFILE、PostgreSQL dblink |
| 链式攻击 | SSRF→RCE、LFI→RCE、SQLi→Shell、gopher协议转换——**根据发现自动编排** |
| 自律循环 | 假设驱动：侦察→假设→测试→学习→迭代，贝叶斯信念更新 |

---

## 架构

系统采用分层架构，各层职责清晰分离：

```
                     ┌──────────────────────┐
                     │   AI Agent            │
                     │  (消费技能模块)        │
                     └──────────┬───────────┘
                                │
                     ┌──────────▼───────────┐
                     │   auto_pwn            │  自律攻击循环
                     │  假设→测试→学习→迭代   │  贝叶斯信念更新
                     │  无新发现自动终止       │  自动触发链式攻击
                     └──────────┬───────────┘
                                │
                     ┌──────────▼───────────┐
                     │   tool_registry       │  插件注册中心
                     │  40+ 检测器注册       │  配置驱动，一行添加
                     └──────────┬───────────┘
                                │
                     ┌──────────▼───────────┐
                     │   ScanContext         │  请求级上下文
                     │  session/timeout/     │  消除全局可变状态
                     │  findings/state       │  支持线程安全并发
                     └──────────────────────┘
```

**关键设计决策：**

- **注册中心模式**：新增检测器只需一行 `register_tool()`，不需要改动核心代码。
- **上下文对象**：`ScanContext` 替代模块级全局变量，确保线程安全。
- **反射分发**：`_run_detector_by_name()` 通过 inspect 解析函数签名，自动适配参数。
- **假设循环**：`auto_pwn` 维护贝叶斯信念，无新发现时自动终止。

---

## 安装

### 基础安装

```bash
git clone https://github.com/your-repo/aimy-sikll.git
cd aimy-sikll
pip install -r requirements.txt
```

### 可选依赖

```bash
# SPA爬虫 & XSS浏览器验证
pip install playwright
playwright install chromium

# SMB/WMI横向移动（impacket）
pip install impacket

# 数据库横向
pip install pymssql pymysql psycopg2-binary

# 全量开发依赖
pip install ".[dev]"
```

### 验证安装

```bash
python -c "from tools import check_sqli; print('OK')"
python main.py list
```

---

## 快速开始

```bash
# CLI — 全自动渗透
python main.py auto -u http://target.com

# 编程调用 — AI Agent 消费
python -c "
from tools import check_sqli, check_ssrf
r1 = check_sqli('http://target.com/page?id=1', 'id')
r2 = check_ssrf('http://target.com/fetch?url=', 'url')
print(r1, r2)
"

# 自律攻击循环
python -c "
from tools.auto_pwn import auto_pwn
report = auto_pwn('http://target.com')
print(f'确认: {len(report.get(\"confirmed\", []))} 个漏洞')
"
```

---

## 工作模式

### 模式一：AI Agent 直接调用（推荐）

AI 按需 import 技能模块，消费富化后的 JSON 结果：

```python
from tools import check_sqli, check_ssrf, check_xss

result = check_sqli("http://target.com/page?id=1", "id")
# → {"vulnerable": true, "type": "boolean_blind",
#     "_ai_advice": "Use sqli_weaponizer for data extraction",
#     "_next_steps": ["sqli_weaponizer"]}
```

### 模式二：自律攻击循环

交给 auto_pwn，系统自主决策：

```bash
python -c "
from tools.auto_pwn import auto_pwn
report = auto_pwn('http://target.com')
#  侦察 → 假设 → 测试 → 学习 → 迭代
#  贝叶斯信念更新，无新发现自动终止
"
```

### 模式三：CLI 全自动渗透

一键跑完侦察→检测→报告：

```bash
python main.py auto -u http://target.com
python main.py deepscan -u http://target.com
python main.py quickscan -u http://target.com  # 极速模式
```

### 模式四：单点检测

针对单个漏洞类型：

```bash
python main.py sqlcheck -u "http://target.com/page?id=1"
python main.py xsscheck -u "http://target.com/search?q=test"
```

### 模式五：内网渗透

```bash
# 存活发现 → 端口扫 → 横向移动
python -c "
from tools.internal_scan import full_network_scan
from tools.smb_lateral import lateral_move
print(full_network_scan('192.168.1.0/24'))
"
```

---

## 命令

### 侦察
```
portscan        TCP端口扫描
dirfuzz         目录枚举
crawl           网页爬虫
param-mine      参数挖掘
```

### 注入检测
```
sqlcheck        SQL注入（5种方法）
sqli-blind      盲注（4种DBMS）
sqli-oob        OOB注入
xsscheck        XSS（8种上下文）
cmdi            命令注入
ssti            模板注入（11种引擎）
ssrf            SSRF（9种协议）
nosqli          NoSQL注入
lfi             本地文件包含
```

### 认证 & 授权
```
auth-bypass     认证绕过（6种技术）
jwt             JWT检测分析
jwt-exploit     JWT破解与伪造
cors            CORS配置检测
```

### 内网渗透
```
internal-scan   网络发现（ICMP/ARP + 端口扫描）
smb-lateral     SMB空会话 + WMI/PsExec/WinRM
responder       LLMNR/NBT-NS哈希捕获
db-lateral      数据库横向（MSSQL/MySQL/PG）
```

### 武器化
```
sqli-weaponize  SQL注入数据提取（列数探测 + UNION）
ssrf-pwn        SSRF云元数据 + IMDSv2
reverse-shell   反弹Shell生成器
deser-weaponize 反序列化payload生成
```

### 自动化流程
```
auto            全自动渗透
auto-pwn        假设驱动自律攻击循环
deepscan        深度扫描
proxy           MITM代理
```

---

## 核心模块

| 模块 | 说明 |
|--------|-------------|
| `sqli_blind` | 4种DBMS盲注，并行二分搜索，OOB通道 |
| `sqli_weaponizer` | 列数探测，自适应UNION提取 |
| `ssrf_pwn` | AWS/GCP/Azure元数据，IMDSv2，Kubernetes |
| `waf_bypass` | 14种WAF指纹，22种自适应编码策略 |
| `attack_surface` | CVE知识库(10技术栈)，攻击路径排序 |
| `chain_engine` | 8条编排规则，根据发现自动组合 |
| `auto_pwn` | 假设驱动循环，贝叶斯信念更新 |
| `internal_scan` | ICMP/ARP存活扫描，多线程端口扫 |
| `smb_lateral` | SMB空会话，WMI，PsExec，WinRM |
| `responder_kit` | LLMNR/NBT-NS欺骗和哈希捕获 |
| `db_lateral` | MSSQL linked server，MySQL OUTFILE，PG dblink |
| `tunnel_agent` | 环境感知隧道，SOCKS级联，SSH跳板 |
| `smart_fuzzer` | 响应指纹识别，差分分数学习 |
| `tool_registry` | 插件系统，配置驱动，一行注册 |

---

## 质量

```
111 模块 · 33,314 行 · 77 测试
ruff: 0 错误 · 编译: 0 错误
```

---

## 环境要求

- Python 3.8+
- 可选：Playwright（SPA爬虫、XSS浏览器验证）
- 可选：impacket（SMB/WMI横向移动）

---

## 许可

MIT。仅限授权安全测试使用。使用者承担所有责任。

---

<div align="center">
  <sub>为 AI Agent 设计。为安全工程师构建。</sub>
</div>
