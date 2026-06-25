<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&pause=1000&color=00FF00&center=true&vCenter=true&width=500&lines=aimy-sikll+v2.1.0;AI-Ready+Penetration+Test+Kit" alt="Typing SVG" />
</p>

<p align="center">
  <b>轻量级 AI 嵌入式渗透测试工具包 — 65 模块 · 35+ CLI 命令 · 双模式输出 · AI Agent 原生</b>
</p>

<p align="center">
  <a href="https://aimy-sikll.netlify.app/">🌐 项目官网</a>
  ·
  <a href="#-命令速查">📖 命令速查</a>
  ·
  <a href="#-快速开始">🚀 快速开始</a>
</p>

---

<<<<<<< HEAD
## 📋 目录

- [一、项目概览](#一项目概览)
- [二、快速开始](#二快速开始)
- [三、架构全景](#三架构全景--10层能力栈)
- [四、模块详解](#四模块详解)
- [五、AI Agent 集成](#五ai-agent-集成)
- [六、命令速查](#六命令速查)
- [七、全局选项](#七全局选项)
- [八、使用示例](#八使用示例)
- [九、测试](#九测试)
- [十、综合评价](#十综合评价)
- [项目宣传网站](#项目宣传网站)
- [法律声明](#法律声明)

---

## 一、项目概览

| 维度 | 描述 |
|------|------|
| **定位** | 面向 AI Agent（Claude Code / AutoGPT / Cursor）的轻量级渗透测试辅助工具包 |
| **规模** | 65 个工具模块，35+ CLI 命令，~10,000 行 Python |
| **入口** | `main.py` — argparse CLI，统一 `check(url, param, sess, timeout) -> dict` 签名 |
| **版本** | v2.1.0 |
| **Python** | 3.8+ |
| **依赖** | requests, beautifulsoup4, playwright, pycryptodome, pyjwt, lxml 等 |
| **设计哲学** | 所有输出 JSON 结构化，AI Agent 可直接解析推理，无需人类干预 |

### 核心特性

- **全攻击链覆盖** — 侦察 → 注入检测 → 认证绕过 → 业务逻辑 → 武器化 → 报告，一站式流水线
- **AI 原生设计** — 统一 `check()` 接口 + JSON 输出 + 80+ Attack Skill，AI Agent 即插即用
- **双模式输出** — `rookie` 模式详细解释每步原理，`veteran` 模式简洁直达核心
- **WAF 绕过引擎** — 14 种 WAF 指纹识别 + 11 种编码器 + HTTP 协议层绕过
- **多身份矩阵** — SessionMatrix 支持多账号跨会话测试，BOLA 差分检测
- **OOB 带外验证** — 内置 DNS/HTTP OOB Server，支持盲注/SSRF/命令注入带外检测

---

## 二、快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/your-repo/aimy-sikll.git
cd aimy-sikll

# 安装依赖
pip install -r requirements.txt

# 安装 Playwright 浏览器（用于 SPA 爬虫和 XSS 验证）
playwright install chromium

# 查看版本
python main.py --version
```

### 基础用法

```bash
# 单点漏洞检测
python main.py sqlcheck -u "http://target.com/page?id=1"
python main.py xsscheck -u "http://target.com/search?q=test"
python main.py ssrf -u "http://target.com/fetch?url=http://example.com"

# 目录枚举
python main.py dirfuzz -u "http://target.com"

# 全自动渗透
python main.py auto -u "http://target.com" --mode veteran

# 带认证的扫描
python main.py deepscan -u "http://target.com/admin" \
  --auth-type form \
  --auth-url "http://target.com/login" \
  --auth-user "admin" \
  --auth-pass "password"

# 代理模式（拦截流量）
python main.py proxy --port 8080
```

---

## 三、架构全景 — 10层能力栈

```
┌───────────────────────────────────────────────────────────────┐
│                     AI Agent 层 (ai-mian/)                     │
│  CLAUDE.md · Rules · Hook · hack-skills (80+ Skill 文件)      │
├───────────────────────────────────────────────────────────────┤
│                     CLI 入口层 (main.py)                        │
│  35+ 命令 · argparse · 认证预处理 · 全局选项                    │
├───────────────────────────────────────────────────────────────┤
│                 自动化编排层 (orchestrator.py)                   │
│  6阶段流水线: Crawl → ParamMine → AuthBypass → Detect →        │
│  Weaponize → Report · ThreadPool · DualSessionManager          │
├────────────┬──────────┬──────────┬──────────┬─────────────────┤
│  基础设施   │  侦查    │  注入检测  │  认证/    │  业务逻辑       │
│            │          │          │  访问控制  │                │
│  http_client│ crawler  │ sql_inj  │ auth_bypass│ biz_logic_v2  │
│  settings   │ spa_crwl │ sqli_blnd│ jwt_detect │ deviation_ora  │
│  log_utils  │ dirfuzz  │ xss_det  │ cors_scan  │ workflow_trace │
│  payload_eng│ param_mn │ ssrf_det │ saml       │ constraint_gr  │
│  fuzz_engine│ portscan │ cmdi_det │ session_mx │ race_cond      │
│  mitm_proxy │ dns_reslv│ ssti_det │ dual_sess  │ race_profiler  │
│  oob_server │          │ nosqli   │            │                │
│  playwright │          │ lfi_scan │            │                │
├────────────┴──────────┴──────────┴──────────┼─────────────────┤
│           武器化层                            │  辅助分析层      │
│  sqli_weaponizer · ssrf_pwn · jwt_exploiter  │  resp_profiler  │
│  deser_weaponizer · reverse_shell            │  flow_reconstr  │
│  chain_engine · ssrf_lateral                 │  semantic_diff  │
│                                              │  html_ctx_parse │
│                                              │  param_classify  │
│                                              │  verification_oc │
└──────────────────────────────────────────────┴─────────────────┘
```

### 数据流

```
用户输入 → CLI 解析 → Orchestrator 编排
  ├─ Crawler: 发现页面/表单/API
  ├─ ParamMiner: 提取参数/端点
  ├─ AuthBypass: 尝试认证绕过
  ├─ Detectors: 并行注入检测 (SQL/XSS/SSRF/CMDI/SSTI...)
  ├─ Weaponizer: 漏洞利用/数据提取
  └─ Reporter: JSON 结构化输出
```

---

## 四、模块详解

### 4.1 基础设施层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `http_client.py` | — | 会话管理、请求重试、TLS配置 | 基础封装，复用 `requests.Session` |
| `settings.py` | — | 全局配置、环境变量、SSL验证 | 简单轻量 |
| `log_utils.py` | 16 | 日志配置、urllib3告警抑制 | 极简 |
| `payload_engine.py` | 417 | YAML种子加载、动态变异、上下文标记 | **深度好** — 支持 YAML 外部payload、上下文感知变异、编码链 |
| `fuzz_engine.py` | — | 通用模糊测试框架 | 基础型 |
| `mitm_proxy.py` | 439 | MITM代理、凭据捕获、请求修改 | **完整** — 可拦截HTTP/HTTPS、捕获form/header/cookie凭据 |
| `oob_server.py` | 190 | 带外服务器(DNS/HTTP)、回调路由 | **实用** — 支持 DNS/HTTP OOB、自动回调验证 |

### 4.2 侦查层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `crawler.py` | 342 | 多线程爬虫、URL去重、表单解析 | 中等 — 基础爬取能力，无JS渲染 |
| `spa_crawler.py` | 261 | SPA爬虫(Playwright)、动态路由、API嗅探 | **好** — 支持 Playwright 渲染 SPA，API调用嗅探 |
| `param_miner.py` | — | GET/POST参数爆破、JS参数提取 | 中等 — 常见参数名字典+响应差异性分析 |
| `param_classifier.py` | — | 参数类型分类 | 基础 |
| `smart_fuzzer.py` | 276 | 智能模糊测试、角色感知、上下文加权 | **好** — 支持 context-based payload 优先级、角色/端点特定fuzz |

### 4.3 注入检测层

| 模块 | 行数 | 检测类型 | 深度评估 |
|------|------|---------|---------|
| `sql_injection.py` | — | Error/Boolean/Time/Union | **中等** — 4种检测 + 6类DBMS指纹 |
| `sqli_blind.py` | 575 | 盲注利用(4DBMS、binary提取) | **核心深度模块** — 支持MySQL/PG/MSSQL/Oracle，4级fallback策略，并行二分法，OOB通道 |
| `sqli_oob.py` | — | OOB SQL注入(DNS/HTTP) | 中等 — DNS/OOB通道检测 |
| `xss_detector.py` | — | 反射型/存储型/属性/事件/JS上下文的XSS | **广度好** — 覆盖7+上下文，130+ payload |
| `xss_browser_verify.py` | — | 浏览器XSS验证(Playwright) | **好** — 真实浏览器验证，减少误报 |
| `ssrf_detector.py` | 381 | SSRF检测、回调验证、盲SSRF | **好** — 9种scheme，OOB验证，WAF绕过 |
| `cmdi_detector.py` | — | 命令注入(time/OOB/error) | 中等 — 时间盲注+OOB+错误检测 |
| `ssti_detector.py` | — | SSTI检测(多引擎) | 中等 — 覆盖Jinja2/Twig/FreeMarker/Velocity等 |
| `nosqli_detector.py` | — | NoSQL注入(MongoDB) | 基础 |
| `lfi_scanner.py` | — | LFI检测、wrapper探测 | 中等 — PHP wrappers /proc/self/environ 等 |
| `graphql_scanner.py` | — | GraphQL扫描(Introspection/Batching/DoS) | 中等 — Introspection+深度查询+批量攻击 |
| `deserialization_detector.py` | — | 反序列化检测(Java/PHP/Python) | 基础 — 简单oob+错误检测 |
| `proto_pollution.py` | — | 原型链污染检测 | 基础 — 有限payload集 |

### 4.4 武器化层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `sqli_weaponizer.py` | — | SQL数据提取(表名/列名/数据) | 中等 — 自动提取表结构 |
| `ssrf_pwn.py` | 335 | SSRF利用(云元数据/内部服务/文件读取) | **核心深度模块** — AWS/GCP/Azure/DO/阿里云4+元数据路径，IMDSv2支持，k8s/Docker/内网发现 |
| `jwt_exploiter.py` | — | JWT破解/伪造/alg混淆 | 中等 — 弱密钥爆破+alg:none |
| `deser_weaponizer.py` | — | Java反序列化payload生成 | 基础 |
| `reverse_shell.py` | — | 反弹Shell生成器 | 基础 — 语言one-liner生成 |
| `chain_engine.py` | — | 利用链组合(SSRF→LFI→RCE等) | 实验性 |

### 4.5 认证/访问控制层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `auth_bypass.py` | 183 | 认证绕过(路径/参数/Cookie/Header/JSON) | **好** — 6种绕过技术，路径规范化+角色枚举 |
| `jwt_detector.py` | 156 | JWT检测/算法识别/弱密钥/claim分析 | 中等 — 算法识别+常见弱密钥检测 |
| `cors_scanner.py` | — | CORS跨域配置检测 | 中等 — 反射origin+可信域检测 |
| `session_matrix.py` | 237 | 多身份矩阵管理、跨会话测试 | **好** — 多账号注册+会话持久化+跨用户测试 |
| `dual_session.py` | 181 | 双会话BOLA检测 | **核心模块** — 高/低权限并行请求，响应差分分析，JSON字段级比对 |
| `auth_engine.py` | — | 认证引擎(form/json/basic/Bearer) | 中等 |

### 4.6 WAF 绕过层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `waf_bypass.py` | 730 | WAF指纹识别+绕过引擎 | **核心深度模块** — 14种WAF指纹(Cloudflare/AWS/Azure/ModSec/Cloudfront/Comodo/Radware/F5等)，11种编码器，4种HTTP协议绕过(POST降级/chunked编码/Content-Type混淆/Header填充)，策略路由引擎 |

### 4.7 业务逻辑层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `biz_logic_scanner.py` | 678 | 9种业务漏洞检测 | 中等 — 价格篡改/数量溢出/重复注册/优惠券重用/Mass Assignment/权限提升等 |
| `biz_logic_v2.py` | 169 | 高级业务扫描(约束/竞态/IDOR链/工作流) | **好** — 多身份矩阵交叉验证 |
| `deviation_oracle.py` | 264 | 偏差预言机(6种测试) | **好** — AuthZ跨用户+IDOR链+状态重放+约束突破+方法篡改+Mass Assignment |
| `workflow_tracer.py` | 294 | 工作流追踪(状态/角色/资源ID) | **好** — 7种步骤角色、自动提取资源ID、生成跳过/重放测试 |
| `constraint_graph.py` | 286 | 约束图(数值关系/参数推断) | 中等 — 正则+JSON提取 |
| `race_condition.py` | 175 | 条件竞争(5种场景) | 中等 — 5种预定义场景+通用 |
| `race_profiler.py` | — | 竞态窗口检测 | 中等 — 并发窗口+状态标志 |

### 4.8 自动化编排层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `orchestrator.py` | 622 | 6阶段渗透流水线 | **好** — 爬虫→参数挖掘→认证绕过→漏洞检测→武器化→报告，线程池并行 |
| `workflow.py` | — | 工作流引擎 | 基础 — YAML定义步骤执行 |

### 4.9 基础设施工具层

| 模块 | 功能 | 评估 |
|------|------|------|
| `playwright_engine.py` | Playwright浏览器自动化 | 好 — SPA爬虫/XSS验证基础 |
| `playwright_auth.py` | Playwright认证 | 基础 |
| `packet_capture.py` | 流量捕获 | 基础 |
| `kali_capture.py` | Kali集成流量捕获 | 基础 |
| `kali_executor.py` | Kali命令执行 | 基础 |
| `kali_toolset.py` | Kali工具集接口 | 实验性 |

### 4.10 辅助分析层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `response_profiler.py` | — | 响应分析器(状态码/长度/关键词) | 中等 — 基线+偏差分析 |
| `response_analyzer.py` | — | 响应内容分析 | 基础 |
| `verification_oracle.py` | — | 漏洞验证预言机 | **好** — 多维度交叉验证 |
| `semantic_diff.py` | — | 语义差异分析 | 基础 |
| `flow_reconstructor.py` | — | 流程重构 | 实验性 |
| `html_context_parser.py` | — | HTML上下文解析 | 基础 — 用于XSS上下文判断 |
| `reporter.py` | — | 报告生成 | 基础 — JSON输出 |

---

## 五、AI Agent 集成

### 5.1 ai-mian/ 目录结构

```
ai-mian/
├── CLAUDE.md.md               # Agent 主配置 → 身份授权+工作方式
├── 模型主配置.md               # AI 模型配置文件
├── 新人上门配置文件.md          # 新项目引导配置
├── hook-security-context-hook.py.md  # 场景Hook → 自动路由到对应Skill
├── rules--security-research-context.md.md  # 规则 → 研究范围+输出标准
└── hack-skills/               # 80+ 专项攻击Skill
    ├── README_CN.md
    ├── README.md
    └── skills/                # 按攻击类型分类的子目录
        ├── 401-403-bypass-techniques/
        ├── active-directory-acl-abuse/
        ├── active-directory-certificate-services/
        ├── active-directory-kerberos-attacks/
        ├── ai-ml-security/
        ├── android-pentesting-tricks/
        ├── anti-debugging-techniques/
        ├── api-auth-and-jwt-abuse/
        ├── api-authorization-and-bola/
        ├── api-recon-and-docs/
        ├── api-sec/
        ├── arbitrary-write-to-rce/
        ├── auth-sec/
        ├── authbypass-authentication-flaws/
        ├── binary-protection-bypass/
        ├── browser-exploitation-v8/
        ├── business-logic-vuln/
        ├── business-logic-vulnerabilities/
        ├── classical-cipher-analysis/
        ├── clickjacking/
        ├── cmdi-command-injection/
        ├── code-obfuscation-deobfuscation/
        ├── container-escape-techniques/
        ├── cors-cross-origin-misconfiguration/
        ├── crlf-injection/
        ├── csp-bypass-advanced/
        ├── csrf-cross-site-request-forgery/
        ├── csv-formula-injection/
        ├── dangling-markup-injection/
        ├── defi-attack-patterns/
        ├── dependency-confusion/
        ├── deserialization-insecure/
        ├── dns-rebinding-attacks/
        ├── email-header-injection/
        ├── expression-language-injection/
        ├── file-access-vuln/
        ├── format-string-exploitation/
        ├── ghost-bits-cast-attack/
        ├── graphql-and-hidden-parameters/
        ├── hack/
        ├── hash-attack-techniques/
        ├── heap-exploitation/
        ├── http-host-header-attacks/
        ├── http-parameter-pollution/
        ├── http2-specific-attacks/
        ├── idor-broken-object-authorization/
        ├── injection-checking/
        ├── insecure-source-code-management/
        ├── ios-pentesting-tricks/
        ├── jndi-injection/
        ├── jwt-oauth-token-attacks/
        ├── kernel-exploitation/
        ├── kubernetes-pentesting/
        ├── lattice-crypto-attacks/
        ├── linux-lateral-movement/
        ├── linux-privilege-escalation/
        ├── linux-security-bypass/
        ├── llm-prompt-injection/
        ├── macos-process-injection/
        ├── macos-security-bypass/
        ├── memory-forensics-volatility/
        ├── mobile-ssl-pinning-bypass/
        ├── network-protocol-attacks/
        ├── ntlm-relay-coercion/
        ├── oauth-oidc-misconfiguration/
        ├── open-redirect/
        ├── path-traversal-lfi/
        ├── prototype-pollution/
        ├── prototype-pollution-advanced/
        ├── race-condition/
        ├── recon-and-methodology/
        ├── recon-for-sec/
        ├── request-smuggling/
        ├── reverse-shell-techniques/
        ├── rsa-attack-techniques/
        ├── saml-sso-assertion-attacks/
        ├── sandbox-escape-techniques/
        ├── smart-contract-vulnerabilities/
        ├── sqli-sql-injection/
        ├── ssrf-server-side-request-forgery/
        ├── ssti-server-side-template-injection/
        ├── stack-overflow-and-rop/
        ├── steganography-techniques/
        ├── subdomain-takeover/
        ├── symbolic-execution-tools/
        ├── symmetric-cipher-attacks/
        ├── traffic-analysis-pcap/
        ├── tunneling-and-pivoting/
        ├── type-juggling/
        ├── unauthorized-access-common-services/
        ├── upload-insecure-files/
        ├── vm-and-bytecode-reverse/
        ├── waf-bypass-techniques/
        ├── web-cache-deception/
        ├── websocket-security/
        ├── windows-av-evasion/
        ├── windows-lateral-movement/
        ├── windows-privilege-escalation/
        ├── xslt-injection/
        ├── xss-cross-site-scripting/
        └── xxe-xml-external-entity/
```

### 5.2 集成评估
=======
# aimy-sikll v2.1.0 — 能力全景评估
## 项目宣传网站:https://aimy-sikll.netlify.app/
## 一、项目概览

| 维度 | 描述 |
|------|------|
| **定位** | 面向 AI Agent（Claude Code / AutoGPT）的轻量级渗透测试辅助工具包 |
| **规模** | 65 个工具模块，35+ CLI 命令，~10,000 行 Python |
| **入口** | `main.py` — argparse CLI，统一 `check(url, param, sess, timeout) -> dict` 签名 |
| **版本** | v2.1.0 |
| **Python** | 3.8+ |
| **设计哲学** | 所有输出 JSON 结构化，AI Agent 可直接解析推理 |

---

## 二、架构全景 — 10层能力栈

```
┌───────────────────────────────────────────────────────────────┐
│                     AI Agent 层 (ai-mian/)                     │
│  CLAUDE.md · Rules · Hook · hack-skills (80+ Skill 文件)      │
├───────────────────────────────────────────────────────────────┤
│                     CLI 入口层 (main.py)                        │
│  35+ 命令 · argparse · 认证预处理 · 全局选项                    │
├───────────────────────────────────────────────────────────────┤
│                 自动化编排层 (orchestrator.py)                   │
│  6阶段流水线: Crawl → ParamMine → AuthBypass → Detect →        │
│  Weaponize → Report · ThreadPool · DualSessionManager          │
├────────────┬──────────┬──────────┬──────────┬─────────────────┤
│  基础设施   │  侦查    │  注入检测  │  认证/    │  业务逻辑       │
│            │          │          │  访问控制  │                │
│  http_client│ crawler  │ sql_inj  │ auth_bypass│ biz_logic_v2  │
│  settings   │ spa_crwl │ sqli_blnd│ jwt_detect │ deviation_ora  │
│  log_utils  │ dirfuzz  │ xss_det  │ cors_scan  │ workflow_trace │
│  payload_eng│ param_mn │ ssrf_det │ saml       │ constraint_gr  │
│  fuzz_engine│ portscan │ cmdi_det │ session_mx │ race_cond      │
│  mitm_proxy │ dns_reslv│ ssti_det │ dual_sess  │ race_profiler  │
│  oob_server │          │ nosqli   │            │                │
│  playwright │          │ lfi_scan │            │                │
├────────────┴──────────┴──────────┴──────────┼─────────────────┤
│           武器化层                            │  辅助分析层      │
│  sqli_weaponizer · ssrf_pwn · jwt_exploiter  │  resp_profiler  │
│  deser_weaponizer · reverse_shell            │  flow_reconstr  │
│  chain_engine · ssrf_lateral                 │  semantic_diff  │
│                                              │  html_ctx_parse │
│                                              │  param_classify  │
│                                              │  verification_oc │
└──────────────────────────────────────────────┴─────────────────┘
```

---

## 三、模块深度分析

### 3.1 基础设施层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `http_client.py` | — | 会话管理、请求重试、TLS配置 | 基础封装，复用 `requests.Session` |
| `settings.py` | — | 全局配置、环境变量、SSL验证 | 简单轻量 |
| `log_utils.py` | 16 | 日志配置、urllib3告警抑制 | 极简 |
| `payload_engine.py` | 417 | YAML种子加载、动态变异、上下文标记 | **深度好** — 支持 YAML 外部payload、上下文感知变异、编码链 |
| `fuzz_engine.py` | — | 通用模糊测试框架 | 基础型 |
| `mitm_proxy.py` | 439 | MITM代理、凭据捕获、请求修改 | **完整** — 可拦截HTTP/HTTPS、捕获form/header/cookie凭据 |
| `oob_server.py` | 190 | 带外服务器(DNS/HTTP)、回调路由 | **实用** — 支持 DNS/HTTP OOB、自动回调验证 |

### 3.2 侦查层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `crawler.py` | 342 | 多线程爬虫、URL去重、表单解析 | 中等 — 基础爬取能力，无JS渲染 |
| `spa_crawler.py` | 261 | SPA爬虫(Playwright)、动态路由、API嗅探 | **好** — 支持 Playwright 渲染 SPA，API调用嗅探 |
| `param_miner.py` | — | GET/POST参数爆破、JS参数提取 | 中等 — 常见参数名字典+响应差异性分析 |
| `param_classifier.py` | — | 参数类型分类 | 基础 |
| `smart_fuzzer.py` | 276 | 智能模糊测试、角色感知、上下文加权 | **好** — 支持 context-based payload 优先级、角色/端点特定fuzz |

### 3.3 注入检测层

| 模块 | 行数 | 检测类型 | 深度评估 |
|------|------|---------|---------|
| `sql_injection.py` | — | Error/Boolean/Time/Union | **中等** — 4种检测 + 6类DBMS指纹 |
| `sqli_blind.py` | 575 | 盲注利用(4DBMS、binary提取) | **核心深度模块** — 支持MySQL/PG/MSSQL/Oracle，4级fallback策略，并行二分法，OOB通道 |
| `sqli_oob.py` | — | OOB SQL注入(DNS/HTTP) | 中等 — DNS/OOB通道检测 |
| `xss_detector.py` | — | 反射型/存储型/属性/事件/JS上下文的XSS | **广度好** — 覆盖7+上下文，130+ payload |
| `xss_browser_verify.py` | — | 浏览器XSS验证(Playwright) | 好 — 真实浏览器验证，减少误报 |
| `ssrf_detector.py` | 381 | SSRF检测、回调验证、盲SSRF | **好** — 9种scheme，OOB验证，WAF绕过 |
| `cmdi_detector.py` | — | 命令注入(time/OOB/error) | 中等 — 时间盲注+OOB+错误检测 |
| `ssti_detector.py` | — | SSTI检测(多引擎) | 中等 — 覆盖Jinja2/Twig/FreeMarker/Velocity等 |
| `nosqli_detector.py` | — | NoSQL注入(MongoDB) | 基础 |
| `lfi_scanner.py` | — | LFI检测、wrapper探测 | 中等 — PHP wrappers /proc/self/environ 等 |
| `graphql_scanner.py` | — | GraphQL扫描(Introspection/Batching/DoS) | 中等 — Introspection+深度查询+批量攻击 |
| `deserialization_detector.py` | — | 反序列化检测(Java/PHP/Python) | 基础 — 简单oob+错误检测 |
| `proto_pollution.py` | — | 原型链污染检测 | 基础 — 有限payload集 |

### 3.4 武器化层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `sqli_weaponizer.py` | — | SQL数据提取(表名/列名/数据) | 中等 — 自动提取表结构 |
| `ssrf_pwn.py` | 335 | SSRF利用(云元数据/内部服务/文件读取) | **核心深度模块** — AWS/GCP/Azure/DO/阿里云4+元数据路径，IMDSv2支持，k8s/Docker/内网发现 |
| `jwt_exploiter.py` | — | JWT破解/伪造/alg混淆 | 中等 — 弱密钥爆破+alg:none |
| `deser_weaponizer.py` | — | Java反序列化payload生成 | 基础 |
| `reverse_shell.py` | — | 反弹Shell生成器 | 基础 — 语言one-liner生成 |
| `chain_engine.py` | — | 利用链组合(SSRF→LFI→RCE等) | 实验性 |

### 3.5 认证/访问控制层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `auth_bypass.py` | 183 | 认证绕过(路径/参数/Cookie/Header/JSON) | **好** — 6种绕过技术，路径规范化+角色枚举 |
| `jwt_detector.py` | 156 | JWT检测/算法识别/弱密钥/claim分析 | 中等 — 算法识别+常见弱密钥检测 |
| `cors_scanner.py` | — | CORS跨域配置检测 | 中等 — 反射origin+可信域检测 |
| `session_matrix.py` | 237 | 多身份矩阵管理、跨会话测试 | **好** — 多账号注册+会话持久化+跨用户测试 |
| `dual_session.py` | 181 | 双会话BOLA检测 | **核心模块** — 高/低权限并行请求，响应差分分析，JSON字段级比对 |
| `auth_engine.py` | — | 认证引擎(form/json/basic/Bearer) | 中等 |

### 3.6 WAF 绕过层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `waf_bypass.py` | 730 | WAF指纹识别+绕过引擎 | **核心深度模块** — 14种WAF指纹(Cloudflare/AWS/Azure/ModSec/Cloudfront/Comodo/Radware/F5/等)，11种编码器，4种HTTP协议绕过(POST降级/chunked编码/Content-Type混淆/Header填充)，策略路由引擎 |

### 3.7 业务逻辑层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `biz_logic_scanner.py` | 678 | 9种业务漏洞检测 | **中等** — 价格篡改/数量溢出/重复注册/优惠券重用/Mass Assignment/权限提升等，payload喷洒型 |
| `biz_logic_v2.py` | 169 | 高级业务扫描(约束/竞态/IDOR链/工作流) | **好** — 多身份矩阵交叉验证 |
| `deviation_oracle.py` | 264 | 偏差预言机(6种测试) | **好** — AuthZ跨用户+IDOR链+状态重放+约束突破+方法篡改+Mass Assignment |
| `workflow_tracer.py` | 294 | 工作流追踪(状态/角色/资源ID) | **好** — 7种步骤角色、自动提取资源ID、生成跳过/重放测试 |
| `constraint_graph.py` | 286 | 约束图(数值关系/参数推断) | **中等** — 正则+JSON提取，无因果推理 |
| `race_condition.py` | 175 | 条件竞争(5种场景) | 中等 — 5种预定义场景+通用 |
| `race_profiler.py` | — | 竞态窗口检测 | 中等 — 并发窗口+状态标志(重复创建/状态不匹配/完整性违反) |

### 3.8 自动化编排层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `orchestrator.py` | 622 | 6阶段渗透流水线 | **好** — 爬虫→参数挖掘→认证绕过→漏洞检测→武器化→报告，线程池并行，双会话管理 |
| `workflow.py` | — | 工作流引擎 | 基础 — YAML定义步骤执行 |

### 3.9 基础设施工具层

| 模块 | 功能 | 评估 |
|------|------|------|
| `playwright_engine.py` | Playwright浏览器自动化 | 好 — SPA爬虫/XSS验证基础 |
| `playwright_auth.py` | Playwright认证 | 基础 |
| `packet_capture.py` | 流量捕获 | 基础 |
| `kali_capture.py` | Kali集成流量捕获 | 基础 |
| `kali_executor.py` | Kali命令执行 | 基础 |
| `kali_toolset.py` | Kali工具集接口 | 实验性 |

### 3.10 辅助分析层

| 模块 | 行数 | 功能 | 评估 |
|------|------|------|------|
| `response_profiler.py` | — | 响应分析器(状态码/长度/关键词) | 中等 — 基线+偏差分析 |
| `response_analyzer.py` | — | 响应内容分析 | 基础 |
| `verification_oracle.py` | — | 漏洞验证预言机 | 好 — 多维度交叉验证 |
| `semantic_diff.py` | — | 语义差异分析 | 基础 — 响应文本差异比较 |
| `flow_reconstructor.py` | — | 流程重构 | 实验性 |
| `html_context_parser.py` | — | HTML上下文解析 | 基础 — 用于XSS上下文判断 |
| `reporter.py` | — | 报告生成 | 基础 — JSON输出 |

---

## 四、AI Agent 集成深度分析

### 4.1 ai-mian/ 目录结构

```
ai-mian/
├── CLAUDE.md.md               # Agent 主配置 → 身份授权+工作方式
├── 模型主配置.md               # AI 模型配置文件
├── 新人上门配置文件.md          # 新项目引导配置
├── hook-security-context-hook.py.md  # 场景Hook → 自动路由到对应Skill
├── rules--security-research-context.md.md  # 规则 → 研究范围+输出标准
└── hack-skills/               # 80+ 专项攻击Skill
    ├── README_CN.md
    ├── README.md
    └── skills/                # 按攻击类型分类的子目录
        ├── 401-403-bypass-techniques/
        ├── active-directory-acl-abuse/
        ├── ... (80+ skills)
        └── xxe-xml-external-entity/
```

### 4.2 集成评估
>>>>>>> d67cba42592db2644681fbcd92fe04e63ab5dca8

| 维度 | 评分 | 说明 |
|------|------|------|
| **Skill 覆盖面** | ⭐⭐⭐⭐⭐ | 80+ Skill 覆盖从 401绕过到 XXE 的全攻击面 |
| **工具调用** | ⭐⭐⭐⭐ | 统一 `check()` 接口，JSON输出，AI直接解析 |
| **自动路由** | ⭐⭐⭐⭐ | Hook 脚本根据上下文自动选择 Skill |
| **实战深度** | ⭐⭐⭐ | Skill 多为方法论指南，需要 AI 理解后手动执行 |

---

## 六、命令速查

### 发现 (Discovery)

| 命令 | 功能 | 用法示例 |
|------|------|---------|
| `portscan` | TCP端口扫描 | `python main.py portscan -u 10.0.0.1` |
| `dirfuzz` | 目录枚举 | `python main.py dirfuzz -u http://target.com` |
| `crawl` | 网页爬虫 | `python main.py crawl -u http://target.com --depth 2` |
| `param-mine` | 参数挖掘 | `python main.py param-mine -u http://target.com/page` |

### 注入检测 (Injection Detection)

| 命令 | 功能 | 用法示例 |
|------|------|---------|
| `sqlcheck` | SQL注入检测 | `python main.py sqlcheck -u "http://target.com/page?id=1"` |
| `sqli-blind` | SQL盲注利用 | `python main.py sqli-blind -u "http://target.com/page?id=1"` |
| `sqli-oob` | OOB SQL注入 | `python main.py sqli-oob -u "http://target.com/page?id=1" --oob-domain your.oob.com` |
| `xsscheck` | XSS检测 | `python main.py xsscheck -u "http://target.com/search?q=test"` |
| `xss-validate` | XSS浏览器验证 | `python main.py xss-validate -u "http://target.com/search?q=<script>alert(1)</script>"` |
| `cmdi` | 命令注入检测 | `python main.py cmdi -u "http://target.com/ping?host=127.0.0.1"` |
| `ssti` | 模板注入检测 | `python main.py ssti -u "http://target.com/hello?name=test"` |
| `ssrf` | SSRF检测 | `python main.py ssrf -u "http://target.com/fetch?url=http://example.com"` |
| `nosqli` | NoSQL注入检测 | `python main.py nosqli -u "http://target.com/api/user?id=1"` |
| `lfi` | 本地文件包含检测 | `python main.py lfi -u "http://target.com/file?name=test"` |

### 认证/授权 (Auth & Access Control)

| 命令 | 功能 | 用法示例 |
|------|------|---------|
| `auth-bypass` | 认证绕过检测 | `python main.py auth-bypass -u "http://target.com/admin"` |
| `jwt` | JWT检测 | `python main.py jwt -u "http://target.com/api/user"` |
| `jwt-exploit` | JWT破解/伪造 | `python main.py jwt-exploit -jwt "eyJhbGciOiJIUzI1NiIs..."` |
| `cors` | CORS检测 | `python main.py cors -u "http://target.com/api"` |

### 业务逻辑 (Business Logic)

| 命令 | 功能 | 用法示例 |
|------|------|---------|
| `bizlogic` | 业务逻辑漏洞检测 | `python main.py bizlogic -u "http://target.com/cart"` |
| `race` | 条件竞争检测 | `python main.py race -u "http://target.com/coupon/redeem"` |
| `workflow` | 工作流执行 | `python main.py workflow -f workflow/cart_flow.yaml` |
| `chain` | 利用链组合攻击 | `python main.py chain -c "ssrf+lfi+rce" -u "http://target.com"` |

### 深度检测 (Deep Detection)

| 命令 | 功能 | 用法示例 |
|------|------|---------|
| `graphql` | GraphQL扫描 | `python main.py graphql -u "http://target.com/graphql"` |
| `deser` | 反序列化检测 | `python main.py deser -u "http://target.com/rpc"` |
| `proto-pollution` | 原型链污染检测 | `python main.py proto-pollution -u "http://target.com/api/config"` |
| `waf` | WAF指纹识别与绕过 | `python main.py waf -u "http://target.com"` |
| `waf-heavy` | WAF严格绕过注入检测 | `python main.py waf-heavy -u "http://target.com/page?id=1"` |

### 武器化 (Weaponization)

| 命令 | 功能 | 用法示例 |
|------|------|---------|
| `sqli-weaponize` | SQL注入数据提取 | `python main.py sqli-weaponize -u "http://target.com/page?id=1" --dump-all` |
| `ssrf-pwn` | SSRF文件读取+云元数据 | `python main.py ssrf-pwn -u "http://target.com/fetch?url="` |
| `ssrf-lateral` | SSRF横向移动 | `python main.py ssrf-lateral -u "http://target.com/fetch?url=" --subnet 10.0.0.0/24` |
| `deser-weaponize` | 反序列化payload生成 | `python main.py deser-weaponize --type java --cmd "whoami"` |
| `reverse-shell` | 反弹Shell生成器 | `python main.py reverse-shell --ip YOUR_IP --port 4444` |

### 综合流程 (Multi-Phase Scans)

| 命令 | 功能 | 用法示例 |
|------|------|---------|
| `deepscan` | 深度扫描 (爬虫+检测+报告) | `python main.py deepscan -u "http://target.com"` |
| `autohunt` | 自动狩猎 (+参数挖掘+武器化) | `python main.py autohunt -u "http://target.com"` |
| `auto` | 全自动渗透 (增强版) | `python main.py auto -u "http://target.com"` |
| `proxy` | MITM代理 (凭据捕获) | `python main.py proxy --port 8080` |
| `capture` | 数据包捕获 | `python main.py capture --interface eth0` |

### 工具 (Utilities)

| 命令 | 功能 | 用法示例 |
|------|------|---------|
| `fuzz` | 模糊测试 | `python main.py fuzz -u "http://target.com/api" --dict params.txt` |
| `payload-mutate` | Payload变异 | `python main.py payload-mutate -f payloads/sqli.yaml --chain b64+url` |
| `list` | 列出所有工具 | `python main.py list` |

---

## 七、全局选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--timeout SEC` | 10.0 | 请求超时秒数 |
| `--delay SEC` | 0.0 | 请求间延迟秒数 |
| `--mode MODE` | rookie | 输出模式: rookie / veteran |
| `--auth-type TYPE` | — | 认证类型 (form/api/basic) |
| `--auth-url URL` | — | 认证URL |
| `--auth-user USER` | — | 认证用户名 |
| `--auth-pass PASS` | — | 认证密码 |
| `--session-file PATH` | — | 会话文件路径 (.pkl) |
| `--ssl-verify` | 关闭 | 启用SSL证书验证 |
| `-v, --version` | — | 显示版本 |

---

## 八、使用示例

### 示例 1：单目标 SQL 注入检测

```bash
python main.py sqlcheck -u "http://testphp.vulnweb.com/artists.php?artist=1"
```

输出示例：
```json
{
  "vulnerable": true,
  "type": "boolean_blind",
  "dbms": "MySQL",
  "payload": "1 AND 1=1",
  "confidence": 0.95
}
```

### 示例 2：全自动渗透扫描

```bash
python main.py auto -u "http://target.com" --mode veteran --timeout 15
```

### 示例 3：带认证的深度扫描

```bash
python main.py deepscan -u "http://target.com/dashboard" \
  --auth-type form \
  --auth-url "http://target.com/login" \
  --auth-user "admin@example.com" \
  --auth-pass "P@ssw0rd" \
  --session-file "session.pkl"
```

### 示例 4：SSRF 云元数据利用

```bash
python main.py ssrf-pwn -u "http://target.com/fetch?url=" \
  --cloud aws \
  --imdsv2
```

### 示例 5：WAF 绕过注入

```bash
# 先识别 WAF
python main.py waf -u "http://target.com"

# 使用绕过引擎检测注入
python main.py waf-heavy -u "http://target.com/page?id=1" --mode veteran
```

---

## 九、测试

```bash
# 运行所有测试
pytest

# 带覆盖率报告
pytest --cov=tools

# 运行特定测试
pytest tests/test_sqli_blind.py -v

# 性能测试
pytest --benchmark
```

### 测试文件

```
tests/
├── test_biz_logic_v2.py       # 7 测试
├── test_crawlers.py           # 7 测试
├── test_http_client.py        # 7 测试
├── test_param_miner.py        # 4 测试
├── test_ssrf_pwn.py           # 8 测试
├── test_sqli_blind.py         # 14 测试
└── test_sqli_basic.py         # 基础 SQL 注入测试
```
<<<<<<< HEAD

=======
>>>>>>> d67cba42592db2644681fbcd92fe04e63ab5dca8
---

## 十、综合评价

### 评分矩阵

| 维度 | 分数 | 说明 |
|------|------|------|
| **覆盖广度** | 8.5/10 | 从侦察→注入→认证→业务→武器化全链路覆盖 |
| **检测深度** | 5.5/10 | 多数模块为 payload 喷洒级，仅 sqli_blind/ssrf_pwn/waf_bypass 有深度 |
| **工程质量** | 7.0/10 | 模块解耦好，统一接口，但配置管理弱，异常处理不一致 |
| **AI 就绪度** | 8.5/10 | JSON输出、统一签名、ai-mian Agent配置、80+ Skill |
| **误报控制** | 6.0/10 | placeholder返回码过滤+verification_oracle验证链，但缺乏统计异常检测 |
| **文档** | 6.5/10 | README命令速查清晰，但缺少模块文档、架构设计图 |
| **代码质量** | 6.5/10 | 设计模式合理，但有些模块风格不一致，缺少类型标注 |

**综合：6.5/10 — 优秀的 AI 嵌入式扫描框架，但检测深度有待提升**

### 核心优势

1. **全攻击链覆盖** — 从端口扫描到内网横向，一站式多阶段流水线
2. **AI Agent 原生设计** — 统一 `check()` 签名 + JSON 输出 + ai-mian 全套 Agent 配置
3. **工程架构干净** — 模块解耦、ThreadPool 并发、ToolRegistry 自动发现
4. **武器化模块实用** — SSRF 云元数据（4+ 云服务商）、SQL 盲注 binary 提取
5. **WAF 绕过引擎** — 14 种 WAF 指纹 + 11 编码器 + HTTP 层绕过
6. **SessionMatrix 多身份矩阵** — 真正的业务逻辑检测基础架构

### 未来规划

- [ ] 增加更多深度检测模块（RCE、XXE、LDAP注入等）
- [ ] 提升测试覆盖率至 60%+
- [ ] 添加 YAML 工作流自定义编排
- [ ] Web 可视化报告面板
- [ ] 插件系统支持第三方扩展
- [ ] 更多云服务商的元数据路径支持
- [ ] AI Agent 自动决策引擎

---

## 项目宣传网站

https://aimy-sikll.netlify.app/

---

<<<<<<< HEAD
=======
## 七、命令速查

### 发现 (Discovery)
| 命令 | 功能 |
|------|------|
| `portscan` | TCP端口扫描 |
| `dirfuzz` | 目录枚举 |
| `crawl` | 网页爬虫 |
| `param-mine` | 参数挖掘 |

### 注入检测 (Injection Detection)
| 命令 | 功能 |
|------|------|
| `sqlcheck` | SQL注入检测 |
| `sqli-blind` | SQL盲注利用 |
| `sqli-oob` | OOB SQL注入 |
| `xsscheck` | XSS检测 |
| `xss-validate` | XSS浏览器验证 |
| `cmdi` | 命令注入检测 |
| `ssti` | 模板注入检测 |
| `ssrf` | SSRF检测 |
| `nosqli` | NoSQL注入检测 |
| `lfi` | 本地文件包含检测 |

### 认证/授权 (Auth & Access Control)
| 命令 | 功能 |
|------|------|
| `auth-bypass` | 认证绕过检测 |
| `jwt` | JWT检测 |
| `jwt-exploit` | JWT破解/伪造 |
| `cors` | CORS检测 |

### 业务逻辑 (Business Logic)
| 命令 | 功能 |
|------|------|
| `bizlogic` | 业务逻辑漏洞检测 |
| `race` | 条件竞争检测 |
| `workflow` | 工作流执行 |
| `chain` | 利用链组合攻击 |

### 深度检测 (Deep Detection)
| 命令 | 功能 |
|------|------|
| `graphql` | GraphQL扫描 |
| `deser` | 反序列化检测 |
| `proto-pollution` | 原型链污染检测 |
| `waf` | WAF指纹识别与绕过 |
| `waf-heavy` | WAF严格绕过注入检测 |

### 武器化 (Weaponization)
| 命令 | 功能 |
|------|------|
| `sqli-weaponize` | SQL注入数据提取 |
| `ssrf-pwn` | SSRF文件读取+云元数据 |
| `ssrf-lateral` | SSRF横向移动 |
| `deser-weaponize` | 反序列化payload生成 |
| `reverse-shell` | 反弹Shell生成器 |

### 综合流程 (Multi-Phase Scans)
| 命令 | 功能 |
|------|------|
| `deepscan` | 深度扫描 (爬虫+检测+报告) |
| `autohunt` | 自动狩猎 (+参数挖掘+武器化) |
| `auto` | 全自动渗透 (增强版) |
| `proxy` | MITM代理 (凭据捕获) |
| `capture` | 数据包捕获 |

### 工具 (Utilities)
| 命令 | 功能 |
|------|------|
| `fuzz` | 模糊测试 |
| `payload-mutate` | Payload变异 |
| `list` | 列出所有工具 |

## 全局选项

```
--timeout SEC      请求超时秒数 (默认: 10.0)
--delay SEC       请求间延迟秒数 (默认: 0.0)
--mode MODE       输出模式: rookie / veteran (默认: rookie)
--auth-type TYPE  认证类型 (form/api/basic)
--auth-url URL    认证URL
--auth-user USER  认证用户名
--auth-pass PASS  认证密码
--session-file    会话文件路径 (.pkl)
--ssl-verify      启用SSL证书验证 (默认关闭)
-v, --version     显示版本
```

## 架构

```
┌───────────────────────────────────────────────────────────────┐
│                     AI Agent 层 (ai-mian/)                     │
├───────────────────────────────────────────────────────────────┤
│                     CLI 入口层 (main.py)                        │
├───────────────────────────────────────────────────────────────┤
│                 自动化编排层 (orchestrator.py)                   │
├────────────┬──────────┬──────────┬──────────┬─────────────────┤
│  基础设施   │  侦查    │  注入检测  │  认证/    │  业务逻辑       │
│            │          │          │  访问控制  │                │
│  http_client│ crawler  │ sql_inj  │ auth_bypass│ biz_logic     │
│  settings   │ spa_crwl │ sqli_blnd│ jwt_detect │ deviation_ora  │
│  log_utils  │ dirfuzz  │ xss_det  │ cors_scan  │ workflow_trace │
│  payload_eng│ param_mn │ ssrf_det │ session_mx │ constraint_gr  │
│  mitm_proxy │ portscan │ cmdi_det │ dual_sess  │ race_cond      │
│  oob_server │          │ ssti_det │            │                │
│  playwright │          │ lfi_scan │            │                │
├────────────┴──────────┴──────────┴──────────┼─────────────────┤
│           武器化层                            │  辅助分析层      │
└──────────────────────────────────────────────┴─────────────────┘
```

核心模块包括:
- **waf_bypass** — 14种WAF指纹 + 11编码器 + HTTP层绕过
- **sqli_blind** — 4种DBMS盲注 + binary提取 + OOB通道
- **ssrf_pwn** — AWS/GCP/Azure/阿里云元数据 + IMDSv2 + k8s发现
- **dual_session** — 双会话BOLA差分检测
- **session_matrix** — 多身份矩阵跨用户测试
- **payload_engine** — YAML种子 + 上下文感知变异 + 编码链

## AI Agent 集成

`ai-mian/` 目录包含 Agent 配置文件与 80+ 专项攻击 Skill，覆盖从 401绕道到 XXE 的全攻击面。统一 `check(url, param, sess, timeout) -> dict` 签名，JSON 输出。

## 测试

```bash
pytest
pytest --cov=tools
```

>>>>>>> d67cba42592db2644681fbcd92fe04e63ab5dca8
## 法律声明

本工具仅限在已获得明确授权的环境中进行安全测试、CTF 竞赛或漏洞研究使用。未经授权的使用可能违反法律法规。使用者需自行承担所有责任。
