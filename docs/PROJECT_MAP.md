# AIMY-Skill Project Map

## Repository Structure

```
D:\Python\aimy-skill\
├── main.py                          # CLI入口点，35+子命令注册点
├── pyproject.toml                   # 项目元数据，依赖，工具配置
├── requirements.txt                 # 运行时依赖列表
├── lab_audit.py                     # 10端点量化验收实验室
├── lab_server.py                    # 测试HTTP服务器
├── ai-mian/                         # AI Agent 交互层 (Claude/AutoGPT/Cursor)
│   └── ...
├── hack-skills/                     # 80+ 安全攻击 Skill (核心资产)
│   ├── sql_injection.py
│   ├── xss_detector.py
│   ├── ssrf_detector.py
│   ├── ... (80+ 文件)
│   └── ...
├── engine/                          # 判定引擎 (证据分层、阈值、CVSS、OOB)
│   ├── __init__.py                   # 核心导出接口
│   ├── config.py                     # 集中化阈值配置 (Thresholds dataclass)
│   ├── diff.py                       # 差分分析 (相对基线 vs 绝对值)
│   ├── layering.py                   # 证据分层分类
│   ├── oob.py                        # OOB 离线判定
│   └── reproducibility.py            # 复现性验证
├── tools/                           # 130+ 安全工具/检测器/模块
│   ├── auth_bypass.py               # 认证绕过
│   ├── auth_engine.py                # 认证会话管理
│   ├── code_audit.py                 # 白盒代码审计入口
│   ├── crawler.py                    # 网页爬虫 (SPA支持)
│   ├── sql_injection.py              # SQL注入检测
│   ├── xss_detector.py               # XSS检测 (7+上下文)
│   ├── ssrf_detector.py              # SSRF检测 (9种scheme)
│   ├── ssti_detector.py              # 模板注入检测
│   ├── cmdi_detector.py              # 命令注入检测
│   ├── nosqli_detector.py            # NoSQL注入检测
│   ├── lfi_scanner.py                # 本地文件包含
│   ├── xxe_detector.py               # XML外部实体
│   ├── jwt_detector.py               # JWT分析
│   ├── jwt_attacker.py               # JWT攻击 (伪造/破解)
│   ├── cors_scanner.py               # CORS misconfiguration
│   ├── graphql_scanner.py            # GraphQL扫描
│   ├── graphql_abuser.py             # GraphQL高级利用
│   ├── waf_bypass.py                 # WAF指纹+绕过 (14种WAF×16编码器)
│   ├── auth_bypass.py                # 认证绕过 (6种技术)
│   ├── biz_logic_scanner.py          # 业务逻辑漏洞
│   ├── biz_logic_v2.py               # 业务逻辑 v2 (改进版)
│   ├── deserialization_detector.py   # 反序列化检测
│   ├── second_order_sqli.py          # 二阶SQL注入
│   ├── second_order_verifier.py      # 二阶验证器
│   ├── payload_engine.py             # payload引擎 (200+种子)
│   ├── payload_mutator.py            # payload变异 (编码/参数名)
│   ├── smuggler.py                     # HTTP请求走私
│   ├── chain_engine.py               # 利用链组合引擎
│   ├── proto_pollution.py            # 原型链污染检测
│   ├── type_confusion.py             # 类型混淆检测
│   ├── csrf_scanner.py               # CSRF检测
│   ├── idor_scanner.py               # 水平越权检测
│   ├── weakpass.py                   # 弱口令检测
│   ├── leak_scanner.py               # 秘密泄露检测
│   ├── domain_hunt.py / domain_attacks.py # 域渗透 (LDAP/Kerberos/ADCS)
│   ├── orchestrator.py               # 6阶段编排引擎 (入口: auto/deepscan/quickscan)
│   ├── reasoning_engine.py           # 贝叶斯推理引擎
│   ├── attack_graph.py               # 攻克图 (循环路径、多路径探索)
│   ├── context_memory.py             # 上下文记忆 (跨模块情报共享)
│   ├── tool_registry.py              # Skill/Tool注册中心
│   ├── oob_server.py                 # OOB服务器 (本地监听)
│   ├── mode.py                       # rookie/veteran模式开关
│   └── ... (约130文件)
├── engine/                          # 判定引擎 (复用)
│   ├── config.py                     # 阈值配置
│   ├── diff.py                       # 响应差分分析
│   ├── layering.py                   # 证据分类
│   ├── oob.py                        # OOB判定
│   └── reproducibility.py            # 复现性
├── payload_seeds/                   # Payload种子库 (YAML配置，6 DBMS分库)
│   ├── mysql.yml
│   ├── mssql.yml
│   ├── postgresql.yml
│   ├── oracle.yml
│   └── sqlite.yml
├── data/                            # 数据持久化
│   ├── storage.py                    # 结果存储
│   └── reporter.py                   # 报告生成 (JSON+HTML)
├── tests/                           # 662+ 测试用例
│   ├── test_sql_injection.py
│   ├── test_xss_detector.py
│   ├── ... (64个测试文件)
│   └── ...
├── tools/__init__.py                # 工具包初始化
├── tools/_session.py                # Session工厂 (_sess函数)
├── tools/_context.py                  # 上下文解析器
├── tools/_enrich.py                   # 结果丰富增强
├── tools/_session.py                # Session管理
├── lab_audit.py                     # 10端点量化验收实验室 (v3.5.1)
├── lab_server.py                    # 测试HTTP服务器
├── .github/                         # CI/CD配置
├── .gitignore
├── CHANGELOG.md                     # 版本变更日志 (v3.5.1细节)
├── README.md                        # 项目文档 (359行)
├── ruff.toml / .ruff_cache          # Lint配置
├── .mypy_cache/                     # Type check缓存
├── .pytest_cache/                   # Test缓存
├── .coverage                        # 覆盖率数据
└── README.md                        # 项目说明 (359行)
```

## 核心模块分类

### 1. 入口与编排
- **main.py**: CLI参数解析, 35+子命令分发
- **orchestrator.py**: 6阶段流水线编排 (recon → detect → verify → weaponize → report)
- **settings.py**: 全局配置 (环境变量驱动: AIMY_VERIFY_SSL, AIMY_MODE, AIMY_TIMEOUT等)

### 2. 检测器 (Detector)
约 30+ 个检测模块，覆盖全漏洞链:
- SQL注入: sql_injection, sqli_blind, sqli_oob, sqli_weaponizer, sqli_second_order
- XSS: xss_detector, xss_validate, xss_browser_verify, dom_xss
- SSRF: ssrf_detector, ssrf_pwn, ssrf_chain, ssrf_lateral
- SSTI: ssti_detector
- 命令注入: cmdi_detector
- NoSQL: nosqli_detector
- LFI: lfi_scanner
- XXE: xxe_detector
- JWT: jwt_detector, jwt_attacker
- CSRF: csrf_scanner
- 认证绕过: auth_bypass
- 业务逻辑: biz_logic_scanner, biz_logic_v2
- 原型链污染: proto_pollution
- 类型混淆: type_confusion
- GraphQL: graphql_scanner, graphql_abuser
- CMS指纹: cms_fingerprint

### 3. 武器化 (Weaponize)
- sqli_weaponizer: SQL注入数据提取 (UNION、布尔盲、时间盲)
- ssrf_pwn: SSRF云凭据+文件读取 (AWS/GCP/Azure/阿里云/IMDSv2/k8s)
- ssrf_chain: 多跳内网穿透 (Redis/SQL/K8s/Docker协议转换)
- deser_weaponizer: 反序列化payload生成
- reverse_shell: 反弹Shell生成器
- c2_beacon: C2心跳/指令验证

### 4. 判定引擎 (Engine)
- **config.py**: 集中化阈值 (Thresholds dataclass), 证据分层配置 (EVIDENCE_FAMILIES)
- **diff.py**: 响应差分分析 (状态码/字节数/关键词相对比率)
- **layering.py**: 证据分层 (同族取max，跨族叠加概率联合)
- **oob.py**: OOB离线判定 (本地0.0.0.0监听 + 公网dnslog)
- **reproducibility.py**: 复现性验证 (贝叶斯后验概率计算)

### 5. 上下文与情报 (Context & Intelligence)
- **context_memory.py**: 线程安全上下文记忆 (跨模块情报共享)
  - DBMS指纹 → 后续SQLi使用对应方言
  - WAF指纹 → 后续绕过使用匹配策略
  - 认证凭证 → 复用于后续测试
  - 内部服务 →  horizontal pivot
- **attack_graph.py**: 攻克图 (循环路径、Dijkstra最短路、状态空间搜索)
- **knowledge_graph.py**: 知识图谱 (技术关联、CVE映射)

### 6. Payload与突变
- **payload_engine.py**: 200+种子 (6 DBMS × 时间型/UNION/XSS/SSTI)
- **payload_mutator.py**: 编码/参数名变异 (raw/url/b64/hex)
- **adaptive_payload**: 智能payload建议

### 7. 存储与报告
- **storage.py**: 结果持久化 (SQLite/JSON)
- **reporter.py**: 报告生成 (JSON + HTML 格式)
- **src_report.py**: SRC工作流报告

### 8. 域渗透与Kali集成
- **domain_hunt.py / domain_attacks.py**: 域渗透 (AS-REP Roast/LDAP枚举/Kerberoast)
- **kali_executor.py**: Kali SSH集成 (Paramiko + 本地工具检测)
  - subprocess.run (本地模式) - 注意 shell=True 风险
  - paramiko.SSHClient (远程模式)
  - 工具检测: sqlmap, nmap, ffuf, nuclei 等 30+ 工具

### 9. AI Agent 集成层
- **ai-mian/**: 与 Claude Code / AutoGPT / Cursor 的统一接口
- **统一 check() 接口**: 所有 Skill 返回结构化 JSON
- **80+ 技能即插即用**: 统一输入输出格式

## 关键数据流

```
CLI (main.py)
    ↓
argparse → 命令分发
    ↓
_sess(args) -> AuthSession (认证上下文)
    ↓
Orchestrator (6阶段):
  1. Recon (指纹/端口/目录)
  2. Crawl (SPA爬虫/参数挖掘)
  3. Detect (30+检测器并行)
  4. Verify (交叉验证/Oracle/误报过滤)
  5. Weaponize (数据提取/利用链)
  6. Report (JSON+HTML报告)
    ↓
Context Memory (跨模块情报共享)
    ↓
Tool Execution (requests/playwright/subprocess/paramiko)
    ↓
Finding → Evidence → Verifier → Report
```

## 关键依赖

```text
requests          # HTTP客户端
beautifulsoup4    # HTML解析
PyJWT             # JWT处理
cryptography      # 密码学基础
paramiko          # SSH连接 (Kali集成)
playwright        # 浏览器自动化 (XSS验证)
setuptools        # 包管理
```

## 测试体系

662+ 个测试用例 (pytest), 分布在 tests/ 目录:
- 单元测试: detector逻辑, engine配置
- 集成测试: orchestrator流水线
-  mock测试: requests-mock, responses

## 安全关注点 (Initial Audit)

1. **subprocess shell=True** in kali_executor.py:196 - 本地模式命令注入风险
2. **硬编码的默认凭证**在 KaliConfig: default user="root", password="" 
3. **XSS在浏览器上下文中的 payload执行** - 潜在的 JS注入风险
4. **OOB 回调域名可配置** 但默认值为空 - 需要 AIMY_OOB_DOMAIN 环境变量
5. **Session 持久化** 通过 pickle 文件 - 可能的序列化安全风险
6. **传播的 Credentials** 在 context_memory.py 中作为明文存储
7. **SSRF 元数据URL** 在 context_memory._cloud_metadata_url 中硬编码 - 可配置但默认常见云平台