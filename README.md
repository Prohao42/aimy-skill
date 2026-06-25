<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&pause=1000&color=00FF00&center=true&vCenter=true&width=500&lines=aimy-sikll+v2.1.0;AI-Ready+Penetration+Test+Kit" alt="Typing SVG" />
</p>

<p align="center">
  <b>轻量级 AI 嵌入式渗透测试工具包 — 65 模块 · 35+ CLI 命令 · 双模式输出</b>
</p>

---

# aimy-sikll

面向 AI Agent（Claude Code / AutoGPT）的轻量级渗透测试辅助工具包。所有输出 JSON 结构化，AI Agent 可直接解析推理。

## 安装

```bash
pip install -r requirements.txt
# 或
uv sync
```

依赖: `requests`, `beautifulsoup4`, `PyJWT`, `cryptography`

## 输出模式

支持 **菜鸟模式** 和 **老鸟模式**，通过 `--mode` 全局参数切换：

| 模式 | 命令 | 适用场景 |
|------|------|----------|
| 菜鸟 (rookie) | `--mode rookie` | 默认。输出详细说明、修复建议，保留所有漏洞 |
| 老鸟 (veteran) | `--mode veteran` | 专注高价值漏洞，自动过滤低危（反射XSS、信息泄露等） |

也支持环境变量 `AIMY_MODE=veteran`。

```bash
# 菜鸟模式 — 完整输出
python main.py --mode rookie sqlcheck --url http://target.com --param id

# 老鸟模式 — 仅高价值漏洞
python main.py --mode veteran sqlcheck --url http://target.com --param id
```

## 命令速查

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

## 法律声明

本工具仅限在已获得明确授权的环境中进行安全测试、CTF 竞赛或漏洞研究使用。未经授权的使用可能违反法律法规。使用者需自行承担所有责任。
