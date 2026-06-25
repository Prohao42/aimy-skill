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

# aimy-sikll v2.1.0 — 能力全景评估
## 项目宣传网站
https://aimy-sikll.netlify.app/
=========
# aimy-sikll
>>>>>>>>> Temporary merge branch 2

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

<<<<<<<<< Temporary merge branch 1
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
=========
## 命令速查
>>>>>>>>> Temporary merge branch 2

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
