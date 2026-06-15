<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&pause=1000&color=00FF00&center=true&vCenter=true&width=500&lines=aimy-sikll;Penetration+Testing+Skill;AI-Ready+%7C+Lightweight" alt="Typing SVG" />
</p>

<p align="center">
  <a href="https://github.com/yangdada863/aimy-sikll/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.8%2B-brightgreen.svg" alt="Python"></a>
  <a href="https://github.com/yangdada863/aimy-sikll/stargazers"><img src="https://img.shields.io/github/stars/yangdada863/aimy-sikll?style=social" alt="Stars"></a>
  <a href="https://github.com/yangdada863/aimy-sikll/issues"><img src="https://img.shields.io/badge/contributions-welcome-orange.svg" alt="Contributions"></a>
</p>

<p align="center">
  <b>⚡ 轻量级渗透测试辅助技能包 · 可嵌入 AI Agent · 让 Claude Code / AutoGPT 真正「动手」执行安全测试</b>
</p>

---

# Aimy-Sikll - AI Agent 轻量级渗透测试辅助工具

`aimy-sikll` 是一个专为 **AI Agent**（如 Claude Code、AutoGPT）设计的轻量级渗透测试辅助工具。所有输出均为 JSON 结构化格式，方便 AI 自动推理。

## 命令速查

### 发现 (Discovery)
| 命令 | 功能 | 示例 |
|------|------|------|
| `portscan` | TCP端口扫描 | `python main.py portscan scanme.nmap.org` |
| `dirfuzz` | 目录枚举 | `python main.py dirfuzz http://example.com --wordlist common.txt` |
| `crawl` | 网页爬虫 | `python main.py crawl http://example.com --depth 2 --max-pages 30` |
| `param-mine` | 参数挖掘 | `python main.py param-mine http://example.com --threads 5` |

### 注入检测 (Injection Detection)
| 命令 | 功能 | 示例 |
|------|------|------|
| `sqlcheck` | SQL注入检测 | `python main.py sqlcheck http://testphp.vulnweb.com/artists.php --param id` |
| `sqli-blind` | SQL盲注利用 | `python main.py sqli-blind http://example.com/page --param id` |
| `sqli-oob` | OOB SQL注入 | `python main.py sqli-oob http://example.com/page --param id --domain oob.local` |
| `xsscheck` | XSS检测 | `python main.py xsscheck http://example.com/search --param q` |
| `xss-validate` | XSS验证 | `python main.py xss-validate http://example.com/search --param q` |
| `cmdi` | 命令注入检测 | `python main.py cmdi http://example.com/exec --param cmd` |
| `ssti` | 模板注入检测 | `python main.py ssti http://example.com/greet --param name` |
| `ssrf` | SSRF检测 | `python main.py ssrf http://example.com/fetch --param url` |
| `nosqli` | NoSQL注入检测 | `python main.py nosqli http://example.com/login --param id` |
| `lfi` | 本地文件包含检测 | `python main.py lfi http://example.com/file --param file` |

### 认证/授权 (Auth & Access Control)
| 命令 | 功能 | 示例 |
|------|------|------|
| `auth-bypass` | 认证绕过检测 | `python main.py auth-bypass http://example.com/admin` |
| `jwt` | JWT检测 | `python main.py jwt http://example.com/api` |
| `jwt-exploit` | JWT利用 (crack/伪造) | `python main.py jwt-exploit http://example.com/api --token eyJ...` |
| `cors` | CORS检测 | `python main.py cors http://example.com/api` |

### 其他检测 (Other Checks)
| 命令 | 功能 | 示例 |
|------|------|------|
| `graphql` | GraphQL扫描 | `python main.py graphql http://example.com/graphql` |
| `deser` | 反序列化检测 | `python main.py deser http://example.com/api --param data` |
| `proto-pollution` | 原型链污染检测 | `python main.py proto-pollution http://example.com/api --param data` |
| `waf` | WAF指纹识别与绕过 | `python main.py waf http://example.com --param id` |

### 武器化 (Weaponization)
| 命令 | 功能 | 示例 |
|------|------|------|
| `sqli-weaponize` | SQL注入数据提取 | `python main.py sqli-weaponize http://example.com/page --param id` |
| `ssrf-pwn` | SSRF文件读取与云元数据 | `python main.py ssrf-pwn http://example.com/fetch --param url` |
| `ssrf-lateral` | SSRF横向移动 | `python main.py ssrf-lateral http://example.com/fetch --param url` |
| `deser-weaponize` | 反序列化payload生成 | `python main.py deser-weaponize` |
| `reverse-shell` | 反弹Shell生成器 | `python main.py reverse-shell --lhost YOUR_IP --lport 4444` |

### 综合流程 (Multi-Phase Scans)
| 命令 | 功能 | 示例 |
|------|------|------|
| `deepscan` | 深度扫描 (爬虫+检测+报告) | `python main.py deepscan http://example.com` |
| `autohunt` | 自动狩猎 (+参数挖掘+武器化) | `python main.py autohunt http://example.com --threads 10` |
| `auto` | 全自动渗透 (增强版) | `python main.py auto http://example.com --threads 10 --max-pages 30` |
| `chain` | 利用链组合攻击 | `python main.py chain http://example.com/page --param id` |
| `proxy` | MITM代理 (凭据捕获) | `python main.py proxy --port 8080 --capture-time 60` |
| `workflow` | 工作流执行 | `python main.py workflow login_and_extract --target http://example.com` |

### 工具 (Utilities)
| 命令 | 功能 | 示例 |
|------|------|------|
| `fuzz` | 模糊测试 | `python main.py fuzz --payloads admin,root,test` |
| `payload-mutate` | Payload变异 | `python main.py payload-mutate --payload "1' OR '1'='1" --param id` |
| `list` | 列出所有可用工具 | `python main.py list` |

### 全局选项
```
--timeout SEC      请求超时秒数 (默认: 10.0)
--delay SEC       请求间延迟秒数 (默认: 0.0)
--auth-type TYPE  认证类型 (form/api/basic)
--auth-url URL    认证URL
--auth-user USER  认证用户名
--auth-pass PASS  认证密码
--session-file    会话文件路径 (.pkl)
-v, --version     显示版本
```

## 输出示例

```bash
# 端口扫描
$ python main.py portscan scanme.nmap.org
{"target": "scanme.nmap.org", "open_ports": [{"port": 22, "state": "open"}, {"port": 80, "state": "open"}], "count": 2}

# SQL注入检测
$ python main.py sqlcheck http://testphp.vulnweb.com/artists.php --param id
{"vulnerable": true, "type": "error", "evidence": ["' OR '1'='1"], "vector": "' OR '1'='1", "dbms": "MySQL"}

# 全自动扫描
$ python main.py auto http://testphp.vulnweb.com --max-pages 20
[*] Phase 1/5: Crawling http://testphp.vulnweb.com ...
  -> 8 pages, 15 endpoints, 5 params
[*] Phase 2/5: Parameter mining ...
  -> 12 params discovered across 3 endpoints
[*] Phase 3/5: Auth bypass probing ...
  -> 3 bypass vectors found (2 path, 1 cookie, 0 header)
[*] Phase 4/5: Vulnerability detection ...
  -> 2 vulnerabilities found: [SQLI:1] [XSS:1]
[*] Phase 5/5: Weaponization ...
  -> 2 exploit paths (1 ready)

[... JSON report ...]
```

## 认证系统

支持三种认证方式，使用 `--auth-type` 指定:

```bash
# 表单登录 (自动提取 CSRF token)
python main.py sqlcheck http://example.com/admin --auth-type form --auth-url http://example.com/login --auth-user admin --auth-pass secret

# API Bearer Token
python main.py deepscan http://example.com/api --auth-type api --auth-url http://example.com/api/login --auth-user admin --auth-pass secret

# HTTP Basic Auth
python main.py dirfuzz http://example.com --auth-type basic --auth-user admin --auth-pass secret
```

## 安装

```bash
pip install -r requirements.txt
# 或
uv sync
```

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest

# 带覆盖率
pytest --cov=tools
```

## 设计架构 (AI-Ready)

```
User Input → AI Agent (Claude Code / AutoGPT)
                ↓
          aimy-sikll
        ┌────┼────┬────┬────┐
        ↓    ↓    ↓    ↓    ↓
    portscan dirfuzz sqlcheck xsscheck ...
        ↓    ↓    ↓    ↓    ↓
   JSON 结构化输出 → 供 AI 进一步推理
```

## 架构优势

- **模块化**: 35+ 个独立工具，统一 `check(url, param, sess, timeout) -> dict` 签名
- **可扩展**: 添加新工具只需在 `tools/` 下创建文件，注册到 `tool_registry.py`
- **AI友好**: 所有输出 JSON 结构化，AI Agent 可直接解析推理
- **认证引擎**: 内置 form/api/basic 三种认证，支持 session 持久化
- **全自动流程**: 从爬虫→参数挖掘→漏洞检测→武器化一站式完成

## ⚠️ 法律声明

本工具仅限在已获得明确授权的环境中进行安全测试、CTF 竞赛或漏洞研究使用。未经授权的使用可能违反法律法规。使用者需自行承担所有责任。

## 🤝 贡献

欢迎提交 Issue 或 Pull Request。Star ⭐ 这个仓库，让更多人看到这个轻量级安全研究助手。
