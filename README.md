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
  <b>⚡ 轻量级渗透测试辅助 Skill | 端口扫描 · 目录枚举 · SQL 注入检测 | 可嵌入 AI Agent (Claude Code / AutoGPT)</b>
</p>

---

## 📦 一条命令安装

```bash
git clone https://github.com/yangdada863/aimy-sikll.git && cd aimy-sikll && pip install -r requirements.txt

# aimy-sikll 功能清单

## 📋 概览

| 模块 | 功能 | 输入 | 输出 |
|:---|:---|:---|:---|
| **端口扫描** | TCP 端口存活探测 | IP / 域名 | JSON 开放端口列表 |
| **目录枚举** | Web 路径模糊测试 | URL + 字典 | 可访问路径 + HTTP 状态码 |
| **SQL 注入检测** | 错误型 / 时间型漏洞探测 | URL + 参数名 | 脆弱点 + Payload + 漏洞类型 |

---

## 🔍 端口扫描 (Port Scanner)

- **默认扫描端口**  
  `21, 22, 23, 25, 80, 443, 445, 8080, 8443, 3306, 3389, 5432, 6379, 27017`

- **特性**
  - 支持自定义端口列表
  - 超时可调（默认 2 秒）
  - 非阻塞并发探测

- **输出示例**
  ```json
  {"target": "scanme.nmap.org", "open_ports": [22, 80, 9929]}
