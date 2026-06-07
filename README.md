markdown
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
#git clone https://github.com/yangdada863/aimy-sikll.git && cd aimy-sikll && pip install -r requirements.txt  先别用  
安装完成后，执行 python main.py --help 验证。

✨ 功能一览
模块	功能	输入	输出
🔍 端口扫描	探测目标主机常见 TCP 端口	IP / 域名	JSON 格式开放端口列表
📂 目录枚举	基于字典进行 Web 路径模糊测试	URL + 字典文件	可访问路径 + HTTP 状态码
💉 SQL 注入检测	错误型 + 时间型 Payload 自动探测	URL + 参数名	脆弱点 + 触发 Payload + 漏洞类型
详细功能说明
<details> <summary><b>🔍 端口扫描</b> (点击展开)</summary>
默认扫描端口
21, 22, 23, 25, 80, 443, 445, 8080, 8443, 3306, 3389, 5432, 6379, 27017

特性

支持自定义端口列表

超时可调（默认 2 秒）

非阻塞并发探测

输出示例

json
{"target": "scanme.nmap.org", "open_ports": [22, 80, 9929]}
</details><details> <summary><b>📂 目录枚举</b> (点击展开)</summary>
字典支持

内置默认字典（兼容 Kali common.txt）

用户自定义字典文件（.txt，每行一个路径）

特性

自动处理 URL 拼接（忽略重复 /）

记录状态码：200, 403, 401, 500 等

可控制是否跟随重定向

输出示例

json
{
  "url": "http://example.com",
  "found": [
    ["http://example.com/admin", 200],
    ["http://example.com/backup.zip", 403]
  ]
}
</details><details> <summary><b>💉 SQL 注入检测</b> (点击展开)</summary>
内置 Payload 集

错误型：', ", ' OR '1'='1, 1' AND '1'='1

时间型：' OR SLEEP(5)--, ' WAITFOR DELAY '0:0:5'--

检测机制

错误型：响应体中出现 mysql、sql、syntax 等关键字

时间型：响应延时 > 3 秒（与正常请求对比）

输出示例

json
{
  "url": "http://testphp.vulnweb.com/artists.php",
  "param": "id",
  "vulnerabilities": [
    ["' OR '1'='1", "error-based"],
    ["' OR SLEEP(5)--", "time-based"]
  ]
}
</details>
🚀 使用示例
端口扫描
bash
python main.py portscan scanme.nmap.org
输出：

json
{"target": "scanme.nmap.org", "open_ports": [22, 80, 9929]}
目录枚举
bash
python main.py dirfuzz http://testphp.vulnweb.com --wordlist common.txt
输出：

json
{
  "url": "http://testphp.vulnweb.com",
  "found": [["http://testphp.vulnweb.com/admin", 200]]
}
SQL 注入检测
bash
python main.py sqlcheck http://testphp.vulnweb.com/artists.php --param id
输出：

json
{
  "url": "http://testphp.vulnweb.com/artists.php",
  "param": "id",
  "vulnerabilities": [["' OR '1'='1", "error-based"]]
}
🧠 设计架构 (AI‑Ready)
text
User Input → AI Agent (Claude Code / AutoGPT)
                ↓
          aimy-sikll (Skill)
        ┌─────────┼─────────┐
        ↓         ↓         ↓
   portscan   dirfuzz   sqlcheck
        ↓         ↓         ↓
   JSON 结构化输出 → 供 AI 进一步推理
与 AI Agent 集成：将本 Skill 的调用命令写入 Agent 的提示词或工具描述中，Agent 即可自动规划并执行渗透测试步骤。

🛠️ 开发与扩展
添加新工具：在 tools/ 目录下创建 .py 文件，实现核心逻辑，然后在 main.py 的 argparse 中注册子命令。

推荐扩展方向：子域名枚举、XSS 检测、CVE 匹配、弱口令爆破（需增加授权提示）。

bash
	模式选择：（rookie菜鸟模式，默认）或veteran（老鸟模式）。也可在对话中用/mode命令实时切换
# 单独运行某个工具（不通过 main.py）
python tools/port_scanner.py 127.0.0.1
⚠️ 法律声明
本工具仅限在已获得明确授权的环境中进行安全测试、CTF 竞赛或漏洞研究使用。
未经授权的使用可能违反法律法规。使用者需自行承担所有责任。

🤝 贡献
欢迎提交 Issue 或 Pull Request。
Star ⭐ 这个仓库，让更多人看到这个轻量级安全研究助手。
