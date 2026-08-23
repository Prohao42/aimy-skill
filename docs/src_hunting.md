# SRC 挖洞实战手册（aimy-skill 配套用法）

> **教程体系**：
> - 本手册：SRC 全流程总纲
> - docs/vuln_playbooks.md：8 类漏洞实战打法（找点→验证→工具→报告）
> - docs/tool_guide.md：全部命令实战参考（按场景分类）
> - docs/report_writing.md：SRC 报告写作指南（怎么被采纳）

> 本手册面向**已获授权**的 SRC 众测。未授权测试违法，后果自负。
> 核心认知：SRC 的洞不是扫出来的，是"人工定向 + 工具验证"挖出来的。
> aimy-skill 的定位：**验证判定层**——你发现可疑点，它快速确认/抽数据/出报告。

## 一、SRC 挖洞全流程

    1. 信息收集   -> 2. 攻击面梳理 -> 3. 认证登录 -> 4. 定向检测 -> 5. 验证利用 -> 6. 报告提交

### 1. 信息收集

    python main.py recon https://target.com --deep
    python main.py portscan target.com --ports 80,443,8080
    python main.py dirfuzz https://target.com --max 200
    python main.py waf https://target.com          # 先看有没有 WAF

判断技术栈：PHP+MySQL 老站 → SQLi 重点；Java+Spring → SpEL/反序列化/越权；Node+Express → NoSQLi/原型链；Go → 少注入多逻辑洞。

### 2. 攻击面梳理

    python main.py crawl https://target.com --depth 2 --max-pages 100   # 找功能点
    python main.py param-mine https://target.com                        # 找参数
    python main.py graphql https://target.com/api/graphql               # GraphQL 优先（SRC 高频）

**SRC 高价值功能点**：登录/注册（越权、逻辑绕过）、密码重置（token 可预测）、文件上传、订单/支付（价格篡改）、API 越权（IDOR/BOLA）、OAuth/SSO 回调、导出/下载（任意文件）。

### 3. 认证登录（关键：90% 功能在登录后）

    # 登录并保存 session（SRC 核心工作流）
    python main.py login --auth-url https://target.com/login --auth-type form \
        --auth-user your_account --auth-pass your_pass --session-file sess.json

    # 后续所有扫描带上登录态
    python main.py sqlcheck "https://target.com/api/user?id=1" --session-file sess.json
    python main.py sqli-weaponize "https://target.com/api/user?id=1" --session-file sess.json

> 提示：SRC 测试优先用**自己的测试账号**，不要撞库/爆破他人账号（违规）。

### 4. 定向检测（对可疑点逐一验证，不是全站乱扫）

    # 发现 id=xxx 就试越权/注入
    python main.py sqlcheck "https://target.com/api/user?id=1" --session-file sess.json
    python main.py sqli-weaponize "https://target.com/api/user?id=1" --session-file sess.json

    # 有输出点就试 XSS（SRC 中反射 XSS 价值低，存储 XSS 高）
    python main.py xsscheck "https://target.com/search?q=test" --session-file sess.json
    python main.py xss-validate "https://target.com/search?q=test" --session-file sess.json

    # 命令/模板/文件
    python main.py cmdi "https://target.com/ping?host=1.1.1.1"
    python main.py ssti "https://target.com/hello?name=test"
    python main.py lfi "https://target.com/download?file=readme.txt"

    # SSRF（SRC 高频：图片代理/URL 抓取/回调）
    python main.py ssrf "https://target.com/fetch?url=http://x"
    python main.py ssrf-pwn "https://target.com/fetch?url=http://x"

### 5. 验证利用（确认漏洞真实存在 + 提取证据）

    # SQLi 命中后抽数据（用自己测试库，别碰真实用户数据）
    python main.py sqli-weaponize "https://target.com/api/user?id=1" --session-file sess.json

    # 二阶注入（存储型 SQLi，注册/资料处注入 -> 登录后触发）
    python main.py sqli-second-order "https://target.com/" --param username --session-file sess.json

### 6. 报告提交（SRC 评审看这个）

    # 用 src_report 生成可提交报告（描述/复现/影响/修复建议）
    python -c "
    from tools.src_report import src_report, src_report_markdown
    finding = {'type': 'boolean', 'url': 'https://target.com/api/user?id=1',
               'param': 'id', 'vector': '1 AND 1=1', 'evidence': ['diff=200']}
    print(src_report_markdown(src_report(finding)))
    "

**报告要点**：复现步骤要可重现（具体 URL+Payload）、影响要说清（能读什么数据）、别贴大段数据（SRC 严禁拖库取证）。

## 二、SRC 高价值漏洞优先级（按收益/难度）

| 优先级 | 漏洞 | 工具 | 注意 |
|---|---|---|---|
| ★★★ | IDOR/越权（改 id 看别人数据） | 手工 + curl | SRC 最常收，先测这个 |
| ★★★ | 存储 XSS（管理员后台执行） | xsscheck + 手工 | 比反射 XSS 价值高 10 倍 |
| ★★★ | SSRF（内网/云元数据） | ssrf / ssrf-pwn | 图片代理/URL 抓取功能 |
| ★★☆ | SQLi（尤其登录/API 参数） | sqlcheck + sqli-weaponize | 现代框架 ORM 少，老站多 |
| ★★☆ | 逻辑漏洞（价格/订单/2FA 绕过） | bizlogic / 手工 | 工具难自动化，靠思路 |
| ★★☆ | GraphQL 信息泄露/批量 | graphql-abuse | 现代 API 常开 |
| ★☆☆ | 反射 XSS / 低危信息泄露 | xsscheck | SRC 一般不收或极低分 |

**关键提醒**：
1. **越权（IDOR/BOLA）是 SRC 最大的洞源**——主要靠手工改参数对比 A/B 账号响应，工具辅助验证。
2. **WAF 目标**：先 waf 识别，命中被拦就换编码（工具已内置 14 种 WAF 策略），真绕不过就换攻击面。
3. **别碰数据**：SQLi 确认后只读 version()/database() 证明，别 SELECT 用户表（违规）。
4. **范围红线**：严格在 scope 内，不做 DoS、不爆破、不碰第三方。

## 三、工具力所不能及（诚实）

- 越权/逻辑漏洞/业务流：工具只能辅助，靠思路
- 强 WAF + 现代框架：自动检测命中率低，靠人工定向
- 子域名接管/API 密钥泄露等：需专门工具链

**正确姿势**：工具做"验证 + 抽数 + 出报告"，你负责"找点 + 想思路 + 讲影响"。
