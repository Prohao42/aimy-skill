"""SRC 提交报告生成：检测结果 -> 可提交漏洞报告（按漏洞类型模板）。"""

SRC_VULN_TEMPLATES = {
    "sqli": {
        "title": "SQL 注入漏洞",
        "severity": "高危",
        "cwe": "CWE-89",
        "description": "目标接口存在 SQL 注入，攻击者可通过构造恶意参数操纵后端 SQL 查询，"
                       "可能导致数据越权读取、绕过认证，严重时可写入/删除数据甚至获取服务器权限。",
        "fix": "1) 使用参数化查询（PreparedStatement / PDO 绑定参数）；2) 对输入做白名单校验；"
               "3) 最小化数据库账户权限；4) 关闭错误信息回显。",
    },
    "xss": {
        "title": "跨站脚本（XSS）",
        "severity": "中危",
        "cwe": "CWE-79",
        "description": "目标页面未对用户输入进行输出编码，攻击者可注入并执行任意脚本，"
                       "窃取会话 Cookie、执行未授权操作或进行钓鱼。",
        "fix": "1) 输出前进行上下文感知的 HTML/JS/CSS 编码；2) 配置 Content-Security-Policy；"
               "3) 设置 HttpOnly + Secure Cookie。",
    },
    "cmdi": {
        "title": "命令注入",
        "severity": "高危",
        "cwe": "CWE-78",
        "description": "目标接口将用户输入拼接进系统命令执行，攻击者可执行任意系统命令，"
                       "获取服务器控制权。",
        "fix": "1) 禁止将用户输入传入命令执行函数；2) 使用白名单映射替代动态命令；"
               "3) 以最小权限运行服务进程。",
    },
    "ssti": {
        "title": "服务端模板注入（SSTI）",
        "severity": "高危",
        "cwe": "CWE-1336",
        "description": "服务端模板引擎直接渲染用户输入，攻击者可通过模板语法执行任意代码，"
                       "获取 RCE 能力。",
        "fix": "1) 用户输入只作为数据传入模板，禁止拼接进模板源码；2) 使用沙箱化的模板引擎；"
               "3) 升级模板引擎到修复版本。",
    },
    "lfi": {
        "title": "本地文件包含（LFI）",
        "severity": "高危",
        "cwe": "CWE-98",
        "description": "目标接口可被用于读取服务器本地文件（如 /etc/passwd、源码、配置文件），"
                       "配合日志投毒等手法可进一步升级为 RCE。",
        "fix": "1) 对文件路径做白名单/规范化校验，拒绝 ../ 与绝对路径；2) 禁用危险 wrapper"
               "（php://、data:// 等）；3) 使用统一资源抽象层。",
    },
    "ssrf": {
        "title": "服务端请求伪造（SSRF）",
        "severity": "高危",
        "cwe": "CWE-918",
        "description": "服务端可根据用户提供的 URL 发起请求，攻击者可探测内网、读取云元数据"
                       "（如 169.254.169.254），获取敏感凭据或进行内网横向。",
        "fix": "1) 对目标地址做协议 + 域名/IP 白名单校验；2) 禁止访问内网/保留地址段；"
               "3) 使用专用出口代理并限制出网。",
    },
    "nosqli": {
        "title": "NoSQL 注入",
        "severity": "高危",
        "cwe": "CWE-943",
        "description": "目标接口未对 NoSQL 查询中的操作符做过滤，"
                       "攻击者可绕过认证、盲注提取数据或触发 ReDoS。",
        "fix": "1) 对输入做类型强校验，禁止传入操作符对象；2) 使用 ORM 白名单字段；"
               "3) 禁用 $where 等 JS 表达式能力。",
    },
    "union": {
        "title": "SQL 注入（UNION 回显）",
        "severity": "高危",
        "cwe": "CWE-89",
        "description": "目标接口存在可回显的 UNION 注入，攻击者可枚举列并直接读取数据库内容。",
        "fix": "同 SQL 注入：参数化查询 + 白名单校验 + 最小权限。",
    },
    "union_blind": {
        "title": "SQL 注入（盲 UNION）",
        "severity": "高危",
        "cwe": "CWE-89",
        "description": "目标接口存在无回显的 UNION 注入，列数可枚举，可通过布尔/时间盲注提取数据。",
        "fix": "同 SQL 注入。",
    },
    "boolean": {
        "title": "SQL 注入（布尔盲注）",
        "severity": "高危",
        "cwe": "CWE-89",
        "description": "目标接口存在布尔盲注，攻击者可通过真假条件差分逐字符提取数据库内容。",
        "fix": "同 SQL 注入。",
    },
    "time": {
        "title": "SQL 注入（时间盲注）",
        "severity": "高危",
        "cwe": "CWE-89",
        "description": "目标接口存在时间盲注，攻击者可通过延迟差分逐字符提取数据库内容。",
        "fix": "同 SQL 注入，并关闭数据库错误回显。",
    },
    "error": {
        "title": "SQL 注入（报错型）",
        "severity": "高危",
        "cwe": "CWE-89",
        "description": "目标接口存在报错型 SQL 注入，数据库错误信息直接回显，可被用于提取数据。",
        "fix": "同 SQL 注入，并关闭数据库错误回显。",
    },
    "csrf": {
        "title": "跨站请求伪造（CSRF）",
        "severity": "中危",
        "cwe": "CWE-352",
        "description": "目标接口缺少 CSRF 防护，攻击者可诱导已登录用户执行未授权操作。",
        "fix": "1) 使用 CSRF Token；2) 校验 Referer/Origin；3) 敏感操作要求二次验证。",
    },
    "cors": {
        "title": "CORS 跨域配置缺陷",
        "severity": "中危",
        "cwe": "CWE-942",
        "description": "目标接口的 CORS 策略允许不可信来源读取敏感响应。",
        "fix": "1) 严格白名单 Access-Control-Allow-Origin；2) 不使用 Origin 反射；"
               "3) 敏感接口不附加凭证访问。",
    },
    "default": {
        "title": "安全漏洞",
        "severity": "中危",
        "cwe": "",
        "description": "目标接口存在安全缺陷，详见复现步骤与证据。",
        "fix": "请结合证据定位修复。",
    },
}


def src_report(finding: dict, target: str = "") -> dict:
    """把单个检测结果转成 SRC 可提交报告结构。"""
    vtype = str(finding.get("type") or "").lower()
    tpl = SRC_VULN_TEMPLATES.get(vtype, SRC_VULN_TEMPLATES["default"])
    url = finding.get("url") or target
    param = finding.get("param", "")
    evidence = finding.get("evidence") or []
    vector = finding.get("vector") or finding.get("payload") or ""
    dbms = finding.get("dbms", "")
    conf = finding.get("confidence_score") or 0.0
    steps = []
    if url:
        steps.append("访问接口：%s" % url)
    if param:
        steps.append("参数：%s" % param)
    if vector:
        steps.append("复现 Payload：%s" % str(vector)[:120])
    if evidence:
        steps.append("观察到的证据：")
        for ev in evidence[:4]:
            steps.append("- %s" % str(ev)[:100])
    if dbms:
        steps.append("后端数据库：%s" % dbms)
    steps.append("修复验证：修复后重放上述请求，确认漏洞不再存在。")
    return {
        "title": "%s - %s" % (tpl["title"], url or ""),
        "target": url,
        "vuln_type": vtype,
        "severity": tpl["severity"],
        "cwe": tpl["cwe"],
        "confidence": round(float(conf), 2),
        "description": tpl["description"],
        "reproduction_steps": steps,
        "impact": tpl.get("impact", "详见描述。"),
        "fix_suggestion": tpl["fix"],
        "evidence": [str(e) for e in evidence[:6]],
    }


def src_report_markdown(report: dict) -> str:
    """报告结构 -> 可直接粘贴的 Markdown（SRC 平台通用格式）。"""
    lines = []
    lines.append("## %s" % report.get("title", ""))
    lines.append("")
    lines.append("- **漏洞类型**: %s (%s)" % (report.get("vuln_type", ""), report.get("cwe", "")))
    lines.append("- **危害等级**: %s" % report.get("severity", ""))
    lines.append("- **目标**: %s" % report.get("target", ""))
    lines.append("- **置信度**: %.2f" % report.get("confidence", 0))
    lines.append("")
    lines.append("### 漏洞描述")
    lines.append(report.get("description", ""))
    lines.append("")
    lines.append("### 复现步骤")
    for i, step in enumerate(report.get("reproduction_steps", []), 1):
        lines.append("%d. %s" % (i, step))
    lines.append("")
    lines.append("### 影响范围")
    lines.append(report.get("impact", ""))
    lines.append("")
    lines.append("### 修复建议")
    lines.append(report.get("fix_suggestion", ""))
    lines.append("")
    if report.get("evidence"):
        lines.append("### 证据")
        for e in report["evidence"]:
            lines.append("- %s" % e)
    lines.append("")
    return "\n".join(lines)
