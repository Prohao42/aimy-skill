from tools.settings import settings


MODE_BANNER = {
    "rookie": """
  ╔══════════════════════════════════════════════╗
  ║         aimy-sikll  菜鸟模式 (Rookie)        ║
  ║  适合入门学习，输出详细说明与修复建议          ║
  ╚══════════════════════════════════════════════╝
""",
    "veteran": """
  ╔══════════════════════════════════════════════╗
  ║         aimy-sikll  老鸟模式 (Veteran)       ║
  ║  专注高价值漏洞，简洁输出，拒绝水洞            ║
  ╚══════════════════════════════════════════════╝
""",
}


def show_banner():
    print(MODE_BANNER.get(settings.mode, MODE_BANNER["rookie"]))


def filter_vulnerabilities(results):
    if not isinstance(results, list):
        return results
    if settings.is_veteran():
        return [r for r in results if not _is_low_value(r)]
    return results


LOW_SIGNAL_PATTERNS = [
    "reflected_xss", "xss_reflected", "open_redirect",
    "info_disclosure", "low", "info", "information",
]


def _is_low_value(result):
    if not isinstance(result, dict):
        return False
    sig = (result.get("risk") or result.get("severity") or result.get("type") or "").lower()
    for pat in LOW_SIGNAL_PATTERNS:
        if pat in sig:
            return True
    return False


def enrich_result(result):
    explanations = {
        "sql_injection": {
            "rookie": "SQL注入漏洞: 攻击者可通过注入SQL语句操纵数据库。\n  修复建议: 使用参数化查询(PreparedStatement)或ORM框架。",
            "veteran": "",
        },
        "xss_reflected": {
            "rookie": "反射型XSS: 攻击者构造恶意链接，用户点击后脚本在浏览器执行。\n  修复建议: 对输出进行HTML实体编码，设置Content-Security-Policy。",
            "veteran": "低危: 反射型XSS，不展开。",
        },
        "ssrf": {
            "rookie": "SSRF (服务端请求伪造): 攻击者可诱导服务器发起内部请求。\n  修复建议: 白名单允许的域名/IP，禁止访问内网地址段。",
            "veteran": "",
        },
        "cmdi": {
            "rookie": "命令注入: 攻击者可在服务器执行系统命令。\n  修复建议: 避免将用户输入传入系统命令执行函数，使用白名单校验。",
            "veteran": "",
        },
    }
    if settings.is_rookie() and isinstance(result, dict):
        vuln_type = (result.get("type") or "").lower()
        if vuln_type in explanations:
            result["_explanation"] = explanations[vuln_type]["rookie"]
    return result