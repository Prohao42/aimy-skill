"""CLI argument parser construction and post-parse validation.

Extracted from ``main.py`` to improve testability and reduce the entry-point
module size.  ``build_parser`` is called by ``main.main()`` with a dict of
dispatchers; it lazily imports the explicit ``cmd_*`` functions from
``main`` to avoid a circular import at module load time.
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.parse as _urlparse
from typing import Optional

from tools.log_utils import get_logger

logger = get_logger("arg_parsers")

URL_SCHEMES = ("http://", "https://", "file://", "gopher://", "dict://")


def _validate_url(url: str, name: str = "url") -> None:
    if not url.startswith(URL_SCHEMES):
        raise ValueError("%s must start with a valid scheme %s: %s" % (name, URL_SCHEMES, url))
    parsed = _urlparse.urlparse(url)
    if not parsed.netloc:
        raise ValueError("Invalid %s (no hostname): %s" % (name, url))


def _add_url_arg(
    p,
    default_param: Optional[str] = "id",
    include_post: bool = False,
    include_data: bool = False,
    context: bool = False,
    token: bool = False,
    vuln_type: bool = False,
    extra_args=None,
):
    """Add common arguments to an injection-style subparser."""
    p.add_argument("url")
    p.add_argument("--param", default=default_param)
    if include_post:
        p.add_argument("--post", action="store_true")
    if include_data:
        p.add_argument("--data", type=json.loads, default=None)
    if context:
        p.add_argument("--context", default="all", help="html/attr/js/all")
    if token:
        p.add_argument("--token", default=None)
    if vuln_type:
        p.add_argument(
            "--vuln-type",
            default="sqli",
            choices=["sqli", "ssrf", "xss", "ssti", "cmdi", "lfi", "nosqli", "xxe"],
        )
    if extra_args:
        for args_spec in extra_args:
            p.add_argument(*args_spec[0], **args_spec[1])


def build_parser(dispatchers: dict) -> argparse.ArgumentParser:
    """Build the full CLI argument parser.

    ``dispatchers`` must contain entries for every command that uses the
    data-driven check table (from ``cli.check_commands``).  Explicit
    ``cmd_*`` functions are imported lazily from ``main``.
    """
    from main import (
        VERSION,
        cmd_auto,
        cmd_autohunt,
        cmd_batch_recon,
        cmd_binary_scan,
        cmd_capture,
        cmd_chain,
        cmd_cloud_pwn,
        cmd_cms_fingerprint,
        cmd_code_audit,
        cmd_csrf,
        cmd_deepscan,
        cmd_dirfuzz,
        cmd_domain,
        cmd_fuzz,
        cmd_fuzz_engine,
        cmd_idor,
        cmd_kali,
        cmd_leak_scan,
        cmd_list,
        cmd_login,
        cmd_mobile_scan,
        cmd_param_mine,
        cmd_payload_mutate,
        cmd_portscan,
        cmd_proxy,
        cmd_quickscan,
        cmd_recon,
        cmd_smuggler,
        cmd_unauth,
        cmd_webshell,
        cmd_workflow,
    )

    parser = argparse.ArgumentParser(
        description="aimy-skill v%s - 轻量级渗透测试辅助工具链" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="请求超时秒数")
    parser.add_argument("--ssl-verify", action="store_true", help="启用SSL证书验证(默认关闭)")
    parser.add_argument(
        "--auth-type", choices=["form", "api", "basic", ""], default="", help="认证类型"
    )
    parser.add_argument("--auth-url", default="", help="认证URL")
    parser.add_argument("--auth-user", default="", help="认证用户名")
    parser.add_argument("--auth-pass", default="", help="认证密码")
    parser.add_argument("--session-file", default="", help="会话文件路径(.pkl)")
    parser.add_argument(
        "--mode",
        choices=["rookie", "veteran"],
        default=None,
        help="输出模式: rookie(详细说明) / veteran(简洁高价值)，默认由 AIMY_MODE 环境变量决定",
    )
    parser.add_argument("--delay", type=float, default=0.0, help="请求间延迟秒数")
    parser.add_argument("--kali-host", default="", help="Kali Linux SSH 主机地址")
    parser.add_argument("--kali-port", type=int, default=22, help="Kali SSH 端口")
    parser.add_argument("--kali-user", default="root", help="Kali SSH 用户名")
    parser.add_argument("--kali-pass", default="", help="Kali SSH 密码")
    parser.add_argument("--kali-key", default="", help="Kali SSH 私钥路径")
    parser.add_argument("--kali-local", action="store_true", help="本地 Kali 模式 (直接用本机工具)")
    parser.add_argument("-v", "--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command")

    # ---- Recon / simple commands ----
    p = sub.add_parser("portscan", help="TCP端口扫描")
    p.add_argument("target")
    p.add_argument("--ports", default="", help="端口列表,逗号分隔")
    p.set_defaults(func=cmd_portscan)

    p = sub.add_parser("dirfuzz", help="目录枚举")
    p.add_argument("url")
    p.add_argument("--wordlist", default="", help="字典路径")
    p.add_argument("--max", type=int, default=50, help="最大路径数")
    p.set_defaults(func=cmd_dirfuzz)

    p = sub.add_parser("sqlcheck", help="SQL注入检测")
    _add_url_arg(p, include_post=True, include_data=True)
    p.set_defaults(func=dispatchers["sqlcheck"])

    p = sub.add_parser("xsscheck", help="XSS检测")
    _add_url_arg(p, default_param="q", include_post=True, include_data=True, context=True)
    p.set_defaults(func=dispatchers["xsscheck"])

    p = sub.add_parser("cmdi", help="命令注入检测")
    _add_url_arg(p, default_param="cmd")
    p.set_defaults(func=dispatchers["cmdi"])

    p = sub.add_parser("ssti", help="模板注入检测")
    _add_url_arg(p, default_param="name")
    p.set_defaults(func=dispatchers["ssti"])

    p = sub.add_parser("ssrf", help="SSRF检测")
    _add_url_arg(p, default_param="url")
    p.set_defaults(func=dispatchers["ssrf"])

    p = sub.add_parser("nosqli", help="NoSQL注入检测")
    _add_url_arg(p, default_param="id")
    p.set_defaults(func=dispatchers["nosqli"])

    p = sub.add_parser("lfi", help="本地文件包含检测")
    _add_url_arg(p, default_param="file")
    p.set_defaults(func=dispatchers["lfi"])

    p = sub.add_parser("sqli-blind", help="SQL盲注利用")
    _add_url_arg(p, include_post=True, include_data=True)
    p.set_defaults(func=dispatchers["sqli-blind"])

    p = sub.add_parser("sqli-oob", help="OOB SQL注入")
    p.add_argument("url")
    p.add_argument("--param", default="id")
    p.add_argument("--domain", default="oob.local")
    p.set_defaults(func=dispatchers["sqli-oob"])

    p = sub.add_parser("auth-bypass", help="认证绕过检测")
    _add_url_arg(p)
    p.set_defaults(func=dispatchers["auth-bypass"])

    p = sub.add_parser("jwt", help="JWT检测")
    p.add_argument("url")
    p.add_argument("--param", default=None)
    p.set_defaults(func=dispatchers["jwt"])

    p = sub.add_parser("graphql", help="GraphQL扫描")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["graphql"])

    p = sub.add_parser("deser", help="反序列化检测")
    p.add_argument("url")
    p.add_argument("--param", default=None)
    p.set_defaults(func=dispatchers["deser"])

    p = sub.add_parser("proto-pollution", help="原型链污染检测")
    p.add_argument("url")
    p.add_argument("--param", default=None)
    p.set_defaults(func=dispatchers["proto-pollution"])

    p = sub.add_parser("cors", help="CORS检测")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["cors"])

    p = sub.add_parser("xss-validate", help="XSS验证")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["xss-validate"])

    p = sub.add_parser("waf", help="WAF指纹识别与绕过")
    p.add_argument("url")
    p.add_argument("--param", default=None)
    p.set_defaults(func=dispatchers["waf"])

    p = sub.add_parser("waf-heavy", help="WAF严格绕过注入检测(HPP/分块/Unicode/注释嵌套)")
    _add_url_arg(p, default_param="id")
    p.set_defaults(func=dispatchers["waf-heavy"])

    p = sub.add_parser("bizlogic", help="深度业务逻辑漏洞挖掘(2FA/价格/MassAssn/逻辑)")
    _add_url_arg(p, default_param="id")
    p.set_defaults(func=dispatchers["bizlogic"])

    p = sub.add_parser("xxe", help="XXE XML外部实体检测")
    p.add_argument("url")
    p.add_argument("--param", default=None)
    p.set_defaults(func=dispatchers["xxe"])

    p = sub.add_parser("smuggler", help="HTTP请求走私检测 (CL.TE/TE.CL/TE.TE/h2c)")
    p.add_argument("url")
    p.add_argument("--exploit", action="store_true", help="检测到后自动利用")
    p.add_argument("--attack-body", default="", help="走私请求体内容")
    p.set_defaults(func=cmd_smuggler)

    p = sub.add_parser("cloud-pwn", help="云凭据利用 (AWS/GCP/Azure)")
    p.add_argument("--raw", default="", help="原始凭据文本")
    p.add_argument("--file", default="", help="从文件读取凭据文本")
    p.add_argument("--cloud", default="", choices=["aws", "gcp", "azure"], help="云平台提示")
    p.set_defaults(func=cmd_cloud_pwn)

    p = sub.add_parser("csrf", help="CSRF检测与绕过")
    p.add_argument("url")
    p.add_argument("--bypass", action="store_true", help="尝试绕过CSRF保护")
    p.add_argument("--action", default="", help="目标action路径")
    p.add_argument("--data", default="", help="JSON格式的POST数据")
    p.add_argument("--param", default=None)
    p.set_defaults(func=cmd_csrf)

    p = sub.add_parser("webshell", help="Webshell生成与部署")
    p.add_argument(
        "--type",
        default="php_cmd",
        choices=[
            "php_cmd",
            "php_exec",
            "php_b64",
            "asp_cmd",
            "aspx_cmd",
            "jsp_cmd",
            "python_flask",
            "node_express",
        ],
        help="Webshell类型",
    )
    p.add_argument("--encode", default="raw", choices=["raw", "b64", "url"])
    p.add_argument("--deploy", action="store_true", help="尝试部署到目标")
    p.add_argument("url", nargs="?", default="", help="目标URL (部署时需要)")
    p.add_argument("--path", default="", help="部署路径")
    p.set_defaults(func=cmd_webshell)

    p = sub.add_parser("graphql-abuse", help="GraphQL高级利用(内省/批量/深度)")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["graphql-abuse"])

    p = sub.add_parser("jwt-attack", help="JWT攻击(算法混淆/弱密钥/注入)")
    p.add_argument("url")
    p.add_argument("--token", default=None)
    p.set_defaults(func=dispatchers["jwt-attack"])

    p = sub.add_parser("verify", help="第二序交叉验证(多方法确认)")
    p.add_argument("url")
    p.add_argument("--param", default="id")
    p.add_argument(
        "--vuln-type",
        default="sqli",
        choices=["sqli", "ssrf", "xss", "ssti", "cmdi", "lfi", "nosqli", "xxe"],
    )
    p.set_defaults(func=dispatchers["verify"])

    p = sub.add_parser("race", help="竞争条件检测")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["race"])

    p = sub.add_parser("race-profile", help="竞争条件探测器(自动分析)")
    p.add_argument("url")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["race-profile"])

    p = sub.add_parser("workflow-trace", help="工作流追踪(业务逻辑流分析)")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["workflow-trace"])

    p = sub.add_parser("deviation", help="偏差检测(异常响应分析)")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["deviation"])

    p = sub.add_parser("constraint", help="约束图分析(BL转储)")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["constraint"])

    p = sub.add_parser("bizlogic-v2", help="业务逻辑v2检测(深度状态分析)")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["bizlogic-v2"])

    p = sub.add_parser("xss-verify", help="浏览器级XSS验证")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["xss-verify"])

    p = sub.add_parser("auth-default-creds", help="默认凭证检测")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["auth-default-creds"])

    p = sub.add_parser("auth-cookie-tamper", help="Cookie篡改检测")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["auth-cookie-tamper"])

    p = sub.add_parser("auth-header-injection", help="HTTP首部注入检测")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["auth-header-injection"])

    p = sub.add_parser("auth-method-bypass", help="HTTP方法绕过检测")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["auth-method-bypass"])

    p = sub.add_parser("auth-mass-assignment", help="批量赋值检测")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["auth-mass-assignment"])

    p = sub.add_parser("chain-sqli-lfi", help="SQLi→LFI链式利用验证")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["chain-sqli-lfi"])

    p = sub.add_parser("chain-sqli-auth", help="SQLi→Auth链式利用验证")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["chain-sqli-auth"])

    p = sub.add_parser("chain-ssrf-lfi", help="SSRF→LFI链式利用验证")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["chain-ssrf-lfi"])

    p = sub.add_parser("smuggle", help="HTTP请求走私检测")
    _add_url_arg(p, default_param=None)
    p.set_defaults(func=dispatchers["smuggle"])

    p = sub.add_parser("clickjacking", help="Clickjacking检测")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["clickjacking"])

    p = sub.add_parser("crlf-injection", help="CRLF注入检测")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["crlf-injection"])

    p = sub.add_parser("open-redirect", help="开放重定向检测")
    _add_url_arg(p, default_param="next")
    p.set_defaults(func=dispatchers["open-redirect"])

    p = sub.add_parser("hpp", help="HTTP参数污染检测")
    _add_url_arg(p, default_param="q")
    p.set_defaults(func=dispatchers["hpp"])

    p = sub.add_parser("web-cache", help="Web缓存反解/投毒检测")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["web-cache"])

    p = sub.add_parser("file-upload", help="文件上传漏洞检测")
    _add_url_arg(p, default_param="file")
    p.set_defaults(func=dispatchers["file-upload"])

    p = sub.add_parser("saml-sso", help="SAML SSO漏洞检测")
    _add_url_arg(p, default_param="SAMLResponse")
    p.set_defaults(func=dispatchers["saml-sso"])

    # ---- Scan orchestration ----
    p = sub.add_parser("recon", help="全面信息收集(指纹/端口/git/目录)")
    p.add_argument("target")
    p.add_argument("--deep", action="store_true", help="深度git泄露检测(所有文件)")
    p.add_argument("--full-ports", action="store_true", help="全端口扫描(>1000)")
    p.set_defaults(func=cmd_recon)

    p = sub.add_parser("deepscan", help="深度扫描(爬虫+检测+报告)")
    p.add_argument("target")
    p.add_argument("--session", default="default", help="持久化会话名(可恢复)")
    p.add_argument("--resume", action="store_true", help="恢复上一次会话状态")
    p.set_defaults(func=cmd_deepscan)

    p = sub.add_parser("quickscan", help="快速扫描(极速发现高危漏洞)")
    p.add_argument("target")
    p.add_argument("--threads", type=int, default=30)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--session", default="quick", help="持久化会话名")
    p.set_defaults(func=cmd_quickscan)

    p = sub.add_parser("autohunt", help="自动狩猎(爬虫+参数挖掘+检测+武器化)")
    p.add_argument("target")
    p.add_argument("--threads", type=int, default=20)
    p.add_argument("--high-value", action="store_true", help="高价值模式:跳过低危,聚焦高影响漏洞")
    p.add_argument("--turbo", action="store_true", help="极速模式:最大并发+智能终止")
    p.add_argument("--skip-verify", action="store_true", help="跳过交叉验证/Oracle/误报过滤")
    p.add_argument("--session", default="default", help="持久化会话名(可恢复)")
    p.add_argument("--resume", action="store_true", help="恢复上一次会话状态")
    p.set_defaults(func=cmd_autohunt)

    p = sub.add_parser("auto", help="全自动渗透(信息收集+攻击面+检测+链式利用)")
    p.add_argument("target")
    p.add_argument("--threads", type=int, default=20)
    p.add_argument("--max-pages", type=int, default=50)
    p.add_argument("--max-depth", type=int, default=3)
    p.add_argument("--no-fast-recon", action="store_true", help="关闭快速侦察模式，进行完整侦察")
    p.add_argument("--no-chain", action="store_true", help="跳过链式利用阶段")
    p.add_argument(
        "--high-value",
        action="store_true",
        help="高价值模式:跳过低危(XSS/CORS等),聚焦RCE/SQLi/SSRF/认证绕过",
    )
    p.add_argument("--turbo", action="store_true", help="极速模式:最大并发+智能终止+自适应策略")
    p.add_argument(
        "--skip-verify", action="store_true", help="跳过交叉验证/Oracle/误报过滤(极速模式)"
    )
    p.add_argument("--save-report", default="", help="保存报告目录(自动生成 JSON + HTML)")
    p.add_argument("--session", default="default", help="持久化会话名(可恢复)")
    p.add_argument("--resume", action="store_true", help="恢复上一次会话状态")
    p.set_defaults(func=cmd_auto)

    p = sub.add_parser("chain", help="利用链组合攻击")
    _add_url_arg(
        p,
        default_param="id",
        extra_args=[
            (("--chain",), {"default": "full_chain"}),
        ],
    )
    p.set_defaults(func=cmd_chain)

    # ---- MITM / domain / workflow ----
    p = sub.add_parser("proxy", help="MITM代理(请求/响应捕获+检测)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--proxy-host", default="127.0.0.1")
    p.add_argument("--proxy-duration", type=int, default=0, help="自动结束秒数(0=手动Ctrl+C)")
    p.set_defaults(func=cmd_proxy)

    p = sub.add_parser("capture", help="环境感知数据包捕获(Kali tcpdump / 本地)")
    p.add_argument("--capture-iface", default="", help="网卡接口名")
    p.add_argument("--capture-count", type=int, default=1000, help="抓包数量")
    p.add_argument("--capture-filter", default="", help="BPF过滤器")
    p.add_argument("--capture-timeout", type=int, default=60, help="超时秒数")
    p.add_argument("--capture-http", action="store_true", help="仅HTTP(80/8080)")
    p.add_argument("--capture-tls", action="store_true", help="仅TLS(443)")
    p.add_argument("--realtime", action="store_true", help="实时HTTP流模式(tshark -T fields)")
    p.set_defaults(func=cmd_capture)

    p = sub.add_parser("domain", help="域渗透审计 (LDAP/Kerberos/SMB/ADCS)")
    p.add_argument("target", help="域名或DC IP")
    p.add_argument("--dc-ip", default="", help="域控IP")
    p.add_argument("--domain", default="", help="域名")
    p.add_argument("--username", default="", help="域用户名")
    p.add_argument("--password", default="", help="域密码")
    p.add_argument("--userlist", default="", help="用户列表文件(AS-REP Roast用)")
    p.add_argument(
        "--native",
        action="store_true",
        help="原生实现(免impacket/ldap3): AS-REP Roast/LDAP枚举/Kerberroast骨架",
    )
    p.set_defaults(func=cmd_domain)

    p = sub.add_parser("workflow", help="工作流执行")
    p.add_argument("workflow", help="工作流名称或JSON文件路径")
    p.add_argument("--target", default="")
    p.add_argument("--username", default="")
    p.add_argument("--password", default="")
    p.set_defaults(func=cmd_workflow)

    # ---- Weaponize ----
    p = sub.add_parser("sqli-second-order", help="二阶SQL注入检测(存储后触发)")
    _add_url_arg(p, default_param="username")
    p.set_defaults(func=dispatchers["sqli-second-order"])

    p = sub.add_parser("sqli-weaponize", help="SQL注入数据提取")
    _add_url_arg(p, default_param="id")
    p.set_defaults(func=dispatchers["sqli-weaponize"])

    p = sub.add_parser("cms-fingerprint", help="CMS版本指纹+已知漏洞映射(74cms等)")
    p.add_argument("url", nargs="?", default="")
    p.add_argument("--urls", action="append", default=[], help="批量目标(可多次)")
    p.set_defaults(func=cmd_cms_fingerprint)

    p = sub.add_parser("dom-xss", help="DOM XSS检测(静态分析sink/source配对)")
    p.add_argument("url")
    p.set_defaults(func=dispatchers["dom-xss"])

    # ---- Auth / access control ----
    p = sub.add_parser("idor", help="水平越权/未授权访问检测(SRC最高频)")
    p.add_argument("url")
    p.add_argument("--param", default="id")
    p.add_argument("--my-id", default="", help="自己资源的id")
    p.add_argument("--other-id", default="", help="目标用户资源的id")
    p.add_argument("--method", default="GET", choices=["GET", "POST"])
    p.add_argument("--json-param", default="", help="POST JSON body 中的参数名")
    p.add_argument("--session-file-b", default="", help="账号B的session文件(对比基准)")
    p.add_argument("--no-auth", action="store_true", help="未授权访问检测(无会话访问)")
    p.set_defaults(func=cmd_idor)

    p = sub.add_parser("login", help="SRC工作流: 登录并保存session文件(供--session-file复用)")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("jwt-exploit", help="JWT利用(crack/伪造)")
    p.add_argument("url", nargs="?", default="")
    p.add_argument("--param", default=None)
    p.add_argument("--token", default=None)
    p.set_defaults(func=dispatchers["jwt-exploit"])

    p = sub.add_parser("ssrf-pwn", help="SSRF文件读取与云元数据")
    _add_url_arg(p, default_param="url")
    p.set_defaults(func=dispatchers["ssrf-pwn"])

    p = sub.add_parser("ssrf-lateral", help="SSRF横向移动")
    _add_url_arg(p, default_param="url")
    p.set_defaults(func=dispatchers["ssrf-lateral"])

    p = sub.add_parser("deser-weaponize", help="反序列化payload生成")
    p.add_argument("url", nargs="?", default="")
    p.add_argument("--param", default=None)
    p.set_defaults(func=dispatchers["deser-weaponize"])

    p = sub.add_parser("reverse-shell", help="反弹Shell生成器")
    p.add_argument("--lhost", default="LHOST")
    p.add_argument("--lport", type=int, default=4444)
    p.add_argument("--encode", default="raw", choices=["raw", "url", "b64", "ps_b64"])
    p.set_defaults(func=dispatchers["reverse-shell"])

    p = sub.add_parser("param-mine", help="参数挖掘")
    p.add_argument("target")
    p.add_argument("--threads", type=int, default=5)
    p.set_defaults(func=cmd_param_mine)

    # ---- Fuzz / audit ----
    p = sub.add_parser("crawl", help="网页爬虫")
    p.add_argument("target")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--max-pages", type=int, default=30)
    p.set_defaults(func=dispatchers["crawl"])

    p = sub.add_parser("fuzz", help="模糊测试")
    p.add_argument("--payloads", default="")
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--delay", type=float, default=0)
    p.set_defaults(func=cmd_fuzz)

    p = sub.add_parser("payload-mutate", help="Payload变异")
    p.add_argument("--payload", default="")
    p.add_argument("--param", default="")
    p.set_defaults(func=cmd_payload_mutate)

    p = sub.add_parser("fuzz-engine", help="高级语法模糊测试(grammar-based)")
    p.add_argument("url")
    p.add_argument("--param", default="id")
    p.add_argument("--vuln-type", default="", help="sql/ssrf/lfi/xss/ssti/cmdi")
    p.add_argument("--count", type=int, default=20, help="payload数量")
    p.set_defaults(func=cmd_fuzz_engine)

    p = sub.add_parser("code-audit", help="源代码审计(静态分析)")
    p.add_argument("path", help="源码目录或文件路径")
    p.add_argument("--threads", type=int, default=4)
    p.set_defaults(func=cmd_code_audit)

    p = sub.add_parser("binary-scan", help="二进制文件分析(PE/ELF)")
    p.add_argument("path", help="文件或目录路径")
    p.add_argument("--threads", type=int, default=4)
    p.set_defaults(func=cmd_binary_scan)

    p = sub.add_parser("mobile-scan", help="移动应用安全扫描(APK/IPA)")
    p.add_argument("path", help="APK或IPA文件路径")
    p.set_defaults(func=cmd_mobile_scan)

    # ---- List / unauth / leak / weakpass / batch ----
    p = sub.add_parser("list", help="列出所有可用工具")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("unauth", help="未授权中间件检测(Redis/ES/Mongo/MySQL/Postgres)")
    p.add_argument("--host", default="", help="单目标 host 或 host:port")
    p.add_argument(
        "--hosts", default="", dest="hosts_file", help="IP列表文件(每行一个 host 或 host:port)"
    )
    p.add_argument("--service", default="redis,es,mongo,mysql,pg", help="检测服务(逗号分隔)")
    p.add_argument("--threads", type=int, default=30)
    p.set_defaults(func=cmd_unauth)

    p = sub.add_parser("leak-scan", help="信息泄露专项扫描(.git/.env/备份/Swagger/actuator)")
    p.add_argument("url")
    p.add_argument("--paths", default="", help="自定义路径列表(逗号分隔, 默认全量)")
    p.set_defaults(func=cmd_leak_scan)

    p = sub.add_parser("weakpass", help="业务系统弱口令/默认凭据检测(低频差分)")
    p.add_argument("url", help="登录页或系统根 URL")
    p.add_argument("--delay", type=float, default=0.3, help="每次尝试间隔秒数(防封)")
    p.add_argument("--max-attempts", type=int, default=0, help="最多尝试组数(0=全部)")
    p.add_argument("--api-url", default="", help="JSON API 登录端点(SPA/Odoo 等, 跳过表单解析)")
    p.add_argument("--user-field", default="username", help="API 用户名字段")
    p.add_argument("--pass-field", default="password", help="API 密码字段")
    p.set_defaults(func=dispatchers["weakpass"])

    p = sub.add_parser("batch-recon", help="批量资产发现(端口+Web指纹+高价值排序)")
    p.add_argument("hosts_file", help="IP/域名列表文件(每行一个)")
    p.add_argument("--ports", default="", help="端口列表(逗号分隔)")
    p.add_argument("--threads", type=int, default=100)
    p.add_argument("--unauth", action="store_true", help="对发现的数据库/中间件端口联动未授权检测")
    p.set_defaults(func=cmd_batch_recon)

    # ---- kali sub-command ----
    pk = sub.add_parser("kali", help="Kali Linux 工具调用 (需配置 --kali-host/--kali-local)")
    ksub = pk.add_subparsers(dest="kali_command")

    pke = ksub.add_parser("exec", help="在 Kali 上执行任意命令")
    pke.add_argument("cmd", help="要执行的命令")
    pke.add_argument("--kali-timeout", type=int, default=120)
    pke.set_defaults(func=cmd_kali)

    ksub.add_parser("connect", help="测试 Kali 连接并检测工具").set_defaults(
        func=cmd_kali, kali_command="connect"
    )
    ksub.add_parser("list-tools", help="列出 Kali 上可用的工具").set_defaults(
        func=cmd_kali, kali_command="list-tools"
    )

    pks = ksub.add_parser("sqlmap", help="sqlmap SQL 注入检测与利用")
    pks.add_argument("url")
    pks.add_argument("--param", default="id")
    pks.add_argument("--dbms", default="")
    pks.add_argument("--dump", action="store_true")
    pks.set_defaults(func=cmd_kali, kali_command="sqlmap")

    pkn = ksub.add_parser("nmap", help="nmap 端口扫描")
    pkn.add_argument("target")
    pkn.add_argument("--ports", default="")
    pkn.add_argument("--full", action="store_true", help="全面扫描 (-sV -sC)")
    pkn.set_defaults(func=cmd_kali, kali_command="nmap")

    pkf = ksub.add_parser("ffuf", help="ffuf 目录/文件枚举")
    pkf.add_argument("url")
    pkf.add_argument("--wordlist", default="")
    pkf.add_argument("--extensions", default="")
    pkf.add_argument("--threads", type=int, default=50)
    pkf.set_defaults(func=cmd_kali, kali_command="ffuf")

    pkg = ksub.add_parser("gobuster", help="gobuster 目录爆破")
    pkg.add_argument("url")
    pkg.add_argument("--wordlist", default="")
    pkg.add_argument("--extensions", default="php,txt,zip,bak,html")
    pkg.add_argument("--threads", type=int, default=30)
    pkg.set_defaults(func=cmd_kali, kali_command="gobuster")

    pknuc = ksub.add_parser("nuclei", help="nuclei 漏洞模板扫描")
    pknuc.add_argument("url")
    pknuc.add_argument("--severity", default="medium,high,critical")
    pknuc.set_defaults(func=cmd_kali, kali_command="nuclei")

    pknik = ksub.add_parser("nikto", help="nikto Web 服务器扫描")
    pknik.add_argument("url")
    pknik.add_argument("--max-time", type=int, default=60)
    pknik.set_defaults(func=cmd_kali, kali_command="nikto")

    pkh = ksub.add_parser("hydra", help="hydra 暴力破解")
    pkh.add_argument("target")
    pkh.add_argument("--service", default="ssh")
    pkh.add_argument("--user", default="")
    pkh.add_argument("--threads", type=int, default=4)
    pkh.add_argument("--port", type=int, default=0)
    pkh.set_defaults(func=cmd_kali, kali_command="hydra")

    pkw = ksub.add_parser("whatweb", help="whatweb 指纹识别")
    pkw.add_argument("target")
    pkw.set_defaults(func=cmd_kali, kali_command="whatweb")

    pkwp = ksub.add_parser("wpscan", help="wpscan WordPress 漏洞扫描")
    pkwp.add_argument("url")
    pkwp.add_argument("--enumerate", action="store_true", default=True)
    pkwp.set_defaults(func=cmd_kali, kali_command="wpscan")

    pkmsf = ksub.add_parser("msfconsole", help="metasploit 漏洞利用")
    pkmsf.add_argument("target")
    pkmsf.add_argument("--module", default="", help="MSF 模块路径")
    pkmsf.add_argument("--rport", type=int, default=80)
    pkmsf.add_argument("--ssl", action="store_true")
    pkmsf.add_argument("--payload", default="")
    pkmsf.add_argument("--lhost", default="")
    pkmsf.add_argument("--lport", type=int, default=4444)
    pkmsf.set_defaults(func=cmd_kali, kali_command="msfconsole")

    pkauto = ksub.add_parser("autoexploit", help="根据漏洞类型自动选择 Kali 工具利用")
    pkauto.add_argument("url")
    pkauto.add_argument(
        "vuln_type", choices=["sqli", "cmdi", "xss", "lfi", "ssrf", "http", "service", "wordpress"]
    )
    pkauto.add_argument("--param", default="")
    pkauto.add_argument("--dbms", default="")
    pkauto.add_argument("--service", default="")
    pkauto.add_argument("--user", default="")
    pkauto.set_defaults(func=cmd_kali, kali_command="autoexploit")

    return parser


def validate_args(args) -> None:
    """Validate parsed args: URLs, ports, wordlists; initialize Kali."""
    from tools.kali_executor import init_kali, init_kali_local
    from tools.kali_executor import is_available as kali_avail

    url_cmds = {
        "dirfuzz",
        "sqlcheck",
        "xsscheck",
        "cmdi",
        "ssti",
        "ssrf",
        "nosqli",
        "lfi",
        "sqli-blind",
        "sqli-oob",
        "auth-bypass",
        "jwt",
        "graphql",
        "deser",
        "proto-pollution",
        "cors",
        "xss-validate",
        "waf",
        "waf-heavy",
        "bizlogic",
        "chain",
        "sqli-weaponize",
        "sqli-second-order",
        "jwt-exploit",
        "ssrf-pwn",
        "ssrf-lateral",
        "deser-weaponize",
        "xxe",
        "graphql-abuse",
        "jwt-attack",
        "verify",
        "smuggler",
        "webshell",
        "csrf",
        "leak-scan",
        "race",
        "race-profile",
        "workflow-trace",
        "deviation",
        "constraint",
        "bizlogic-v2",
        "xss-verify",
        "auth-default-creds",
        "auth-cookie-tamper",
        "auth-header-injection",
        "auth-method-bypass",
        "auth-mass-assignment",
        "chain-sqli-lfi",
        "chain-sqli-auth",
        "chain-ssrf-lfi",
        "smuggle",
    }
    if args.command in url_cmds:
        u = getattr(args, "url", "") or ""
        if u:
            try:
                _validate_url(u)
            except ValueError as e:
                logger.error("URL validation failed: %s", e)
                import sys

                sys.exit(1)
    target_cmds = (
        "portscan",
        "param-mine",
        "crawl",
        "deepscan",
        "autohunt",
        "auto",
        "recon",
        "quickscan",
    )
    if args.command in target_cmds:
        t = getattr(args, "target", "") or ""
        try:
            _validate_url(t, "target")
        except ValueError as e:
            logger.error("Target validation failed: %s", e)
            import sys

            sys.exit(1)
    if args.command == "portscan" and args.ports:
        for p in args.ports.split(","):
            p = p.strip()
            if not p.isdigit() or not (1 <= int(p) <= 65535):
                logger.error("Invalid port number: %s", p)
                import sys

                sys.exit(1)
    if args.command == "dirfuzz" and args.wordlist and not os.path.isfile(args.wordlist):
        logger.error("Wordlist file not found: %s", args.wordlist)
        import sys

        sys.exit(1)

    if args.kali_local:
        init_kali_local()
        logger.info("Kali initialized in local mode")
    elif args.kali_host:
        init_kali(
            host=args.kali_host,
            port=args.kali_port,
            user=args.kali_user,
            password=args.kali_pass,
            key_file=args.kali_key,
        )
        if kali_avail():
            logger.info("Kali connected: %s@%s:%d", args.kali_user, args.kali_host, args.kali_port)
        else:
            logger.warning("Kali connection failed, check credentials")
