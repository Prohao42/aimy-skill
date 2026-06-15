#!/usr/bin/env python3
import argparse, json, sys, os, time, ssl, urllib.parse as _urlparse
from requests.adapters import HTTPAdapter

from tools.log_utils import get_logger

logger = get_logger("main")

VERSION = "2.1.0"


URL_SCHEMES = ("http://", "https://", "file://", "gopher://", "dict://")


class _TLS12Adapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = ctx
        kwargs["assert_hostname"] = False
        return super().init_poolmanager(connections, maxsize=max(100, maxsize), block=block, **kwargs)


_ADAPTER_CACHE = None
def _tls12_adapter():
    global _ADAPTER_CACHE
    if _ADAPTER_CACHE is None:
        _ADAPTER_CACHE = _TLS12Adapter()
    return _ADAPTER_CACHE


_CHALLENGE_PATTERN = None
_AES_JS_CACHE = None

def _detect_challenge(html):
    global _CHALLENGE_PATTERN
    if _CHALLENGE_PATTERN is None:
        import re
        _CHALLENGE_PATTERN = re.compile(
            r'toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)',
            re.DOTALL,
        )
    return _CHALLENGE_PATTERN.search(html[:2000])


def _solve_with_node(match):
    import subprocess, socket as _sk
    a, b, c = match.group(1), match.group(2), match.group(3)
    global _AES_JS_CACHE
    if _AES_JS_CACHE is None:
        try:
            sock = _sk.create_connection(("idcard.kesug.com", 443), timeout=10)
            sctx = ssl.create_default_context()
            sctx.check_hostname = False
            sctx.verify_mode = ssl.CERT_NONE
            ssock = sctx.wrap_socket(sock, server_hostname="idcard.kesug.com")
            req = (
                b"GET /aes.js HTTP/1.1\r\n"
                b"Host: idcard.kesug.com\r\n"
                b"User-Agent: Mozilla/5.0\r\n"
                b"Connection: close\r\n\r\n"
            )
            ssock.sendall(req)
            data = b""
            while True:
                try:
                    chunk = ssock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                except Exception:
                    break
            ssock.close()
            body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
            _AES_JS_CACHE = body.decode("utf-8", errors="replace") if len(body) > 1000 else ""
        except Exception:
            _AES_JS_CACHE = ""
    if not _AES_JS_CACHE:
        return None
    js_code = _AES_JS_CACHE + f"""
function toNumbers(d){{var e=[];d.replace(/(..)/g,function(d){{e.push(parseInt(d,16))}});return e}}
function toHex(){{for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e='',f=0;f<d.length;f++)e+=(16>d[f]?'0':'')+d[f].toString(16);return e.toLowerCase()}}
try {{ console.log(toHex(slowAES.decrypt(toNumbers("{c}"),2,toNumbers("{a}"),toNumbers("{b}")))); }} catch(e) {{ console.error(e.message); }}
"""
    try:
        result = subprocess.run(["node", "-e", js_code], capture_output=True, text=True, timeout=15)
        val = result.stdout.strip()
        if val and len(val) == 32 and all(c in "0123456789abcdef" for c in val):
            return val
    except Exception:
        pass
    return None


def _sess(args):
    from tools.auth_engine import auth_from_args
    sess = auth_from_args(args)
    sess.mount("https://", _tls12_adapter())
    if "User-Agent" not in sess.headers:
        sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    _orig_send = sess.send
    _challenge_solved = [False]

    def _patched_send(req, **kwargs):
        resp = _orig_send(req, **kwargs)
        if not _challenge_solved[0]:
            body = resp.text[:2000]
            if "slowAES" in body:
                m = _detect_challenge(body)
                if m:
                    cookie_val = _solve_with_node(m)
                    if cookie_val:
                        logger.info("Anti-bot challenge solved, retrying %s %s", req.method, req.url)
                        _challenge_solved[0] = True
                        # Add cookie to the prepared request and retry
                        existing = req.headers.get("Cookie", "")
                        req.headers["Cookie"] = ("%s; __test=%s" % (existing, cookie_val)).strip("; ")
                        resp = _orig_send(req, **kwargs)
        return resp

    sess.send = _patched_send
    return sess


def _validate_url(url: str, name: str = "url") -> None:
    if not url.startswith(URL_SCHEMES):
        raise ValueError("%s must start with a valid scheme %s: %s" % (name, URL_SCHEMES, url))
    parsed = _urlparse.urlparse(url)
    if not parsed.netloc:
        raise ValueError("Invalid %s (no hostname): %s" % (name, url))


def cmd_portscan(args):
    from tools.http_client import HttpClient
    http = HttpClient(_sess(args), args.timeout)
    import socket as _socket
    target = args.target
    ports = [int(p) for p in args.ports.split(",")] if args.ports else [21,22,80,443,3306,6379,8080,8443,9200,27017]
    results = []
    for port in ports:
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(args.timeout)
            r = sock.connect_ex((target, port))
            sock.close()
            if r == 0:
                results.append({"port": port, "state": "open"})
        except Exception as e:
            logger.debug("port %d: %s", port, e)
    print(json.dumps({"target": target, "open_ports": results, "count": len(results)}))


def cmd_dirfuzz(args):
    http = _sess(args)
    url = args.url.rstrip("/")
    wordlist = args.wordlist
    results = []
    try:
        with open(wordlist, "r") as f:
            paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.debug("dirfuzz wordlist: %s", e)
        paths = ["admin", "login", "wp-admin", "backup", "api",
                  "config", ".git", ".env", "robots.txt", "sitemap.xml"]
    for path in paths[:args.max]:
        try:
            r = http.get("%s/%s" % (url, path), timeout=args.timeout, verify=False)
            if r.status_code not in (404,):
                results.append({"path": "/%s" % path, "status": r.status_code,
                                "size": len(r.text)})
        except Exception as e:
            logger.debug("dirfuzz %s: %s", path, e)
    print(json.dumps({"target": url, "found": results, "count": len(results)}))


def cmd_sqlcheck(args):
    from tools.sql_injection import check as sqli_check
    r = sqli_check(args.url, args.param, _sess(args), args.timeout, args.post, args.data)
    print(json.dumps(r))


def cmd_xsscheck(args):
    from tools.xss_detector import check as xss_check
    r = xss_check(args.url, args.param, _sess(args), args.timeout, args.post, args.data, args.context)
    print(json.dumps(r))


def cmd_cmdi(args):
    from tools.cmdi_detector import check as cmdi_check
    r = cmdi_check(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_ssti(args):
    from tools.ssti_detector import check as ssti_check
    r = ssti_check(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_ssrf(args):
    from tools.ssrf_detector import check as ssrf_check
    r = ssrf_check(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_nosqli(args):
    from tools.nosqli_detector import check as nosqli_check
    r = nosqli_check(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_lfi(args):
    from tools.lfi_scanner import check as lfi_check
    r = lfi_check(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_sqli_blind(args):
    from tools.sqli_blind import check as blind_check
    r = blind_check(args.url, args.param, _sess(args), args.timeout, args.post, args.data)
    print(json.dumps(r))


def cmd_sqli_oob(args):
    from tools.sqli_oob import check as oob_check
    r = oob_check(args.url, args.param, args.domain, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_auth_bypass(args):
    from tools.auth_bypass import check as ab_check
    r = ab_check(args.url, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_jwt(args):
    from tools.jwt_detector import check as jwt_check
    r = jwt_check(args.url, getattr(args, "param", None), _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_graphql(args):
    from tools.graphql_scanner import check as gql_check
    r = gql_check(args.url, None, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_deser(args):
    from tools.deserialization_detector import check as deser_check
    r = deser_check(args.url, getattr(args, "param", None), _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_proto(args):
    from tools.proto_pollution import check as pp_check
    r = pp_check(args.url, getattr(args, "param", None), _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_cors(args):
    from tools.cors_scanner import check as cors_check
    r = cors_check(args.url, None, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_bizlogic(args):
    from tools.biz_logic_scanner import check as biz_check
    r = biz_check(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_waf_heavy(args):
    from tools.waf_heavy_bypass import check as wh_check
    r = wh_check(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_xss_validate(args):
    from tools.xss_validator import check as xssv_check
    r = xssv_check(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_waf(args):
    from tools.waf_bypass import check as waf_check
    r = waf_check(args.url, getattr(args, "param", None), _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_deepscan(args):
    from tools.orchestrator import Orchestrator
    engine = Orchestrator(args.target, _sess(args), args.timeout)
    report = engine.run()
    print(json.dumps(report))


def cmd_autohunt(args):
    from tools.orchestrator import Orchestrator
    engine = Orchestrator(args.target, _sess(args), args.timeout, args.threads)
    report = engine.run()
    print(json.dumps(report))


def cmd_auto(args):
    from tools.orchestrator import Orchestrator
    engine = Orchestrator(args.target, _sess(args), args.timeout,
                           args.threads, args.max_pages, args.max_depth)
    report = engine.run()
    print()
    print("=" * 70)
    s = report.get("summary", {})
    print("[+] AUTO REPORT: %s" % args.target)
    print("    Crawl: %d pages / %d endpoints / %d params" % (
        report.get("recon", {}).get("pages_crawled", 0),
        report.get("recon", {}).get("endpoints", 0),
        report.get("recon", {}).get("params_mined", 0),
    ))
    print("    Vulnerabilities: %d" % s.get("vulnerabilities", 0))
    by_type = s.get("by_type", {})
    for vt, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print("      %s: %d" % (vt.upper(), count))
    print("    Exploit paths: %d" % s.get("exploit_ready", 0))
    print("    Critical: %s" % s.get("critical", False))
    print("    Time: %.1fs" % report.get("elapsed_seconds", 0))
    print()
    print(json.dumps(report))


def cmd_chain(args):
    from tools.chain_engine import ChainEngine
    engine = ChainEngine(_sess(args), args.timeout)
    r = engine.run(args.url, args.param, getattr(args, "chain", "full_chain"))
    print(json.dumps(r))


def cmd_proxy(args):
    from tools.packet_capture import run_capture
    r = run_capture(args)
    print(json.dumps(r))


def cmd_capture(args):
    from tools.packet_capture import run_capture, run_realtime
    if args.realtime:
        r = run_realtime(args)
    else:
        r = run_capture(args)
    print(json.dumps(r))


def cmd_workflow(args):
    from tools.workflow import run as wf_run
    ctx = {}
    if args.target:
        ctx["target"] = args.target
    if args.username:
        ctx["username"] = args.username
    if args.password:
        ctx["password"] = args.password
    r = wf_run(args.workflow, ctx)
    print(json.dumps(r))


def cmd_sqli_weaponize(args):
    from tools.sqli_weaponizer import check as sqliw_check
    r = sqliw_check(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_jwt_exploit(args):
    from tools.jwt_exploiter import check as jwte_check
    r = jwte_check(url=args.url, param=getattr(args, "param", None),
                    token=getattr(args, "token", None), sess=_sess(args),
                    timeout=args.timeout)
    print(json.dumps(r))


def cmd_ssrf_pwn(args):
    from tools.ssrf_pwn import check as ssrfp_check
    r = ssrfp_check(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_deser_weaponize(args):
    from tools.deser_weaponizer import check as deserw_check
    r = deserw_check(url=args.url, param=getattr(args, "param", None),
                     sess=_sess(args), timeout=args.timeout)
    print(json.dumps(r))


def cmd_reverse_shell(args):
    from tools.reverse_shell import run as rs_run
    r = rs_run(args.lhost, args.lport, args.encode)
    print(json.dumps(r))


def cmd_ssrf_lateral(args):
    from tools.ssrf_lateral import run as sslat_run
    r = sslat_run(args.url, args.param, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_param_mine(args):
    from tools.param_miner import mine
    endpoints = {"/": {"url": args.target, "methods": ["GET"], "params": []}}
    r = mine(args.target, endpoints, _sess(args), args.timeout, args.threads)
    print(json.dumps(r))


def cmd_crawl(args):
    from tools.crawler import crawl
    r = crawl(args.target, args.depth, args.max_pages, _sess(args), args.timeout)
    print(json.dumps(r))


def cmd_fuzz(args):
    from tools.fuzz_engine import FuzzEngine
    fe = FuzzEngine(args.threads, args.delay)
    if args.payloads:
        payloads = [p.strip() for p in args.payloads.split(",")]
    else:
        payloads = ["test", "admin", "1", "true"]
    result = fe.fuzz(payloads, lambda payload: {"tested": payload})
    print(json.dumps({"payloads_tested": len(result)}))


def cmd_payload_mutate(args):
    from tools.payload_mutator import encode_payload, mutate_value, mutate_param_name
    result = {"originals": [], "encoded": [], "mutations": []}
    if args.payload:
        result["encoded"] = [
            {"method": m, "result": encode_payload(args.payload, m)}
            for m in ["raw", "url", "b64", "hex"]
        ]
        result["mutations"] = [{"variant": v} for v in mutate_value(args.payload)]
    if args.param:
        result["param_mutations"] = [{"variant": v} for v in mutate_param_name(args.param)]
    print(json.dumps(result))


def cmd_list(args):
    from tools.tool_registry import list_tools
    print(json.dumps(list_tools(), indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="aimy-sikll v%s - 轻量级渗透测试辅助工具链" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--timeout", type=float, default=10.0, help="请求超时秒数")
    parser.add_argument("--auth-type", choices=["form", "api", "basic", ""], default="",
                        help="认证类型")
    parser.add_argument("--auth-url", default="", help="认证URL")
    parser.add_argument("--auth-user", default="", help="认证用户名")
    parser.add_argument("--auth-pass", default="", help="认证密码")
    parser.add_argument("--session-file", default="", help="会话文件路径(.pkl)")
    parser.add_argument("--delay", type=float, default=0.0, help="请求间延迟秒数")
    parser.add_argument("--kali-host", default="", help="Kali Linux SSH 主机地址")
    parser.add_argument("--kali-port", type=int, default=22, help="Kali SSH 端口")
    parser.add_argument("--kali-user", default="root", help="Kali SSH 用户名")
    parser.add_argument("--kali-pass", default="", help="Kali SSH 密码")
    parser.add_argument("--kali-key", default="", help="Kali SSH 私钥路径")
    parser.add_argument("--kali-local", action="store_true", help="本地 Kali 模式 (直接用本机工具)")
    parser.add_argument("-v", "--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command")

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
    p.add_argument("url"); p.add_argument("--param", default="id")
    p.add_argument("--post", action="store_true"); p.add_argument("--data", type=json.loads, default=None)
    p.set_defaults(func=cmd_sqlcheck)

    p = sub.add_parser("xsscheck", help="XSS检测")
    p.add_argument("url"); p.add_argument("--param", default="q")
    p.add_argument("--post", action="store_true"); p.add_argument("--data", type=json.loads, default=None)
    p.add_argument("--context", default="all", help="html/attr/js/all")
    p.set_defaults(func=cmd_xsscheck)

    p = sub.add_parser("cmdi", help="命令注入检测")
    p.add_argument("url"); p.add_argument("--param", default="cmd")
    p.set_defaults(func=cmd_cmdi)

    p = sub.add_parser("ssti", help="模板注入检测")
    p.add_argument("url"); p.add_argument("--param", default="name")
    p.set_defaults(func=cmd_ssti)

    p = sub.add_parser("ssrf", help="SSRF检测")
    p.add_argument("url"); p.add_argument("--param", default="url")
    p.set_defaults(func=cmd_ssrf)

    p = sub.add_parser("nosqli", help="NoSQL注入检测")
    p.add_argument("url"); p.add_argument("--param", default="id")
    p.set_defaults(func=cmd_nosqli)

    p = sub.add_parser("lfi", help="本地文件包含检测")
    p.add_argument("url"); p.add_argument("--param", default="file")
    p.set_defaults(func=cmd_lfi)

    p = sub.add_parser("sqli-blind", help="SQL盲注利用")
    p.add_argument("url"); p.add_argument("--param", default="id")
    p.add_argument("--post", action="store_true"); p.add_argument("--data", type=json.loads, default=None)
    p.set_defaults(func=cmd_sqli_blind)

    p = sub.add_parser("sqli-oob", help="OOB SQL注入")
    p.add_argument("url"); p.add_argument("--param", default="id")
    p.add_argument("--domain", default="oob.local")
    p.set_defaults(func=cmd_sqli_oob)

    p = sub.add_parser("auth-bypass", help="认证绕过检测")
    p.add_argument("url")
    p.set_defaults(func=cmd_auth_bypass)

    p = sub.add_parser("jwt", help="JWT检测")
    p.add_argument("url"); p.add_argument("--param", default=None)
    p.set_defaults(func=cmd_jwt)

    p = sub.add_parser("graphql", help="GraphQL扫描")
    p.add_argument("url")
    p.set_defaults(func=cmd_graphql)

    p = sub.add_parser("deser", help="反序列化检测")
    p.add_argument("url"); p.add_argument("--param", default=None)
    p.set_defaults(func=cmd_deser)

    p = sub.add_parser("proto-pollution", help="原型链污染检测")
    p.add_argument("url"); p.add_argument("--param", default=None)
    p.set_defaults(func=cmd_proto)

    p = sub.add_parser("cors", help="CORS检测")
    p.add_argument("url")
    p.set_defaults(func=cmd_cors)

    p = sub.add_parser("xss-validate", help="XSS验证")
    p.add_argument("url"); p.add_argument("--param", default="q")
    p.set_defaults(func=cmd_xss_validate)

    p = sub.add_parser("waf", help="WAF指纹识别与绕过")
    p.add_argument("url"); p.add_argument("--param", default=None)
    p.set_defaults(func=cmd_waf)

    p = sub.add_parser("waf-heavy", help="WAF严格绕过注入检测(HPP/分块/Unicode/注释嵌套)")
    p.add_argument("url"); p.add_argument("--param", default="id")
    p.set_defaults(func=cmd_waf_heavy)

    p = sub.add_parser("bizlogic", help="深度业务逻辑漏洞挖掘(2FA/价格/MassAssn/逻辑)")
    p.add_argument("url"); p.add_argument("--param", default="id")
    p.set_defaults(func=cmd_bizlogic)

    p = sub.add_parser("deepscan", help="深度扫描(爬虫+检测+报告)")
    p.add_argument("target")
    p.set_defaults(func=cmd_deepscan)

    p = sub.add_parser("autohunt", help="自动狩猎(爬虫+参数挖掘+检测+武器化)")
    p.add_argument("target")
    p.add_argument("--threads", type=int, default=10)
    p.set_defaults(func=cmd_autohunt)

    p = sub.add_parser("auto", help="全自动渗透(autohunt增强版)")
    p.add_argument("target")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--max-pages", type=int, default=30)
    p.add_argument("--max-depth", type=int, default=2)
    p.set_defaults(func=cmd_auto)

    p = sub.add_parser("chain", help="利用链组合攻击")
    p.add_argument("url"); p.add_argument("--param", default="id")
    p.add_argument("--chain", default="full_chain")
    p.set_defaults(func=cmd_chain)

    p = sub.add_parser("proxy", help="MITM代理(请求/响应捕获+检测)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--proxy-host", default="127.0.0.1")
    p.add_argument("--proxy-duration", type=int, default=0,
                   help="自动结束秒数(0=手动Ctrl+C)")
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

    p = sub.add_parser("workflow", help="工作流执行")
    p.add_argument("workflow", help="工作流名称或JSON文件路径")
    p.add_argument("--target", default="")
    p.add_argument("--username", default="")
    p.add_argument("--password", default="")
    p.set_defaults(func=cmd_workflow)

    p = sub.add_parser("sqli-weaponize", help="SQL注入数据提取")
    p.add_argument("url"); p.add_argument("--param", default="id")
    p.set_defaults(func=cmd_sqli_weaponize)

    p = sub.add_parser("jwt-exploit", help="JWT利用(crack/伪造)")
    p.add_argument("url", nargs="?", default="")
    p.add_argument("--param", default=None)
    p.add_argument("--token", default=None)
    p.set_defaults(func=cmd_jwt_exploit)

    p = sub.add_parser("ssrf-pwn", help="SSRF文件读取与云元数据")
    p.add_argument("url"); p.add_argument("--param", default="url")
    p.set_defaults(func=cmd_ssrf_pwn)

    p = sub.add_parser("ssrf-lateral", help="SSRF横向移动")
    p.add_argument("url"); p.add_argument("--param", default="url")
    p.set_defaults(func=cmd_ssrf_lateral)

    p = sub.add_parser("deser-weaponize", help="反序列化payload生成")
    p.add_argument("url", nargs="?", default="")
    p.add_argument("--param", default=None)
    p.set_defaults(func=cmd_deser_weaponize)

    p = sub.add_parser("reverse-shell", help="反弹Shell生成器")
    p.add_argument("--lhost", default="LHOST")
    p.add_argument("--lport", type=int, default=4444)
    p.add_argument("--encode", default="raw", choices=["raw", "url", "b64", "ps_b64"])
    p.set_defaults(func=cmd_reverse_shell)

    p = sub.add_parser("param-mine", help="参数挖掘")
    p.add_argument("target")
    p.add_argument("--threads", type=int, default=5)
    p.set_defaults(func=cmd_param_mine)

    p = sub.add_parser("crawl", help="网页爬虫")
    p.add_argument("target")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--max-pages", type=int, default=30)
    p.set_defaults(func=cmd_crawl)

    p = sub.add_parser("fuzz", help="模糊测试")
    p.add_argument("--payloads", default="")
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--delay", type=float, default=0)
    p.set_defaults(func=cmd_fuzz)

    p = sub.add_parser("payload-mutate", help="Payload变异")
    p.add_argument("--payload", default="")
    p.add_argument("--param", default="")
    p.set_defaults(func=cmd_payload_mutate)

    p = sub.add_parser("list", help="列出所有可用工具")
    p.set_defaults(func=cmd_list)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    url_cmds = {"dirfuzz", "sqlcheck", "xsscheck", "cmdi", "ssti", "ssrf",
                "nosqli", "lfi", "sqli-blind", "sqli-oob", "auth-bypass",
                "jwt", "graphql", "deser", "proto-pollution", "cors",
                "xss-validate", "waf", "waf-heavy", "bizlogic",
                "chain", "sqli-weaponize",
                "jwt-exploit", "ssrf-pwn", "ssrf-lateral", "deser-weaponize"}
    if args.command in url_cmds:
        u = getattr(args, "url", "") or ""
        if u:
            try:
                _validate_url(u)
            except ValueError as e:
                logger.error("URL validation failed: %s", e)
                sys.exit(1)
    if args.command in ("portscan", "param-mine", "crawl", "deepscan", "autohunt", "auto"):
        t = getattr(args, "target", "") or ""
        try:
            _validate_url(t, "target")
        except ValueError as e:
            logger.error("Target validation failed: %s", e)
            sys.exit(1)
    if args.command == "portscan" and args.ports:
        for p in args.ports.split(","):
            p = p.strip()
            if not p.isdigit() or not (1 <= int(p) <= 65535):
                logger.error("Invalid port number: %s", p)
                sys.exit(1)
    if args.command == "dirfuzz" and args.wordlist and not os.path.isfile(args.wordlist):
        logger.error("Wordlist file not found: %s", args.wordlist)
        sys.exit(1)

    try:
        args.func(args)
    except Exception as e:
        logger.error("Command '%s' failed: %s", args.command, e)
        logger.debug("Full traceback:", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
