#!/usr/bin/env python3
import argparse, json, sys, os, time

VERSION = "2.0.0"


def _sess(args):
    from tools.auth_engine import auth_from_args
    return auth_from_args(args)


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
        except:
            pass
    print(json.dumps({"target": target, "open_ports": results, "count": len(results)}))


def cmd_dirfuzz(args):
    http = _sess(args)
    url = args.url.rstrip("/")
    wordlist = args.wordlist
    results = []
    try:
        with open(wordlist, "r") as f:
            paths = [line.strip() for line in f if line.strip()]
    except:
        paths = ["admin", "login", "wp-admin", "backup", "api",
                  "config", ".git", ".env", "robots.txt", "sitemap.xml"]
    for path in paths[:args.max]:
        try:
            r = http.get("%s/%s" % (url, path), timeout=args.timeout, verify=False)
            if r.status_code not in (404,):
                results.append({"path": "/%s" % path, "status": r.status_code,
                                "size": len(r.text)})
        except:
            pass
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
    from tools.proxy import start_proxy
    r = start_proxy(args.port, args.capture_time)
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
    result = {
        "originals": [],
        "encoded": [],
        "mutations": [],
    }
    if args.payload:
        result["encoded"] = [
            {"method": m, "result": encode_payload(args.payload, m)}
            for m in ["raw", "url", "b64", "hex"]
        ]
        result["mutations"] = [{"variant": v} for v in mutate_value(args.payload)]
    if args.param:
        result["param_mutations"] = [{"variant": v} for v in mutate_param_name(args.param)]
    print(json.dumps(result))


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
    parser.add_argument("-v", "--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command")

    # Discovery
    p = sub.add_parser("portscan", help="TCP端口扫描")
    p.add_argument("target")
    p.add_argument("--ports", default="", help="端口列表,逗号分隔")
    p.set_defaults(func=cmd_portscan)

    p = sub.add_parser("dirfuzz", help="目录枚举")
    p.add_argument("url")
    p.add_argument("--wordlist", default="", help="字典路径")
    p.add_argument("--max", type=int, default=50, help="最大路径数")
    p.set_defaults(func=cmd_dirfuzz)

    # Detection
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

    # Multi-phase
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

    p = sub.add_parser("proxy", help="MITM代理(凭据捕获)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--capture-time", type=int, default=60)
    p.set_defaults(func=cmd_proxy)

    p = sub.add_parser("workflow", help="工作流执行")
    p.add_argument("workflow", help="工作流名称或JSON文件路径")
    p.add_argument("--target", default="")
    p.add_argument("--username", default="")
    p.add_argument("--password", default="")
    p.set_defaults(func=cmd_workflow)

    # Weaponization
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

    # Utilities
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

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
