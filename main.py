#!/usr/bin/env python3
import json
import sys

import requests

from cli.arg_parsers import build_parser, validate_args
from cli.check_commands import COMMAND_SPECS, build_dispatcher
from tools.kali_executor import get_kali
from tools.kali_executor import is_available as kali_avail
from tools.log_utils import get_logger
from tools.output import output as _output
from tools.session import build_session as _sess
from tools.settings import settings

logger = get_logger("main")

VERSION = "3.7.5"


def cmd_portscan(args):
    import concurrent.futures as _futures
    import socket as _socket
    target = args.target
    ports = [int(p) for p in args.ports.split(",")] if args.ports else [21,22,80,443,3306,6379,8080,8443,9200,27017]

    def _scan(port):
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        try:
            r = sock.connect_ex((target, port))
            return {"port": port, "state": "open"} if r == 0 else None
        except Exception:
            return None
        finally:
            sock.close()

    with _futures.ThreadPoolExecutor(max_workers=min(50, max(1, len(ports)))) as ex:
        results = [f for f in ex.map(_scan, ports) if f]
    _output({"target": target, "open_ports": results, "count": len(results)})


def cmd_dirfuzz(args):
    import concurrent.futures as _futures
    http = _sess(args)
    url = args.url.rstrip("/")
    wordlist = args.wordlist
    try:
        with open(wordlist, "r") as f:
            paths = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.debug("dirfuzz wordlist: %s", e)
        paths = ["admin", "login", "wp-admin", "backup", "api",
                  "config", ".git", ".env", "robots.txt", "sitemap.xml"]

    def _probe(path):
        try:
            r = http.get("%s/%s" % (url, path), timeout=args.timeout)
            if r.status_code not in (404,):
                return {"path": "/%s" % path, "status": r.status_code,
                        "size": len(r.text)}
        except Exception as e:
            logger.debug("dirfuzz %s: %s", path, e)
        return None

    with _futures.ThreadPoolExecutor(max_workers=min(30, max(1, args.max))) as ex:
        results = [f for f in ex.map(_probe, paths[:args.max]) if f]
    _output({"target": url, "found": results, "count": len(results)})


def cmd_smuggler(args):
    from tools.smuggler import check as smuggle_check
    r = smuggle_check(args.url, sess=_sess(args), timeout=args.timeout)
    _output(r)
    if r.get("vulnerable") and args.exploit:
        from tools.smuggler import exploit as smuggle_exploit
        attack_body = args.attack_body or "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
        e = smuggle_exploit(args.url, attack_type=r["smuggling_type"],
                           attack_body=attack_body, timeout=args.timeout)
        _output({"smuggling_exploit": e})


def cmd_cloud_pwn(args):
    raw_text = args.raw
    if args.file:
        try:
            with open(args.file, "r") as f:
                raw_text = f.read()
        except Exception as e:
            _output({"success": False, "error": str(e)})
            return
    from tools.cloud_pwn import check as cloud_check
    r = cloud_check(raw_text, cloud_hint=args.cloud)
    _output(r)


def cmd_webshell(args):
    from tools.reverse_shell import deploy_webshell, generate_webshell
    if args.deploy:
        r = deploy_webshell(args.url, webshell_type=args.type,
                           path=args.path, sess=_sess(args), timeout=args.timeout)
    else:
        r = generate_webshell(args.type, args.encode)
    _output(r)


def cmd_csrf(args):
    from tools.csrf_scanner import check as csrf_check
    if args.bypass:
        import json

        from tools.csrf_scanner import bypass_check as csrf_bypass
        data = json.loads(args.data) if args.data else {"test": "value"}
        r = csrf_bypass(args.url, args.action or "/", data, _sess(args), args.timeout)
    else:
        r = csrf_check(args.url, _sess(args), args.timeout)
    _output(r)


def cmd_deepscan(args):
    from tools.orchestrator import Orchestrator
    engine = Orchestrator(args.target, _sess(args), args.timeout)
    engine.init_storage(resume=getattr(args, "resume", False),
                        name=getattr(args, "session", "default"))
    report = engine.run()
    _output(report)


def cmd_quickscan(args):
    from tools.orchestrator import Orchestrator
    engine = Orchestrator(
        args.target, _sess(args), args.timeout,
        threads=args.threads, max_pages=20, max_depth=2,
        fast_recon=True, high_value=True, turbo=True
    )
    engine.init_storage(resume=False, name=getattr(args, "session", "quick"))
    report = engine.run()
    s = report.get("summary", {})
    print()
    print("=" * 60)
    print("[QUICK SCAN] %s" % args.target)
    print("  Vulnerabilities: %d" % s.get("vulnerabilities", 0))
    by_type = s.get("by_type", {})
    for vt, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print("    %s: %d" % (vt.upper(), count))
    print("  Critical: %s" % s.get("critical", False))
    print("  Time: %.1fs" % report.get("elapsed_seconds", 0))
    print()
    _output(report)


def cmd_autohunt(args):
    from tools.orchestrator import Orchestrator
    engine = Orchestrator(args.target, _sess(args), args.timeout, args.threads,
                           high_value=getattr(args, "high_value", False),
                           turbo=getattr(args, "turbo", False),
                           skip_verify=getattr(args, "skip_verify", False))
    engine.init_storage(resume=getattr(args, "resume", False),
                        name=getattr(args, "session", "default"))
    report = engine.run()
    _output(report)


def cmd_auto(args):
    from tools.orchestrator import Orchestrator
    engine = Orchestrator(args.target, _sess(args), args.timeout,
                           args.threads, args.max_pages, args.max_depth,
                           fast_recon=not getattr(args, "no_fast_recon", False),
                           high_value=getattr(args, "high_value", False),
                           turbo=getattr(args, "turbo", False),
                           skip_verify=getattr(args, "skip_verify", False))
    engine.init_storage(resume=getattr(args, "resume", False),
                        name=getattr(args, "session", "default"))
    report = engine.run()
    if getattr(args, "save_report", ""):
        from tools.reporter import save_report
        paths = save_report(report, args.save_report)
        if paths:
            print("[+] Report saved: %s / %s" % (paths.get("json", ""), paths.get("html", "")))
    s = report.get("summary", {})
    if settings.is_rookie():
        print()
        print("=" * 70)
        print("[+] AUTO REPORT: %s" % args.target)
        rc = report.get("recon", {})
        print("    Recon: %d techs / %d open ports / git:%s / %d dirs" % (
            len(rc.get("technologies", [])),
            len(rc.get("open_ports", [])),
            "LEAK!" if rc.get("git_exposed") else "ok",
            rc.get("directories", 0),
        ))
        print("    Crawl: %d pages / %d endpoints / %d params" % (
            rc.get("pages_crawled", 0),
            rc.get("endpoints", 0),
            rc.get("params_mined", 0),
        ))
        print("    Risk score: %d" % rc.get("risk_score", 0))
        print("    Vulnerabilities: %d" % s.get("vulnerabilities", 0))
        by_type = s.get("by_type", {})
        for vt, count in sorted(by_type.items(), key=lambda x: -x[1]):
            print("      %s: %d" % (vt.upper(), count))
        print("    Exploit paths: %d" % s.get("exploit_ready", 0))
        print("    Critical: %s" % s.get("critical", False))
        print("    Time: %.1fs" % report.get("elapsed_seconds", 0))
        print()
    else:
        print("[Veteran] %s — vulns=%d critical=%s time=%.1fs" % (
            args.target, s.get("vulnerabilities", 0),
            s.get("critical", False), report.get("elapsed_seconds", 0)))
    _output(report)


def cmd_recon(args):
    from tools.recon import (
        check_git_leak,
        fingerprint_tech,
        fuzz_directories,
        scan_ports,
    )
    target = args.target
    result = {"target": target, "phases": {}}

    print("[Recon] Fingerprinting technologies ...")
    result["phases"]["tech_fingerprint"] = fingerprint_tech(target, _sess(args), args.timeout)

    print("[Recon] Scanning ports ...")
    result["phases"]["port_scan"] = scan_ports(target, fast=not args.full_ports)

    print("[Recon] Checking git leaks ...")
    result["phases"]["git_leak"] = check_git_leak(target, _sess(args), args.timeout, deep=args.deep)

    print("[Recon] Directory fuzzing ...")
    result["phases"]["dir_fuzz"] = fuzz_directories(target, sess=_sess(args), timeout=args.timeout)

    _output(result)


def cmd_chain(args):
    from tools.chain_engine import ChainEngine
    engine = ChainEngine(_sess(args), args.timeout)
    r = engine.run(args.url, args.param, getattr(args, "chain", "full_chain"))
    _output(r)


def cmd_proxy(args):
    from tools.packet_capture import run_capture
    r = run_capture(args)
    _output(r)


def cmd_domain(args):
    userlist = []
    if args.userlist:
        try:
            with open(args.userlist, "r") as f:
                userlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error("userlist: %s", e)
    if getattr(args, "native", False):
        from tools.domain_attacks import run as domain_attacks
        r = domain_attacks(
            target=args.target,
            dc_ip=args.dc_ip or None,
            domain=args.domain or None,
            username=args.username or None,
            password=args.password or None,
            userlist=userlist or None,
        )
    else:
        from tools.domain_hunt import run as domain_hunt
        r = domain_hunt(
            target=args.target,
            dc_ip=args.dc_ip or None,
            domain=args.domain or None,
            username=args.username or None,
            password=args.password or None,
            userlist=userlist or None,
        )
    _output(r)


def cmd_capture(args):
    from tools.packet_capture import run_capture, run_realtime
    if args.realtime:
        r = run_realtime(args)
    else:
        r = run_capture(args)
    _output(r)


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
    _output(r)


def cmd_cms_fingerprint(args):
    from tools.cms_fingerprint import check_batch, fingerprint
    urls = [u for u in (getattr(args, "urls", []) or [])]
    if not urls:
        r = fingerprint(args.url, sess=_sess(args), timeout=args.timeout)
        _output(r)
    else:
        rs = check_batch(urls, timeout=args.timeout)
        _output(rs)


def cmd_idor(args):
    """水平越权检测: A 账号会话访问 B 账号资源。需两个 session 文件或 -id 参数。"""
    from tools.idor_scanner import check as idor_check
    from tools.idor_scanner import check_unauthorized
    sess_a = _sess(args)
    sess_b = None
    if getattr(args, "session_file_b", ""):
        from tools.auth_engine import AuthSession
        b = requests.Session()
        b.verify = settings.verify_ssl
        AuthSession(b).load_session(args.session_file_b)
        sess_b = b
    if getattr(args, "no_auth", False):
        r = check_unauthorized(args.url, sess=sess_a, timeout=args.timeout)
    else:
        r = idor_check(args.url, param=args.param, sess_a=sess_a, sess_b=sess_b,
                       my_id=args.my_id, other_id=args.other_id,
                       method=args.method,
                       json_param=args.json_param or None,
                       timeout=args.timeout)
    _output(r)


def cmd_login(args):
    """SRC 工作流: 登录 -> 保存 session 文件 -> 后续扫描 --session-file 复用登录态。"""
    from tools.auth_engine import AuthSession
    if not (args.auth_url and args.auth_user and args.auth_pass):
        from tools.log_utils import get_logger
        get_logger("main").error("login 需要 --auth-url --auth-user --auth-pass")
        sys.exit(1)
    sess = requests.Session()
    sess.verify = settings.verify_ssl
    engine = AuthSession(sess)
    ok = False
    if args.auth_type == "form":
        ok = engine.login_form(args.auth_url, args.auth_user, args.auth_pass)
    elif args.auth_type == "api":
        ok = engine.login_api(args.auth_url, args.auth_user, args.auth_pass)
    elif args.auth_type == "basic":
        ok = engine.login_basic(args.auth_url, args.auth_user, args.auth_pass)
    else:
        ok = engine.login_form(args.auth_url, args.auth_user, args.auth_pass) or \
             engine.login_api(args.auth_url, args.auth_user, args.auth_pass)
    if ok:
        path = args.session_file or "session.json"
        engine.save_session(path)
        print(json.dumps({"success": True, "session_file": path,
                          "cookies": len(sess.cookies)}, ensure_ascii=False))
    else:
        print(json.dumps({"success": False, "error": "login failed"},
                         ensure_ascii=False))
        sys.exit(1)


def cmd_param_mine(args):
    from tools.param_miner import mine
    endpoints = {"/": {"url": args.target, "methods": ["GET"], "params": []}}
    r = mine(args.target, endpoints, _sess(args), args.timeout, args.threads)
    _output(r)


def cmd_fuzz(args):
    from tools.fuzz_engine import FuzzEngine
    fe = FuzzEngine(args.threads, args.delay)
    if args.payloads:
        payloads = [p.strip() for p in args.payloads.split(",")]
    else:
        payloads = ["test", "admin", "1", "true"]
    result = fe.fuzz(payloads, lambda payload: {"tested": payload})
    _output({"payloads_tested": len(result)})


def cmd_fuzz_engine(args):
    import requests

    from tools.fuzz_engine import FuzzEngine
    sess = requests.Session()
    fe = FuzzEngine(sess, args.timeout)
    vt = args.vuln_type or "sql"
    payloads = fe.generate(vt, count=args.count)
    results = fe.test_payloads(args.url, args.param, payloads)
    interesting = [r for r in results if r.get("interesting")]
    print("  Payloads tested: %d" % len(results))
    print("  Interesting: %d" % len(interesting))
    for r in interesting[:5]:
        print("    [%d] %s (%.1fs, ratio=%.1f)" % (
            r["status"], r["payload"][:50], r["time"], r["size_ratio"]))
    _output({"payloads_tested": len(results), "interesting": len(interesting), "results": results[:20]})


def cmd_code_audit(args):
    from tools.code_audit import run_audit
    result = run_audit([args.path], threads=args.threads)
    print("  Files scanned: %d" % result.get("files_scanned", 0))
    print("  Total findings: %d" % result.get("total_findings", 0))
    for sev, cnt in result.get("by_severity", {}).items():
        print("    %s: %d" % (sev, cnt))
    for f in result.get("findings", [])[:10]:
        print("  [%s] %s:%d %s" % (f["severity"], f["file"], f["line"], f["rule"]))
        print("    %s" % f["snippet"][:100])
        print("    -> %s" % f["rec"][:80])
    _output(result)


def cmd_binary_scan(args):
    from tools.binary_analyzer import run_binary_scan
    result = run_binary_scan([args.path], threads=args.threads)
    print("  Binaries scanned: %d" % result.get("files_scanned", 0))
    print("  Analyzed: %d" % result.get("binaries_analyzed", 0))
    print("  Suspicious: %d" % result.get("suspicious_count", 0))
    s = result.get("summary", {})
    if s.get("packed"):
        print("  Packed: %d" % s["packed"])
    if s.get("has_suspicious_imports"):
        print("  Suspicious imports: %d" % s["has_suspicious_imports"])
    for b in result.get("suspicious", [])[:5]:
        print("    %s (entropy=%.2f, packed=%s)" % (
            b.get("filepath", "?"), b.get("entropy", 0), b.get("packed")))
    _output(result)


def cmd_mobile_scan(args):
    path = args.path.lower()
    if path.endswith(".apk"):
        from tools.mobile_scanner import scan_android
        result = scan_android(args.path)
        print("  Android scan: %d findings" % result.get("total_findings", 0))
    elif path.endswith(".ipa"):
        from tools.mobile_scanner import scan_ios
        result = scan_ios(args.path)
        print("  iOS scan: %d findings" % result.get("total_findings", 0))
    else:
        result = {"error": "Unsupported format: %s (use .apk or .ipa)" % path}
        print(result["error"])
        _output(result)
        return
    for sev, cnt in result.get("by_severity", {}).items():
        print("    %s: %d" % (sev, cnt))
    for f in result.get("findings", [])[:10]:
        print("  [%s] %s: %s" % (f["severity"], f["category"], f["title"]))
    _output(result)


def cmd_payload_mutate(args):
    from tools.payload_mutator import encode_payload, mutate_param_name, mutate_value
    result = {"originals": [], "encoded": [], "mutations": []}
    if args.payload:
        result["encoded"] = [
            {"method": m, "result": encode_payload(args.payload, m)}
            for m in ["raw", "url", "b64", "hex"]
        ]
        result["mutations"] = [{"variant": v} for v in mutate_value(args.payload)]
    if args.param:
        result["param_mutations"] = [{"variant": v} for v in mutate_param_name(args.param)]
    _output(result)


def cmd_leak_scan(args):
    from tools.leak_scanner import check as leak_check
    paths = None
    if getattr(args, "paths", ""):
        paths = [p.strip() for p in args.paths.split(",") if p.strip()]
    r = leak_check(args.url, paths=paths, timeout=args.timeout)
    _output(r)


def cmd_batch_recon(args):
    from tools.batch_recon import run as batch_run
    r = batch_run(args.hosts_file, ports=getattr(args, "ports", ""),
                  threads=args.threads, timeout=min(args.timeout, 3.0),
                  unauth=getattr(args, "unauth", False))
    _output(r)


def cmd_unauth(args):
    from tools.unauth_scan import check as unauth_check
    hosts = []
    if getattr(args, "host", ""):
        hosts.append(args.host)
    if getattr(args, "hosts_file", ""):
        try:
            with open(args.hosts_file, "r") as f:
                hosts += [line.strip() for line in f if line.strip()]
        except Exception as e:
            _output({"success": False, "error": str(e)})
            return
    if not hosts:
        _output({"success": False, "error": "需要 --host 或 --hosts 文件"})
        return
    services = [s.strip() for s in args.service.split(",") if s.strip()]
    r = unauth_check(hosts, services=services, threads=args.threads, timeout=args.timeout)
    _output(r)


def cmd_kali(args):
    if not kali_avail():
        _output({"success": False, "error": "Kali not connected. Use --kali-local or --kali-host/--kali-user/--kali-pass"})
        return

    sub = args.kali_command

    if sub == "exec":
        r = get_kali().run(args.cmd, timeout=args.kali_timeout)
        _output({
            "success": r["success"],
            "exit_code": r.get("exit_code", -1),
            "stdout": r.get("stdout", ""),
            "stderr": r.get("stderr", ""),
        })

    elif sub == "connect":
        _output({
            "success": True,
            "local": get_kali().config.local,
            "host": get_kali().config.host,
            "tools": {t: get_kali().check_tool(t) for t in
                       ["sqlmap","nmap","ffuf","gobuster","nuclei","hydra",
                        "nikto","whatweb","wpscan","msfconsole","dirb","wfuzz"]},
        })

    elif sub == "list-tools":
        _output({"available_tools": [t for t in [
            "sqlmap","nmap","ffuf","gobuster","nuclei","hydra",
            "nikto","whatweb","wpscan","msfconsole","dirb","wfuzz",
            "amass","subfinder","httpx","crackmapexec","responder",
        ] if get_kali().check_tool(t)]})

    elif sub == "sqlmap":
        from tools.kali_toolset import sqlmap_detect, sqlmap_extract
        r = sqlmap_detect(args.url, args.param, dbms=getattr(args, "dbms", None))
        if r.get("vulnerable") and getattr(args, "dump", False):
            r["extract"] = sqlmap_extract(args.url, args.param, dbms=r.get("dbms"))
        _output(r)

    elif sub == "nmap":
        from tools.kali_toolset import nmap_scan
        ports = getattr(args, "ports", "") or "21,22,80,443,3306,6379,8080,8443,9200,27017"
        r = nmap_scan(args.target, ports=ports, fast=not getattr(args, "full", False))
        _output(r)

    elif sub == "ffuf":
        from tools.kali_toolset import ffuf_discover
        r = ffuf_discover(args.url, wordlist=getattr(args, "wordlist", ""),
                          extensions=getattr(args, "extensions", ""),
                          threads=getattr(args, "threads", 50))
        _output(r)

    elif sub == "gobuster":
        from tools.kali_toolset import gobuster_discover
        r = gobuster_discover(args.url, wordlist=getattr(args, "wordlist", ""),
                              extensions=getattr(args, "extensions", "php,txt,zip,bak,html"),
                              threads=getattr(args, "threads", 30))
        _output(r)

    elif sub == "nuclei":
        from tools.kali_toolset import nuclei_scan
        r = nuclei_scan(args.url, severity=getattr(args, "severity", "medium,high,critical"))
        _output(r)

    elif sub == "nikto":
        from tools.kali_toolset import nikto_scan
        r = nikto_scan(args.url, max_time=getattr(args, "max_time", 60))
        _output(r)

    elif sub == "hydra":
        from tools.kali_toolset import hydra_brute
        r = hydra_brute(args.target, service=getattr(args, "service", "ssh"),
                        user=getattr(args, "user", ""),
                        threads=getattr(args, "threads", 4),
                        port=getattr(args, "port", 0))
        _output(r)

    elif sub == "whatweb":
        from tools.kali_toolset import whatweb_identify
        r = whatweb_identify(args.target)
        _output(r)

    elif sub == "wpscan":
        from tools.kali_toolset import wpscan_scan
        r = wpscan_scan(args.url, enumerate_all=getattr(args, "enumerate", True))
        _output(r)

    elif sub == "msfconsole":
        from tools.kali_toolset import metasploit_exploit
        r = metasploit_exploit(
            getattr(args, "module", ""), args.target,
            rport=getattr(args, "rport", 80),
            payload=getattr(args, "payload", ""),
            lhost=getattr(args, "lhost", ""),
            lport=getattr(args, "lport", 4444),
            ssl=getattr(args, "ssl", False))
        _output(r)

    elif sub == "autoexploit":
        from tools.kali_toolset import autoexploit
        r = autoexploit(args.url, args.vuln_type, param=getattr(args, "param", ""),
                        extra={"dbms": getattr(args, "dbms", ""),
                               "service": getattr(args, "service", ""),
                               "user": getattr(args, "user", "")})
        _output(r)

    else:
        _output({"success": False, "error": "Unknown kali sub-command: %s" % sub})


def cmd_list(args):
    from tools.tool_registry import list_all
    tools = list_all()
    if settings.is_rookie():
        print(json.dumps(tools, indent=2, ensure_ascii=False))
    else:
        print("  ".join(tools.keys()))


def main():
    dispatchers = {name: build_dispatcher(spec, _sess, _output)
                   for name, spec in COMMAND_SPECS.items()}
    parser = build_parser(dispatchers)
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.ssl_verify:
        settings.verify_ssl = True
    if hasattr(args, "mode") and args.mode is not None:
        settings.set_mode(args.mode)
    from tools.mode import show_banner
    show_banner()

    validate_args(args)

    try:
        args.func(args)
    except Exception as e:
        logger.error("Command '%s' failed: %s", args.command, e)
        logger.debug("Full traceback:", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
