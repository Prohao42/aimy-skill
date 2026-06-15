import json, os, re, time, uuid, subprocess
from typing import Optional, Dict, List
from tools.log_utils import get_logger

logger = get_logger("kali_executor")

HAS_PARAMIKO = False
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    pass


KALI_KNOWN_TOOLS = [
    "sqlmap", "nmap", "ffuf", "gobuster", "nuclei",
    "whatweb", "hashcat", "john", "hydra", "medusa",
    "nikto", "wpscan", "dirb", "wfuzz", "amass",
    "subfinder", "httpx", "dnsx", "crackmapexec",
    "impacket-smbserver", "responder", "bettercap",
    "metasploit", "msfconsole", "searchsploit",
    "aircrack-ng", "burpsuite", "zap-cli",
]


def detect_local_tools() -> Dict[str, bool]:
    available = {}
    for tool in KALI_KNOWN_TOOLS:
        try:
            r = subprocess.run(
                ["which", tool], capture_output=True, text=True, timeout=5
            )
            available[tool] = r.returncode == 0 and r.stdout.strip() != ""
        except Exception:
            available[tool] = False
    count = sum(1 for v in available.values() if v)
    logger.info("Local Kali tools detected: %d/%d", count, len(available))
    return available


class KaliConfig:
    def __init__(self, host: str = "", port: int = 22, user: str = "root",
                 password: str = "", key_file: str = "", timeout: int = 30,
                 local: bool = False):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.local = local
        self.available = (local or (bool(host) and HAS_PARAMIKO))

    def __bool__(self):
        return self.available


class KaliExecutor:
    def __init__(self, config: KaliConfig):
        self.config = config
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp = None

    def connect(self) -> bool:
        if self.config.local:
            return True
        if not self.config.host or not HAS_PARAMIKO:
            logger.warning("Kali SSH not configured or paramiko not installed")
            return False
        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs = {
                "hostname": self.config.host,
                "port": self.config.port,
                "username": self.config.user,
                "timeout": self.config.timeout,
            }
            if self.config.key_file:
                key = paramiko.RSAKey.from_private_key_file(self.config.key_file)
                kwargs["pkey"] = key
            else:
                kwargs["password"] = self.config.password
            self._client.connect(**kwargs)
            self._sftp = self._client.open_sftp()
            logger.info("Connected to Kali: %s@%s", self.config.user, self.config.host)
            return True
        except Exception as e:
            logger.error("Kali SSH connect failed: %s", e)
            self._client = None
            return False

    def disconnect(self):
        if self._sftp:
            try: self._sftp.close()
            except: pass
        if self._client:
            try: self._client.close()
            except: pass
        self._client = None
        self._sftp = None

    def run(self, command: str, timeout: int = 120) -> Dict:
        if self.config.local:
            return _run_local(command, timeout)
        if not self._client:
            return {"success": False, "error": "Not connected", "stdout": "", "stderr": ""}
        try:
            logger.debug("Kali[SSH]: %s", command[:120])
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            logger.debug("Kali exit=%d, stdout=%dB, stderr=%dB", exit_code, len(out), len(err))
            return {
                "success": exit_code == 0,
                "exit_code": exit_code,
                "stdout": out,
                "stderr": err,
            }
        except Exception as e:
            logger.error("Kali command failed: %s", e)
            return {"success": False, "error": str(e), "stdout": "", "stderr": ""}

    def write_file(self, remote_path: str, content: str) -> bool:
        if self.config.local:
            try:
                os.makedirs(os.path.dirname(remote_path), exist_ok=True)
                with open(remote_path, "w") as f:
                    f.write(content)
                return True
            except Exception as e:
                logger.error("local write_file: %s", e)
                return False
        try:
            with self._sftp.open(remote_path, "w") as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error("Kali write_file: %s", e)
            return False

    def read_file(self, remote_path: str) -> Optional[str]:
        if self.config.local:
            try:
                with open(remote_path, "r") as f:
                    return f.read()
            except Exception as e:
                logger.debug("local read_file: %s", e)
                return None
        try:
            with self._sftp.open(remote_path, "r") as f:
                return f.read()
        except Exception as e:
            logger.debug("Kali read_file: %s", e)
            return None

    def file_exists(self, remote_path: str) -> bool:
        if self.config.local:
            return os.path.isfile(remote_path)
        try:
            self._sftp.stat(remote_path)
            return True
        except:
            return False

    def list_dir(self, remote_path: str) -> List[str]:
        if self.config.local:
            try:
                return os.listdir(remote_path)
            except:
                return []
        try:
            return self._sftp.listdir(remote_path)
        except:
            return []

    def read_file_lines(self, remote_path: str) -> List[str]:
        content = self.read_file(remote_path)
        if content:
            return content.splitlines()
        return []

    def check_tool(self, tool: str) -> bool:
        r = self.run(f"which {tool} 2>/dev/null && {tool} --version 2>&1 | head -1", timeout=10)
        return r["success"] and tool in r["stdout"]


def _run_local(command: str, timeout: int = 120) -> Dict:
    try:
        logger.debug("Kali[LOCAL]: %s", command[:120])
        r = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "success": r.returncode == 0,
            "exit_code": r.returncode,
            "stdout": r.stdout,
            "stderr": r.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout", "stdout": "", "stderr": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "stdout": "", "stderr": ""}


KALI_INSTANCE: Optional[KaliExecutor] = None
KALI_LOCAL_TOOLS: Dict[str, bool] = {}


def init_kali(host: str = "", port: int = 22, user: str = "root",
              password: str = "", key_file: str = "") -> KaliExecutor:
    global KALI_INSTANCE
    cfg = KaliConfig(host, port, user, password, key_file)
    ex = KaliExecutor(cfg)
    if cfg.available:
        ex.connect()
    KALI_INSTANCE = ex
    return ex


def init_kali_local() -> KaliExecutor:
    global KALI_INSTANCE, KALI_LOCAL_TOOLS
    cfg = KaliConfig(local=True)
    ex = KaliExecutor(cfg)
    ex.connect()
    KALI_INSTANCE = ex
    KALI_LOCAL_TOOLS = detect_local_tools()
    avail = [k for k, v in KALI_LOCAL_TOOLS.items() if v]
    logger.info("Local Kali mode: %s", " ".join(avail[:8]) + "..." if len(avail) > 8 else " ".join(avail))
    return ex


def get_kali() -> Optional[KaliExecutor]:
    return KALI_INSTANCE


def is_available() -> bool:
    if KALI_INSTANCE is None:
        return False
    if KALI_INSTANCE.config.local:
        return True
    return KALI_INSTANCE._client is not None


def has_tool(tool: str) -> bool:
    if not KALI_LOCAL_TOOLS:
        return False
    return KALI_LOCAL_TOOLS.get(tool, False)
