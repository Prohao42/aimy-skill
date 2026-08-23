import base64
import re
import socket
import threading

from tools.tunnel_agent import (
    Socks5Proxy,
    auto_tunnel,
    chisel_tunnel,
    detect_environment,
    forward_port,
    socks5_over_webshell,
    socks_cascade,
    socks_cascade_deploy,
    ssh_jump_chain,
    ssh_tunnel,
)


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestCommandGenerators:
    def test_socks5_over_webshell(self):
        r = socks5_over_webshell("http://t/shell.php", bind_port=1080)
        assert r["success"] is True
        assert r["bind_port"] == 1080
        assert r["deploy_commands"]
        assert "1080" in r["note"]

    def test_chisel_tunnel(self):
        r = chisel_tunnel("1.2.3.4", lport=8080)
        assert r["success"] is True
        assert "8080" in r["server_command"]
        assert len(r["client_commands"]) == 4
        assert r["client_commands"][0]["platform"] == "linux_amd64"

    def test_ssh_tunnel_simple(self):
        r = ssh_tunnel("host", "user", "KEYDATA", local_port=1080)
        assert r["success"] is True
        assert "-D 1080" in r["tunnel_command"]
        assert "KEYDATA" in r["key_setup"]

    def test_ssh_tunnel_with_jump(self):
        r = ssh_tunnel("host", "user", "KEY", local_port=1080, jump_host="jump:22")
        assert "-J jump:22" in r["tunnel_command"]

    def test_forward_port(self):
        r = forward_port("LHOST", 4444, "10.0.0.5", 80)
        assert r["success"] is True
        assert r["forward_to"] == "10.0.0.5:80"
        assert r["local_port"] == 4444
        m = re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", r["command"])
        assert m, "base64 payload not found in command"
        decoded = base64.b64decode(m.group(1)).decode()
        assert "10.0.0.5" in decoded


class TestEnvironment:
    def test_detect_environment_linux(self):
        def exec_fn(cmd):
            return "Python 3.10.2"

        env = detect_environment(exec_fn)
        assert env["os"] == "linux"
        assert "python3" in env["tools"]

    def test_detect_environment_unknown(self):
        def exec_fn(cmd):
            return ""

        env = detect_environment(exec_fn)
        assert env["os"] == "unknown"

    def test_detect_environment_exception(self):
        def exec_fn(cmd):
            raise RuntimeError("no")

        env = detect_environment(exec_fn)
        assert env["tools"] == {}

    def test_auto_tunnel_python_shell(self):
        recorded = []

        def exec_fn(cmd):
            recorded.append(cmd)
            return "started"

        r = auto_tunnel(exec_fn, lhost="LHOST", lport=1080)
        assert r["environment"]["os"] == "linux"
        assert r["success"] is True
        assert recorded

    def test_auto_tunnel_port_forward(self):
        def exec_fn(cmd):
            return "Python 3.10.2 (detected)"

        r = auto_tunnel(
            exec_fn, lhost="LHOST", lport=2222, target_host="10.0.0.9", target_port=3306
        )
        assert r["success"] is True

    def test_auto_tunnel_no_tools(self):
        def exec_fn(cmd):
            return ""

        r = auto_tunnel(exec_fn)
        assert r["success"] is False


class TestCascade:
    def test_socks_cascade_two_hops(self):
        r = socks_cascade(
            [
                {"host": "a", "port": 1080},
                {"host": "b", "port": 1081},
            ]
        )
        assert r["success"] is True
        assert len(r["chain"]) == 2
        assert "a:1080" in r["usage"]

    def test_socks_cascade_single_hop(self):
        r = socks_cascade([{"host": "a"}])
        assert r["success"] is False
        assert len(r["chain"]) == 1

    def test_ssh_jump_chain(self):
        r = ssh_jump_chain(
            [{"host": "j1", "user": "root"}, {"host": "j2", "user": "u2"}],
            target_host="10.1.1.1",
            target_port=80,
            local_port=8888,
        )
        assert r["success"] is True
        assert "-J root@j1:22,u2@j2:22" in r["steps"][0]
        assert "8888" in r["steps"][0]

    def test_cascade_deploy(self, monkeypatch):
        calls = []

        def exec_fn(cmd):
            calls.append(cmd)

        r = socks_cascade_deploy(
            exec_fn,
            [
                {"host": "h1", "port": 1080, "upstream_host": "h2", "upstream_port": 1081},
            ],
        )
        assert r["success"] is True
        assert len(r["deployed"]) == 1
        assert calls

    def test_cascade_deploy_error(self):
        def exec_fn(cmd):
            raise RuntimeError("boom")

        r = socks_cascade_deploy(exec_fn, [{"host": "h1", "port": 1080}])
        assert r["success"] is False


class TestSocks5Proxy:
    def test_start_stop(self):
        proxy = Socks5Proxy("127.0.0.1", _free_port())
        proxy.start()
        assert proxy._running
        proxy.stop()
        assert not proxy._running

    def test_full_socks5_handshake(self):
        echo_port = _free_port()
        echo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        echo.bind(("127.0.0.1", echo_port))
        echo.listen(1)
        echo.settimeout(5.0)

        def echo_loop():
            conn, _ = echo.accept()
            try:
                data = conn.recv(64)
                conn.sendall(b"ECHO:" + data)
            finally:
                conn.close()

        threading.Thread(target=echo_loop, daemon=True).start()

        proxy = Socks5Proxy("127.0.0.1", _free_port())
        proxy.start()
        try:
            real_port = proxy._server.getsockname()[1]
            c = socket.create_connection(("127.0.0.1", real_port), timeout=5.0)
            c.sendall(b"\x05\x01\x00")
            assert c.recv(2) == b"\x05\x00"

            c.sendall(
                b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + echo_port.to_bytes(2, "big")
            )
            reply = c.recv(10)
            assert reply[1] == 0

            c.sendall(b"ping")
            echoed = c.recv(64)
            assert echoed == b"ECHO:ping"
            c.close()
        finally:
            proxy.stop()
            echo.close()
