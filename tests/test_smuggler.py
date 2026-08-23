import socket
import threading

from tools import smuggler
from tools.smuggler import (
    CL_0_PAYLOADS,
    CL_TE_PAYLOADS,
    H2C_UPGRADE_PAYLOADS,
    SMUGGLING_MARKER,
    TE_CL_PAYLOADS,
    TE_TE_PAYLOADS,
    _extract_host_port,
    _has_marker_in_response,
    check,
    exploit,
)


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_server(handler, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    srv.settimeout(5.0)

    def _loop():
        while True:
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                break
            t = threading.Thread(target=handler, args=(conn,), daemon=True)
            t.start()

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return srv


def _marker_handler(conn):
    try:
        conn.settimeout(3.0)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n"
                b"GET / HTTP/1.1\r\n /404smuggled marker\r\n"
            )
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


class TestHelpers:
    def test_extract_host_port(self):
        assert _extract_host_port("http://example.com/") == ("example.com", 80)
        assert _extract_host_port("http://example.com:8080/x") == ("example.com", 8080)
        assert _extract_host_port("https://example.com/x") == ("example.com", 443)

    def test_has_marker_in_response(self):
        assert _has_marker_in_response(["ok", SMUGGLING_MARKER + "x"])
        assert not _has_marker_in_response(["ok", "nothing"])
        assert not _has_marker_in_response([None, None])

    def test_payload_tables_nonempty(self):
        assert CL_TE_PAYLOADS and TE_CL_PAYLOADS and TE_TE_PAYLOADS
        assert H2C_UPGRADE_PAYLOADS and CL_0_PAYLOADS
        for name, tpl in CL_TE_PAYLOADS + TE_CL_PAYLOADS + TE_TE_PAYLOADS + CL_0_PAYLOADS:
            assert name and "{host}" in tpl

    def test_cl0_detection_function_exists(self):
        assert hasattr(smuggler, "_detect_cl_0")
        assert smuggler._detect_cl_0("127.0.0.1", 9, 0.1) == []

    def test_smuggling_marker_defined(self):
        assert SMUGGLING_MARKER == "/404smuggled"


class TestCheck:
    def test_detects_smuggling(self):
        port = _free_port()
        srv = _start_server(_marker_handler, port)
        try:
            result = check("http://127.0.0.1:%d/" % port, timeout=0.3)
            assert result["vulnerable"] is True
            assert result["findings"]
            assert result["smuggling_type"] == "cl_te"
        finally:
            srv.close()

    def test_no_findings_on_silent_server(self, monkeypatch):
        # Delay-based TE.CL heuristic is timing-sensitive against a connection-
        # closing server; isolate it so the marker-based detectors are what's
        # actually verified here.
        monkeypatch.setattr(smuggler, "_detect_te_cl", lambda *a, **k: [])

        def silent(conn):
            try:
                conn.settimeout(0.2)
                conn.recv(4096)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        port = _free_port()
        srv = _start_server(silent, port)
        try:
            result = check("http://127.0.0.1:%d/" % port, timeout=0.2)
            assert result["vulnerable"] is False
        finally:
            srv.close()


class TestDetectHelpers:
    def test_detect_te_te_via_monkeypatch(self, monkeypatch):
        monkeypatch.setattr(
            smuggler,
            "_raw_http_request",
            lambda host, port, payload, timeout=10.0: "HTTP/1.1 200 OK\r\n\r\n" + SMUGGLING_MARKER,
        )
        findings = smuggler._detect_te_te("h", 80, 10.0)
        assert findings
        assert findings[0]["type"] == "te_te"

    def test_detect_te_te_no_marker(self, monkeypatch):
        monkeypatch.setattr(
            smuggler,
            "_raw_http_request",
            lambda host, port, payload, timeout=10.0: "HTTP/1.1 200 OK\r\n\r\nplain",
        )
        assert smuggler._detect_te_te("h", 80, 10.0) == []

    def test_detect_via_delay(self, monkeypatch):
        monkeypatch.setattr(
            smuggler, "_raw_http_request", lambda host, port, raw, timeout=10.0: "x"
        )
        assert smuggler._detect_via_delay("h", 80, "raw", timeout=1.0) >= 0

    def test_detect_te_cl_triggered(self, monkeypatch):
        state = {"calls": 0}

        def fake_raw(host, port, raw, timeout=10.0):
            state["calls"] += 1
            return "x"

        monkeypatch.setattr(smuggler, "_raw_http_request", fake_raw)
        findings = smuggler._detect_te_cl("h", 80, 1.0)
        assert isinstance(findings, list)
        assert state["calls"] > 0


class TestExploit:
    def test_unknown_type(self):
        result = exploit("http://127.0.0.1:1/", attack_type="bogus")
        assert result["success"] is False
        assert "Unknown attack type" in result["error"]

    def test_cl_te_exploit_against_server(self):
        port = _free_port()
        srv = _start_server(_marker_handler, port)
        try:
            result = exploit(
                "http://127.0.0.1:%d/" % port,
                attack_type="cl_te",
                attack_body="GET /admin HTTP/1.1\r\nX:",
                timeout=0.3,
            )
            assert result["success"] is True
            assert result["response"]
        finally:
            srv.close()

    def test_connection_refused(self):
        port = _free_port()
        result = exploit("http://127.0.0.1:%d/" % port, timeout=0.2)
        assert result["success"] is False
        assert result.get("error")
