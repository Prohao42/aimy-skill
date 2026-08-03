import threading

from tools.protocol_fuzzer import (
    BASELINE_PROBES,
    SERVICE_PAYLOADS,
    ProtocolFuzzer,
    _family_of,
    _repr_payload,
    default_sender,
    fuzz_ports,
)


def _state_with_ports(ports):
    return {
        "phases": {
            "recon": {
                "open_ports": {
                    "open_ports": [
                        {"port": p[0], "service": p[1], "state": "open"}
                        for p in ports
                    ]
                }
            }
        }
    }


def _ok(host, port, payload, timeout=3.0):
    return {"connected": True, "reply": b"+OK\r\n", "error": None, "elapsed": 0.01}


def _drop(host, port, payload, timeout=3.0):
    return {"connected": False, "reply": b"", "error": "Connection refused",
            "elapsed": 0.01}


def _echo(host, port, payload, timeout=3.0):
    return {"connected": True, "reply": b"E:" + payload, "error": None,
            "elapsed": 0.01}


def _empty(host, port, payload, timeout=3.0):
    return {"connected": True, "reply": b"", "error": None, "elapsed": 0.01}


class TestFamily:
    def test_normalizes_service_name(self):
        assert _family_of("MySQL", 0) == "mysql"
        assert _family_of("redis", 0) == "redis"
        assert _family_of("Microsoft-ds", 0) == "smb"
        assert _family_of("", 0) == "generic"

    def test_port_fallback_for_unknown_service(self):
        assert _family_of("unknown", 6379) == "redis"
        assert _family_of("", 3306) == "mysql"
        assert _family_of("unknown", 9999) == "generic"

    def test_payload_tables_cover_all_families(self):
        for family in ("ftp", "ssh", "smtp", "redis", "mysql", "generic"):
            assert SERVICE_PAYLOADS.get(family)
            assert family in BASELINE_PROBES

    def test_repr_payload_is_bounded(self):
        assert len(_repr_payload(b"A" * 5000)) <= 60
        assert _repr_payload(b"\x00\x01") != ""


class TestJudgment:
    def test_connection_dropped_is_interesting(self):
        fz = ProtocolFuzzer(sender=_drop)
        baseline = {"connected": True, "reply": b"220 ok\r\n", "error": None,
                    "elapsed": 0.01}
        res = fz._judge(b"RCPT\r\n", baseline, _drop("h", 25, b"x"), "smtp")
        assert res["interesting"]
        assert "connection_dropped" in res["reasons"]

    def test_reply_gone_is_interesting(self):
        fz = ProtocolFuzzer(sender=_empty)
        baseline = {"connected": True, "reply": b"220 ok\r\n", "error": None,
                    "elapsed": 0.01}
        res = fz._judge(b"USER x\r\n", baseline, _empty("h", 21, b"x"), "ftp")
        assert res["interesting"]
        assert "reply_gone" in res["reasons"]

    def test_oversized_reply_is_interesting(self):
        fz = ProtocolFuzzer(sender=_echo)
        baseline = {"connected": True, "reply": b"short", "error": None,
                    "elapsed": 0.01}
        res = fz._judge(b"A" * 1000, baseline,
                        {"connected": True, "reply": b"E:" + b"A" * 1000,
                         "error": None, "elapsed": 0.01}, "generic")
        assert res["interesting"]
        assert "oversized_reply" in res["reasons"]

    def test_benign_response_not_interesting(self):
        fz = ProtocolFuzzer(sender=_ok)
        baseline = {"connected": True, "reply": b"+OK\r\n", "error": None,
                    "elapsed": 0.01}
        res = fz._judge(b"STAT\r\n", baseline,
                        {"connected": True, "reply": b"+OK\r\n", "error": None,
                         "elapsed": 0.02}, "pop3")
        assert not res["interesting"]
        assert res["reasons"] == []


class TestFuzzService:
    def test_aggregates_probes(self):
        fz = ProtocolFuzzer(sender=_ok)
        out = fz.fuzz_service("db.local", 6379, "redis")
        assert out["family"] == "redis"
        assert out["probes"] == len(SERVICE_PAYLOADS["redis"])
        assert out["interesting"] == 0
        assert len(out["results"]) == out["probes"]

    def test_counts_interesting(self):
        def flaky(host, port, payload, timeout=3.0):
            if b"CONFIG" in payload:
                return _drop(host, port, payload)
            return _ok(host, port, payload)

        fz = ProtocolFuzzer(sender=flaky)
        out = fz.fuzz_service("r.local", 6379, "redis")
        assert out["interesting"] >= 1
        assert any("connection_dropped" in r["reasons"]
                   for r in out["interesting_results"])

    def test_custom_payloads(self):
        fz = ProtocolFuzzer(sender=_ok)
        out = fz.fuzz_service("h", 21, "ftp", payloads=[b"X", b"Y"])
        assert out["probes"] == 2


class TestDefaultSender:
    def test_send_and_receive(self):
        listener = __import__("socket").socket(__import__("socket").AF_INET,
                                               __import__("socket").SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            try:
                conn.sendall(b"220 ready\r\n")
                data = conn.recv(64)
                conn.sendall(b"ACK:" + data)
            finally:
                conn.close()
                listener.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        res = default_sender("127.0.0.1", port, b"HELLO", timeout=3.0)
        t.join(timeout=3.0)
        assert res["connected"]
        assert b"220 ready" in res["reply"]
        assert b"ACK:HELLO" in res["reply"]

    def test_connection_refused(self):
        res = default_sender("127.0.0.1", 1, b"X", timeout=1.0)
        assert res["connected"] is False
        assert res["error"]


class TestFuzzState:
    def test_consumes_recon_open_ports(self):
        state = _state_with_ports([(6379, "redis"), (3306, "mysql")])
        fz = ProtocolFuzzer(sender=_ok)
        out = fz.fuzz_state(state, "http://db.local")
        assert out["host"] == "db.local"
        assert out["ports_fuzzed"] == 2
        assert out["total_interesting"] == 0

    def test_host_extraction(self):
        fz = ProtocolFuzzer(sender=_ok)
        out = fz.fuzz_state(_state_with_ports([(21, "ftp")]), "10.0.0.9")
        assert out["host"] == "10.0.0.9"

    def test_empty_state(self):
        fz = ProtocolFuzzer(sender=_ok)
        out = fz.fuzz_state({}, "http://x.test")
        assert out["ports_fuzzed"] == 0
        assert out["results"] == []


class TestFuzzPortsFn:
    def test_state_mode(self):
        state = _state_with_ports([(21, "ftp")])
        out = fuzz_ports(state, "http://x.test", sender=_ok)
        assert out["ports_fuzzed"] == 1

    def test_direct_ports_mode(self):
        out = fuzz_ports(target="db.local", ports=[6379], sender=_ok)
        assert out["ports_fuzzed"] == 1
        assert out["host"] == "db.local"

    def test_no_args(self):
        out = fuzz_ports()
        assert out["ports_fuzzed"] == 0
