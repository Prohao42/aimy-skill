"""Offline coverage tests for tools.ssrf_detector and tools.semantic_analyzer.

All network I/O is mocked (fake sessions / monkeypatched listeners); nothing
touches the network. Tests assert the fixed detection behavior: private-range
172.* handling, cloud-metadata evidence patterns, negative-control internal
probes, OOB retry promotion, void-tag depth, error-pattern precision, and
reflection contexts.
"""

import socket
import struct
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from tools import semantic_analyzer, ssrf_detector
from tools.settings import settings


class FakeResp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class FakeSession:
    def __init__(self, handler=None):
        self.handler = handler or (lambda url: FakeResp(404, "x" * 30))
        self.calls = []
        self.verify = True
        self.timeouts = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        self.timeouts.append(kwargs.get("timeout"))
        return self.handler(url)


class FakeEvent:
    def __init__(self, flag=False):
        self.flag = flag

    def wait(self, timeout=None):
        return self.flag

    def set(self):
        self.flag = True

    def is_set(self):
        return self.flag


def _install_fake_oob(
    monkeypatch, http_url=None, http_caught=False, dns_domain=None, dns_caught=False, counters=None
):
    counters = counters if counters is not None else {}

    class FakeHttpListener:
        def __init__(self, port=0, timeout=6.0, custom_callback=None):
            counters["http_started"] = counters.get("http_started", 0) + 1
            self.custom_callback = custom_callback
            self.caught = FakeEvent(http_caught)
            self.request_data = {"path": "/oob", "headers": {"Host": "x"}}

        def start(self):
            return self.custom_callback or http_url

        def stop(self):
            pass

    class FakeDnsListener:
        def __init__(self, port=0, timeout=6.0):
            counters["dns_started"] = counters.get("dns_started", 0) + 1
            self.caught = FakeEvent(dns_caught)
            self.queried_domain = dns_domain

        def start(self):
            return dns_domain

        def stop(self):
            pass

    monkeypatch.setattr(ssrf_detector, "OOBListener", FakeHttpListener)
    monkeypatch.setattr(ssrf_detector, "DnsOobListener", FakeDnsListener)
    return counters


class TestIsLocalTarget:
    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/fetch",
            "http://127.0.0.1/fetch",
            "http://0.0.0.0/fetch",
            "http://10.1.2.3/fetch",
            "http://192.168.1.10/fetch",
            "http://[::1]/fetch",
        ],
    )
    def test_local_targets(self, url):
        assert ssrf_detector._is_local_target(url) is True

    def test_external_target(self):
        assert ssrf_detector._is_local_target("http://example.com/fetch") is False

    def test_172_range_only_private_second_octets_are_local(self):
        """Only 172.16.0.0/12 is private; public 172.217.x.x (and 172.15/172.32)
        must not be treated as local targets."""
        assert ssrf_detector._is_local_target("http://172.217.0.1/fetch") is False
        assert ssrf_detector._is_local_target("http://172.15.0.1/fetch") is False
        assert ssrf_detector._is_local_target("http://172.32.0.1/fetch") is False
        assert ssrf_detector._is_local_target("http://172.16.0.1/fetch") is True
        assert ssrf_detector._is_local_target("http://172.31.255.254/fetch") is True


class TestGetLanIp:
    def test_udp_socket_success(self, monkeypatch):
        class OkSock:
            def __init__(self, *a, **k):
                pass

            def connect(self, addr):
                pass

            def getsockname(self):
                return ("10.9.8.7", 12345)

            def close(self):
                pass

        monkeypatch.setattr(ssrf_detector.socket, "socket", OkSock)
        assert ssrf_detector._get_lan_ip() == "10.9.8.7"

    def test_udp_failure_falls_back_to_hostname(self, monkeypatch):
        def broken_socket(*a, **k):
            raise OSError("no route")

        monkeypatch.setattr(ssrf_detector.socket, "socket", broken_socket)
        monkeypatch.setattr(ssrf_detector.socket, "gethostname", lambda: "myhost")
        monkeypatch.setattr(ssrf_detector.socket, "gethostbyname", lambda h: "192.168.5.5")
        assert ssrf_detector._get_lan_ip() == "192.168.5.5"

    def test_loopback_hostname_rejected(self, monkeypatch):
        def broken_socket(*a, **k):
            raise OSError("no route")

        monkeypatch.setattr(ssrf_detector.socket, "socket", broken_socket)
        monkeypatch.setattr(ssrf_detector.socket, "gethostname", lambda: "myhost")
        monkeypatch.setattr(ssrf_detector.socket, "gethostbyname", lambda h: "127.0.0.1")
        assert ssrf_detector._get_lan_ip() == "127.0.0.1"

    def test_all_probes_fail(self, monkeypatch):
        def broken_socket(*a, **k):
            raise OSError("no route")

        def broken_hostname():
            raise OSError("no hostname")

        monkeypatch.setattr(ssrf_detector.socket, "socket", broken_socket)
        monkeypatch.setattr(ssrf_detector.socket, "gethostname", broken_hostname)
        assert ssrf_detector._get_lan_ip() == "127.0.0.1"


class TestOobListener:
    def test_custom_callback_short_circuits(self):
        listener = ssrf_detector.OOBListener(timeout=0.01, custom_callback="http://cb.example/oob")
        assert listener.start() == "http://cb.example/oob"
        assert listener.caught.is_set() is False

    def test_start_binds_and_returns_lan_url(self, monkeypatch):
        fake_server = mock.Mock()
        fake_server.server_address = ("127.0.0.1", 54321)
        monkeypatch.setattr(
            ssrf_detector.http.server, "HTTPServer", mock.Mock(return_value=fake_server)
        )
        monkeypatch.setattr(ssrf_detector, "_get_lan_ip", lambda: "192.168.7.7")

        listener = ssrf_detector.OOBListener(port=0, timeout=0.01)
        assert listener.start() == "http://192.168.7.7:54321/oob"
        assert listener.port == 54321
        assert listener._thread is not None
        listener._thread.join(2.0)
        listener.stop()
        fake_server.shutdown.assert_called_once()

    def test_start_bind_failure_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            ssrf_detector.http.server, "HTTPServer", mock.Mock(side_effect=OSError("port in use"))
        )
        listener = ssrf_detector.OOBListener(timeout=0.01)
        assert listener.start() is None

    def test_stop_without_server_is_noop(self):
        listener = ssrf_detector.OOBListener(timeout=0.01)
        listener.stop()
        assert listener._server is None

    def test_handler_records_callback(self):
        listener = ssrf_detector.OOBListener(timeout=0.01)
        handler_cls = ssrf_detector.OOBListener._make_handler(listener)
        fake_self = mock.Mock()
        fake_self.path = "/oob?token=abc"
        fake_self.headers = {"Host": "10.0.0.5"}
        handler_cls.do_GET(fake_self)
        assert listener.caught.is_set() is True
        assert listener.request_data["path"] == "/oob?token=abc"
        assert handler_cls.log_message(fake_self, "ignored") is None


class _QueuedSock:
    def __init__(self, items):
        self.items = list(items)

    def recvfrom(self, n):
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def close(self):
        pass


class _RaisingSock:
    def recvfrom(self, n):
        raise ValueError("garbage")

    def close(self):
        raise OSError("close failed")


def _dns_query(domain):
    labels = b"".join(bytes([len(part)]) + part.encode() for part in domain.split("."))
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00"


class TestDnsOobListener:
    @pytest.mark.parametrize(
        "data,expected",
        [
            (struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x05hello\x03com\x00", "hello.com"),
            (b"\x00", None),
            (struct.pack("!HHHHHH", 1, 0, 0, 0, 0, 0), None),
            (struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x03abc\xc0\x0c", "abc"),
            (struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x10abc", None),
        ],
        ids=["valid", "too-short", "qdcount-zero", "compression-pointer", "label-overflow"],
    )
    def test_parse_dns_query(self, data, expected):
        assert ssrf_detector.DnsOobListener._parse_dns_query(data) == expected

    def test_parse_dns_query_non_ascii_label(self):
        data = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x03\xff\xfe\xfd\x00"
        parsed = ssrf_detector.DnsOobListener._parse_dns_query(data)
        assert parsed is not None
        assert len(parsed) == 3

    def test_parse_dns_query_non_bytes_returns_none(self):
        assert ssrf_detector.DnsOobListener._parse_dns_query("x" * 12) is None

    def test_start_binds_udp_and_builds_domain(self, monkeypatch):
        class FakeUdpSock:
            def __init__(self, *a, **k):
                pass

            def bind(self, addr):
                pass

            def settimeout(self, t):
                pass

            def getsockname(self):
                return ("127.0.0.1", 5353)

            def recvfrom(self, n):
                raise socket.timeout()

            def close(self):
                pass

        monkeypatch.setattr(ssrf_detector.socket, "socket", FakeUdpSock)
        monkeypatch.setattr(ssrf_detector, "_get_lan_ip", lambda: "10.1.2.3")
        listener = ssrf_detector.DnsOobListener(timeout=0.01)
        domain = listener.start()
        assert domain.endswith(".10-1-2-3.oob")
        assert listener.port == 5353
        listener._thread.join(2.0)
        listener.stop()

    def test_start_bind_failure_returns_none(self, monkeypatch):
        def broken_socket(*a, **k):
            raise OSError("in use")

        monkeypatch.setattr(ssrf_detector.socket, "socket", broken_socket)
        assert ssrf_detector.DnsOobListener(timeout=0.01).start() is None

    def test_listen_captures_matching_query(self):
        listener = ssrf_detector.DnsOobListener(timeout=0.01)
        listener.domain_token = "tok12345"
        listener._sock = _QueuedSock(
            [
                (_dns_query("tok12345.oob"), ("127.0.0.1", 5300)),
                socket.timeout(),
            ]
        )
        listener._listen()
        assert listener.caught.is_set() is True
        assert listener.queried_domain == "tok12345.oob"
        listener.stop()

    def test_listen_ignores_other_domains_then_times_out(self):
        listener = ssrf_detector.DnsOobListener(timeout=0.01)
        listener.domain_token = "tok12345"
        listener._sock = _QueuedSock(
            [
                (_dns_query("attacker.example"), ("127.0.0.1", 5300)),
                socket.timeout(),
            ]
        )
        listener._listen()
        assert listener.caught.is_set() is False
        assert listener.queried_domain is None

    def test_listen_breaks_on_unexpected_error(self):
        listener = ssrf_detector.DnsOobListener(timeout=0.01)
        listener.domain_token = "tok12345"
        listener._sock = _RaisingSock()
        listener._listen()
        assert listener.caught.is_set() is False

    def test_stop_closes_socket_and_survives_close_error(self):
        listener = ssrf_detector.DnsOobListener(timeout=0.01)
        listener._sock = _RaisingSock()
        listener.stop()
        assert listener.caught.is_set() is True
        listener._sock = None
        listener.stop()


class TestTestOob:
    def test_http_callback_detected(self, monkeypatch):
        _install_fake_oob(monkeypatch, http_url="http://10.0.0.9:4444/oob", http_caught=True)
        sess = FakeSession()
        result = ssrf_detector._test_oob("http://10.0.0.9/fetch", "url", sess, 1.0)
        assert result["vulnerable"] is True
        assert result["type"] == "oob_http_callback"
        assert result["payload"] == "http://10.0.0.9:4444/oob"
        assert result["oob_methods"] == ["http"]
        assert "HTTP OOB" in result["evidence"][0]

    def test_external_target_gets_note_and_skips_dns(self, monkeypatch):
        counters = _install_fake_oob(
            monkeypatch, http_url="http://10.0.0.9:4444/oob", http_caught=False
        )
        sess = FakeSession()
        result = ssrf_detector._test_oob("http://ext.example/fetch", "url", sess, 0.1)
        assert result["vulnerable"] is False
        assert "External target" in result["note"]
        assert counters.get("dns_started", 0) == 0

    def test_dns_callback_detected_for_local_target(self, monkeypatch):
        _install_fake_oob(
            monkeypatch,
            http_url=None,
            http_caught=False,
            dns_domain="tok.10-0-0-1.oob",
            dns_caught=True,
        )
        sess = FakeSession()
        result = ssrf_detector._test_oob("http://localhost/fetch", "url", sess, 0.1)
        assert result["vulnerable"] is True
        assert result["type"] == "oob_dns_callback"
        assert result["oob_methods"] == ["dns"]
        assert result["payload"] == "http://tok.10-0-0-1.oob/"

    def test_custom_callback_suppresses_external_note(self, monkeypatch):
        _install_fake_oob(
            monkeypatch, http_url=None, http_caught=False, dns_domain=None, dns_caught=False
        )
        sess = FakeSession()
        result = ssrf_detector._test_oob(
            "http://localhost/fetch", "url", sess, 0.1, custom_callback="http://cb.example/oob"
        )
        assert result["vulnerable"] is False
        assert "note" not in result
        assert sess.calls
        assert "http%3A%2F%2Fcb.example%2Foob" in sess.calls[0]

    def test_oob_request_exceptions_are_swallowed(self, monkeypatch):
        counters = _install_fake_oob(
            monkeypatch,
            http_url="http://10.0.0.9:4444/oob",
            http_caught=False,
            dns_domain="tok.10-0-0-9.oob",
            dns_caught=False,
        )

        class RaisingSession:
            def get(self, *a, **k):
                raise RuntimeError("connection refused")

        result = ssrf_detector._test_oob("http://localhost/fetch", "url", RaisingSession(), 0.1)
        assert result["vulnerable"] is False
        assert counters["http_started"] == 1
        assert counters["dns_started"] == 1


class TestCheck:
    def _patch_oob(self, **kwargs):
        return mock.patch.object(ssrf_detector, "_test_oob", **kwargs)

    def test_disclosure_returns_after_first_payload(self):
        def handler(url):
            return FakeResp(200, "ami-id: ami-0123456789abcdef0")

        sess = FakeSession(handler)
        result = ssrf_detector.check("http://t.test/fetch", "url", sess=sess, timeout=1.0)
        assert result["vulnerable"] is True
        assert result["type"] == "disclosure"
        assert result["confidence"] == "high"
        assert result["confirmed"] is True
        assert result["payload"] == ssrf_detector.SSRF_URLS[0]
        assert len(sess.calls) == 1

    def test_generic_xml_does_not_match_cloud_metadata_disclosure(self):
        """Generic <Name>/<Contents>/<Key> XML must not be flagged as cloud metadata
        disclosure; only cloud-specific evidence patterns count."""
        sess = FakeSession(lambda url: FakeResp(200, "<Config><Name>x</Name></Config>"))
        with self._patch_oob(return_value={"vulnerable": False, "oob_methods": []}):
            result = ssrf_detector.check("http://t.test/fetch", "url", sess=sess, timeout=1.0)
        assert result["vulnerable"] is False
        assert result["type"] is None
        assert result["payload"] is None
        assert result["evidence"] == []
        assert result["confidence"] == "low"
        assert len(sess.calls) == len(ssrf_detector.SSRF_URLS) + 1 + len(
            ssrf_detector.INTERNAL_PROBES
        )

    def test_internal_reachable_requires_response_distinct_from_control(self):
        """A generic fallback page identical to the unreachable-port control
        (http://127.0.0.1:9/) is not internal_reachable; a distinct internal-only
        response is still reported."""
        generic = "Welcome to our corporate site, please log in."
        sess = FakeSession(lambda url: FakeResp(200, generic))
        with self._patch_oob(return_value={"vulnerable": False, "oob_methods": []}):
            result = ssrf_detector.check("http://t.test/fetch", "url", sess=sess, timeout=1.0)
        assert result["vulnerable"] is False
        assert result["type"] is None
        assert result["payload"] is None
        assert len(sess.calls) == len(ssrf_detector.SSRF_URLS) + 1 + len(
            ssrf_detector.INTERNAL_PROBES
        )

        def handler(url):
            if "8080" in url:
                return FakeResp(200, generic)
            return FakeResp(404, "x" * 30)

        distinct = FakeSession(handler)
        result2 = ssrf_detector.check("http://t.test/fetch", "url", sess=distinct, timeout=1.0)
        assert result2["vulnerable"] is True
        assert result2["type"] == "internal_reachable"
        assert result2["confidence"] == "medium"
        assert result2["confirmed"] is False
        assert result2["payload"] == ssrf_detector.INTERNAL_PROBES[0]
        assert len(distinct.calls) == len(ssrf_detector.SSRF_URLS) + 2

    def test_internal_probe_filters_short_and_error_statuses(self):
        sess = FakeSession(lambda url: FakeResp(200, "short"))
        with self._patch_oob(return_value={"vulnerable": False, "oob_methods": []}):
            result = ssrf_detector.check("http://t.test/fetch", "url", sess=sess, timeout=1.0)
        assert result["vulnerable"] is False
        assert result["type"] is None
        assert len(sess.calls) == len(ssrf_detector.SSRF_URLS) + 1 + len(
            ssrf_detector.INTERNAL_PROBES
        )

    def test_oob_callback_promotes_finding_to_high_confidence(self):
        sess = FakeSession()
        oob_result = {
            "vulnerable": True,
            "type": "oob_http_callback",
            "evidence": ["HTTP OOB: {'path': '/oob'"],
            "payload": "http://10.0.0.9:4444/oob",
            "oob_methods": ["http"],
        }
        with self._patch_oob(return_value=oob_result):
            result = ssrf_detector.check("http://t.test/fetch", "url", sess=sess, timeout=1.0)
        assert result["vulnerable"] is True
        assert result["confidence"] == "high"
        assert result["confirmed"] is True
        assert result["oob_tested"] is True
        assert result["evidence"] == oob_result["evidence"]
        assert result["oob_methods"] == ["http"]

    def test_oob_retry_promotes_to_high_confidence_and_keeps_payload(self):
        """An OOB callback found on the local-target retry is a confirmed finding:
        confidence=high, confirmed=True, payload/evidence preserved from the retry."""
        sess = FakeSession()
        oob_retry = {
            "vulnerable": True,
            "type": "oob_http_callback",
            "evidence": ["HTTP OOB: {'path': '/oob'"],
            "payload": "http://10.0.0.9:4444/oob",
            "oob_methods": ["http"],
        }
        with self._patch_oob(
            side_effect=[
                {"vulnerable": False, "oob_methods": []},
                oob_retry,
            ]
        ) as fake:
            result = ssrf_detector.check("http://localhost/fetch", "url", sess=sess, timeout=1.0)
        assert result["vulnerable"] is True
        assert result["type"] == "oob_http_callback"
        assert result["confidence"] == "high"
        assert result["confirmed"] is True
        assert result["payload"] == oob_retry["payload"]
        assert result["evidence"] == oob_retry["evidence"]
        assert result["oob_methods"] == ["http"]
        assert fake.call_args_list[0].args[3] == pytest.approx(1.0)
        assert fake.call_args_list[1].args[3] == pytest.approx(1.5)

    def test_oob_retry_exception_is_swallowed(self):
        sess = FakeSession()
        with self._patch_oob(
            side_effect=[
                {"vulnerable": False, "oob_methods": []},
                RuntimeError("listener crashed"),
            ]
        ):
            result = ssrf_detector.check("http://localhost/fetch", "url", sess=sess, timeout=1.0)
        assert result["vulnerable"] is False
        assert result["confidence"] == "low"

    def test_oob_test_exception_keeps_oob_tested_false(self):
        sess = FakeSession()
        with self._patch_oob(side_effect=RuntimeError("listener crashed")):
            result = ssrf_detector.check("http://t.test/fetch", "url", sess=sess, timeout=1.0)
        assert result["vulnerable"] is False
        assert result["oob_tested"] is False

    def test_external_target_not_retried_and_gets_note(self):
        sess = FakeSession()
        with self._patch_oob(return_value={"vulnerable": False, "oob_methods": []}) as fake:
            result = ssrf_detector.check("http://ext.test/fetch", "url", sess=sess, timeout=1.0)
        assert fake.call_count == 1
        assert result["oob_tested"] is True
        assert "External target" in result["note"]
        assert result["confidence"] == "low"

    def test_oob_server_passthrough_and_note(self):
        sess = FakeSession()
        oob_result = {"vulnerable": False, "oob_methods": [], "note": "use --oob-server"}
        with self._patch_oob(return_value=oob_result) as fake:
            result = ssrf_detector.check(
                "http://t.test/fetch",
                "url",
                sess=sess,
                timeout=1.0,
                oob_server="http://cb.example/oob",
            )
        assert result["oob_server_used"] == "http://cb.example/oob"
        assert result["oob_note"] == "use --oob-server"
        assert fake.call_args.kwargs["custom_callback"] == "http://cb.example/oob"

    def test_network_errors_never_propagate_and_yield_not_vulnerable(self):
        class RaisingSession:
            def __init__(self):
                self.verify = True

            def get(self, *a, **k):
                raise RuntimeError("connection refused")

        with self._patch_oob(return_value={"vulnerable": False, "oob_methods": []}):
            result = ssrf_detector.check(
                "http://t.test/fetch", "url", sess=RaisingSession(), timeout=0.01
            )
        assert result["vulnerable"] is False
        assert result["confidence"] == "low"
        assert result["evidence"] == []

    def test_creates_session_and_sets_verify(self):
        fake = FakeSession(lambda url: FakeResp(200, "ami-id: ami-0123456789abcdef0"))
        with mock.patch.object(ssrf_detector.requests, "Session") as session_cls:
            session_cls.return_value = fake
            result = ssrf_detector.check("http://t.test/fetch", "url", timeout=1.0)
        assert result["vulnerable"] is True
        assert fake.verify == settings.verify_ssl


class TestSemanticStructure:
    def test_extract_structure_counts_and_depth(self):
        s = semantic_analyzer.extract_structure("<div><form><input></form></div><script></script>")
        assert s["tag_counts"]["div"] == 1
        assert s["tag_counts"]["form"] == 1
        assert s["tag_counts"]["input"] == 1
        assert s["max_depth"] == 2
        assert s["form_count"] == 1
        assert s["input_count"] == 1
        assert s["script_count"] == 1
        assert s["total_tags"] == 4

    def test_closing_tags_never_drive_depth_negative(self):
        s = semantic_analyzer.extract_structure("</div></div><p>")
        assert s["max_depth"] == 1

    def test_void_tags_do_not_contribute_to_depth(self):
        """Void tags (input/img/br) never close, so they must not raise nesting depth;
        only real open/close pairs do."""
        s = semantic_analyzer.extract_structure("<input><input><input>")
        assert s["max_depth"] == 0
        assert s["tag_counts"]["input"] == 3
        s2 = semantic_analyzer.extract_structure("<div><img><br><span></span></div>")
        assert s2["max_depth"] == 2

    def test_structure_hash_is_stable_within_process(self):
        body = "<div><form></form></div>"
        assert semantic_analyzer.structure_hash(body) == semantic_analyzer.structure_hash(body)

    def test_structure_hash_is_stable_across_processes(self):
        """structure_hash() uses md5 instead of the PYTHONHASHSEED-randomized builtin
        hash(), so persisted hashes match across runs and processes."""
        root = Path(semantic_analyzer.__file__).resolve().parents[1]
        code = (
            "from tools.semantic_analyzer import structure_hash;"
            "print(structure_hash('<div><form></form></div>'))"
        )
        outs = [
            subprocess.run(
                [sys.executable, "-c", code], cwd=str(root), capture_output=True, encoding="utf-8"
            ).stdout.strip()
            for _ in range(2)
        ]
        assert outs[0]
        assert outs[0] == outs[1]
        assert outs[0] == semantic_analyzer.structure_hash("<div><form></form></div>")


class TestSemanticErrors:
    @pytest.mark.parametrize(
        "text,label",
        [
            ("SQL syntax near 'x' in MySQL", "mysql"),
            ("Warning: mysql_connect refused", "mysql"),
            ("Warning: something PHP failed", "php"),
            ("java.lang.NullPointerException at x", "java_spring"),
            ("PostgreSQL ERROR: relation missing", "postgresql"),
            ("Microsoft OLE DB Provider for SQL", "mssql"),
            ("ORA-01756: quoted string not terminated", "oracle"),
            ("NameError: name 'x' is not defined", "python"),
            ("Warning: SimpleXML invalid", "xml_xxe"),
            ("Parse error: unexpected T_STRING", "php_parse"),
            ("root@server:~# id", "shell_output"),
            ("uid=33(www-data) gid=33(www-data)", "unix_id"),
            ("<h1>404 Not Found</h1>", "not_found"),
            ("<h1>500 Internal Server Error</h1>", "server_error"),
            ("<h1>403 Forbidden</h1>", "forbidden"),
            ("Warning: file_get_contents(x): failed to open stream", "file_read_error"),
            ("Warning: include(x): failed to open", "include_error"),
        ],
    )
    def test_error_pattern_labels(self, text, label):
        assert label in semantic_analyzer.extract_error_patterns(text)

    def test_no_errors_on_clean_body(self):
        assert semantic_analyzer.extract_error_patterns("<div>hello world</div>") == []

    def test_python_pattern_matches_tracebacks_not_prose(self):
        """'File listings on line 5' is prose; python errors require a Traceback, a
        File "x", line N frame, or a named exception."""
        assert "python" not in semantic_analyzer.extract_error_patterns("File listings on line 5")
        assert "python" in semantic_analyzer.extract_error_patterns(
            "Traceback (most recent call last):"
        )
        assert "python" in semantic_analyzer.extract_error_patterns(
            'File "/app/server.py", line 5, in handle'
        )
        assert "python" in semantic_analyzer.extract_error_patterns(
            "ValueError: invalid literal for int()"
        )


class TestAnalyzeSingleResponse:
    def test_extracts_title_keywords_errors_hash(self):
        body = "<title>\n Login Page \n</title><div>Alpha Beta</div>"
        result = semantic_analyzer.analyze_single_response(body, 200, "text/html")
        assert result["title"] == "Login Page"
        assert {"Alpha", "Beta"} <= set(result["keywords"])
        assert result["length"] == len(body)
        assert result["content_type"] == "text/html"
        assert result["status"] == 200
        assert result["errors"] == []
        assert result["hash"] == semantic_analyzer.structure_hash(body)

    def test_keywords_only_scanned_in_first_500_chars(self):
        body = "x" * 500 + " ZetaBeyondWindow"
        result = semantic_analyzer.analyze_single_response(body, 200)
        assert "ZetaBeyondWindow" not in result["keywords"]

    def test_keywords_capped_to_20(self):
        body = " ".join("Word%02d" % i for i in range(30))
        result = semantic_analyzer.analyze_single_response(body, 200)
        assert len(result["keywords"]) == 20


class TestCompareResponses:
    def test_identical_responses_have_no_changes(self):
        base = {
            "status": 200,
            "length": 10,
            "hash": "a",
            "errors": [],
            "structure": {"tag_counts": {}},
        }
        assert semantic_analyzer.compare_responses(dict(base), dict(base)) == {}

    def test_status_length_and_errors_are_reported(self):
        baseline = semantic_analyzer.analyze_single_response("<div>hello</div>", 200, "text/html")
        probe = semantic_analyzer.analyze_single_response(
            "<form><input></form><p>500 Internal Server Error</p>", 500, "text/html"
        )
        changes = semantic_analyzer.compare_responses(baseline, probe)
        assert changes["status"] == "200 -> 500"
        assert "length" in changes
        assert changes["structure_changed"] is True
        assert changes["new_errors"] == ["server_error"]
        assert changes["anomaly_score"] == pytest.approx(1.0)

    def test_cleared_errors_reported(self):
        baseline = semantic_analyzer.analyze_single_response(
            "<p>404 Not Found</p>", 404, "text/html"
        )
        probe = semantic_analyzer.analyze_single_response("<p>ok</p>", 200, "text/html")
        changes = semantic_analyzer.compare_responses(baseline, probe)
        assert changes["errors_cleared"] == ["not_found"]

    def test_same_tag_counts_but_different_depth_still_anomalous(self):
        baseline = {
            "status": 200,
            "length": 10,
            "hash": "a",
            "errors": [],
            "structure": {"tag_counts": {"div": 2}},
        }
        probe = {
            "status": 200,
            "length": 10,
            "hash": "b",
            "errors": [],
            "structure": {"tag_counts": {"div": 2}},
        }
        changes = semantic_analyzer.compare_responses(baseline, probe)
        assert changes == {"structure_changed": True, "anomaly_score": 0.3}

    @pytest.mark.parametrize(
        "changes,expected",
        [
            ({"new_errors": ["x"]}, 0.4),
            ({"structure_changed": True}, 0.3),
            ({"status": "200 -> 500"}, 0.2),
            ({"new_errors": ["x"], "length": "+5 (25.0%)"}, 0.6),
            ({"new_errors": ["x"], "length": "+5 (abc%)"}, 0.4),
            (
                {
                    "new_errors": ["x"],
                    "structure_changed": True,
                    "status": "1 -> 2",
                    "length": "+5 (50.0%)",
                },
                1.0,
            ),
        ],
    )
    def test_score_anomaly(self, changes, expected):
        assert semantic_analyzer._score_anomaly(changes) == pytest.approx(expected)


class TestResponseSignatureDiff:
    def test_diff_reports_all_change_classes(self):
        sig1 = semantic_analyzer.ResponseSignature(200, 100, "h1", ["a"], "text/html", title="Home")
        sig2 = semantic_analyzer.ResponseSignature(
            500, 200, "h2", ["a", "b"], "text/html", title="Error"
        )
        changes = sig1.diff(sig2)
        assert changes["status"] == (200, 500)
        assert changes["length_ratio"] == 0.5
        assert changes["structure_changed"] is True
        assert changes["new_errors"] == ["b"]

    def test_diff_identical_has_no_changes(self):
        sig = semantic_analyzer.ResponseSignature(200, 10, "h", [], "text/html")
        assert sig.diff(semantic_analyzer.ResponseSignature(200, 10, "h", [], "text/html")) == {}


class TestClusterTextSimilarity:
    def test_overlap_ratio(self):
        assert semantic_analyzer.cluster_text_similarity("a\nb\nc", "b\nc\nd") == 0.5

    def test_empty_vs_text(self):
        assert semantic_analyzer.cluster_text_similarity("", "x") == 0.0

    def test_empty_texts_are_not_similar(self):
        """Any empty/blank side returns 0.0, so blank pages never cluster together."""
        assert semantic_analyzer.cluster_text_similarity("", "") == 0.0
        assert semantic_analyzer.cluster_text_similarity("  \n ", "") == 0.0
        assert semantic_analyzer.cluster_text_similarity("", "body") == 0.0
        assert semantic_analyzer.cluster_text_similarity("a\nb", "a\nb") == 1.0


class TestDetectContentReflection:
    def test_plain_payload_reflected(self):
        result = semantic_analyzer.detect_content_reflection(
            "alertPAYLOAD123", "<div>alertPAYLOAD123</div>"
        )
        assert result["reflected"] is True
        assert result["positions"][0]["offset"] == 5

    def test_escaped_payload_not_counted(self):
        result = semantic_analyzer.detect_content_reflection(
            "<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;"
        )
        assert result["reflected"] is False

    def test_short_payloads_are_checked(self):
        """The fragment loop reaches length 1, so payloads of five chars or fewer are
        detected like any other reflection (no five-char lower bound)."""
        three = semantic_analyzer.detect_content_reflection("abc", "xxabcxx")
        assert three["reflected"] is True
        assert three["positions"][0]["offset"] == 2
        assert three["context"] == "html"
        five = semantic_analyzer.detect_content_reflection("abcde", "xxabcdexx")
        assert five["reflected"] is True
        assert five["positions"][0]["offset"] == 2

    def test_positions_capped_at_three(self):
        body = "PAYLOAD123 and PAYLOAD123 and PAYLOAD123 and PAYLOAD123"
        result = semantic_analyzer.detect_content_reflection("PAYLOAD123", body)
        assert result["reflected"] is True
        assert len(result["positions"]) == 3

    @pytest.mark.parametrize(
        "body,expected",
        [
            ("<script>var a=PAYLOAD123", "js"),
            ("<img src=x onerror=PAYLOAD123>", "event_handler"),
            ("<a href=PAYLOAD123>", "attribute"),
            ('<div data-x="PAYLOAD123">', "attribute_value"),
            ("PAYLOAD123", "html"),
            ("<div>PAYLOAD123", "unknown"),
        ],
    )
    def test_reflection_context(self, body, expected):
        assert (
            semantic_analyzer.detect_content_reflection("PAYLOAD123", body)["context"] == expected
        )

    def test_long_script_block_context_detected_as_js(self):
        """An unclosed <script> anywhere before the payload makes the context 'js', not
        just within the last 50 chars; a closed script block does not leak 'js'."""
        body = "<script>" + "a" * 60 + "PAYLOAD123"
        result = semantic_analyzer.detect_content_reflection("PAYLOAD123", body)
        assert result["reflected"] is True
        assert result["context"] == "js"
        closed = "<script>x</script><div>PAYLOAD123</div>"
        assert (
            semantic_analyzer.detect_content_reflection("PAYLOAD123", closed)["context"]
            == "unknown"
        )
