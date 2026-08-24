from unittest import mock

from tools import unauth_scan


class TestRedis:
    def test_unauth(self):
        with mock.patch("tools.unauth_scan._sock_send", side_effect=[
            b"+PONG\r\n",
            b"redis_version:7.0.0\r\nrole:master\r\n"
            b"db0:keys=4,expires=0,avg_ttl=0,subexpiry=0\r\n",
            b":4\r\n",
        ]):
            r = unauth_scan.check_redis("1.2.3.4", 6379)
        assert r["unauth"] is True
        assert r["version"] == "7.0.0"
        assert r["dbsize"] == 4
        assert "keys=4" in r["keyspace"]

    def test_auth_required(self):
        with mock.patch("tools.unauth_scan._sock_send",
                        return_value=b"-NOAUTH Authentication required.\r\n"):
            r = unauth_scan.check_redis("1.2.3.4", 6379)
        assert r["unauth"] is False
        assert r["honey"] is False

    def test_echo_back_honey(self):
        with mock.patch("tools.unauth_scan._sock_send", return_value=b"PING\r\n"):
            r = unauth_scan.check_redis("1.2.3.4", 6379)
        assert r["honey"] is True
        assert r["unauth"] is False


class TestMongo:
    def test_echo_back_honey(self):
        # 36-byte OP_REPLY header + echoed field name in the document.
        resp = (b"\x3a\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff"
                b"\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x10isMaster\x00\x01\x00\x00\x00\x00")
        with mock.patch("tools.unauth_scan._sock_send", return_value=resp):
            r = unauth_scan.check_mongo("1.2.3.4", 27017)
        assert r["honey"] is True
        assert r["unauth"] is False

    def test_anonymous_ok(self):
        resp = (b"\x3a\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff"
                b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x10ok\x00\x01\x00\x00\x00")
        with mock.patch("tools.unauth_scan._sock_send", return_value=resp):
            r = unauth_scan.check_mongo("1.2.3.4", 27017)
        assert r["unauth"] is True
        assert r["honey"] is False


class TestBatch:
    def test_filters_honeypots(self):
        def fake_redis(ip, port, timeout=5.0):
            return {"service": "redis", "ip": ip, "port": port,
                    "unauth": True, "honey": False, "version": "7.0"}

        def fake_mongo(ip, port, timeout=5.0):
            return {"service": "mongo", "ip": ip, "port": port,
                    "unauth": False, "honey": True}

        with mock.patch.dict(unauth_scan.CHECKERS, {
            "redis": fake_redis,
            "mongo": fake_mongo,
            "es": fake_redis,
            "mysql": fake_redis,
            "pg": fake_redis,
        }):
            r = unauth_scan.check(["1.2.3.4", "5.6.7.8"], services=["redis", "mongo"])
        assert r["scanned"] == 4
        assert r["vulnerable"] == 2
        assert len(r["honeypots"]) == 2
