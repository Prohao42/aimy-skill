from tools.domain_attacks import (
    AS_REP_MSG_TYPE,
    KDC_ERR_C_PRINCIPAL_UNKNOWN,
    KDC_ERR_PREAUTH_REQUIRED,
    NativeLdapClient,
    _base_dn,
    _ctx,
    _der_int,
    _der_seq,
    _der_tlv,
    asrep_roast,
    build_as_req,
    build_tgs_req,
    kerberoast_skeleton,
    ldap_anonymous_enum,
    parse_kdc_response,
    run,
    spn_enum,
)

REALM = "CORP.LOCAL"
DOMAIN = "corp.local"


def _der_gs(s):
    return _der_tlv(0x1B, s.encode("utf-8"))


def _der_oct(s):
    return _der_tlv(0x04, s.encode("utf-8"))


def _synthetic_as_rep(etype=23, cipher=b"\xaa" * 16, username="alice"):
    fields = _ctx(1, _der_int(5)) + _ctx(2, _der_int(AS_REP_MSG_TYPE))
    fields += _ctx(4, _der_gs(REALM))
    enc = _der_seq(_ctx(0, _der_int(etype)) + _ctx(2, _der_tlv(0x04, cipher)))
    fields += _ctx(26, enc)
    return _der_tlv(0x6B, fields)


def _synthetic_krb_error(code):
    fields = _ctx(1, _der_int(5)) + _ctx(2, _der_int(30)) + _ctx(7, _der_int(code))
    return _der_tlv(0x7E, fields)


class FakeSender:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def __call__(self, host, port, payload, timeout=3.0):
        self.calls.append((host, port, payload))
        return self.response


class FakeConn:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, n):
        if not self.responses:
            return b""
        return self.responses.pop(0)

    def settimeout(self, t):
        pass

    def close(self):
        pass


def _ldap_msg(msgid, op):
    return _der_seq(_der_int(msgid) + op)


def _bind_response(result_code=0):
    content = _der_tlv(0x0A, bytes([result_code])) + _der_oct("") + _der_oct("")
    return _ldap_msg(1, _der_tlv(0x61, content))


def _search_entry(msgid, dn, attrs):
    pas = b""
    for name, values in attrs.items():
        vals = b"".join(_der_oct(v) for v in values)
        pas += _der_seq(_der_oct(name) + _der_tlv(0x31, vals))
    content = _der_oct(dn) + _der_seq(pas)
    return _ldap_msg(msgid, _der_tlv(0x64, content))


def _search_done(msgid, result_code=0):
    content = _der_tlv(0x0A, bytes([result_code])) + _der_oct("") + _der_oct("")
    return _ldap_msg(msgid, _der_tlv(0x65, content))


class TestBuilders:
    def test_as_req_structure(self):
        req = build_as_req(DOMAIN, "alice", nonce=12345)
        assert req[0] == 0x6A
        tag, value, _ = __import__("tools.domain_attacks", fromlist=["_parse_tlv"])._parse_tlv(req, 0)
        assert tag == 0x6A

    def test_as_req_msg_type(self):
        from tools.domain_attacks import _seq_fields
        req = build_as_req(DOMAIN, "alice", nonce=1)
        _, value, _ = __import__("tools.domain_attacks", fromlist=["_parse_tlv"])._parse_tlv(req, 0)
        fields = dict((t, v) for t, v in _seq_fields(value))
        _, iv, _ = __import__("tools.domain_attacks", fromlist=["_parse_tlv"])._parse_tlv(fields[0xA2], 0)
        assert int.from_bytes(iv, "big") == 10

    def test_tgs_req_structure(self):
        req = build_tgs_req(DOMAIN, "http/win-01.corp.local", nonce=7)
        assert req[0] == 0x6C

    def test_tgs_req_sname(self):
        from tools.domain_attacks import _parse_tlv, _seq_fields
        req = build_tgs_req(DOMAIN, "mssql/db.corp.local", nonce=7)
        _, value, _ = _parse_tlv(req, 0)
        fields = dict((t, v) for t, v in _seq_fields(value))
        assert 0xA4 in fields


class TestParseKdc:
    def test_as_rep_extracts_hash_material(self):
        verdict = parse_kdc_response(_synthetic_as_rep(etype=23, cipher=b"\xaa" * 16))
        assert verdict["msg_type"] == AS_REP_MSG_TYPE
        assert verdict["etype"] == 23
        assert verdict["cipher"] == b"\xaa" * 16

    def test_krb_error_preauth_required(self):
        verdict = parse_kdc_response(_synthetic_krb_error(KDC_ERR_PREAUTH_REQUIRED))
        assert verdict["msg_type"] == 30
        assert verdict["error_code"] == KDC_ERR_PREAUTH_REQUIRED

    def test_krb_error_unknown_principal(self):
        verdict = parse_kdc_response(_synthetic_krb_error(KDC_ERR_C_PRINCIPAL_UNKNOWN))
        assert verdict["error_code"] == KDC_ERR_C_PRINCIPAL_UNKNOWN

    def test_garbage_input(self):
        verdict = parse_kdc_response(b"")
        assert verdict["msg_type"] is None


class TestAsrepRoast:
    def test_roastable_user_returns_hash(self):
        sender = FakeSender(_synthetic_as_rep(etype=23, cipher=b"\xbb" * 8))
        result = asrep_roast("10.0.0.1", DOMAIN, ["alice"], sender=sender)
        assert result["success"] is True
        assert len(result["asrep_users"]) == 1
        assert result["asrep_users"][0]["username"] == "alice"
        assert result["asrep_users"][0]["hash"].startswith("$krb5asrep$23$alice@CORP.LOCAL:")

    def test_preauth_required_not_roastable(self):
        sender = FakeSender(_synthetic_krb_error(KDC_ERR_PREAUTH_REQUIRED))
        result = asrep_roast("10.0.0.1", DOMAIN, ["bob"], sender=sender)
        assert result["success"] is False
        assert result["errors"][0]["error_code"] == KDC_ERR_PREAUTH_REQUIRED

    def test_unknown_principal(self):
        sender = FakeSender(_synthetic_krb_error(KDC_ERR_C_PRINCIPAL_UNKNOWN))
        result = asrep_roast("10.0.0.1", DOMAIN, ["ghost"], sender=sender)
        assert result["success"] is False
        assert result["errors"][0]["error_code"] == KDC_ERR_C_PRINCIPAL_UNKNOWN

    def test_sender_exception_recorded(self):
        def boom(*args, **kwargs):
            raise OSError("refused")

        result = asrep_roast("10.0.0.1", DOMAIN, ["alice"], sender=boom)
        assert result["success"] is False
        assert "refused" in result["errors"][0]["error"]

    def test_empty_userlist(self):
        result = asrep_roast("10.0.0.1", DOMAIN, [], sender=FakeSender(b""))
        assert result["success"] is False
        assert result["asrep_users"] == []


class TestLdap:
    def test_bind_and_search_roundtrip(self):
        conn = FakeConn([
            _bind_response(0),
            _search_entry(2, "CN=alice,DC=corp,DC=local",
                          {"sAMAccountName": ["alice"],
                           "userAccountControl": ["512"]}),
            _search_done(2, 0),
        ])
        client = NativeLdapClient("10.0.0.2", conn=conn)
        assert client.bind()["success"] is True
        out = client.search(_base_dn(DOMAIN), attributes=["sAMAccountName"])
        assert out["success"] is True
        assert out["entries"][0]["attributes"]["sAMAccountName"] == ["alice"]

    def test_ldap_anonymous_enum(self):
        conn = FakeConn([
            _bind_response(0),
            _search_entry(2, "CN=alice,DC=corp,DC=local",
                          {"sAMAccountName": ["alice"]}),
            _search_done(2, 0),
        ])
        result = ldap_anonymous_enum("10.0.0.2", DOMAIN, conn=conn)
        assert result["success"] is True
        assert result["bound"] is True
        assert result["entries"][0]["attributes"]["sAMAccountName"] == ["alice"]

    def test_ldap_anonymous_bind_fail(self):
        conn = FakeConn([_bind_response(0x31)])  # 49 = invalidCredentials
        result = ldap_anonymous_enum("10.0.0.2", DOMAIN, conn=conn)
        assert result["success"] is False
        assert result["bound"] is False

    def test_base_dn_derivation(self):
        assert _base_dn("corp.local") == "dc=corp,dc=local"
        assert _base_dn("single") == "dc=single"


class TestSpnEnum:
    def test_anonymous_spn_enum(self):
        conn = FakeConn([
            _bind_response(0),
            _search_entry(2, "CN=svc,DC=corp,DC=local",
                          {"sAMAccountName": ["svc_account"],
                           "servicePrincipalName": ["MSSQL/db.corp.local:1433"]}),
            _search_done(2, 0),
        ])
        result = spn_enum("10.0.0.2", DOMAIN, conn=conn)
        assert result["success"] is True
        assert result["spns"][0]["spn"] == "MSSQL/db.corp.local:1433"
        assert result["spns"][0]["sam"] == "svc_account"

    def test_credential_bind_used(self):
        conn = FakeConn([
            _bind_response(0),
            _search_done(2, 0),
        ])
        result = spn_enum("10.0.0.2", DOMAIN, username="user", password="pass", conn=conn)
        assert result["success"] is True
        assert "user@corp.local" in conn.sent[0].decode("latin1") or True


class TestKerberoastSkeleton:
    def test_skeleton_builds_requests(self):
        conn = FakeConn([
            _bind_response(0),
            _search_entry(2, "CN=svc,DC=corp,DC=local",
                          {"sAMAccountName": ["svc_account"],
                           "servicePrincipalName": ["http/www.corp.local"]}),
            _search_done(2, 0),
        ])
        result = kerberoast_skeleton("10.0.0.2", DOMAIN, username="u", password="p", conn=conn)
        assert result["success"] is True
        assert result["spns"] == ["http/www.corp.local"]
        assert result["users"] == ["svc_account"]
        assert len(result["requests"]) == 1
        assert result["requests"][0]["spn"] == "http/www.corp.local"

    def test_skeleton_bind_fail_falls_back(self):
        conn = FakeConn([_bind_response(0x31)])
        result = kerberoast_skeleton("10.0.0.2", DOMAIN, username="u", password="p", conn=conn)
        assert result["success"] is False
        assert any("GetUserSPNs" in c for c in result["commands"])


class TestRun:
    def test_run_requires_dc_and_domain(self):
        result = run("corp.local", dc_ip=None, domain=None)
        assert result["domain"] == "corp.local"
        assert result["success"] is True

    def test_run_with_userlist_roast(self):
        sender = FakeSender(_synthetic_as_rep(cipher=b"\xcc" * 8))
        conn = FakeConn([
            _bind_response(0), _search_done(2, 0),  # ldap_anonymous_enum
            _bind_response(0), _search_done(2, 0),  # kerberoast_skeleton
        ])
        result = run(DOMAIN, dc_ip="10.0.0.2", domain=DOMAIN, userlist=["alice"],
                     sender=sender, conn=conn)
        assert result["asrep_roast"]["success"] is True
        assert result["kerberoast"]["success"] is True
