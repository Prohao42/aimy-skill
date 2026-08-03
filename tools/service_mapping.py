"""Service banner -> known CVE / default credential mapping.

Subset scope: static mapping tables + a look-up that normalizes a service
banner to a family, extracts a version string, and returns (a) known CVEs whose
keywords appear in the banner (optionally constrained by a version window) and
(b) well-known default credentials. No exploit development.

Consumes recon.open_ports entries that carry ``service`` / ``banner`` fields
and produces a per-service mapping report with a risk rating.
"""
import re
from typing import Dict, List, Optional, Sequence

from tools.log_utils import get_logger

logger = get_logger("service_mapping")

SERVICE_FAMILIES: Dict[str, Sequence[str]] = {
    "ftp": ["ftp"], "ssh": ["ssh"], "telnet": ["telnet"],
    "smtp": ["smtp", "submission"], "pop3": ["pop3"], "imap": ["imap"],
    "dns": ["dns"], "ldap": ["ldap"], "smb": ["smb", "netbios", "microsoft-ds", "cifs"],
    "snmp": ["snmp"], "mysql": ["mysql", "mariadb"], "mssql": ["mssql", "ms-sql"],
    "oracle": ["oracle"], "postgres": ["postgres"], "redis": ["redis"],
    "memcached": ["memcached"], "mongodb": ["mongodb", "mongo"],
    "elasticsearch": ["elasticsearch", "elastic"], "kafka": ["kafka"],
    "couchdb": ["couchdb"], "influxdb": ["influxdb"], "prometheus": ["prometheus"],
    "splunk": ["splunk"], "rabbitmq": ["rabbitmq"], "activemq": ["activemq"],
    "weblogic": ["weblogic"], "tomcat": ["tomcat", "coyote"], "jenkins": ["jenkins"],
    "webmin": ["webmin"], "docker": ["docker"], "hbase": ["hbase"],
    "nfs": ["nfs"], "rpc": ["rpc", "statd"], "winrm": ["winrm"], "rdp": ["rdp"],
    "ajp": ["ajp"], "vnc": ["vnc"], "cassandra": ["cassandra"], "graphql": ["graphql"],
}

PORT_FAMILY: Dict[int, str] = {
    9200: "elasticsearch", 9300: "elasticsearch", 9092: "kafka",
    5984: "couchdb", 8086: "influxdb", 9090: "prometheus", 8089: "splunk",
    15672: "rabbitmq", 61616: "activemq", 8161: "activemq",
    7001: "weblogic", 7002: "weblogic", 8009: "ajp", 2375: "docker", 2376: "docker",
    4848: "glassfish", 7199: "cassandra", 9042: "cassandra", 50000: "jenkins",
    16010: "hbase", 2049: "nfs", 111: "rpc", 5985: "winrm", 5986: "winrm",
    3389: "rdp", 5900: "vnc", 5800: "vnc", 10000: "webmin",
}

DEFAULT_CREDS: Dict[str, List[Dict[str, str]]] = {
    "ftp": [{"user": "anonymous", "pass": "anonymous"},
            {"user": "admin", "pass": "admin"},
            {"user": "root", "pass": "root"}],
    "ssh": [{"user": "root", "pass": "root"},
            {"user": "admin", "pass": "admin"},
            {"user": "pi", "pass": "raspberry"}],
    "telnet": [{"user": "admin", "pass": "admin"},
               {"user": "root", "pass": "root"}],
    "mysql": [{"user": "root", "pass": ""},
              {"user": "root", "pass": "root"},
              {"user": "root", "pass": "password"}],
    "mssql": [{"user": "sa", "pass": "sa"},
              {"user": "sa", "pass": "password"}],
    "oracle": [{"user": "system", "pass": "oracle"},
               {"user": "sys", "pass": "oracle"}],
    "postgres": [{"user": "postgres", "pass": "postgres"},
                 {"user": "postgres", "pass": ""}],
    "redis": [{"user": "", "pass": ""}],
    "snmp": [{"user": "community", "pass": "public"},
             {"user": "community", "pass": "private"}],
    "smb": [{"user": "guest", "pass": ""}],
    "mongodb": [{"user": "", "pass": ""}],
    "memcached": [{"user": "", "pass": ""}],
    "rabbitmq": [{"user": "guest", "pass": "guest"}],
    "activemq": [{"user": "admin", "pass": "admin"}],
    "weblogic": [{"user": "weblogic", "pass": "weblogic"},
                 {"user": "weblogic", "pass": "welcome1"}],
    "tomcat": [{"user": "tomcat", "pass": "tomcat"},
               {"user": "admin", "pass": "admin"},
               {"user": "admin", "pass": "password"}],
    "jenkins": [{"user": "admin", "pass": "admin"}],
    "couchdb": [{"user": "admin", "pass": "admin"}],
    "influxdb": [{"user": "admin", "pass": "admin"}],
    "splunk": [{"user": "admin", "pass": "changeme"}],
    "webmin": [{"user": "admin", "pass": "admin"},
               {"user": "root", "pass": "root"}],
    "cassandra": [{"user": "cassandra", "pass": "cassandra"}],
}

_RISK = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}

SERVICE_CVES: Dict[str, List[Dict]] = {
    "ftp": [
        {"cve": "CVE-2011-2523", "desc": "vsftpd 2.3.4 backdoor", "risk": "critical",
         "match": ["vsftpd 2.3.4"]},
        {"cve": "CVE-2015-3306", "desc": "ProFTPD mod_copy CPFR/CPTO RCE", "risk": "critical",
         "match": ["proftpd"]},
    ],
    "ssh": [
        {"cve": "CVE-2023-48795", "desc": "Terrapin prefix truncation", "risk": "medium",
         "match": ["openssh", "libssh"], "versions": (None, "9.5")},
        {"cve": "CVE-2016-20012", "desc": "libssh pre-auth memory DoS", "risk": "medium",
         "match": ["libssh"], "versions": (None, "0.8.1")},
    ],
    "smb": [
        {"cve": "CVE-2017-0144", "desc": "EternalBlue SMB RCE", "risk": "critical",
         "match": ["samba"]},
        {"cve": "2020-0796", "desc": "SMBGhost compression RCE", "risk": "critical",
         "match": ["srv.sys", "windows"]},
    ],
    "redis": [
        {"cve": "CVE-2022-0543", "desc": "Lua sandbox escape RCE", "risk": "critical",
         "match": ["redis"]},
        {"cve": "CVE-2021-32761", "desc": "open redirect to cross-site", "risk": "low",
         "match": ["redis"]},
    ],
    "mysql": [
        {"cve": "CVE-2012-2122", "desc": "auth bypass by repeated handshake", "risk": "critical",
         "match": ["mysql", "mariadb"], "versions": (None, "5.5.51")},
    ],
    "mssql": [
        {"cve": "CVE-2019-1402", "desc": "Extended Procedure elevation", "risk": "high",
         "match": ["microsoft sql"]},
    ],
    "postgres": [
        {"cve": "CVE-2018-1058", "desc": "search_path privilege escalation", "risk": "high",
         "match": ["postgresql"]},
        {"cve": "CVE-2019-10130", "desc": "arbitrary write via select privilege", "risk": "high",
         "match": ["postgresql"]},
    ],
    "memcached": [
        {"cve": "CVE-2016-8704", "desc": "memcached buffer overflow", "risk": "critical",
         "match": ["memcached"], "versions": (None, "1.4.32")},
        {"cve": "CVE-2016-8705", "desc": "SASL buffer overflow", "risk": "critical",
         "match": ["memcached"], "versions": (None, "1.4.32")},
    ],
    "mongodb": [
        {"cve": "CVE-2017-14399", "desc": "auth bypass via crafted createUser", "risk": "high",
         "match": ["mongodb"]},
    ],
    "elasticsearch": [
        {"cve": "CVE-2014-3120", "desc": "dynamic scripting RCE (MVEL)", "risk": "critical",
         "match": ["elasticsearch"], "versions": (None, "1.2.0")},
        {"cve": "CVE-2015-1427", "desc": "Groovy scripting sandbox RCE", "risk": "critical",
         "match": ["elasticsearch"], "versions": (None, "1.4.3")},
    ],
    "docker": [
        {"cve": "CVE-2017-17064", "desc": "daemon TCP exposed / unauthenticated API", "risk": "critical",
         "match": ["docker"]},
    ],
    "weblogic": [
        {"cve": "CVE-2020-14882", "desc": "console RCE", "risk": "critical",
         "match": ["weblogic"]},
        {"cve": "CVE-2019-2725", "desc": "wls9-async deserialization RCE", "risk": "critical",
         "match": ["weblogic"]},
        {"cve": "CVE-2023-21839", "desc": "IIOP/T3 deserialization RCE", "risk": "critical",
         "match": ["weblogic"]},
    ],
    "tomcat": [
        {"cve": "CVE-2017-12615", "desc": "PUT JSP upload RCE", "risk": "critical",
         "match": ["tomcat"], "versions": (None, "8.5.12")},
        {"cve": "CVE-2020-1938", "desc": "Ghostcat AJP file read/RCE", "risk": "critical",
         "match": ["coyote", "tomcat"]},
    ],
    "jenkins": [
        {"cve": "CVE-2017-1000353", "desc": "classloader deserialization RCE", "risk": "critical",
         "match": ["jenkins"], "versions": (None, "2.56")},
    ],
    "splunk": [
        {"cve": "CVE-2018-11409", "desc": "remote code execution", "risk": "critical",
         "match": ["splunk"]},
    ],
    "couchdb": [
        {"cve": "CVE-2017-12635", "desc": "admin auth bypass (json key dup)", "risk": "critical",
         "match": ["couchdb"], "versions": (None, "1.7.1")},
        {"cve": "CVE-2017-12636", "desc": "config write RCE", "risk": "critical",
         "match": ["couchdb"], "versions": (None, "1.7.1")},
    ],
    "influxdb": [
        {"cve": "CVE-2019-20933", "desc": "unauthenticated JWT bypass", "risk": "high",
         "match": ["influxdb"], "versions": (None, "1.7.9")},
    ],
    "rabbitmq": [
        {"cve": "CVE-2019-18609", "desc": "management UI SSRF", "risk": "medium",
         "match": ["rabbitmq"], "versions": (None, "3.7.17")},
    ],
    "activemq": [
        {"cve": "CVE-2015-5254", "desc": "deserialization RCE", "risk": "critical",
         "match": ["activemq"], "versions": (None, "5.13.1")},
        {"cve": "CVE-2016-3088", "desc": "put/read file upload RCE", "risk": "critical",
         "match": ["activemq"], "versions": (None, "5.14.0")},
    ],
    "webmin": [
        {"cve": "CVE-2019-15107", "desc": "password reset backdoor RCE", "risk": "critical",
         "match": ["webmin"], "versions": (None, "1.930")},
    ],
    "hbase": [
        {"cve": "CVE-2015-1857", "desc": "Thrift RPC RCE", "risk": "critical",
         "match": ["hbase"]},
    ],
}


def map_family(service: str, port: int = 0, banner: str = "") -> str:
    s = (service or "").lower()
    for family, keywords in SERVICE_FAMILIES.items():
        if any(k in s for k in keywords):
            return family
    if banner:
        b = banner.lower()
        for family, keywords in SERVICE_FAMILIES.items():
            if any(k in b for k in keywords):
                return family
    if port in PORT_FAMILY:
        return PORT_FAMILY[port]
    return "generic"


def extract_version(banner: str) -> str:
    if not banner:
        return ""
    matches = re.findall(r"(\d+\.\d+(?:\.\d+)?(?:[.\-_]?[prc]?\d+)?)", banner)
    return matches[-1] if matches else ""


def _ver_tuple(version: str) -> tuple:
    parts = re.findall(r"\d+", version or "")
    return tuple(int(p) for p in parts)


def _version_in_window(version: str, window: Optional[tuple]) -> bool:
    if not window:
        return True
    if not version:
        return True
    v = _ver_tuple(version)
    lo, hi = window
    if lo and v < _ver_tuple(lo):
        return False
    if hi and v > _ver_tuple(hi):
        return False
    return True


def match_cves(service: str, banner: str = "", version: str = "",
               port: int = 0) -> List[Dict]:
    if not version:
        version = extract_version(banner)
    family = map_family(service, port, banner)
    if family not in SERVICE_CVES:
        return []
    haystack = "%s %s" % (service or "", banner or "")
    out = []
    for entry in SERVICE_CVES[family]:
        if any(m.lower() in haystack.lower() for m in entry.get("match", [family])):
            if _version_in_window(version, entry.get("versions")):
                out.append({
                    "cve": entry["cve"], "desc": entry["desc"],
                    "risk": entry["risk"], "family": family,
                })
    return out


def default_creds(service: str, port: int = 0, banner: str = "") -> List[Dict]:
    family = map_family(service, port, banner)
    return DEFAULT_CREDS.get(family, [])


def map_service(service: str, banner: str = "", version: str = "",
                port: int = 0) -> Dict:
    if not version:
        version = extract_version(banner)
    family = map_family(service, port, banner)
    cves = match_cves(service, banner, version, port)
    creds = default_creds(service, port, banner)
    risk = "low"
    if cves:
        risk = max((_RISK.get(c["risk"], 0.2) for c in cves), default=0.2)
        risk = next((r for r, v in sorted(_RISK.items(), key=lambda x: -x[1])
                     if _RISK[r] == risk), "medium")
    return {
        "service": service, "family": family, "port": port,
        "banner": (banner or "")[:200], "version": version,
        "cves": cves, "default_credentials": creds,
        "risk": risk,
    }


def map_open_ports(state: Dict) -> Dict:
    recon = (state.get("phases") or {}).get("recon", {})
    data = recon.get("open_ports", {})
    if isinstance(data, dict):
        data = data.get("open_ports", [])
    rows = []
    for p in data:
        if not isinstance(p, dict):
            continue
        svc = str(p.get("service") or "")
        if not svc:
            continue
        rows.append(map_service(svc, str(p.get("banner") or ""),
                                port=int(p.get("port") or 0)))
    return {
        "mapped": len(rows),
        "with_cves": sum(1 for r in rows if r["cves"]),
        "with_default_creds": sum(1 for r in rows if r["default_credentials"]),
        "services": rows,
    }
