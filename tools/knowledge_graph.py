from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from tools.log_utils import get_logger

logger = get_logger("knowledge_graph")

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
VERSION_INF = (float("inf"), float("inf"), float("inf"))


def _parse_ver(s: str) -> Tuple[int, ...]:
    parts = s.split(".")
    out = []
    for p in parts:
        try:
            out.append(int(p))
        except ValueError:
            out.append(0)
    return tuple(out)


def _ver_in_range(ver: str, low: str, high: str) -> bool:
    try:
        v = _parse_ver(ver)
        return _parse_ver(low) <= v <= _parse_ver(high)
    except Exception:
        return False


VULN_TYPES = ["rce", "sqli", "ssrf", "lfi", "xss", "ssti", "deser",
              "cmdi", "auth_bypass", "info_disclosure", "privilege_escalation",
              "path_traversal", "xxe", "proto_pollution", "nosqli"]


@dataclass
class CVERecord:
    cve_id: str
    vuln_type: str
    severity: int
    technology: str
    versions_affected: List[Tuple[str, str]]
    detection: List[str]
    exploit_available: bool
    exploit_method: Optional[str] = None
    requires_condition: Optional[str] = None
    cve_url: Optional[str] = None
    description: str = ""


CVE_DATABASE: List[CVERecord] = [
    CVERecord("CVE-2022-22965", "rce", 0, "spring",
              [("5.0.0", "5.3.17")], ["/actuator", "Spring4Shell pattern"], True, "chain_ssrf_to_rce"),
    CVERecord("CVE-2022-22947", "rce", 0, "spring",
              [("3.1.0", "3.1.6"), ("3.0.0", "3.0.6")], ["/actuator/gateway"], True, "chain_ssrf_to_rce"),
    CVERecord("CVE-2018-1273", "rce", 0, "spring",
              [("4.0.0", "4.0.9"), ("5.0.0", "5.0.4"), ("5.1.0", "5.1.1")], ["/users{?q}"], True),
    CVERecord("CVE-2017-10271", "rce", 0, "weblogic",
              [("10.3.6", "10.3.6"), ("12.1.3", "12.2.1.2")], ["/wls-wsat"], True, "chain_deser_to_rce"),
    CVERecord("CVE-2020-14882", "rce", 0, "weblogic",
              [("10.3.6", "14.1.1")], ["/console/images/%2e%2e%2f"], True),
    CVERecord("CVE-2020-1938", "lfi", 0, "tomcat",
              [("6.0.0", "9.0.30")], ["8009/AJP open"], True, "chain_lfi_to_rce", "requires AJP port 8009"),
    CVERecord("CVE-2017-12617", "rce", 0, "tomcat",
              [("7.0.0", "7.0.80")], ["/examples", "PUT method allowed"], True),
    CVERecord("CVE-2021-3129", "rce", 0, "laravel",
              [("5.0.0", "8.99")], ["/_ignition"], True, "chain_lfi_to_rce", "requires debug mode"),
    CVERecord("SH-2022-01", "rce", 0, "thinkphp",
              [("5.0.0", "6.0.99")], ["/index.php?s=index/think"], True, "chain_lfi_to_rce"),
    CVERecord("CVE-2018-1000001", "cmdi", 0, "thinkphp",
              [("5.0.0", "5.0.23")], ["/index.php?s=/Index/index"], True),
    CVERecord("CVE-2022-22963", "rce", 0, "spring",
              [("3.0.0", "3.0.6")], ["/functionRouter"], True),
    CVERecord("CVE-2021-44228", "rce", 0, "log4j",
              [("2.0.0", "2.14.1")], ["${jndi:ldap:// pattern}"], True, "chain_ssrf_to_rce"),
    CVERecord("CVE-2021-45046", "rce", 0, "log4j",
              [("2.15.0", "2.16.0")], ["${jndi:ldap:// pattern}"], True),
    CVERecord("CVE-2019-17558", "rce", 0, "solr",
              [("8.2.0", "8.2.2")], ["/solr/{core}/config"], True),
    CVERecord("CVE-2019-0193", "rce", 0, "solr",
              [("8.1.0", "8.1.1")], ["/solr/{core}/dataimport"], True),
    CVERecord("CVE-2021-26084", "rce", 0, "confluence",
              [("6.0.0", "7.12.4")], ["/pages/doenterpagevariables.action"], True),
    CVERecord("CVE-2021-22986", "rce", 0, "f5_bigip",
              [("12.1.0", "16.0.1")], ["/mgmt/tm/util/bash"], True),
    CVERecord("CVE-2020-5902", "rce", 0, "f5_bigip",
              [("11.6.0", "15.1.0")], ["/tmui/login.jsp"], True),
    CVERecord("CVE-2021-21972", "rce", 0, "vsphere",
              [("6.5.0", "7.0.1")], ["/ui/vropspluginui/rest/services/uploadova"], True),
    CVERecord("CVE-2021-22005", "rce", 0, "vcenter",
              [("6.5.0", "7.0.2")], ["/analytics/telemetry/ph"], True),
    CVERecord("CVE-2019-2725", "rce", 0, "weblogic",
              [("10.3.6", "12.2.1.3")], ["/_async/AsyncResponseService"], True),
    CVERecord("CVE-2020-2551", "rce", 0, "weblogic",
              [("10.3.6", "14.1.1")], ["IIOP protocol"], True),
    CVERecord("CVE-2021-2109", "rce", 0, "weblogic",
              [("10.3.6", "14.1.1")], ["/console"], True),
    CVERecord("CVE-2019-0232", "rce", 0, "tomcat",
              [("7.0.0", "7.0.93"), ("8.0.0", "8.5.39"), ("9.0.0", "9.0.17")], ["CGI enabled"], True),
    CVERecord("CVE-2017-5638", "rce", 0, "struts2",
              [("2.0.0", "2.3.32"), ("2.5.0", "2.5.10.1")], ["Content-Type: ${...}"], True),
    CVERecord("CVE-2017-9805", "rce", 0, "struts2",
              [("2.5.0", "2.5.12")], ["/rest/..."], True),
    CVERecord("CVE-2017-9791", "ssti", 0, "struts2",
              [("2.0.0", "2.3.31")], ["OGNL injection"], True),
    CVERecord("CVE-2018-11776", "rce", 0, "struts2",
              [("2.3.0", "2.3.35"), ("2.5.0", "2.5.16")], ["/struts/..."], True),
    CVERecord("CVE-2019-0230", "rce", 0, "struts2",
              [("2.0.0", "2.5.22")], ["/struts/..."], True),
    CVERecord("CVE-2018-7600", "rce", 0, "drupal",
              [("6.0.0", "7.58"), ("8.0.0", "8.3.8"), ("8.4.0", "8.4.5"), ("8.5.0", "8.5.1")],
              ["/user/register", "/node/add"], True),
    CVERecord("CVE-2018-7602", "rce", 0, "drupal",
              [("7.0.0", "7.59"), ("8.5.0", "8.5.3"), ("8.6.0", "8.6.2")],
              ["/user/register", "/node/add"], True),
    CVERecord("CVE-2020-17530", "ssti", 0, "struts2",
              [("2.0.0", "2.5.25")], ["OGNL injection in tag attributes"], True),
    CVERecord("CVE-2022-26134", "rce", 0, "confluence",
              [("1.0.0", "7.18.2")], ["/${...}/pages/..."], True),
    CVERecord("CVE-2021-26855", "ssrf", 0, "exchange",
              [("2013.0.0", "2019.0.0")], ["/owa/...", "SSRF via X-Forwarded-For"], True),
    CVERecord("CVE-2021-27065", "rce", 0, "exchange",
              [("2013.0.0", "2019.0.0")], ["/ecp/..."], True, "chain_ssrf_to_rce"),
    CVERecord("CVE-2020-16875", "rce", 0, "exchange",
              [("2016.0.0", "2019.0.0")], ["/ecp/DLPPolicy"], True),
    CVERecord("CVE-2021-34473", "ssrf", 0, "exchange",
              [("2013.0.0", "2019.0.0")], ["/owa/..."], True),
    CVERecord("CVE-2020-1472", "rce", 0, "windows",
              [("6.0.0", "10.0.0")], ["ZeroLogon - Netlogon elevation"], True),
    CVERecord("CVE-2021-1675", "rce", 0, "windows",
              [("6.0.0", "10.0.0")], ["PrintNightmare - SpoolService"], True),
    CVERecord("CVE-2020-0796", "rce", 0, "windows",
              [("10.0.0", "10.0.19041")], ["SMBv3 compression"], True),
    CVERecord("CVE-2021-34527", "rce", 0, "windows",
              [("6.0.0", "10.0.0")], ["PrintNightmare - RpcAddPrinterDriver"], True),
    CVERecord("CVE-2019-0708", "rce", 0, "windows",
              [("6.1.0", "6.1.0"), ("6.0.0", "6.0.0"), ("5.1.0", "5.1.0"), ("5.0.0", "5.0.0")],
              ["Port 3389/RDP - BlueKeep"], True),
    CVERecord("CVE-2021-40444", "rce", 0, "windows",
              [("8.1.0", "10.0.0")], ["MSHTML remote code execution"], True),
    CVERecord("CVE-2022-30190", "rce", 0, "windows",
              [("10.0.0", "10.0.0")], ["Follina - MSDT RCE via Office"], True),
    CVERecord("CVE-2021-22204", "rce", 0, "gitlab",
              [("0.0.0", "13.9.6"), ("13.10.0", "13.10.3"), ("13.11.0", "13.11.4"), ("13.12.0", "13.12.1")],
              ["ExifTool RCE via upload"], True),
    CVERecord("CVE-2021-22205", "rce", 0, "gitlab",
              [("11.9.0", "13.10.3"), ("13.11.0", "13.11.3"), ("13.12.0", "13.12.1")],
              ["Upload validation RCE"], True),
    CVERecord("CVE-2021-22941", "rce", 0, "citrix",
              [("12.0.0", "13.0.0")], ["/vpn/../vpns/"], True),
    CVERecord("CVE-2022-27518", "rce", 0, "citrix",
              [("12.1.0", "13.0.0")], ["/gwtest/formssso"], True),
    CVERecord("CVE-2019-19781", "rce", 0, "citrix",
              [("10.5.0", "12.1.0")], ["/vpn/../vpns/cfg/smb.conf"], True),
    CVERecord("CVE-2020-2021", "rce", 0, "palo_alto",
              [("7.1.0", "9.1.0")], ["/php/ultimos_downloads.php"], True),
    CVERecord("CVE-2021-30563", "rce", 0, "chrome",
              [("90.0.0", "93.0.0")], ["V8 type confusion"], True),
    CVERecord("CVE-2020-16040", "rce", 0, "chrome",
              [("84.0.0", "87.0.0")], ["V8 insufficient data validation"], True),
    CVERecord("CVE-2021-21224", "rce", 0, "chrome",
              [("87.0.0", "90.0.0")], ["V8 type confusion in LoadElement"], True),
    CVERecord("CVE-2022-22978", "auth_bypass", 0, "spring",
              [("5.3.0", "5.3.17"), ("5.2.0", "5.2.19")],
              ["Regex bypass in security"], True),
    CVERecord("CVE-2020-5405", "lfi", 1, "spring",
              [("5.2.0", "5.2.3")], ["/..;/ path traversal"], True),
    CVERecord("CVE-2021-22118", "ssrf", 1, "spring",
              [("5.0.0", "5.3.0")], ["/oauth2-redirect.html"], True),
    CVERecord("CVE-2020-11991", "xxe", 1, "cocoon",
              [("2.0.0", "2.2.0")], ["XML upload XXE"], True),
    CVERecord("CVE-2019-12409", "rce", 0, "solr",
              [("8.1.0", "8.2.0")], ["/solr/{core}/config/jmx"], True),
    CVERecord("CVE-2020-13942", "rce", 0, "mongodb",
              [("4.0.0", "4.4.0")], ["/mongodb-linux-x86_64"], True),
    CVERecord("CVE-2021-22555", "rce", 0, "linux",
              [("5.0.0", "5.11.0")], ["Netfilter heap overflow"], True),
    CVERecord("CVE-2022-0847", "privilege_escalation", 0, "linux",
              [("5.10.0", "5.16.11")], ["DirtyPipe - /proc/self/fd/..."], True),
    CVERecord("CVE-2021-3493", "privilege_escalation", 0, "linux",
              [("5.0.0", "5.12.0")], ["OverlayFS LPE"], True),
    CVERecord("CVE-2021-4034", "privilege_escalation", 0, "linux",
              [("5.0.0", "5.10.0")], ["pkexec LPE"], True),
    CVERecord("CVE-2022-0185", "privilege_escalation", 0, "linux",
              [("5.0.0", "5.16.0")], ["Filesystem context LPE"], True),
    CVERecord("CVE-2021-3156", "privilege_escalation", 0, "linux",
              [("7.0.0", "8.28.0")], ["sudo Baron Samedit LPE"], True),
    CVERecord("CVE-2021-33909", "privilege_escalation", 0, "linux",
              [("3.0.0", "5.13.4")], ["seq_file LPE"], True),
    CVERecord("CVE-2022-23222", "privilege_escalation", 0, "linux",
              [("5.8.0", "5.16.0")], ["eBPF verifier LPE"], True),
    CVERecord("CVE-2020-8835", "privilege_escalation", 0, "linux",
              [("5.4.0", "5.5.0")], ["eBPF LPE"], True),
    CVERecord("CVE-2021-26708", "privilege_escalation", 0, "linux",
              [("5.5.0", "5.10.0")], ["AF_VSOCK LPE"], True),
    CVERecord("CVE-2019-18935", "rce", 0, "telerik",
              [("1.0.0", "2.0.0")], ["/Telerik.Web.UI.WebResource.axd"], True),
    CVERecord("CVE-2020-1147", "rce", 0, "sharepoint",
              [("2010.0.0", "2019.0.0")], ["/__ssrs/..."], True),
    CVERecord("CVE-2020-17087", "privilege_escalation", 0, "windows",
              [("10.0.0", "10.0.0")], ["Windows Kernel - cng.sys pool overflow"], True),
    CVERecord("CVE-2021-1732", "privilege_escalation", 0, "windows",
              [("10.0.0", "10.0.19041")], ["Win32k LPE"], True),
    CVERecord("CVE-2021-31979", "privilege_escalation", 0, "windows",
              [("10.0.0", "10.0.19042")], ["Win32k LPE"], True),
    CVERecord("CVE-2021-40449", "privilege_escalation", 0, "windows",
              [("10.0.0", "10.0.0")], ["Win32k LPE callbacks"], True),
    CVERecord("CVE-2022-22718", "rce", 0, "windows",
              [("8.1.0", "10.0.0")], ["Windows Print Spooler LPE"], True),
    CVERecord("CVE-2022-21999", "privilege_escalation", 0, "windows",
              [("10.0.0", "10.0.0")], ["Win32k LPE"], True),
    CVERecord("CVE-2020-0688", "rce", 0, "exchange",
              [("2016.0.0", "2019.0.0")], ["/ecp/..."], True),
    CVERecord("CVE-2020-17144", "rce", 0, "exchange",
              [("2010.0.0", "2019.0.0")], ["/ecp/..."], True),
    CVERecord("CVE-2021-26857", "rce", 0, "exchange",
              [("2013.0.0", "2019.0.0")], ["/ecp/..."], True),
    CVERecord("CVE-2021-26414", "rce", 0, "exchange",
              [("2013.0.0", "2019.0.0")], ["/ecp/..."], True),
    CVERecord("CVE-2020-19596", "rce", 0, "drupal",
              [("7.0.0", "7.39")], ["/user/password"], True),
    CVERecord("CVE-2020-13671", "rce", 0, "drupal",
              [("8.0.0", "9.0.0")], ["/admin/modules"], True),
    CVERecord("CVE-2021-22973", "rce", 0, "drupal",
              [("9.0.0", "9.1.8")], ["/user/register"], True),
    CVERecord("CVE-2022-25262", "rce", 0, "drupal",
              [("9.0.0", "9.3.11")], ["/admin/reports"], True),
    CVERecord("CVE-2021-29447", "xxe", 1, "wordpress",
              [("5.6.0", "5.7.1")], ["/wp-admin/...", "XXE via media upload"], True),
    CVERecord("CVE-2020-24186", "rce", 0, "wordpress",
              [("5.4.0", "5.4.0")], ["/wp-admin/admin-ajax.php"], True),
    CVERecord("CVE-2021-24235", "sqli", 1, "wordpress",
              [("1.0.0", "1.0.99")], ["/wp-admin/admin-ajax.php"], True),
    CVERecord("CVE-2022-21661", "sqli", 0, "wordpress",
              [("5.8.0", "5.8.2")], ["/wp-admin/edit.php"], True),
    CVERecord("CVE-2022-26114", "rce", 0, "thinkphp",
              [("6.0.0", "6.0.3")], ["/index.php/..."], True),
    CVERecord("CVE-2022-22980", "sqli", 1, "spring",
              [("5.3.0", "5.3.20")], ["MongoDB Reactive SQLi"], True),
]

TECH_TO_CVES: Dict[str, List[CVERecord]] = {}
for rec in CVE_DATABASE:
    TECH_TO_CVES.setdefault(rec.technology, []).append(rec)

PORT_TO_TECH = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 389: "ldap", 443: "https",
    445: "smb", 500: "ike", 636: "ldaps", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5555: "android_adb",
    5900: "vnc", 5984: "couchdb", 5985: "winrm", 5986: "winrm",
    6379: "redis", 6443: "k8s_api", 7001: "weblogic", 8009: "ajp",
    8161: "activemq", 8200: "vault", 8500: "consul", 8686: "jmx",
    8761: "eureka", 9090: "prometheus", 9092: "kafka", 9200: "elasticsearch",
    9300: "es_transport", 27017: "mongodb", 50070: "hdfs",
    61616: "activemq",
}

DEFENSE_TECH = [
    "cloudflare", "akamai", "cloudfront", "fastly", "imperva",
    "incapsula", "sucuri", "stackpath", "azion", "qrator",
    "aliyun_waf", "baidu_yunjiasu", "tencent_waf", "360_wangzhan",
    "chaitin_waf", "hws_waf", "webknight", "barracuda", "f5_bigip",
    "aws_waf", "azure_waf", "gcp_armor", "fortinet",
]

VULN_PRIORITY = {
    "rce": 0, "sqli": 0, "deser": 0, "cmdi": 0,
    "ssrf": 1, "lfi": 1, "ssti": 1, "privilege_escalation": 1,
    "xxe": 2, "auth_bypass": 2, "path_traversal": 2,
    "xss": 3, "nosqli": 3, "proto_pollution": 3,
    "info_disclosure": 4,
}

CHAIN_MAP = {
    "ssrf": ["ssrf_to_rce"], "lfi": ["lfi_to_rce"],
    "sqli": ["sqli_to_rce"], "xss": ["xss_to_hijack"],
    "deser": ["deser_to_rce"], "auth_bypass": ["auth_bypass_to_rce"],
}


class KnowledgeGraph:
    def __init__(self):
        self.cves = CVE_DATABASE
        self.tech_cves = TECH_TO_CVES
        self.port_tech = PORT_TO_TECH
        self.defense_tech = DEFENSE_TECH
        self.chains = CHAIN_MAP

    def get_cves_for_tech(self, tech: str, version: Optional[str] = None) -> List[CVERecord]:
        tech = tech.lower()
        matches = self.tech_cves.get(tech, [])
        if version:
            version = version.split("/")[0].strip("vV")
            return [c for c in matches if any(_ver_in_range(version, l, h) for l, h in c.versions_affected)]
        return matches

    def get_cves_for_ports(self, ports: List[int]) -> Dict[int, List[CVERecord]]:
        result = {}
        for p in ports:
            tech = self.port_tech.get(p)
            if tech:
                cves = self.get_cves_for_tech(tech)
                if cves:
                    result[p] = cves
        return result

    def get_cves_for_dirs(self, dirs: List[str]) -> List[Dict]:
        result = []
        for d in dirs:
            path = d.get("path", "") if isinstance(d, dict) else d
            for cve in self.cves:
                for det in cve.detection:
                    if det.lower() in path.lower():
                        result.append({"path": path, "cve": cve.cve_id, "vuln_type": cve.vuln_type,
                                       "severity": cve.severity})
                        break
        return result

    def find_attack_paths(self, techs: List[str], ports: List[int],
                           dirs: List[str]) -> List[Dict]:
        paths = []

        for tech in techs:
            cves = self.get_cves_for_tech(tech)
            for cve in cves:
                matched_detections = [d for d in cve.detection if any(
                    d.lower() in dir_path.lower() for dir_path in dirs
                )]
                path = {
                    "tech": tech,
                    "cve_id": cve.cve_id,
                    "vuln_type": cve.vuln_type,
                    "severity": SEVERITY.get(cve.vuln_type, 5) if not cve.severity else cve.severity,
                    "priority": VULN_PRIORITY.get(cve.vuln_type, 9),
                    "exploit_available": cve.exploit_available,
                    "exploit_method": cve.exploit_method,
                    "detection_matched": matched_detections,
                    "description": cve.description,
                }
                if cve.requires_condition:
                    path["condition"] = cve.requires_condition
                paths.append(path)

        for p in ports:
            tech = self.port_tech.get(p)
            if tech and tech not in techs:
                cves = self.get_cves_for_tech(tech)
                for cve in cves:
                    paths.append({
                        "tech": tech,
                        "cve_id": cve.cve_id,
                        "vuln_type": cve.vuln_type,
                        "severity": cve.severity,
                        "priority": VULN_PRIORITY.get(cve.vuln_type, 9),
                        "exploit_available": cve.exploit_available,
                        "exploit_method": cve.exploit_method,
                        "port": p,
                        "description": cve.description,
                    })

        paths.sort(key=lambda p: (p.get("priority", 9), p.get("severity", 5)))
        return paths

    def get_exploit_priority(self, vuln_type: str) -> int:
        return VULN_PRIORITY.get(vuln_type, 9)

    def get_tech_for_port(self, port: int) -> Optional[str]:
        return self.port_tech.get(port)

    def is_defense(self, tech: str) -> bool:
        return tech.lower() in self.defense_tech

    def suggest_chains_for_vuln(self, vuln_type: str) -> List[str]:
        return self.chains.get(vuln_type, [])

    def summarize_tech_risks(self, techs: List[str], version_hints: Optional[Dict[str, str]] = None) -> dict:
        risks = {}
        for tech in techs:
            tid = tech.get("id", "").lower() if isinstance(tech, dict) else tech.lower()
            ver = None
            if version_hints and tid in version_hints:
                ver = version_hints[tid]
            cves = self.get_cves_for_tech(tid, ver)
            if cves:
                risks[tid] = {
                    "total_cves": len(cves),
                    "critical_cves": sum(1 for c in cves if c.severity == 0),
                    "exploit_available": sum(1 for c in cves if c.exploit_available),
                    "top_cves": [c.cve_id for c in cves[:5]],
                }
        return risks


kg = KnowledgeGraph()
