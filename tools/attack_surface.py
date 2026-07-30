import re
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("attack_surface")

TECH_STACK_ATTACK_MAP = {
    "spring": {
        "detectors": ["ssti", "deser", "ssrf", "sql_injection"],
        "priority_modules": ["/actuator", "/swagger-resources"],
        "specific_checks": ["spel_injection", "actuator_health", "env_leak", "heapdump"],
        "risk": "critical",
        "vuln_types": ["SpEL Injection", "Actuator Leak", "Spring4Shell", "CVE-2022-22965"],
    },
    "wordpress": {
        "detectors": ["sql_injection", "xss", "lfi", "cmdi"],
        "priority_modules": ["wpscan", "/wp-admin"],
        "specific_checks": ["wp_user_enum", "timthumb_rce", "wp_json_leak", "plugin_version"],
        "risk": "high",
        "vuln_types": ["WP User Enum", "Plugin RCE", "SQLi via plugins", "XSS via themes"],
    },
    "django": {
        "detectors": ["sql_injection", "ssti", "ssrf", "xss"],
        "priority_modules": ["/admin", "csrf_token"],
        "specific_checks": ["debug_mode", "secret_key_leak", "ssti_django", "mass_assignment"],
        "risk": "high",
        "vuln_types": ["Debug Mode", "SECRET_KEY Leak", "SSTI", "Mass Assignment"],
    },
    "flask": {
        "detectors": ["ssti", "ssrf", "xss", "sql_injection"],
        "priority_modules": ["/console", "/config"],
        "specific_checks": ["ssti_jinja2", "werkzeug_debug", "secret_key_leak"],
        "risk": "high",
        "vuln_types": ["Jinja2 SSTI", "Werkzeug Console RCE", "Secret Key"],
    },
    "thinkphp": {
        "detectors": ["cmdi", "lfi", "sql_injection", "deser"],
        "priority_modules": ["/index.php"],
        "specific_checks": ["thinkphp_rce", "thinkphp_invoke_func"],
        "risk": "critical",
        "vuln_types": ["ThinkPHP RCE", "Invoke Function RCE"],
    },
    "laravel": {
        "detectors": ["sql_injection", "ssti", "deser", "ssrf"],
        "priority_modules": ["/_debugbar", "/_ignition"],
        "specific_checks": ["debugbar_leak", "ignition_rce", "app_key_leak", "mass_assignment"],
        "risk": "high",
        "vuln_types": ["Debugbar Leak", "Ignition RCE", "APP_KEY", "Mass Assignment"],
    },
    "iis": {
        "detectors": ["xss", "lfi", "ssrf", "sql_injection"],
        "priority_modules": ["/app_data", "/bin", "/web.config"],
        "specific_checks": ["iis_shortname", "webdav", "http_methods"],
        "risk": "medium",
        "vuln_types": ["Short Name Leak", "WebDAV", "PUT Upload"],
    },
    "tomcat": {
        "detectors": ["lfi", "ssrf", "deser", "cmdi"],
        "priority_modules": ["/manager", "/examples", "/host-manager"],
        "specific_checks": ["ghostcat", "manager_brute", "jmx_leak"],
        "risk": "high",
        "vuln_types": ["Ghostcat (AJP)", "Tomcat RCE", "Manager Brute"],
    },
    "weblogic": {
        "detectors": ["deser", "cmdi", "ssrf", "lfi"],
        "priority_modules": ["/_async", "/wls-wsat"],
        "specific_checks": ["weblogic_rce", "weblogic_deser", "iiop_leak"],
        "risk": "critical",
        "vuln_types": ["WebLogic RCE", "Deserialization", "IIOP Leak"],
    },
    "php": {
        "detectors": ["lfi", "cmdi", "sql_injection", "xss", "deser"],
        "priority_modules": ["/phpinfo.php", "/info.php"],
        "specific_checks": ["lfi_log_poison", "php_filter_chain", "php_deser", "upload_bypass"],
        "risk": "high",
        "vuln_types": ["LFI → RCE", "PHP Deserialization", "Filter Chain RCE"],
    },
    "nodejs": {
        "detectors": ["ssrf", "ssti", "xss", "lfi", "proto_pollution"],
        "priority_modules": ["/debug", "/__devtools"],
        "specific_checks": ["pp_rce", "node_ssti", "express_cookie_secret"],
        "risk": "high",
        "vuln_types": ["Prototype Pollution", "Node SSTI", "Cookie Secret"],
    },
    "express": {
        "detectors": ["ssrf", "xss", "lfi", "proto_pollution"],
        "priority_modules": ["/sitemap.xml"],
        "specific_checks": ["express_ssti", "session_token_leak", "helmet_missing"],
        "risk": "medium",
        "vuln_types": ["Session Token Weakness", "SSTI", "Security Header Missing"],
    },
    "asp.net": {
        "detectors": ["xss", "lfi", "sql_injection", "ssrf", "deser"],
        "priority_modules": ["/web.config", "/bin"],
        "specific_checks": ["viewstate_decrypt", "machine_key_check", "iis_shortname"],
        "risk": "high",
        "vuln_types": ["ViewState RCE", "MachineKey Brute", "IIS Short Name"],
    },
    "graphql": {
        "detectors": ["graphql", "auth_bypass", "biz_logic"],
        "priority_modules": ["/graphql", "/graphiql", "/playground"],
        "specific_checks": ["introspection", "graphql_batch", "graphql_depth", "graphql_auth"],
        "risk": "high",
        "vuln_types": ["Introspection", "Batch Attack", "Depth Attack", "AuthZ Bypass"],
    },
    "nginx": {
        "detectors": ["lfi", "ssrf", "xss"],
        "priority_modules": ["/", "/status"],
        "specific_checks": ["nginx_aliasing", "nginx_merge_slashes", "path_normalization"],
        "risk": "medium",
        "vuln_types": ["Aliasing Traversal", "Merge Slashes Bypass"],
    },
}

OPEN_PORT_ATTACK_MAP = {
    21: {"module": "ftp", "checks": ["anonymous_login", "ftp_brute"], "risk": "medium"},
    22: {"module": "ssh", "checks": ["ssh_banner", "ssh_auth_methods"], "risk": "low"},
    25: {"module": "smtp", "checks": ["smtp_enum", "open_relay"], "risk": "high"},
    53: {"module": "dns", "checks": ["zone_transfer", "dns_enum"], "risk": "medium"},
    80: {"module": "http", "checks": ["tech_fingerprint", "dir_fuzz"], "risk": "medium"},
    110: {"module": "pop3", "checks": ["pop3_banner"], "risk": "low"},
    111: {"module": "rpc", "checks": ["rpc_info"], "risk": "medium"},
    143: {"module": "imap", "checks": ["imap_banner"], "risk": "low"},
    389: {"module": "ldap", "checks": ["ldap_anonymous"], "risk": "high"},
    443: {"module": "https", "checks": ["tech_fingerprint", "dir_fuzz"], "risk": "medium"},
    445: {"module": "smb", "checks": ["smb_null_session", "smb_eternal_blue"], "risk": "critical"},
    500: {"module": "ike", "checks": ["ike_vpn_scan"], "risk": "medium"},
    636: {"module": "ldaps", "checks": ["ldap_anonymous"], "risk": "high"},
    993: {"module": "imaps", "checks": ["imap_banner"], "risk": "low"},
    995: {"module": "pop3s", "checks": ["pop3_banner"], "risk": "low"},
    1433: {"module": "mssql", "checks": ["mssql_null_auth", "mssql_sa_brute"], "risk": "critical"},
    1521: {"module": "oracle", "checks": ["oracle_tns_listener"], "risk": "high"},
    2049: {"module": "nfs", "checks": ["nfs_showmount"], "risk": "high"},
    2375: {"module": "docker", "checks": ["docker_noauth"], "risk": "critical"},
    2376: {"module": "docker_tls", "checks": ["docker_tls_bypass"], "risk": "critical"},
    3306: {"module": "mysql", "checks": ["mysql_noauth", "mysql_brute"], "risk": "high"},
    3389: {"module": "rdp", "checks": ["rdp_bluekeep_check"], "risk": "high"},
    5432: {"module": "postgres", "checks": ["postgres_noauth", "postgres_brute"], "risk": "high"},
    5555: {"module": "android_adb", "checks": ["adb_unauth"], "risk": "critical"},
    5900: {"module": "vnc", "checks": ["vnc_noauth"], "risk": "high"},
    5984: {"module": "couchdb", "checks": ["couchdb_noauth"], "risk": "high"},
    5985: {"module": "winrm_http", "checks": ["winrm_brute"], "risk": "high"},
    5986: {"module": "winrm_https", "checks": ["winrm_brute"], "risk": "high"},
    6379: {"module": "redis", "checks": ["redis_noauth"], "risk": "critical"},
    6443: {"module": "k8s_api", "checks": ["k8s_anonymous"], "risk": "critical"},
    7001: {"module": "weblogic", "checks": ["weblogic_rce"], "risk": "critical"},
    7070: {"module": "tomcat", "checks": ["tomcat_status"], "risk": "medium"},
    8000: {"module": "http_alt", "checks": ["tech_fingerprint", "dir_fuzz"], "risk": "medium"},
    8009: {"module": "ajp", "checks": ["ghostcat"], "risk": "high"},
    8080: {"module": "http_proxy", "checks": ["tech_fingerprint", "dir_fuzz"], "risk": "medium"},
    8090: {"module": "http_alt", "checks": ["tech_fingerprint"], "risk": "medium"},
    8161: {"module": "activemq", "checks": ["activemq_noauth"], "risk": "high"},
    8200: {"module": "vault", "checks": ["vault_noauth"], "risk": "critical"},
    8443: {"module": "https_alt", "checks": ["tech_fingerprint", "dir_fuzz"], "risk": "medium"},
    8500: {"module": "consul", "checks": ["consul_noauth"], "risk": "critical"},
    8686: {"module": "jmx", "checks": ["jmx_leak"], "risk": "high"},
    8761: {"module": "eureka", "checks": ["eureka_leak"], "risk": "high"},
    8888: {"module": "http_alt", "checks": ["tech_fingerprint", "dir_fuzz"], "risk": "medium"},
    9000: {"module": "hadoop", "checks": ["hadoop_noauth"], "risk": "high"},
    9090: {"module": "prometheus", "checks": ["prometheus_leak"], "risk": "medium"},
    9092: {"module": "kafka", "checks": ["kafka_produce"], "risk": "medium"},
    9100: {"module": "node_exporter", "checks": ["node_exp_leak"], "risk": "low"},
    9200: {"module": "elasticsearch", "checks": ["es_noauth"], "risk": "high"},
    9300: {"module": "es_transport", "checks": ["es_transport_rce"], "risk": "high"},
    9418: {"module": "git", "checks": ["git_daemon_leak"], "risk": "medium"},
    9999: {"module": "http_alt", "checks": ["tech_fingerprint"], "risk": "low"},
    10000: {"module": "webmin", "checks": ["webmin_rce"], "risk": "high"},
    11211: {"module": "memcached", "checks": ["memcached_stats"], "risk": "medium"},
    15672: {"module": "rabbitmq", "checks": ["rabbitmq_guest"], "risk": "high"},
    16379: {"module": "redis_alt", "checks": ["redis_noauth"], "risk": "critical"},
    27017: {"module": "mongodb", "checks": ["mongodb_noauth"], "risk": "critical"},
    28017: {"module": "mongodb_http", "checks": ["mongodb_status"], "risk": "medium"},
    50070: {"module": "hdfs", "checks": ["hdfs_list"], "risk": "high"},
    61616: {"module": "activemq_transport", "checks": ["activemq_rce"], "risk": "critical"},
}

DETECTOR_PRIORITY_BY_TECH = {
    "ssrf": ["spring", "flask", "nodejs", "express", "django", "asp.net", "graphql"],
    "ssti": ["spring", "flask", "django", "nodejs", "laravel"],
    "deser": ["java", "spring", "weblogic", "tomcat", "php", "asp.net"],
    "proto_pollution": ["nodejs", "express"],
    "lfi": ["php", "tomcat", "nginx", "iis", "asp.net"],
    "cmdi": ["thinkphp", "php", "iis", "tomcat"],
    "sqli": ["all"],
    "xss": ["all"],
    "biz_logic": ["graphql", "spring", "laravel"],
}


# ---------------------------------------------------------------------------
# CVE knowledge base — version-aware vulnerability lookup
# ---------------------------------------------------------------------------

TECH_CVE_DB: Dict[str, List[Dict]] = {
    "spring": [
        {"cve": "CVE-2022-22965", "range": (5, 6), "name": "Spring4Shell", "impact": "RCE", "cvss": 9.8},
        {"cve": "CVE-2022-22963", "range": (5, 6), "name": "SpEL RCE", "impact": "RCE", "cvss": 9.8},
        {"cve": "CVE-2022-22950", "range": (5, 6), "name": "DoS", "impact": "DoS", "cvss": 7.5},
        {"cve": "CVE-2023-20861", "range": (6, 7), "name": "Spring Boot Actuator Leak", "impact": "Info Leak", "cvss": 5.5},
    ],
    "tomcat": [
        {"cve": "CVE-2020-1938", "range": (6, 10), "name": "Ghostcat (AJP)", "impact": "LFI/RCE", "cvss": 9.8},
        {"cve": "CVE-2020-13935", "range": (9, 10), "name": "WebSocket DoS", "impact": "DoS", "cvss": 7.5},
        {"cve": "CVE-2021-42340", "range": (10, 11), "name": "Memory Leak", "impact": "Info Leak", "cvss": 7.5},
    ],
    "weblogic": [
        {"cve": "CVE-2017-10271", "range": (10, 13), "name": "WebLogic WLS RCE", "impact": "RCE", "cvss": 9.8},
        {"cve": "CVE-2020-14882", "range": (12, 15), "name": "WebLogic Console RCE", "impact": "RCE", "cvss": 9.8},
        {"cve": "CVE-2021-2109", "range": (12, 15), "name": "WebLogic JNDI RCE", "impact": "RCE", "cvss": 9.8},
    ],
    "thinkphp": [
        {"cve": "CVE-2018-20062", "range": (5, 6), "name": "ThinkPHP5 RCE", "impact": "RCE", "cvss": 9.8},
        {"cve": "CVE-2019-9082", "range": (5, 6), "name": "ThinkPHP5 Inject RCE", "impact": "RCE", "cvss": 9.8},
    ],
    "laravel": [
        {"cve": "CVE-2021-3129", "range": (8, 9), "name": "Laravel Ignition RCE", "impact": "RCE", "cvss": 9.8},
        {"cve": "CVE-2021-4359", "range": (8, 10), "name": "App Key Leak", "impact": "Info Leak", "cvss": 7.5},
    ],
    "wordpress": [
        {"cve": "ANY-PLUGIN", "range": (4, 7), "name": "Unpatched Plugin RCE", "impact": "RCE", "cvss": 9.8},
    ],
    "drupal": [
        {"cve": "CVE-2018-7600", "range": (7, 9), "name": "Drupalgeddon2", "impact": "RCE", "cvss": 9.8},
        {"cve": "CVE-2019-6341", "range": (8, 9), "name": "Drupal REST RCE", "impact": "RCE", "cvss": 9.8},
    ],
    "struts": [
        {"cve": "CVE-2017-5638", "range": (2, 3), "name": "Struts2 Content-Type RCE", "impact": "RCE", "cvss": 10.0},
        {"cve": "CVE-2017-9805", "range": (2, 3), "name": "Struts2 REST RCE", "impact": "RCE", "cvss": 9.8},
    ],
    "flask": [
        {"cve": "WERKZEUG-CONSOLE", "range": (0, 2), "name": "Werkzeug Console RCE", "impact": "RCE", "cvss": 9.8},
    ],
    "jenkins": [
        {"cve": "CVE-2019-1003000", "range": (2, 3), "name": "Jenkins RCE", "impact": "RCE", "cvss": 9.8},
    ],
}

EXPLOIT_AVAILABILITY: Dict[str, Dict] = {
    "CVE-2022-22965": {"public_poc": True, "difficulty": "easy", "type": "http_get"},
    "CVE-2020-1938": {"public_poc": True, "difficulty": "easy", "type": "ajp_protocol"},
    "CVE-2017-10271": {"public_poc": True, "difficulty": "easy", "type": "http_post_xml"},
    "CVE-2018-20062": {"public_poc": True, "difficulty": "easy", "type": "http_get"},
    "CVE-2018-7600": {"public_poc": True, "difficulty": "easy", "type": "http_post"},
}


def lookup_cves(tech_id: str, version_str: str = "") -> List[Dict]:
    if tech_id not in TECH_CVE_DB:
        return []
    version_match = re.search(r'(\d+)', version_str)
    major = int(version_match.group(1)) if version_match else 0
    hits = []
    for entry in TECH_CVE_DB[tech_id]:
        start, end = entry["range"]
        if start <= major <= end or not version_str:
            info = dict(entry)
            exploit = EXPLOIT_AVAILABILITY.get(entry["cve"], {})
            info["exploit_available"] = exploit.get("public_poc", False)
            info["difficulty"] = exploit.get("difficulty", "unknown")
            info["exploit_type"] = exploit.get("type", "unknown")
            hits.append(info)
    return hits


# ---------------------------------------------------------------------------
# Smart attack path ranking — considers CVE availability + exploit ease + impact
# ---------------------------------------------------------------------------

IMPACT_WEIGHTS = {"RCE": 10, "LFI/RCE": 9, "LFI": 8, "Data Exfil": 7,
                   "Auth Bypass": 6, "Info Leak": 4, "DoS": 3, "Priv Esc": 8}


def rank_attack_paths(techs: List[Dict], open_ports: List[Dict],
                       git_leak: Optional[Dict] = None) -> List[Dict]:
    paths = []
    for t in techs:
        tech_id = t.get("id", "").lower()
        version = t.get("version", "")
        cves = lookup_cves(tech_id, version)
        for cve in cves:
            weight = IMPACT_WEIGHTS.get(cve["impact"], 5)
            if cve.get("exploit_available"):
                weight *= 1.5
            if cve.get("difficulty") == "easy":
                weight *= 1.2
            paths.append({
                "type": "cve",
                "tech": tech_id,
                "cve": cve["cve"],
                "name": cve["name"],
                "impact": cve["impact"],
                "score": round(weight, 1),
                "exploit_type": cve.get("exploit_type", "manual"),
                "cvss": cve.get("cvss", 0),
            })

    for port_info in open_ports:
        port = port_info.get("port")
        if port in OPEN_PORT_ATTACK_MAP:
            entry = OPEN_PORT_ATTACK_MAP[port]
            risk = entry["risk"]
            weight = {"critical": 8, "high": 5, "medium": 3, "low": 1}.get(risk, 3)
            for check in entry["checks"]:
                paths.append({
                    "type": "open_port",
                    "port": port,
                    "module": entry["module"],
                    "check": check,
                    "score": weight,
                    "impact": "RCE" if risk == "critical" else "Access",
                })

    if git_leak and git_leak.get("git_exposed"):
        sensitive_count = len(git_leak.get("sensitive_finds", []))
        paths.append({
            "type": "git_leak",
            "score": min(7 + sensitive_count, 10),
            "impact": "Data Exfil",
            "sensitive_finds": sensitive_count,
        })

    paths.sort(key=lambda p: -p["score"])
    return paths


def visualize_attack_paths(paths: List[Dict]) -> str:
    if not paths:
        return "No attack paths identified."
    lines = ["Attack Path Ranking (by score):"]
    for i, p in enumerate(paths[:15]):
        prefix = {10: "[CRIT]", 9: "[CRIT]", 8: "[HIGH]", 7: "[HIGH]",
                  6: "[MED]", 5: "[MED]"}.get(int(p.get("score", 0)), "[LOW]")
        if p["type"] == "cve":
            lines.append(f"  {i+1}. {prefix} {p['cve']} ({p['name']}) — impact={p['impact']} score={p['score']} exploit={p['exploit_type']}")
        elif p["type"] == "open_port":
            lines.append(f"  {i+1}. {prefix} Port {p['port']} ({p['module']}) — {p['check']} score={p['score']}")
        elif p["type"] == "git_leak":
            lines.append(f"  {i+1}. {prefix} .git leak ({p['sensitive_finds']} sensitive files) score={p['score']}")
    return "\n".join(lines)


def _tech_id_from_tech(tech: Dict) -> str:
    return tech.get("id", "").lower()


def build_attack_plan(recon_results: Dict) -> Dict:
    plan = {
        "target": recon_results.get("target", ""),
        "phases": [],
        "recommended_detectors": [],
        "critical_paths": [],
        "risk_score": 0,
    }

    techs = recon_results.get("technologies", [])
    open_ports = recon_results.get("open_ports", [])
    recon_results.get("subdomains", [])
    git_leak = recon_results.get("git_leak", {})
    recon_results.get("directories", [])

    detected_tech_ids = set()
    for t in techs:
        tid = _tech_id_from_tech(t)
        detected_tech_ids.add(tid)
        if tid in TECH_STACK_ATTACK_MAP:
            entry = TECH_STACK_ATTACK_MAP[tid]
            plan["phases"].append({
                "phase": "tech_specific",
                "tech": tid,
                "risk": entry["risk"],
                "detectors": entry["detectors"],
                "priority_modules": entry["priority_modules"],
                "specific_checks": entry["specific_checks"],
                "vuln_types": entry["vuln_types"],
            })
            for d in entry["detectors"]:
                if d not in plan["recommended_detectors"]:
                    plan["recommended_detectors"].append(d)
            plan["critical_paths"].extend(entry["priority_modules"])

    for port_info in open_ports:
        port = port_info.get("port")
        if port in OPEN_PORT_ATTACK_MAP:
            entry = OPEN_PORT_ATTACK_MAP[port]
            plan["phases"].append({
                "phase": "open_port",
                "port": port,
                "module": entry["module"],
                "risk": entry["risk"],
                "checks": entry["checks"],
            })

    if git_leak.get("git_exposed"):
        plan["phases"].append({
            "phase": "git_leak",
            "risk": "critical",
            "detail": ".git directory exposed with %d sensitive finds" % len(git_leak.get("sensitive_finds", [])),
        })
        plan["risk_score"] += 10

    if not detected_tech_ids:
        plan["phases"].append({
            "phase": "generic",
            "detectors": ["sql_injection", "xss", "lfi", "ssrf", "cmdi", "ssti"],
            "strategy": "no tech detected, run broad scan",
        })
        plan["recommended_detectors"] = [
            "sql_injection", "xss", "lfi", "ssrf", "cmdi", "ssti",
            "cors", "jwt", "graphql", "nosqli", "proto_pollution",
        ]

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    plan["phases"].sort(key=lambda p: priority_order.get(p.get("risk", "low"), 4))

    score = 0
    for p in plan["phases"]:
        risk = p.get("risk", "low")
        if risk == "critical":
            score += 5
        elif risk == "high":
            score += 3
        elif risk == "medium":
            score += 1
    plan["risk_score"] += score

    plan["recommended_detectors"] = list(dict.fromkeys(plan["recommended_detectors"]))

    return plan


def pivot_on_intermediate_result(current_findings: Dict, current_plan: Dict) -> Dict:
    findings = current_findings.get("vulnerabilities", [])
    plan = dict(current_plan)
    new_phases = []

    for vuln in findings:
        vtype = vuln.get("type", "").lower()

        if vtype == "ssrf":
            new_phases.append({
                "phase": "ssrf_pivot",
                "trigger": "ssrf_detected",
                "actions": ["cloud_metadata", "internal_port_scan", "aws_cred_leak"],
                "risk": "critical",
            })
            if "ssrf_pwn" not in plan.get("recommended_detectors", []):
                plan.setdefault("recommended_detectors", []).append("ssrf_pwn")

        elif vtype == "jwt":
            new_phases.append({
                "phase": "jwt_pivot",
                "trigger": "jwt_found",
                "actions": ["alg_none", "weak_secret_crack", "kid_injection", "jku_injection"],
                "risk": "critical",
            })

        elif vtype in ("sql_injection", "sqli"):
            new_phases.append({
                "phase": "sqli_pivot",
                "trigger": "sqli_detected",
                "actions": ["data_extraction", "file_read", "os_shell", "sqlmap_chain"],
                "risk": "critical",
            })

        elif vtype == "lfi":
            new_phases.append({
                "phase": "lfi_pivot",
                "trigger": "lfi_detected",
                "actions": ["log_poison_rce", "php_filter_chain", "proc_self_environ"],
                "risk": "critical",
            })

        elif vtype == "deser":
            new_phases.append({
                "phase": "deser_pivot",
                "trigger": "deser_detected",
                "actions": ["ysoserial_chain", "rce_via_gadget"],
                "risk": "critical",
            })

        elif vtype in ("auth_bypass", "auth-bypass"):
            new_phases.append({
                "phase": "auth_pivot",
                "trigger": "auth_bypass_found",
                "actions": ["privilege_escalation", "admin_endpoint_access", "data_exfil"],
                "risk": "high",
            })

        elif vtype in ("graphql",):
            new_phases.append({
                "phase": "graphql_pivot",
                "trigger": "graphql_detected",
                "actions": ["introspection_deep", "batch_attack", "query_depth", "authz_bypass"],
                "risk": "high",
            })

    if new_phases:
        plan["phases"] = new_phases + plan["phases"]
        plan["pivoted"] = True

    return plan
