import re, json
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field

from tools.log_utils import get_logger
from tools.knowledge_graph import kg as _kg
from tools.attack_tree import AttackTree, AttackTreeNode

logger = get_logger("reasoning")

TECH_PRIORITY = {
    "spring": 1, "weblogic": 1, "thinkphp": 1, "php": 2,
    "wordpress": 2, "tomcat": 2, "laravel": 2, "django": 2,
    "flask": 3, "nodejs": 3, "express": 3, "asp.net": 2,
    "graphql": 2, "nginx": 4, "iis": 4,
}

PORT_CRITICAL = {21, 25, 389, 445, 1433, 1521, 2049, 2375, 2376, 3306,
                 3389, 5432, 5555, 5900, 5984, 6379, 6443, 7001, 8161,
                 8200, 8500, 8686, 8761, 9200, 27017, 50070, 61616}


@dataclass
class Hypothesis:
    vuln_type: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    suggested_detector: Optional[str] = None
    suggested_chain: Optional[str] = None
    priority: int = 5
    param: Optional[str] = None
    endpoint: Optional[str] = None
    detail: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "vuln_type": self.vuln_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "suggested_detector": self.suggested_detector,
            "suggested_chain": self.suggested_chain,
            "priority": self.priority,
            "param": self.param,
            "endpoint": self.endpoint,
            "detail": self.detail,
        }


class ReasoningEngine:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.bayesian_likelihoods = {
            "rce": 0.95, "sqli": 0.90, "cmdi": 0.88, "deser": 0.85,
            "ssrf": 0.82, "lfi": 0.80, "ssti": 0.75, "xss": 0.70,
            "nosqli": 0.65, "auth_bypass": 0.60, "jwt_exploit": 0.55,
            "proto_pollution": 0.50, "xxe": 0.50, "biz_logic": 0.45,
            "info_disclosure": 0.40, "graphql_abuse": 0.35,
        }
        self.prior_map: Dict[str, List[Hypothesis]] = {}

    def update_with_evidence(self, hypotheses: List[Hypothesis],
                              evidence: Dict[str, Dict]) -> List[Hypothesis]:
        updated = []
        for h in hypotheses:
            vt = h.vuln_type
            likelihood = self.bayesian_likelihoods.get(vt, 0.5)
            prior = h.confidence

            if vt in evidence:
                ev = evidence[vt]
                confirmed = ev.get("vulnerable") or ev.get("total_bypasses", 0) > 0
                if confirmed:
                    posterior = (prior * likelihood) / (prior * likelihood + (1 - prior) * (1 - likelihood))
                    h.confidence = min(posterior * 1.05, 0.99)
                    h.evidence.append("Confirmed by detector with %.0f%% likelihood" % (likelihood * 100))
                else:
                    false_pos = 1.0 - likelihood
                    posterior = (prior * false_pos) / (prior * false_pos + (1 - prior) * likelihood)
                    h.confidence = max(posterior * 0.95, 0.01)
                    h.evidence.append("Detector ran but no finding (fpr=%.0f%%)" % (false_pos * 100))
            else:
                h.confidence *= 0.98

            if h.suggested_chain and h.confidence > 0.60:
                h.priority = min(h.priority, 0)

            updated.append(h)

        return updated

    def update_from_findings(self, hypotheses: List[Hypothesis],
                              findings: Dict[str, Dict]) -> List[Hypothesis]:
        evidence_map = {}
        for key, f in findings.items():
            vt = f.get("type", "").lower()
            evidence_map[vt] = f.get("result", f)
        return self.update_with_evidence(hypotheses, evidence_map)

    def analyze(self, context: Dict) -> List[Hypothesis]:
        hypotheses: List[Hypothesis] = []

        techs = context.get("technologies", [])
        tech_ids = [t.get("id", "").lower() for t in techs]
        tech_names = [t.get("name", "").lower() for t in techs]
        all_techs = tech_ids + tech_names

        ports = [p.get("port") for p in context.get("open_ports", [])]
        port_data = context.get("open_ports", [])

        dirs = [d.get("path", "") for d in context.get("directories", [])]
        dir_full = context.get("directories", [])

        git = context.get("git_leak", {})
        existing_vulns = context.get("vulnerabilities", [])
        existing_types = {v.get("type", "").lower() for v in existing_vulns}
        crawled_endpoints = context.get("crawl_endpoints", {})
        plan = context.get("attack_plan", {})

        for rule in self._all_rules(target=self.target, all_techs=all_techs,
                                    ports=ports, port_data=port_data,
                                    dirs=dirs, dir_full=dir_full,
                                    git=git, existing_vulns=existing_vulns,
                                    existing_types=existing_types,
                                    crawled_endpoints=crawled_endpoints,
                                    plan=plan):
            h = rule()
            if h is not None:
                hypotheses.append(h)

        existing_vuln_types = set()
        for v in existing_vulns:
            existing_vuln_types.add(v.get("type", "").lower())
            existing_vuln_types.add(v.get("result", {}).get("type", "").lower())

        hypotheses.sort(key=lambda h: (h.priority, -h.confidence))
        return hypotheses

    def build_attack_tree(self, context: Dict) -> AttackTree:
        """Build hierarchical attack tree from recon context."""
        tree = AttackTree()

        techs = context.get("technologies", [])
        tech_ids = [t.get("id", "").lower() for t in techs]
        tech_names = [t.get("name", "").lower() for t in techs]

        ports = [p.get("port") for p in context.get("open_ports", [])]
        dirs = [d.get("path", "") for d in context.get("directories", [])]
        vulns = context.get("vulnerabilities", [])

        tree.build_from_recon(
            technologies=tech_ids + tech_names,
            open_ports=ports,
            directories=dirs,
            vulns=vulns,
        )

        hypotheses = context.get("hypotheses")
        if hypotheses:
            for h in hypotheses:
                for nid, node in tree.nodes.items():
                    if node.vuln_type == h.vuln_type and not node.verified:
                        node.confidence = max(node.confidence, h.confidence)

            tree.propagate()

        return tree

    def best_attack_paths(self, tree: AttackTree,
                           min_confidence: float = 0.20) -> List[dict]:
        """Get ranked attack paths from the tree."""
        return tree.best_paths(min_confidence=min_confidence)

    def correlate_hypotheses(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        """Detect and merge dependent/correlated hypotheses.

        If two hypotheses share the same param or endpoint and are of related types,
        their confidences should be partially merged (they aren't independent events).

        Examples:
          - SSRF + LFI on same ?url= param → likely the same root cause, not independent
          - SQLi + LFI → INTO OUTFILE RCE chain
          - XSS + auth_bypass → account takeover
        """
        merged = {}
        param_map = {}
        endpoint_map = {}

        for h in hypotheses:
            key = h.vuln_type
            if h.param:
                param_map.setdefault(h.param, []).append(h)
            if h.endpoint:
                endpoint_map.setdefault(h.endpoint, []).append(h)

        for _, group in param_map.items():
            if len(group) < 2:
                continue
            types = [g.vuln_type for g in group]
            if "ssrf" in types and "lfi" in types:
                for g in group:
                    if g.vuln_type == "ssrf":
                        g.confidence = min(g.confidence * 1.10, 0.95)
                        g.evidence.append("Correlated: same param has LFI surface")
                    elif g.vuln_type == "lfi":
                        g.evidence.append("Correlated: same param has SSRF surface")
            if "xss" in types and ("auth_bypass" in types or "privilege_escalation" in types):
                for g in group:
                    if g.vuln_type == "xss":
                        g.confidence = min(g.confidence * 1.15, 0.95)
                        g.evidence.append("Correlated: XSS + auth gap on same param")

        for _, group in endpoint_map.items():
            if len(group) < 2:
                continue
            types = [g.vuln_type for g in group]
            if "sqli" in types and "lfi" in types:
                for source in group:
                    if source.vuln_type == "sqli":
                        merge = Hypothesis(
                            vuln_type="rce",
                            confidence=min(
                                source.confidence * 0.80, 0.85),
                            evidence=["SQLi + LFI on same endpoint → MySQL INTO OUTFILE RCE"],
                            suggested_chain="sqli_to_rce",
                            priority=0,
                            endpoint=source.endpoint,
                            param=source.param,
                        )
                        merged["sqli+lfi_rce"] = merge

        result = list(hypotheses)
        result.extend(merged.values())
        result.sort(key=lambda h: (h.priority, -h.confidence))
        return result

    def suggest_detectors(self, hypotheses: List[Hypothesis]) -> List[str]:
        seen = set()
        ordered = []
        for h in hypotheses:
            d = h.suggested_detector
            if d and d not in seen:
                seen.add(d)
                ordered.append(d)
        return ordered

    def suggest_chains(self, hypotheses: List[Hypothesis],
                       confirmed_types: set) -> List[Tuple[str, str, str]]:
        chains = []
        seen = set()
        for h in hypotheses:
            c = h.suggested_chain
            if c and c not in seen and h.vuln_type in confirmed_types:
                seen.add(c)
                chains.append((c, h.endpoint or "", h.param or ""))
        return chains

    def score_endpoint(self, param_name: str, techs: List[str]) -> float:
        name = param_name.lower()
        tech_set = set(t.lower() for t in techs)

        high_value = {
            "file", "path", "page", "include", "template", "document",
            "cmd", "command", "exec", "run", "ping", "nslookup",
            "url", "host", "target", "redirect", "next", "callback",
            "token", "jwt", "api_key", "secret", "password", "key",
            "sql", "query", "id", "uid", "user_id", "order", "sort",
            "email", "user", "username", "login", "pass",
        }
        if name in high_value:
            return 0.9

        for prefix in ("file_", "path_", "url_", "api_", "user_", "token_"):
            if name.startswith(prefix):
                return 0.7

        for kw in ("name", "title", "desc", "category", "type", "status", "role", "group"):
            if kw in name:
                return 0.4

        if any(t in tech_set for t in ("spring", "php", "wordpress", "laravel", "thinkphp")):
            return 0.3

        return 0.1

    def _all_rules(self, **ctx) -> List[Callable[[], Optional[Hypothesis]]]:
        rules = []

        rules.append(lambda: _rule_spring_actuator(**ctx))
        rules.append(lambda: _rule_php_lfi(**ctx))
        rules.append(lambda: _rule_graphql(**ctx))
        rules.append(lambda: _rule_jwt_found(**ctx))
        rules.append(lambda: _rule_cloud_ssrf(**ctx))
        rules.append(lambda: _rule_redis_noauth(**ctx))
        rules.append(lambda: _rule_mysql_exposed(**ctx))
        rules.append(lambda: _rule_docker_exposed(**ctx))
        rules.append(lambda: _rule_git_exposed(**ctx))
        rules.append(lambda: _rule_debugbar_leak(**ctx))
        rules.append(lambda: _rule_admin_panel(**ctx))
        rules.append(lambda: _rule_swagger_exposed(**ctx))
        rules.append(lambda: _rule_phpmyadmin(**ctx))
        rules.append(lambda: _rule_weblogic(**ctx))
        rules.append(lambda: _rule_thinkphp_rce(**ctx))
        rules.append(lambda: _rule_wordpress_wpadmin(**ctx))
        rules.append(lambda: _rule_elasticsearch_noauth(**ctx))
        rules.append(lambda: _rule_spring_cloud_gateway(**ctx))
        rules.append(lambda: _rule_ssrf_internal_es(**ctx))
        rules.append(lambda: _rule_sqli_and_lfi_composite(**ctx))
        rules.append(lambda: _rule_deser_php_gadget(**ctx))
        rules.append(lambda: _rule_xss_sensitive_form(**ctx))
        rules.append(lambda: _rule_proto_pollution(**ctx))
        rules.append(lambda: _rule_nosqli_express(**ctx))
        rules.append(lambda: _rule_tomcat_manager(**ctx))
        rules.append(lambda: _rule_jenkins(**ctx))
        rules.append(lambda: _rule_k8s_api(**ctx))
        rules.append(lambda: _rule_nfs_exposed(**ctx))
        rules.append(lambda: _rule_ldap_anonymous(**ctx))
        rules.append(lambda: _rule_winrm_exposed(**ctx))
        rules.append(lambda: _rule_cve_database(**ctx))

        return rules


def _has_tech(all_techs: List[str], name: str) -> bool:
    return any(name in t for t in all_techs)


def _has_dir(dirs: List[str], pattern: str) -> bool:
    return any(pattern in d for d in dirs)


def _dir_detail(dir_full: List[Dict], pattern: str) -> Optional[Dict]:
    for d in dir_full:
        if pattern in d.get("path", ""):
            return d
    return None


def _has_port(ports: List[int], port: int) -> bool:
    return port in ports


def _has_vuln(existing_types: set, vtype: str) -> bool:
    return vtype in existing_types


def _rule_spring_actuator(**ctx) -> Optional[Hypothesis]:
    if not _has_tech(ctx["all_techs"], "spring"):
        return None
    env_leak = _dir_detail(ctx["dir_full"], "/actuator/env")
    heapdump = _dir_detail(ctx["dir_full"], "/actuator/heapdump")
    if env_leak and env_leak.get("status") == 200:
        return Hypothesis(
            vuln_type="info_disclosure",
            confidence=0.95,
            evidence=["/actuator/env returns 200 — Spring env leak confirmed"],
            suggested_detector="ssrf",
            suggested_chain="ssrf_to_rce",
            priority=0,
            endpoint="/actuator/env",
            detail={"status": env_leak.get("status"), "size": env_leak.get("size")},
        )
    if heapdump and heapdump.get("status") == 200:
        return Hypothesis(
            vuln_type="info_disclosure",
            confidence=0.90,
            evidence=["/actuator/heapdump returns 200 — Spring heap dump leak"],
            suggested_detector="ssrf",
            suggested_chain="ssrf_to_rce",
            priority=0,
            endpoint="/actuator/heapdump",
        )
    if _has_dir(ctx["dirs"], "/actuator"):
        return Hypothesis(
            vuln_type="actuator_exposed",
            confidence=0.60,
            evidence=["/actuator path found — verify env/heapdump/mappings"],
            suggested_detector="ssrf",
            priority=1,
            endpoint="/actuator",
        )
    return None


def _rule_php_lfi(**ctx) -> Optional[Hypothesis]:
    if not _has_tech(ctx["all_techs"], "php"):
        return None
    has_lfi = _has_vuln(ctx["existing_types"], "lfi")
    if has_lfi:
        return Hypothesis(
            vuln_type="rce",
            confidence=0.80,
            evidence=["PHP + LFI confirmed — log poisoning → RCE is viable"],
            suggested_chain="lfi_to_rce",
            priority=0,
        )
    if _has_dir(ctx["dirs"], "index.php"):
        return Hypothesis(
            vuln_type="lfi",
            confidence=0.50,
            evidence=["PHP detected with index.php — LFI likely testable via file params"],
            suggested_detector="lfi",
            priority=1,
        )
    return None


def _rule_graphql(**ctx) -> Optional[Hypothesis]:
    found_gql = _has_dir(ctx["dirs"], "/graphql") or _has_dir(ctx["dirs"], "/graphiql") or _has_dir(ctx["dirs"], "/playground")
    if not found_gql:
        return None
    has_vuln = _has_vuln(ctx["existing_types"], "graphql")
    if has_vuln:
        return Hypothesis(
            vuln_type="graphql_abuse",
            confidence=0.85,
            evidence=["GraphQL detected with confirmed vuln — batch + depth + authz attacks"],
            suggested_chain="ssrf_to_rce",
            priority=1,
            endpoint="/graphql",
            detail={"existing_vulns": True},
        )
    for path, info in ctx.get("crawled_endpoints", {}).items():
        if "graphql" in path.lower():
            return Hypothesis(
                vuln_type="graphql",
                confidence=0.60,
                evidence=["GraphQL endpoint found — check introspection + batching + auth"],
                suggested_detector="graphql",
                priority=1,
                endpoint=path,
            )
    return Hypothesis(
        vuln_type="graphql",
        confidence=0.40,
        evidence=["/graphql path discovered — verify if endpoint is active"],
        suggested_detector="graphql",
        priority=2,
        endpoint="/graphql",
    )


def _rule_jwt_found(**ctx) -> Optional[Hypothesis]:
    has_jwt = _has_vuln(ctx["existing_types"], "jwt")
    if has_jwt:
        return Hypothesis(
            vuln_type="jwt_exploit",
            confidence=0.85,
            evidence=["JWT found in traffic — alg none + weak secret + KID injection"],
            suggested_chain="deser_to_rce",
            priority=0,
        )
    return None


def _rule_cloud_ssrf(**ctx) -> Optional[Hypothesis]:
    cloud_providers = {"aws", "gcp", "azure", "cloudflare", "alibaba cloud", "tencent cloud", "huawei cloud"}
    detected_cloud = any(c in ctx["all_techs"] for c in cloud_providers)
    has_ssrf = _has_vuln(ctx["existing_types"], "ssrf")
    if detected_cloud and has_ssrf:
        return Hypothesis(
            vuln_type="cloud_credential_leak",
            confidence=0.90,
            evidence=["Cloud environment + SSRF confirmed — metadata endpoint accessible"],
            suggested_chain="ssrf_to_rce",
            priority=0,
        )
    if detected_cloud:
        return Hypothesis(
            vuln_type="ssrf",
            confidence=0.40,
            evidence=["Cloud provider detected — SSRF would enable metadata extraction"],
            suggested_detector="ssrf",
            priority=1,
        )
    return None


def _rule_redis_noauth(**ctx) -> Optional[Hypothesis]:
    if not _has_port(ctx["ports"], 6379):
        return None
    return Hypothesis(
        vuln_type="unauthorized_access",
        confidence=0.70,
        evidence=["Port 6379/redis open — likely noauth RCE if accessible"],
        priority=0,
        detail={"port": 6379, "service": "redis"},
    )


def _rule_mysql_exposed(**ctx) -> Optional[Hypothesis]:
    if not _has_port(ctx["ports"], 3306):
        return None
    return Hypothesis(
        vuln_type="unauthorized_access",
        confidence=0.50,
        evidence=["Port 3306/MySQL exposed — check weak creds / noauth"],
        priority=1,
        detail={"port": 3306, "service": "mysql"},
    )


def _rule_docker_exposed(**ctx) -> Optional[Hypothesis]:
    for p in (2375, 2376):
        if _has_port(ctx["ports"], p):
            svc = "Docker (TLS)" if p == 2376 else "Docker"
            return Hypothesis(
                vuln_type="unauthorized_access",
                confidence=0.85,
                evidence=["Port %d/%s exposed — container escape via Docker API" % (p, svc)],
                priority=0,
                detail={"port": p, "service": svc.lower()},
            )
    return None


def _rule_git_exposed(**ctx) -> Optional[Hypothesis]:
    git = ctx["git"]
    if git.get("git_exposed"):
        sensitive = len(git.get("sensitive_finds", []))
        conf = 0.95 if sensitive > 0 else 0.80
        return Hypothesis(
            vuln_type="git_leak",
            confidence=conf,
            evidence=[".git exposed with %d sensitive finds" % sensitive],
            priority=0,
            detail={"sensitive_finds": git.get("sensitive_finds", [])},
        )
    return None


def _rule_debugbar_leak(**ctx) -> Optional[Hypothesis]:
    if _has_dir(ctx["dirs"], "/_debugbar"):
        return Hypothesis(
            vuln_type="info_disclosure",
            confidence=0.85,
            evidence=["Laravel Debugbar exposed — DB queries, session data, env vars"],
            priority=0,
            endpoint="/_debugbar",
        )
    if _has_dir(ctx["dirs"], "/_ignition"):
        return Hypothesis(
            vuln_type="rce",
            confidence=0.70,
            evidence=["Laravel Ignition exposed — CVE-2021-3129 RCE possible"],
            priority=0,
            endpoint="/_ignition",
        )
    return None


def _rule_admin_panel(**ctx) -> Optional[Hypothesis]:
    admin_patterns = ["/admin", "/administrator", "/wp-admin", "/dashboard", "/panel", "/manager"]
    found = [d for d in ctx["dirs"] if any(a in d for a in admin_patterns)]
    if found and _has_vuln(ctx["existing_types"], "auth_bypass"):
        return Hypothesis(
            vuln_type="privilege_escalation",
            confidence=0.75,
            evidence=["Admin panel %s + auth bypass confirmed" % found[0]],
            suggested_chain="auth_bypass_to_rce",
            priority=0,
            endpoint=found[0],
        )
    if found:
        return Hypothesis(
            vuln_type="auth_bypass",
            confidence=0.40,
            evidence=["Admin panel found %s — test bypass techniques" % found[0]],
            suggested_detector="auth_bypass",
            priority=1,
            endpoint=found[0],
        )
    return None


def _rule_swagger_exposed(**ctx) -> Optional[Hypothesis]:
    swagger = _has_dir(ctx["dirs"], "/swagger") or _has_dir(ctx["dirs"], "/v2/api-docs") or _has_dir(ctx["dirs"], "/v3/api-docs")
    if not swagger:
        swagger = _has_dir(ctx["dirs"], "/api-docs") or _has_dir(ctx["dirs"], "/openapi.json")
    if swagger:
        return Hypothesis(
            vuln_type="api_doc_leak",
            confidence=0.80,
            evidence=["API docs exposed via Swagger/OpenAPI — full endpoint inventory"],
            priority=1,
        )
    return None


def _rule_phpmyadmin(**ctx) -> Optional[Hypothesis]:
    pma = _has_dir(ctx["dirs"], "/phpmyadmin") or _has_dir(ctx["dirs"], "/pma") or _has_dir(ctx["dirs"], "/adminer")
    if pma:
        return Hypothesis(
            vuln_type="unauthorized_access",
            confidence=0.60,
            evidence=["phpMyAdmin/Adminer exposed — SQL shell if creds weak"],
            priority=0,
        )
    return None


def _rule_weblogic(**ctx) -> Optional[Hypothesis]:
    if not _has_tech(ctx["all_techs"], "weblogic"):
        return None
    weblogic_paths = _has_dir(ctx["dirs"], "/wls-wsat") or _has_dir(ctx["dirs"], "/_async")
    if weblogic_paths:
        return Hypothesis(
            vuln_type="rce",
            confidence=0.75,
            evidence=["WebLogic + known RCE paths exposed — CVE-2017-10271 etc."],
            suggested_detector="deser",
            priority=0,
        )
    return Hypothesis(
        vuln_type="deser",
        confidence=0.50,
        evidence=["WebLogic detected — deserialization RCE likely exploitable"],
        suggested_detector="deser",
        priority=1,
    )


def _rule_thinkphp_rce(**ctx) -> Optional[Hypothesis]:
    if not _has_tech(ctx["all_techs"], "thinkphp"):
        return None
    return Hypothesis(
        vuln_type="rce",
        confidence=0.65,
        evidence=["ThinkPHP detected — RCE via invoke_func / class loader"],
        suggested_detector="cmdi",
        priority=0,
    )


def _rule_wordpress_wpadmin(**ctx) -> Optional[Hypothesis]:
    if not _has_tech(ctx["all_techs"], "wordpress"):
        return None
    xmlrpc = _has_dir(ctx["dirs"], "/xmlrpc.php")
    wp_admin = _has_dir(ctx["dirs"], "/wp-admin")
    if xmlrpc:
        return Hypothesis(
            vuln_type="wordpress_abuse",
            confidence=0.70,
            evidence=["WordPress + /xmlrpc.php — SSRF + brute force via wp.getUsersBlogs"],
            suggested_detector="ssrf",
            priority=1,
            endpoint="/xmlrpc.php",
        )
    if wp_admin:
        return Hypothesis(
            vuln_type="auth_bypass",
            confidence=0.35,
            evidence=["WordPress /wp-admin exposed — test creds + user enum"],
            suggested_detector="bizlogic",
            priority=2,
        )
    return None


def _rule_elasticsearch_noauth(**ctx) -> Optional[Hypothesis]:
    if _has_port(ctx["ports"], 9200):
        return Hypothesis(
            vuln_type="unauthorized_access",
            confidence=0.75,
            evidence=["Port 9200/Elasticsearch exposed — data access if noauth"],
            priority=0,
            detail={"port": 9200, "service": "elasticsearch"},
        )
    return None


def _rule_spring_cloud_gateway(**ctx) -> Optional[Hypothesis]:
    if not _has_tech(ctx["all_techs"], "spring"):
        return None
    if not _has_dir(ctx["dirs"], "/actuator/gateway"):
        return None
    return Hypothesis(
        vuln_type="rce",
        confidence=0.70,
        evidence=["Spring Cloud Gateway actuator exposed — CVE-2022-22947 RCE"],
        priority=0,
        endpoint="/actuator/gateway",
    )


def _rule_ssrf_internal_es(**ctx) -> Optional[Hypothesis]:
    has_ssrf = _has_vuln(ctx["existing_types"], "ssrf")
    if not has_ssrf:
        return None
    return Hypothesis(
        vuln_type="internal_pivot",
        confidence=0.60,
        evidence=["SSRF available — scan internal network for ES, Redis, internal APIs"],
        suggested_chain="ssrf_to_rce",
        priority=0,
    )


def _rule_sqli_and_lfi_composite(**ctx) -> Optional[Hypothesis]:
    has_sqli = _has_vuln(ctx["existing_types"], "sqli") or _has_vuln(ctx["existing_types"], "sql_injection")
    has_lfi = _has_vuln(ctx["existing_types"], "lfi")
    if has_sqli and has_lfi:
        return Hypothesis(
            vuln_type="rce",
            confidence=0.85,
            evidence=["SQLi + LFI simultaneously — use SQLi INTO OUTFILE for shell, LFI for log poison"],
            suggested_chain="sqli_to_rce",
            priority=0,
        )
    return None


def _rule_deser_php_gadget(**ctx) -> Optional[Hypothesis]:
    has_php = _has_tech(ctx["all_techs"], "php")
    has_deser = _has_vuln(ctx["existing_types"], "deser")
    if has_php and has_deser:
        return Hypothesis(
            vuln_type="rce",
            confidence=0.80,
            evidence=["PHP + deserialization confirmed — gadget chain RCE likely"],
            suggested_chain="deser_to_rce",
            priority=0,
        )
    return None


def _rule_xss_sensitive_form(**ctx) -> Optional[Hypothesis]:
    has_xss = _has_vuln(ctx["existing_types"], "xss")
    if not has_xss:
        return None
    pages = ctx.get("crawled_endpoints", {})
    sensitive_kw = {"transfer", "payment", "checkout", "order", "cart", "profile", "account", "admin"}
    found_sensitive = [p for p in pages if any(k in p.lower() for k in sensitive_kw)]
    if found_sensitive:
        return Hypothesis(
            vuln_type="xss_to_hijack",
            confidence=0.70,
            evidence=["XSS + sensitive endpoint %s — account takeover via CSRF" % found_sensitive[0]],
            suggested_chain="xss_to_hijack",
            priority=1,
        )
    return None


def _rule_proto_pollution(**ctx) -> Optional[Hypothesis]:
    if not _has_tech(ctx["all_techs"], "nodejs"):
        return None
    return Hypothesis(
        vuln_type="proto_pollution",
        confidence=0.35,
        evidence=["Node.js detected — check prototype pollution via JSON merge"],
        suggested_detector="proto_pollution",
        priority=3,
    )


def _rule_nosqli_express(**ctx) -> Optional[Hypothesis]:
    if not _has_tech(ctx["all_techs"], "express"):
        return None
    return Hypothesis(
        vuln_type="nosqli",
        confidence=0.30,
        evidence=["Express.js detected — test NoSQL injection if MongoDB in stack"],
        suggested_detector="nosqli",
        priority=3,
    )


def _rule_tomcat_manager(**ctx) -> Optional[Hypothesis]:
    if not _has_tech(ctx["all_techs"], "tomcat"):
        return None
    manager = _has_dir(ctx["dirs"], "/manager") or _has_dir(ctx["dirs"], "/host-manager")
    if manager:
        return Hypothesis(
            vuln_type="unauthorized_access",
            confidence=0.60,
            evidence=["Tomcat Manager exposed — WAR upload RCE if creds weak"],
            priority=0,
        )
    if _has_port(ctx["ports"], 8009):
        return Hypothesis(
            vuln_type="lfi",
            confidence=0.75,
            evidence=["Port 8009/AJP open — Ghostcat (CVE-2020-1938) LFI possible"],
            suggested_detector="lfi",
            priority=0,
            detail={"port": 8009, "service": "ajp"},
        )
    return None


def _rule_jenkins(**ctx) -> Optional[Hypothesis]:
    jenkins = _has_dir(ctx["dirs"], "/jenkins") or _has_dir(ctx["dirs"], "/jenkins/") or _has_dir(ctx["dirs"], "/script")
    if not jenkins:
        jenkins = _has_dir(ctx["dirs"], "/cli") or _has_dir(ctx["dirs"], "/asynchPeople")
    if jenkins:
        return Hypothesis(
            vuln_type="unauthorized_access",
            confidence=0.70,
            evidence=["Jenkins endpoint found — script console RCE if noauth"],
            priority=0,
        )
    return None


def _rule_k8s_api(**ctx) -> Optional[Hypothesis]:
    if _has_port(ctx["ports"], 6443):
        return Hypothesis(
            vuln_type="unauthorized_access",
            confidence=0.65,
            evidence=["Port 6443/K8s API exposed — pod exec if anonymous auth enabled"],
            priority=0,
            detail={"port": 6443, "service": "k8s_api"},
        )
    return None


def _rule_nfs_exposed(**ctx) -> Optional[Hypothesis]:
    if _has_port(ctx["ports"], 2049):
        return Hypothesis(
            vuln_type="unauthorized_access",
            confidence=0.70,
            evidence=["Port 2049/NFS exposed — mount remote filesystems if no_root_squash"],
            priority=0,
            detail={"port": 2049, "service": "nfs"},
        )
    return None


def _rule_ldap_anonymous(**ctx) -> Optional[Hypothesis]:
    for p in (389, 636):
        if _has_port(ctx["ports"], p):
            svc = "LDAPS" if p == 636 else "LDAP"
            return Hypothesis(
                vuln_type="info_disclosure",
                confidence=0.50,
                evidence=["Port %d/%s exposed — anonymous bind possible, dump directory" % (p, svc)],
                priority=1,
                detail={"port": p, "service": svc.lower()},
            )
    return None


def _rule_winrm_exposed(**ctx) -> Optional[Hypothesis]:
    for p in (5985, 5986):
        if _has_port(ctx["ports"], p):
            svc = "WinRM (HTTPS)" if p == 5986 else "WinRM (HTTP)"
            return Hypothesis(
                vuln_type="unauthorized_access",
                confidence=0.55,
                evidence=["Port %d/%s exposed — RCE via WinRM if creds obtained" % (p, svc)],
                priority=1,
                detail={"port": p, "service": "winrm"},
            )
    return None


def _rule_cve_database(**ctx) -> Optional[Hypothesis]:
    tech_ids = [t.get("id", "").lower() for t in ctx.get("technologies", [])]
    tech_names = [t.get("name", "").lower() for t in ctx.get("technologies", [])]
    all_tech_items = tech_ids + tech_names

    ports = ctx.get("ports", []) or [p.get("port") for p in ctx.get("port_data", [])]
    dirs = [d.get("path", "") for d in ctx.get("dir_full", [])]
    dir_paths = ctx.get("dirs", []) + dirs

    tech_objs = ctx.get("technologies", [])
    version_hints = {}
    for t in tech_objs:
        tid = t.get("id", "").lower()
        ver = t.get("version", "")
        if ver:
            version_hints[tid] = ver

    matched = []
    for tech in set(all_tech_items):
        if tech and tech in _kg.tech_cves:
            ver = version_hints.get(tech)
            cves = _kg.get_cves_for_tech(tech, ver)
            for cve in cves:
                for det in cve.detection:
                    for dp in dir_paths:
                        if det.lower() in dp.lower():
                            matched.append(cve)
                            break

    if matched:
        matched.sort(key=lambda c: (c.severity, c.exploit_available), reverse=True)
        top = matched[0]
        return Hypothesis(
            vuln_type=top.vuln_type,
            confidence=0.75 if top.exploit_available else 0.50,
            evidence=["CVE match: %s — %s (exploit:%s)" % (
                top.cve_id, top.description or top.vuln_type, "YES" if top.exploit_available else "maybe")],
            suggested_detector=top.vuln_type if top.vuln_type in (
                "sqli", "xss", "ssrf", "lfi", "ssti", "cmdi", "deser") else None,
            suggested_chain=top.exploit_method if top.exploit_available else None,
            priority=top.severity,
            detail={"cve_id": top.cve_id, "matched_cves": [c.cve_id for c in matched[:3]]},
        )

    for tech in all_tech_items:
        if tech and tech in _kg.tech_cves:
            top_sev = min((c.severity for c in _kg.tech_cves[tech]), default=5)
            if top_sev <= 1:
                return Hypothesis(
                    vuln_type="known_risks",
                    confidence=0.40,
                    evidence=["%s has %d CVEs in database, %d with exploits" % (
                        tech, len(_kg.tech_cves[tech]),
                        sum(1 for c in _kg.tech_cves[tech] if c.exploit_available))],
                    priority=1,
                    detail={"tech": tech, "cve_count": len(_kg.tech_cves[tech])},
                )

    for p in ports:
        tech = _kg.get_tech_for_port(p)
        if tech and tech not in all_tech_items and tech in _kg.tech_cves:
            return Hypothesis(
                vuln_type="known_risks",
                confidence=0.30,
                evidence=["Port %d → %s — %d CVEs known" % (p, tech, len(_kg.tech_cves[tech]))],
                priority=2,
                detail={"port": p, "tech": tech},
            )

    return None
