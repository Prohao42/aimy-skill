"""
Attack Tree: hierarchical attack path reasoning with confidence propagation.

An attack tree models the step-by-step progression of a real penetration test.
Each node represents an achievable goal with a confidence score. Parent confidence
propagates to children via transition probabilities. Evidence updates propagate
both up and down the tree.

Structure:
  Root → Web/Service/Credential branches → specific exploits → post-exploitation steps

Confidence rules:
  - P(child) = P(parent) * transition_prob (prior, before evidence)
  - P(parent|child_confirmed) >= P(parent) (child affirmed → boost parent)
  - P(child|parent_not_possible) = 0 (parent impossible → child impossible)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import json


@dataclass
class AttackTreeNode:
    id: str
    vuln_type: str
    description: str
    confidence: float
    parent_id: Optional[str] = None
    transition_prob: float = 0.5
    evidence: List[str] = field(default_factory=list)
    children: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    verified: bool = False
    chain_name: Optional[str] = None
    param: Optional[str] = None
    endpoint: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type,
            "description": self.description,
            "confidence": round(self.confidence, 4),
            "children": self.children,
            "verified": self.verified,
            "chain_name": self.chain_name,
            "cve_ids": self.cve_ids,
        }


class AttackTree:
    """
    Attack tree with hierarchical confidence propagation.

    Core operations:
      - build_tree(recon_context) → construct tree from scan data
      - propagate() → push confidence parent→child, child→parent
      - integrate_evidence(node_id, confirmed) → Bayesian update + repropagate
      - best_paths(min_confidence=0.5, max_depth=5) → ranked attack paths
    """

    ENTRY_TEMPLATES = {
        "ssrf": {
            "children": [
                ("cloud_metadata", "Cloud Metadata Read", 0.85, [
                    ("iam_keys", "IAM Key Extraction", 0.75, "ssrf_to_rce"),
                    ("k8s_metadata", "K8s Secrets via Metadata", 0.65, "ssrf_to_rce"),
                ]),
                ("internal_port", "Internal Port Scan", 0.70, [
                    ("redis_internal", "Internal Redis Exploit", 0.80, "ssrf_to_rce"),
                    ("internal_web", "Internal Web App Attack", 0.60, None),
                ]),
                ("source_code", "Source Code Read", 0.60, [
                    ("db_creds_from_code", "DB Credentials from Code", 0.70, "ssrf_to_rce"),
                    ("api_keys", "API Keys from Code", 0.65, None),
                ]),
            ]
        },
        "sqli": {
            "children": [
                ("data_exfil", "Data Exfiltration", 0.90, [
                    ("creds_from_db", "Credentials from DB", 0.80, "sqli_to_rce"),
                    ("admin_from_db", "Admin Panel Access", 0.85, None),
                ]),
                ("file_write", "INTO OUTFILE Webshell", 0.60, [
                    ("rce_via_webshell", "RCE via Webshell", 0.90, "sqli_to_rce"),
                ]),
                ("os_cmd", "MSSQL xp_cmdshell / MySQL udf", 0.40, [
                    ("os_rce", "OS-level RCE", 0.85, "sqli_to_rce"),
                ]),
            ]
        },
        "lfi": {
            "children": [
                ("passwd_read", "/etc/passwd Read", 0.95, [
                    ("user_enum", "User Enumeration", 0.70, None),
                    ("ssh_key_read", "SSH Key Read", 0.40, "lfi_to_rce"),
                ]),
                ("log_poison", "Log Poisoning", 0.60, [
                    ("rce_log", "RCE via Log Poison", 0.85, "lfi_to_rce"),
                ]),
                ("php_wrapper", "PHP Wrapper Source", 0.75, [
                    ("code_creds", "Credentials from Source", 0.60, None),
                ]),
            ]
        },
        "xss": {
            "children": [
                ("cookie_steal", "Cookie Theft", 0.60, [
                    ("session_hijack", "Session Hijack", 0.80, "xss_to_creds"),
                ]),
                ("csrf_token", "CSRF Token Theft", 0.50, [
                    ("admin_action", "Admin Action CSRF", 0.70, None),
                ]),
                ("keylogger", "Keylogger Injection", 0.40, [
                    ("cred_capture", "Credential Capture", 0.60, None),
                ]),
            ]
        },
        "rce": {
            "children": [
                ("reverse_shell", "Reverse Shell", 0.95, [
                    ("full_access", "Full Host Access", 0.90, None),
                    ("internal_pivot", "Internal Network Pivot", 0.70, None),
                ]),
                ("webshell_persist", "Webshell Persistence", 0.85, [
                    ("c2_beacon", "C2 Beacon", 0.60, None),
                ]),
            ]
        },
    }

    SERVICE_TEMPLATES = {
        "redis": {
            "children": [
                ("ssh_key_inject", "SSH Key Injection", 0.85, [
                    ("root_shell", "Root Shell", 0.90, "redis_unauth"),
                ]),
                ("cron_rce", "Cron Overwrite RCE", 0.70, [
                    ("root_shell_cron", "Root Shell", 0.85, "redis_unauth"),
                ]),
            ]
        },
        "docker": {
            "children": [
                ("container_exec", "Container Exec", 0.95, [
                    ("host_escape", "Host Escape", 0.40, None),
                    ("secret_exfil", "Container Secrets", 0.70, None),
                ]),
            ]
        },
        "mysql": {
            "children": [
                ("data_exfil_mysql", "Data Exfiltration", 0.85, [
                    ("creds_mysql", "Credentials", 0.75, None),
                ]),
                ("file_write_mysql", "INTO OUTFILE", 0.50, [
                    ("webshell_mysql", "Webshell", 0.90, None),
                ]),
            ]
        },
    }

    def __init__(self):
        self.nodes: Dict[str, AttackTreeNode] = {}
        self.root_id: Optional[str] = None

    def add_node(self, node: AttackTreeNode) -> str:
        self.nodes[node.id] = node
        return node.id

    def _make_id(self, prefix: str, idx: int) -> str:
        return "%s_%d" % (prefix, idx)

    def build_from_recon(self, technologies: List[str], open_ports: List[int],
                         directories: List[str], vulns: List[dict]) -> None:
        root = AttackTreeNode(
            id="root", vuln_type="root",
            description="Target is accessible and scoped for testing",
            confidence=1.0,
        )
        self.root_id = self.add_node(root)

        techs_lower = [t.lower() for t in technologies]
        dirs_lower = [d.lower() for d in directories]
        vuln_types = {v.get("type", "").lower() for v in vulns}

        web_idx = 0
        web_root_id = self.add_node(AttackTreeNode(
            id="branch_web", vuln_type="web",
            description="Web application attack surface",
            confidence=0.90, parent_id="root",
            transition_prob=0.95,
        ))
        self.nodes["root"].children.append("branch_web")

        service_idx = 0
        service_root_id = self.add_node(AttackTreeNode(
            id="branch_service", vuln_type="service",
            description="Network service attack surface",
            confidence=0.70, parent_id="root",
            transition_prob=0.80,
        ))
        self.nodes["root"].children.append("branch_service")

        web_root = self.nodes[web_root_id]
        service_root = self.nodes[service_root_id]

        path_prefixes = {d.split("/")[1] if d.count("/") > 1 else d.strip("/")
                         for d in dirs_lower if d.strip("/")}

        for vt in vuln_types:
            if vt in self.ENTRY_TEMPLATES:
                matched_cves = []
                for v in vulns:
                    if isinstance(v, dict) and v.get("type", "").lower() == vt:
                        matched_cves.extend(v.get("cve_ids", []))
                self._build_entry_branch(
                    vt, web_root, web_idx,
                    overrides={"cve_ids": matched_cves},
                )

        web_exploit_paths = self._detect_web_exploit_paths(
            techs_lower, dirs_lower, path_prefixes)
        for path_type, confidence, cves in web_exploit_paths:
            web_idx += 1
            self._build_entry_branch(path_type, self.nodes["branch_web"], web_idx,
                                     overrides={"cve_ids": cves},
                                     confidence_override=confidence)

        for port in open_ports:
            svc = self._port_to_service(port)
            if svc and svc in self.SERVICE_TEMPLATES:
                service_idx += 1
                self._build_service_branch(svc, self.nodes["branch_service"], service_idx)

        self.propagate()

    def _detect_web_exploit_paths(self, techs: List[str], dirs: List[str],
                                  prefixes: set) -> List[Tuple[str, float, List[str]]]:
        results = []

        if "spring" in techs or "spring boot" in techs:
            has_actuator = any("actuator" in d for d in dirs)
            c = 0.95 if has_actuator else 0.70
            results.append(("ssrf", c, ["CVE-2022-22965"]))

        if "wordpress" in techs:
            has_wp_json = any("wp-json" in d for d in dirs)
            has_xmlrpc = any("xmlrpc" in d for d in dirs)
            if has_wp_json or has_xmlrpc:
                results.append(("sqli", 0.75, ["CVE-2022-21661"]))
            results.append(("xss", 0.60, []))

        if "laravel" in techs:
            has_ignition = any("ignition" in d for d in dirs)
            c = 0.85 if has_ignition else 0.60
            results.append(("rce", c, ["CVE-2021-3129"]))

        if "thinkphp" in techs:
            results.append(("sqli", 0.75, ["CVE-2018-1000001"]))
            results.append(("rce", 0.65, []))

        if "php" in techs:
            has_phpinfo = any("phpinfo" in d for d in dirs)
            results.append(("lfi", 0.70 if not has_phpinfo else 0.85, []))

        if "tomcat" in techs:
            has_manager = any("manager" in d for d in dirs)
            c = 0.85 if has_manager else 0.65
            results.append(("rce", c, ["CVE-2020-1938"]))

        if "weblogic" in techs:
            results.append(("rce", 0.85, ["CVE-2020-14882", "CVE-2017-10271"]))

        if "struts" in techs:
            results.append(("rce", 0.85, ["CVE-2017-5638"]))

        if "drupal" in techs:
            results.append(("rce", 0.75, ["CVE-2018-7600"]))

        if "exchange" in techs:
            results.append(("ssrf", 0.80, ["CVE-2021-26855"]))

        if "asp.net" in techs or "iis" in techs:
            results.append(("lfi", 0.55, []))

        if "jenkins" in techs:
            results.append(("rce", 0.70, []))

        return results

    def _build_entry_branch(self, vuln_type: str, parent_node: AttackTreeNode,
                            idx: int, overrides: Optional[dict] = None,
                            confidence_override: Optional[float] = None):
        template = self.ENTRY_TEMPLATES.get(vuln_type)
        if not template:
            return

        entry_id = self._make_id("entry_%s" % vuln_type, idx)
        base_conf = confidence_override or 0.70
        entry = AttackTreeNode(
            id=entry_id, vuln_type=vuln_type,
            description="%s detected — exploring exploitation paths" % vuln_type.upper(),
            confidence=base_conf, parent_id=parent_node.id,
            transition_prob=0.80, chain_name=self._first_chain(template),
            cve_ids=(overrides or {}).get("cve_ids", []),
        )
        self.add_node(entry)
        self.nodes[parent_node.id].children.append(entry_id)

        for child_data in template.get("children", []):
            self._build_child_nodes(entry, [child_data])

    def _build_child_nodes(self, parent: AttackTreeNode,
                           children_spec: List[tuple],
                           depth: int = 0):
        if depth > 3:
            return
        for spec in children_spec:
            if len(spec) == 4:
                child_id, desc, trans_prob, chain = spec
                grand_children = []
            elif len(spec) == 5:
                child_id, desc, trans_prob, chain, grand_children = spec
                child_id = "%s_%s" % (parent.id, child_id)
            else:
                continue

            child_id_full = "%s_%s" % (parent.id, child_id)
            child = AttackTreeNode(
                id=child_id_full, vuln_type=child_id,
                description=desc,
                confidence=parent.confidence * trans_prob,
                parent_id=parent.id,
                transition_prob=trans_prob,
                chain_name=chain,
            )
            self.add_node(child)
            self.nodes[parent.id].children.append(child_id_full)

            if grand_children:
                self._build_child_nodes(child, grand_children, depth + 1)

    def _build_service_branch(self, service: str, parent_node: AttackTreeNode, idx: int):
        template = self.SERVICE_TEMPLATES.get(service)
        if not template:
            return

        svc_id = "svc_%s_%d" % (service, idx)
        svc_node = AttackTreeNode(
            id=svc_id, vuln_type=service,
            description="%s service — unauthorized access exploitation" % service.upper(),
            confidence=0.80, parent_id=parent_node.id,
            transition_prob=0.75,
        )
        self.add_node(svc_node)
        self.nodes[parent_node.id].children.append(svc_id)

        for child_data in template.get("children", []):
            self._build_child_nodes(svc_node, [child_data])

    def _first_chain(self, template: dict) -> Optional[str]:
        for c in template.get("children", []):
            if len(c) >= 4 and c[3]:
                return c[3]
        return None

    def _port_to_service(self, port: int) -> Optional[str]:
        m = {6379: "redis", 3306: "mysql", 5432: "postgres",
             2375: "docker", 2376: "docker", 9200: "elasticsearch",
             27017: "mongodb", 11211: "memcached", 4899: "rsync"}
        return m.get(port)

    def propagate(self) -> None:
        self._propagate_down(self.root_id, 1.0)

    def _propagate_down(self, node_id: str, parent_conf: float) -> None:
        node = self.nodes.get(node_id)
        if not node:
            return

        if node.parent_id and node_id != "root":
            parent = self.nodes.get(node.parent_id)
            if parent and parent.confidence > 0:
                propagated = parent.confidence * node.transition_prob
                node.confidence = max(node.confidence, propagated)

        for child_id in node.children:
            self._propagate_down(child_id, node.confidence)

    def integrate_evidence(self, node_id: str, confirmed: bool) -> None:
        """Bayesian update at a tree node, then propagate up and down."""
        node = self.nodes.get(node_id)
        if not node:
            return

        likelihood = 0.90 if confirmed else 0.30
        prior = node.confidence
        posterior = (prior * likelihood) / (prior * likelihood + (1 - prior) * (1 - likelihood))
        posterior = min(posterior, 0.99)
        posterior = max(posterior, 0.01)
        node.confidence = posterior
        node.verified = confirmed
        node.evidence.append("confirmed" if confirmed else "not_found")

        self._propagate_up(node_id)
        self._propagate_down(node_id, self.nodes[node_id].confidence)

    def _propagate_up(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if not node or not node.parent_id:
            return
        parent = self.nodes.get(node.parent_id)
        if not parent:
            return

        child_confs = [
            self.nodes[cid].confidence / max(self.nodes[cid].transition_prob, 0.01)
            for cid in parent.children
            if cid in self.nodes and self.nodes[cid].transition_prob > 0
        ]
        if child_confs:
            inferred = max(child_confs) * 0.85 + sum(child_confs) / len(child_confs) * 0.15
            inferred = max(inferred, 0.05)
            inferred = min(inferred, 0.99)
            if inferred > parent.confidence:
                parent.confidence = inferred
                parent.evidence.append("boosted_by_child_%s" % node_id)
                self._propagate_up(parent.id)

    def best_paths(self, min_confidence: float = 0.20,
                   max_depth: int = 6) -> List[dict]:
        paths = []
        leaf_confirmed = []

        for nid, node in self.nodes.items():
            if not node.children and node.id != "root":
                leaf_confirmed.append(node)

        leaf_confirmed.sort(key=lambda n: n.confidence, reverse=True)

        for leaf in leaf_confirmed[:15]:
            path = []
            cur = leaf.id
            conf = leaf.confidence
            while cur and cur in self.nodes:
                n = self.nodes[cur]
                path.append(n.to_dict())
                cur = n.parent_id
            path.reverse()

            vuln_types = [p["vuln_type"] for p in path if p["vuln_type"] != "root"]
            path_str = " → ".join(vuln_types)

            paths.append({
                "path": path,
                "confidence": round(conf, 4),
                "path_string": path_str,
                "leaf_id": leaf.id,
                "chain": leaf.chain_name,
                "cve_ids": leaf.cve_ids,
                "depth": len(path),
            })

        paths.sort(key=lambda p: p["confidence"], reverse=True)
        return [p for p in paths if p["confidence"] >= min_confidence][:10]

    def summary(self) -> Dict:
        paths = self.best_paths()
        verified = [n.to_dict() for n in self.nodes.values() if n.verified]

        return {
            "total_nodes": len(self.nodes),
            "best_paths": paths[:5],
            "verified_nodes": verified,
            "root_confidence": self.nodes.get(self.root_id, AttackTreeNode(
                id="", vuln_type="", description="", confidence=0
            )).confidence,
        }

    def to_json(self) -> str:
        return json.dumps(self.summary(), indent=2, default=str)
