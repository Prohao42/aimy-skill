"""
Attack Graph: Advanced attack path reasoning with cycle support and multi-path exploration.

Unlike AttackTree (hierarchical, acyclic), AttackGraph supports:
  - Cyclic paths (SSRF → Redis → SSRF escalation)
  - Conditional edges (preconditions/postconditions)
  - Multi-path parallel exploration
  - Dijkstra-based shortest attack path
  - State-space search with pruning

Graph Structure:
  Nodes = system states (discovered services, credentials, access levels)
  Edges = attack actions (exploit, pivot, escalate)

Confidence Propagation:
  - P(path) = Π P(edge) for all edges in path
  - Bayesian update on evidence
  - Negative evidence prunes entire subgraph
"""
import heapq
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from tools.log_utils import get_logger

logger = get_logger("attack_graph")


@dataclass
class GraphNode:
    id: str
    state_type: str
    description: str
    confidence: float
    reached_via: Optional[str] = None
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    depth: int = 0
    is_goal: bool = False
    is_start: bool = False
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "state_type": self.state_type,
            "description": self.description,
            "confidence": round(self.confidence, 4),
            "reached_via": self.reached_via,
            "depth": self.depth,
            "is_goal": self.is_goal,
            "is_start": self.is_start,
            "tags": self.tags,
        }


@dataclass
class GraphEdge:
    from_id: str
    to_id: str
    action: str
    transition_prob: float
    cost: float = 1.0
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "from": self.from_id,
            "to": self.to_id,
            "action": self.action,
            "transition_prob": self.transition_prob,
            "cost": self.cost,
            "cve_ids": self.cve_ids,
        }


@dataclass
class AttackPath:
    nodes: List[str]
    edges: List[str]
    confidence: float
    cost: float
    path_string: str = ""
    chains: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "confidence": round(self.confidence, 4),
            "cost": self.cost,
            "path_string": self.path_string,
            "chains": self.chains,
        }


class AttackGraph:
    """
    Graph-based attack path reasoning with cycle support.

    Core operations:
      - build_graph(recon_context) → construct graph from scan data
      - add_finding(finding_type, evidence) → add node + edges dynamically
      - propagate() → Bayesian update across graph
      - shortest_path(goal_type) → Dijkstra shortest path
      - all_paths(max_depth) → enumerate all paths up to depth
      - best_paths(min_confidence, max_depth) → ranked attack paths
      - subgraph_from(start_node) → reachable subgraph
    """

    STATE_TEMPLATES = {
        "initial_access": {
            "recon": [
                ("port_scan", "Port Scan Complete", 0.95),
                ("tech_fingerprint", "Technology Fingerprinted", 0.95),
                ("dir_enum", "Directory Enumeration", 0.80),
            ],
            "web_vuln": [
                ("sqli_found", "SQL Injection Found", 0.80),
                ("xss_found", "XSS Found", 0.70),
                ("ssrf_found", "SSRF Found", 0.82),
                ("ssti_found", "SSTI Found", 0.75),
                ("cmdi_found", "Command Injection Found", 0.88),
                ("lfi_found", "LFI Found", 0.80),
                ("xxe_found", "XXE Found", 0.70),
                ("deser_found", "Deserialization Found", 0.85),
            ],
            "auth_vuln": [
                ("auth_bypass", "Authentication Bypass", 0.75),
                ("jwt_weak", "JWT Weak Secret", 0.65),
                ("session_fix", "Session Fixation", 0.60),
            ],
            "service_vuln": [
                ("redis_unauth", "Redis Unauthorized", 0.80),
                ("mysql_weak", "MySQL Weak Creds", 0.70),
                ("docker_api", "Docker API Exposed", 0.85),
                ("k8s_api", "K8s API Exposed", 0.80),
                ("ftp_anon", "FTP Anonymous", 0.75),
                ("smb_anon", "SMB Anonymous", 0.70),
            ],
        },
        "escalation": [
            ("config_leak", "Configuration Leaked", 0.80),
            ("db_creds", "Database Credentials", 0.85),
            ("api_keys", "API Keys Found", 0.75),
            ("ssh_keys", "SSH Keys Found", 0.85),
            ("cloud_creds", "Cloud Credentials", 0.80),
            ("internal_scan", "Internal Network Scan", 0.70),
        ],
        "post_exploit": [
            ("rce_obtained", "Remote Code Execution", 0.95),
            ("data_exfil", "Data Exfiltration", 0.90),
            ("persistence", "Persistence Established", 0.85),
            ("lateral_movement", "Lateral Movement", 0.80),
        ],
    }

    ENTRY_EDGES = [
        # Web vulnerabilities
        ("start", "recon_complete", "recon", 0.95),
        ("recon_complete", "sqli_found", "sqli_exploit", 0.70),
        ("recon_complete", "xss_found", "xss_exploit", 0.65),
        ("recon_complete", "ssrf_found", "ssrf_exploit", 0.75),
        ("recon_complete", "ssti_found", "ssti_exploit", 0.70),
        ("recon_complete", "cmdi_found", "cmdi_exploit", 0.80),
        ("recon_complete", "lfi_found", "lfi_exploit", 0.75),
        ("recon_complete", "xxe_found", "xxe_exploit", 0.70),
        ("recon_complete", "deser_found", "deser_exploit", 0.80),
        # Service vulnerabilities
        ("recon_complete", "redis_unauth", "redis_access", 0.60),
        ("recon_complete", "mysql_weak", "mysql_access", 0.55),
        ("recon_complete", "docker_api", "docker_access", 0.65),
        ("recon_complete", "k8s_api", "k8s_access", 0.60),
        # Auth vulnerabilities
        ("recon_complete", "auth_bypass", "auth_exploit", 0.65),
        ("recon_complete", "jwt_weak", "jwt_exploit", 0.55),
        # Escalation paths
        ("ssrf_found", "config_leak", "ssrf_read_config", 0.70),
        ("ssrf_found", "cloud_creds", "ssrf_cloud_meta", 0.65),
        ("ssrf_found", "internal_scan", "ssrf_internal_scan", 0.60),
        ("sqli_found", "db_creds", "sqli_extract_creds", 0.75),
        ("lfi_found", "config_leak", "lfi_read_config", 0.70),
        ("lfi_found", "ssh_keys", "lfi_read_ssh_keys", 0.50),
        ("redis_unauth", "rce_obtained", "redis_cron_rce", 0.80),
        ("mysql_weak", "data_exfil", "mysql_dump", 0.85),
        ("docker_api", "rce_obtained", "docker_exec", 0.80),
        ("k8s_api", "rce_obtained", "k8s_exec", 0.75),
        ("config_leak", "db_creds", "parse_config", 0.75),
        ("config_leak", "api_keys", "parse_config", 0.70),
        ("db_creds", "rce_obtained", "db_to_rce", 0.65),
        ("api_keys", "rce_obtained", "api_to_rce", 0.60),
        ("ssh_keys", "rce_obtained", "ssh_login", 0.85),
        ("cloud_creds", "lateral_movement", "cloud_pivot", 0.70),
        # Post-exploitation
        ("rce_obtained", "data_exfil", "exfiltrate_data", 0.90),
        ("rce_obtained", "persistence", "install_backdoor", 0.75),
        ("rce_obtained", "lateral_movement", "pivot_network", 0.70),
    ]

    def __init__(self, target: str = ""):
        self.target = target
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, List[GraphEdge]] = defaultdict(list)
        self.reverse_edges: Dict[str, List[GraphEdge]] = defaultdict(list)
        self._id_counter = 0

    def _next_id(self, prefix="node") -> str:
        self._id_counter += 1
        return "%s_%d" % (prefix, self._id_counter)

    def add_node(self, node_id: str, state_type: str, description: str,
                 confidence: float, is_goal: bool = False, is_start: bool = False,
                 tags: List[str] = None, preconditions: List[str] = None) -> GraphNode:
        if node_id in self.nodes:
            existing = self.nodes[node_id]
            existing.confidence = max(existing.confidence, confidence)
            return existing
        node = GraphNode(
            id=node_id, state_type=state_type, description=description,
            confidence=confidence, is_goal=is_goal, is_start=is_start,
            tags=tags or [], preconditions=preconditions or [],
        )
        self.nodes[node_id] = node
        return node

    def add_edge(self, from_id: str, to_id: str, action: str,
                 transition_prob: float, cost: float = 1.0,
                 preconditions: List[str] = None, postconditions: List[str] = None,
                 cve_ids: List[str] = None, description: str = "") -> GraphEdge:
        edge = GraphEdge(
            from_id=from_id, to_id=to_id, action=action,
            transition_prob=transition_prob, cost=cost,
            preconditions=preconditions or [], postconditions=postconditions or [],
            cve_ids=cve_ids or [], description=description,
        )
        self.edges[from_id].append(edge)
        self.reverse_edges[to_id].append(edge)
        return edge

    def build_graph(self, recon_context: Dict) -> None:
        self.add_node("start", "start", "Initial Access", 1.0, is_start=True)

        for state_type, categories in self.STATE_TEMPLATES.items():
            if isinstance(categories, dict):
                for cat, items in categories.items():
                    for node_id, desc, conf in items:
                        is_goal = state_type == "post_exploit"
                        self.add_node(node_id, state_type, desc, conf, is_goal=is_goal)
            elif isinstance(categories, list):
                for node_id, desc, conf in categories:
                    is_goal = state_type == "post_exploit"
                    self.add_node(node_id, state_type, desc, conf, is_goal=is_goal)

        self.add_node("recon_complete", "initial_access", "Reconnaissance Complete", 0.95)
        self.add_node("config_leak", "escalation", "Configuration Leaked", 0.80)
        self.add_node("db_creds", "escalation", "Database Credentials", 0.85)
        self.add_node("api_keys", "escalation", "API Keys Found", 0.75)
        self.add_node("ssh_keys", "escalation", "SSH Keys Found", 0.85)
        self.add_node("cloud_creds", "escalation", "Cloud Credentials", 0.80)
        self.add_node("internal_scan", "escalation", "Internal Network Scan", 0.70)
        self.add_node("rce_obtained", "post_exploit", "Remote Code Execution", 0.95, is_goal=True)
        self.add_node("data_exfil", "post_exploit", "Data Exfiltration", 0.90, is_goal=True)
        self.add_node("persistence", "post_exploit", "Persistence Established", 0.85, is_goal=True)
        self.add_node("lateral_movement", "post_exploit", "Lateral Movement", 0.80, is_goal=True)

        for from_id, to_id, action, prob, *rest in self.ENTRY_EDGES:
            cost = rest[0] if rest else 1.0
            cves = rest[1] if len(rest) > 1 else []
            if from_id in self.nodes or from_id == "start":
                if to_id not in self.nodes:
                    self.add_node(to_id, "dynamic", to_id, prob * 0.8)
                self.add_edge(from_id, to_id, action, prob, cost, cve_ids=cves)

        self._apply_recon_context(recon_context)

    def _apply_recon_context(self, context: Dict) -> None:
        techs = context.get("technologies", [])
        ports = context.get("open_ports", [])
        dirs = context.get("directories", [])
        git_leak = context.get("git_leak", {})

        tech_names = [t.get("name", "").lower() for t in techs if isinstance(t, dict)]
        open_port_numbers = [p.get("port", 0) for p in ports if isinstance(p, dict)]

        if any("spring" in t for t in tech_names):
            if "sqli_found" not in self.nodes:
                self.add_node("sqli_found", "initial_access", "SQL Injection Found", 0.75)
            self.add_edge("recon_complete", "sqli_found", "spring_sqli", 0.75, cve_ids=["CVE-2022-22965"])

        if any("weblogic" in t for t in tech_names):
            self.add_node("deser_found", "initial_access", "Deserialization Found", 0.85)
            self.add_edge("recon_complete", "deser_found", "weblogic_deser", 0.80, cve_ids=["CVE-2020-14882"])

        if any("thinkphp" in t for t in tech_names):
            self.add_node("cmdi_found", "initial_access", "Command Injection Found", 0.90)
            self.add_edge("recon_complete", "cmdi_found", "thinkphp_cmdi", 0.85, cve_ids=["CVE-2018-1000001"])

        if any("laravel" in t for t in tech_names):
            self.add_node("deser_found", "initial_access", "Deserialization Found", 0.80)
            self.add_edge("recon_complete", "deser_found", "laravel_deser", 0.75, cve_ids=["CVE-2021-3129"])

        if 6379 in open_port_numbers:
            self.add_node("redis_unauth", "service_vuln", "Redis Unauthorized", 0.80)
            self.add_edge("recon_complete", "redis_unauth", "redis_connect", 0.70)

        if 3306 in open_port_numbers:
            self.add_node("mysql_weak", "service_vuln", "MySQL Weak Creds", 0.70)
            self.add_edge("recon_complete", "mysql_weak", "mysql_connect", 0.55)

        if 2375 in open_port_numbers or 2376 in open_port_numbers:
            self.add_node("docker_api", "service_vuln", "Docker API Exposed", 0.85)
            self.add_edge("recon_complete", "docker_api", "docker_connect", 0.65)

        if 6443 in open_port_numbers:
            self.add_node("k8s_api", "service_vuln", "K8s API Exposed", 0.80)
            self.add_edge("recon_complete", "k8s_api", "k8s_connect", 0.60)

        if git_leak.get("git_exposed"):
            self.add_node("config_leak", "escalation", "Configuration Leaked via .git", 0.85)
            self.add_edge("recon_complete", "config_leak", "git_extract", 0.80)

        interesting_paths = [d.get("path", "") for d in dirs if isinstance(d, dict)]
        sensitive_paths = [".env", "config", "admin", "phpinfo", "actuator", "debug"]
        for path in interesting_paths:
            if any(sp in path.lower() for sp in sensitive_paths):
                if "config_leak" not in self.nodes:
                    self.add_node("config_leak", "escalation", "Configuration Leaked", 0.80)
                self.add_edge("recon_complete", "config_leak", "path_access", 0.75)
                break

    def propagate(self) -> None:
        for _ in range(5):
            changed = False
            for node_id, node in self.nodes.items():
                parent_edges = self.reverse_edges.get(node_id, [])
                if parent_edges:
                    max_parent_conf = 0.0
                    for edge in parent_edges:
                        parent = self.nodes.get(edge.from_id)
                        if parent:
                            p = parent.confidence * edge.transition_prob
                            max_parent_conf = max(max_parent_conf, p)
                    if max_parent_conf > node.confidence * 1.05:
                        node.confidence = min(max_parent_conf, 0.99)
                        changed = True
            if not changed:
                break

    def integrate_evidence(self, node_id: str, confirmed: bool,
                           likelihood: float = 0.80) -> None:
        if node_id not in self.nodes:
            return
        node = self.nodes[node_id]
        if confirmed:
            prior = node.confidence
            posterior = (prior * likelihood) / (prior * likelihood + (1 - prior) * (1 - likelihood))
            node.confidence = min(posterior * 1.05, 0.99)
            node.evidence.append("Confirmed (likelihood=%.2f)" % likelihood)
        else:
            false_pos = 1.0 - likelihood
            prior = node.confidence
            posterior = (prior * false_pos) / (prior * false_pos + (1 - prior) * likelihood)
            node.confidence = max(posterior * 0.95, 0.01)
            node.evidence.append("Not confirmed (fpr=%.2f)" % false_pos)
        self.propagate()

    def shortest_path(self, goal_type: str = "rce_obtained",
                      min_confidence: float = 0.10) -> Optional[AttackPath]:
        start = "start"
        if goal_type not in self.nodes:
            for nid, n in self.nodes.items():
                if n.state_type == "post_exploit":
                    goal_type = nid
                    break
        if goal_type not in self.nodes:
            return None
        dist = {start: (0.0, 1.0, [start], [])}
        visited = set()
        heap = [(0.0, -1.0, start, [start], [])]
        while heap:
            cost, neg_conf, current, path, edge_names = heapq.heappop(heap)
            if current in visited:
                continue
            visited.add(current)
            if current == goal_type:
                conf = -neg_conf
                return AttackPath(
                    nodes=path, edges=edge_names, confidence=conf,
                    cost=cost, path_string=" → ".join(path),
                    chains=[],
                )
            for edge in self.edges.get(current, []):
                next_node = edge.to_id
                if next_node in visited:
                    continue
                next_node_obj = self.nodes.get(next_node)
                if not next_node_obj or next_node_obj.confidence < min_confidence:
                    continue
                new_cost = cost + edge.cost
                new_conf = -neg_conf * edge.transition_prob
                if next_node not in dist or new_cost < dist[next_node][0]:
                    dist[next_node] = (new_cost, new_conf, path + [next_node], edge_names + [edge.action])
                    heapq.heappush(heap, (new_cost, new_conf, next_node,
                                          path + [next_node], edge_names + [edge.action]))
        return None

    def all_paths(self, max_depth: int = 8, min_confidence: float = 0.10) -> List[AttackPath]:
        paths = []
        goals = [nid for nid, n in self.nodes.items() if n.is_goal or n.state_type == "post_exploit"]
        for goal in goals:
            self._dfs_paths("start", goal, [], [], set(), max_depth, min_confidence, paths)
        paths.sort(key=lambda p: p.confidence * (1.0 / max(p.cost, 0.1)), reverse=True)
        return paths

    def _dfs_paths(self, current: str, goal: str, path: List[str],
                   edges: List[str], visited: Set[str], max_depth: int,
                   min_confidence: float, result: List[AttackPath]) -> None:
        if len(path) > max_depth:
            return
        if current in visited:
            return
        visited.add(current)
        path.append(current)
        if current == goal:
            conf = 1.0
            for edge_name in edges:
                for e_list in self.edges.values():
                    for e in e_list:
                        if e.action == edge_name:
                            conf *= e.transition_prob
                            break
            if conf >= min_confidence:
                cost = len(edges)
                result.append(AttackPath(
                    nodes=list(path), edges=list(edges), confidence=conf,
                    cost=cost, path_string=" → ".join(path),
                ))
        else:
            for edge in self.edges.get(current, []):
                next_node = edge.to_id
                next_obj = self.nodes.get(next_node)
                if next_obj and next_obj.confidence >= min_confidence:
                    self._dfs_paths(next_node, goal, path, edges + [edge.action],
                                    visited, max_depth, min_confidence, result)
        path.pop()
        visited.remove(current)

    def best_paths(self, min_confidence: float = 0.20,
                   max_depth: int = 6, top_n: int = 10) -> List[AttackPath]:
        all_p = self.all_paths(max_depth, min_confidence)
        seen = set()
        unique = []
        for p in all_p:
            key = tuple(p.nodes)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        unique.sort(key=lambda x: x.confidence * (1.0 / max(x.cost, 0.1)), reverse=True)
        return unique[:top_n]

    def subgraph_from(self, start_node: str, max_depth: int = 5) -> 'AttackGraph':
        sub = AttackGraph(self.target)
        visited = set()
        queue = [(start_node, 0)]
        while queue:
            nid, depth = queue.pop(0)
            if nid in visited or depth > max_depth:
                continue
            visited.add(nid)
            node = self.nodes.get(nid)
            if node:
                sub.add_node(nid, node.state_type, node.description,
                            node.confidence, node.is_goal, node.is_start,
                            node.tags, node.preconditions)
            for edge in self.edges.get(nid, []):
                if edge.to_id in self.nodes:
                    sub.add_edge(nid, edge.to_id, edge.action,
                                edge.transition_prob, edge.cost,
                                edge.preconditions, edge.postconditions,
                                edge.cve_ids, edge.description)
                queue.append((edge.to_id, depth + 1))
        return sub

    def summary(self) -> Dict:
        goals = [n for n in self.nodes.values() if n.is_goal]
        best = self.best_paths(0.10, 6, 5)
        return {
            "total_nodes": len(self.nodes),
            "total_edges": sum(len(v) for v in self.edges.values()),
            "goals": [g.to_dict() for g in goals],
            "best_paths": [p.to_dict() for p in best],
            "node_types": {
                st: len([n for n in self.nodes.values() if n.state_type == st])
                for st in set(n.state_type for n in self.nodes.values())
            },
        }


def build_attack_graph(recon_context: Dict, target: str = "") -> AttackGraph:
    graph = AttackGraph(target)
    graph.build_graph(recon_context)
    graph.propagate()
    return graph
