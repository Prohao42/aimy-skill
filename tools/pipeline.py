"""
Pipeline: recon products -> asset graph -> business-value ranking -> differential
verification -> BFS-to-crown-jewel -> report section.

Round 3 orchestration layer. Pure functions on scan state, no live I/O.

Graph semantics
---------------
* Nodes are concrete assets (host / service / endpoint), not abstract attack states.
* Endpoints sharing a host are always interconnected (same_host edges): a confirmed
  finding on one endpoint can pivot to any sibling endpoint or service on the same box.
* Crown jewels are inferred from recon (admin/login/api/db/sensitive paths) and can be
  overridden explicitly by the caller.
* Attack chains = shortest paths on the asset graph from the proven attack surface to a
  crown jewel, ranked by accumulated business value and edge confidence.
"""
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from tools.attack_surface import OPEN_PORT_ATTACK_MAP, TECH_STACK_ATTACK_MAP, lookup_cves
from tools.log_utils import get_logger

logger = get_logger("pipeline")

HOST_ID_PREFIX = "host:"
PORT_ID_PREFIX = "port:"
ENDPOINT_ID_PREFIX = "endpoint:"

# ---------------------------------------------------------------------------
# Crown jewel inference patterns
# ---------------------------------------------------------------------------

CROWN_JEWEL_PATH_PATTERNS: Tuple[str, ...] = (
    "/admin", "/administrator", "/manage", "/management", "/dashboard",
    "/console", "/wp-admin", "/actuator", "/api/", "/graphql", "/upload",
    "/phpmyadmin", "/swagger", "/debug", "/config", "/login", "/signin",
    "/database", "/phpinfo", "/manager", "/jenkins", "/kibana", "/grafana",
    "/cpanel", "/swagger-resources", "/.env", "/.git",
)

# DB / infra ports that usually gate the most valuable data
CROWN_JEWEL_PORTS: Tuple[int, ...] = (
    1433, 1521, 2375, 2376, 3306, 5432, 5984, 6379, 6443, 7001, 8161,
    8500, 9200, 27017, 50070, 61616,
)

HIGH_VALUE_TECHS: Tuple[str, ...] = (
    "spring", "weblogic", "thinkphp", "laravel", "wordpress", "tomcat",
    "flask", "django", "jenkins", "struts", "drupal", "asp.net", "graphql",
)

ROLE_WEIGHTS: Dict[str, float] = {
    "/console": 1.0, "/admin": 1.0, "/manager": 0.9, "/phpmyadmin": 0.9,
    "/login": 0.9, "/signin": 0.9, "/actuator": 0.9, "/graphql": 0.9,
    "/jenkins": 0.9, "/swagger": 0.8, "/api": 0.8, "/upload": 0.8,
    "/config": 0.8, "/debug": 0.8, "/dashboard": 0.8, "/database": 0.8,
    "/.env": 0.9, "/.git": 0.8,
}

DEFAULT_VALUE_WEIGHTS: Dict[str, float] = {
    "role": 3.0, "port": 2.0, "tech": 1.5, "cve": 1.0, "auth": 1.0,
    "git": 1.0, "finding": 1.5, "auth_bypass": 1.0,
}

_PORT_RISK_SCORE = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}
_TECH_RISK_SCORE = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


# ---------------------------------------------------------------------------
# URL / id helpers
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    return url.rstrip("/") if url else url


def _extract_host(target: str) -> str:
    target = (target or "").strip()
    if "://" not in target:
        target = "http://" + target
    try:
        netloc = urlparse(target).netloc
    except ValueError:
        netloc = target
    host = netloc.split(":")[0].strip().strip("/")
    return host or "unknown"


def _join_url(base: str, path: str) -> str:
    if not path:
        return base.rstrip("/")
    if path.startswith("http://") or path.startswith("https://"):
        return path.rstrip("/")
    return "%s/%s" % (base.rstrip("/"), path.lstrip("/"))


def host_id(host: str) -> str:
    return "%s%s" % (HOST_ID_PREFIX, host)


def port_id(host: str, port: int) -> str:
    return "%s%s:%d" % (PORT_ID_PREFIX, host, port)


def endpoint_id(url: str) -> str:
    return "%s%s" % (ENDPOINT_ID_PREFIX, _normalize_url(url))


# ---------------------------------------------------------------------------
# Asset graph
# ---------------------------------------------------------------------------

@dataclass
class AssetNode:
    id: str
    kind: str  # host | service | endpoint
    url: str = ""
    host: str = ""
    port: int = 0
    value: float = 0.0
    tags: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "value": self.value,
            "tags": self.tags[:6],
        }


@dataclass
class AssetEdge:
    from_id: str
    to_id: str
    relation: str  # runs_on | reachable | same_host
    confidence: float = 1.0


class AssetGraph:
    """Concrete asset topology: hosts run services and endpoints, and every
    endpoint/service on the same host is mutually reachable (same_host)."""

    def __init__(self, target: str = ""):
        self.target = target
        self.nodes: Dict[str, AssetNode] = {}
        self.edges: Dict[str, List[AssetEdge]] = defaultdict(list)
        self.adj: Dict[str, set] = defaultdict(set)

    def add_node(self, node_id: str, kind: str, url: str = "", host: str = "",
                 port: int = 0, value: float = 0.0, tags: Optional[List[str]] = None) -> AssetNode:
        if node_id in self.nodes:
            existing = self.nodes[node_id]
            if tags:
                existing.tags = list(dict.fromkeys(existing.tags + tags))
            return existing
        node = AssetNode(
            id=node_id, kind=kind, url=url, host=host, port=port,
            value=value, tags=tags or [],
        )
        self.nodes[node_id] = node
        return node

    def add_edge(self, from_id: str, to_id: str, relation: str, confidence: float = 1.0) -> AssetEdge:
        for edge in self.edges.get(from_id, []):
            if edge.to_id == to_id and edge.relation == relation:
                edge.confidence = max(edge.confidence, confidence)
                return edge
        edge = AssetEdge(from_id, to_id, relation, confidence)
        self.edges[from_id].append(edge)
        self.adj[from_id].add(to_id)
        self.adj[to_id].add(from_id)
        return edge

    def interconnect_same_host(self) -> int:
        """Connect every endpoint/service sharing a host (bidirectional same_host)."""
        by_host: Dict[str, List[str]] = defaultdict(list)
        for nid, node in self.nodes.items():
            if node.kind in ("endpoint", "service") and node.host:
                by_host[node.host].append(nid)
        count = 0
        for host, ids in by_host.items():
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    self.add_edge(ids[i], ids[j], "same_host", 0.9)
                    self.add_edge(ids[j], ids[i], "same_host", 0.9)
                    count += 2
        return count

    def bfs(self, starts: Sequence[str], goals: Sequence[str], max_depth: int = 8) -> List[List[str]]:
        """Shortest paths (BFS) from any start to any goal, returning node-id paths."""
        if not goals:
            return []
        goal_set = set(goals)
        found: Dict[str, List[str]] = {}
        for start in starts:
            if start not in self.adj:
                continue
            queue: Deque[Tuple[str, List[str]]] = deque([(start, [start])])
            visited = {start}
            while queue:
                node, path = queue.popleft()
                if node in goal_set and len(path) > 1:
                    if node not in found:
                        found[node] = path
                    continue
                if len(path) >= max_depth:
                    continue
                for nxt in self.adj.get(node, []):
                    if nxt not in visited:
                        visited.add(nxt)
                        queue.append((nxt, path + [nxt]))
        return list(found.values())

    def path_confidence(self, path: Sequence[str]) -> float:
        if len(path) < 2:
            return 1.0
        conf = 1.0
        for a, b in zip(path, path[1:]):
            best = 0.0
            for edge in self.edges.get(a, []):
                if edge.to_id == b:
                    best = max(best, edge.confidence)
            for edge in self.edges.get(b, []):
                if edge.to_id == a:
                    best = max(best, edge.confidence)
            conf *= max(best, 0.1)
        return round(min(conf, 1.0), 4)

    def connected_components(self) -> List[List[str]]:
        seen = set()
        components = []
        for nid in self.nodes:
            if nid in seen:
                continue
            component = []
            stack = [nid]
            seen.add(nid)
            while stack:
                cur = stack.pop()
                component.append(cur)
                for nxt in self.adj.get(cur, []):
                    if nxt not in seen:
                        seen.add(nxt)
                        stack.append(nxt)
            components.append(component)
        return components

    def summary(self) -> Dict:
        return {
            "total_nodes": len(self.nodes),
            "total_edges": sum(len(v) for v in self.edges.values()),
            "hosts": len({n.host for n in self.nodes.values() if n.host}),
            "connected_components": len(self.connected_components()),
            "node_kinds": {
                kind: len([n for n in self.nodes.values() if n.kind == kind])
                for kind in ("host", "service", "endpoint")
            },
        }


# ---------------------------------------------------------------------------
# Asset graph construction from scan state
# ---------------------------------------------------------------------------

def _techs_of(recon: Dict) -> List[Dict]:
    techs = recon.get("technologies", {})
    if isinstance(techs, dict):
        return techs.get("technologies", [])
    return techs if isinstance(techs, list) else []


def _ports_of(recon: Dict) -> List[Dict]:
    ports = recon.get("open_ports", {})
    if isinstance(ports, dict):
        return ports.get("open_ports", [])
    return ports if isinstance(ports, list) else []


def _dirs_of(recon: Dict) -> List[Dict]:
    dirs = recon.get("directories", {})
    if isinstance(dirs, dict):
        return dirs.get("interesting", [])
    return dirs if isinstance(dirs, list) else []


def _findings_of(state: Dict) -> Dict:
    detect = (state.get("phases") or {}).get("detect", {})
    return detect.get("findings", {}) if isinstance(detect, dict) else {}


def _subdomains_of(recon: Dict) -> Dict:
    subs = recon.get("subdomains", {})
    return subs if isinstance(subs, dict) else {}


def _add_endpoint(graph: AssetGraph, base: str, url: str, tags=None, evidence=None) -> str:
    """Add an endpoint node, wiring it to the host its URL actually belongs to."""
    if "://" in url:
        ep_host = _extract_host(url)
    else:
        ep_host = _extract_host(base)
    hid = host_id(ep_host)
    if hid not in graph.nodes:
        graph.add_node(hid, "host", host=ep_host)
    nid = endpoint_id(url)
    graph.add_node(nid, "endpoint", url=url, host=ep_host, tags=tags or [])
    graph.add_edge(hid, nid, "reachable", 0.9)
    graph.add_edge(nid, hid, "reachable", 0.9)
    if evidence:
        graph.nodes[nid].evidence.extend(evidence)
    return nid



def _auth_bypasses_of(state: Dict) -> List[Dict]:
    auth = (state.get("phases") or {}).get("auth_bypass", {})
    if not isinstance(auth, dict):
        return []
    bypasses = []
    for key in ("path_bypasses", "cookie_bypasses", "header_bypasses", "method_bypasses"):
        for b in auth.get(key, []):
            if isinstance(b, dict):
                bypasses.append(b)
    return bypasses


def build_asset_graph(state: Dict, target: str = "") -> AssetGraph:
    """Build the asset topology from recon / crawl / mine / detect / auth state."""
    graph = AssetGraph(target)
    base = target or "http://localhost"
    host = _extract_host(base)
    host_node = graph.add_node(host_id(host), "host", host=host)

    recon = (state.get("phases") or {}).get("recon", {})

    for t in _techs_of(recon):
        tid = t.get("id", "") or t.get("name", "")
        if tid:
            tid = str(tid).lower()
            host_node.tags.append(tid)
        name = t.get("name", "")
        if name:
            host_node.evidence.append("tech:%s" % name)

    for s in _subdomains_of(recon).get("resolved", []):
        shost = str(s.get("domain", "")).strip().strip("/")
        if not shost or shost == host:
            continue
        snid = host_id(shost)
        graph.add_node(snid, "host", host=shost,
                       tags=["ip:%s" % s["ip"]] if s.get("ip") else [])
        graph.add_edge(host_id(host), snid, "subdomain", 0.7)
        graph.add_edge(snid, host_id(host), "subdomain", 0.7)

    for r in _subdomains_of(recon).get("http_reachable", []):
        shost = str(r.get("domain", "")).strip().strip("/")
        if not shost:
            continue
        snid = host_id(shost)
        graph.add_node(snid, "host", host=shost,
                       tags=["status:%s" % r.get("status", "")] if r.get("status") else [])
        node = graph.nodes[snid]
        if r.get("server"):
            node.evidence.append("server:%s" % r["server"])
        if r.get("title"):
            node.evidence.append("title:%s" % r["title"][:80])
        if r.get("tech"):
            node.tags.extend("proto:%s" % t for t in r["tech"])
        graph.add_edge(host_id(host), snid, "subdomain", 0.8)
        graph.add_edge(snid, host_id(host), "subdomain", 0.8)

    for p in _ports_of(recon):
        port = p.get("port", 0)
        if not port:
            continue
        svc = p.get("service", "")
        sid = port_id(host, port)
        graph.add_node(sid, "service", host=host, port=int(port),
                       tags=[str(svc)] if svc else [])
        graph.add_edge(host_id(host), sid, "runs_on", 1.0)
        graph.add_edge(sid, host_id(host), "runs_on", 1.0)

    for d in _dirs_of(recon):
        path = d.get("path", "")
        if not path:
            continue
        tags = []
        status = d.get("status")
        if status:
            tags.append("status:%s" % status)
        _add_endpoint(graph, base, _join_url(base, path), tags=tags)

    git = recon.get("git_leak", {})
    if isinstance(git, dict) and git.get("git_exposed"):
        _add_endpoint(graph, base, _join_url(base, "/.git"), tags=["git_leak"])

    crawl = (state.get("phases") or {}).get("crawl", {})
    for path, info in (crawl.get("endpoints", {}) or {}).items():
        if isinstance(info, dict):
            url = info.get("url") or _join_url(base, path)
            tags = ["spa_api"] if info.get("spa_api") else []
            nid = _add_endpoint(graph, base, url, tags=tags)
            for param in info.get("params", [])[:5]:
                graph.nodes[nid].evidence.append("param:%s" % param)

    mine = (state.get("phases") or {}).get("param_mine", {})
    for path, pd in (mine or {}).items():
        if not isinstance(pd, dict):
            continue
        _add_endpoint(graph, base, _join_url(base, path))

    for key, f in _findings_of(state).items():
        furl = f.get("url", "")
        if not furl:
            continue
        nid = endpoint_id(furl)
        if nid not in graph.nodes:
            _add_endpoint(graph, base, furl)
        graph.nodes[nid].evidence.append("finding:%s" % f.get("type", ""))

    for b in _auth_bypasses_of(state):
        burl = b.get("url")
        if not burl:
            continue
        nid = endpoint_id(burl)
        if nid in graph.nodes:
            graph.nodes[nid].evidence.append("auth_bypass")

    graph.interconnect_same_host()
    return graph


# ---------------------------------------------------------------------------
# Crown jewel inference
# ---------------------------------------------------------------------------

def infer_crown_jewels(state: Dict, target: str = "",
                       override: Optional[Sequence[str]] = None) -> List[str]:
    """Infer crown jewels from recon; an explicit override always wins."""
    if override:
        return [str(j) for j in override]

    base = target or "http://localhost"
    host = _extract_host(base)
    recon = (state.get("phases") or {}).get("recon", {})
    jewels: List[str] = []
    seen = set()

    def _add(node_id: str) -> None:
        if node_id and node_id not in seen:
            seen.add(node_id)
            jewels.append(node_id)

    for d in _dirs_of(recon):
        path = (d.get("path") or "").lower()
        if any(pattern in path for pattern in CROWN_JEWEL_PATH_PATTERNS):
            _add(endpoint_id(_join_url(base, d.get("path", path))))

    for p in _ports_of(recon):
        port = p.get("port", 0)
        if int(port) in CROWN_JEWEL_PORTS:
            _add(port_id(host, int(port)))

    for t in _techs_of(recon):
        tid = (t.get("id") or t.get("name") or "").lower()
        if any(tid.startswith(hv) for hv in HIGH_VALUE_TECHS):
            _add("tech:%s" % tid)

    git = recon.get("git_leak", {})
    if isinstance(git, dict) and git.get("git_exposed"):
        _add(endpoint_id(_join_url(base, "/.git")))

    crawl = (state.get("phases") or {}).get("crawl", {})
    for path, info in (crawl.get("endpoints", {}) or {}).items():
        low = path.lower()
        if any(pattern in low for pattern in CROWN_JEWEL_PATH_PATTERNS):
            if isinstance(info, dict):
                _add(endpoint_id(info.get("url") or _join_url(base, path)))
            else:
                _add(endpoint_id(_join_url(base, path)))

    return jewels


# ---------------------------------------------------------------------------
# Business value scoring (multi-factor)
# ---------------------------------------------------------------------------

def _role_score(url: str) -> float:
    path = (url or "").split("?", 1)[0].lower()
    best = 0.0
    for pattern, weight in ROLE_WEIGHTS.items():
        if pattern in path:
            best = max(best, weight)
    return best


def _port_score(port: int) -> float:
    entry = OPEN_PORT_ATTACK_MAP.get(int(port), {})
    return _PORT_RISK_SCORE.get(entry.get("risk", "low"), 0.1)


def _tech_risk(tech_id: str) -> float:
    entry = TECH_STACK_ATTACK_MAP.get(tech_id, {})
    return _TECH_RISK_SCORE.get(entry.get("risk", "low"), 0.2)


def score_assets(graph: AssetGraph, state: Dict,
                 weights: Optional[Dict[str, float]] = None) -> Dict[str, float]:
    """Multi-factor business value per asset node, normalized to 0..10."""
    w = dict(DEFAULT_VALUE_WEIGHTS)
    if weights:
        w.update(weights)

    techs_by_host: Dict[str, List[str]] = {}
    for node in graph.nodes.values():
        if node.kind == "host":
            techs_by_host[node.host] = list(node.tags)

    scores: Dict[str, float] = {}
    for nid, node in graph.nodes.items():
        score = 0.0

        if node.kind == "endpoint":
            score += w["role"] * _role_score(node.url)

        if node.kind == "service":
            score += w["port"] * _port_score(node.port)

        host_techs = techs_by_host.get(node.host, [])
        if host_techs:
            score += w["tech"] * max(_tech_risk(t) for t in host_techs)
            cve_count = sum(len(lookup_cves(t)) for t in host_techs)
            score += w["cve"] * min(cve_count, 3)

        if any(t.startswith("status:401") or t.startswith("status:403") for t in node.tags):
            score += w["auth"]

        if any(t == "git_leak" for t in node.tags):
            score += w["git"]

        finding_count = sum(1 for e in node.evidence if e.startswith("finding:"))
        if finding_count:
            score += w["finding"] * min(finding_count, 3)

        if any(e == "auth_bypass" for e in node.evidence):
            score += w["auth_bypass"]

        node.value = round(min(score, 10.0), 2)
        scores[nid] = node.value

    return scores


# ---------------------------------------------------------------------------
# Differential verification: predicted attack surface vs confirmed findings
# ---------------------------------------------------------------------------

def differential_verify(graph: AssetGraph, scores: Dict[str, float],
                        crown_jewels: Sequence[str], state: Dict) -> Dict:
    confirmed = [nid for nid, node in graph.nodes.items()
                 if any(e.startswith("finding:") for e in node.evidence)]
    high_value = [nid for nid in scores if scores[nid] >= 6.0]
    confirmed_set = set(confirmed)
    hit = [nid for nid in high_value if nid in confirmed_set]

    precision = len(hit) / len(high_value) if high_value else 0.0
    coverage = len(hit) / len(confirmed) if confirmed else 0.0

    reached = [j for j in crown_jewels if j in confirmed_set]
    auth_gated = sum(1 for nid, node in graph.nodes.items()
                     if any(e == "auth_bypass" for e in node.evidence))

    return {
        "expected_high_value": len(high_value),
        "confirmed_endpoints": len(confirmed),
        "confirmed_on_high_value": len(hit),
        "high_value_hit_rate": round(precision, 3),
        "coverage_of_confirmed": round(coverage, 3),
        "auth_bypass_assets": auth_gated,
        "crown_jewel_reached": reached,
    }


# ---------------------------------------------------------------------------
# BFS-to-crown-jewel chain ranking
# ---------------------------------------------------------------------------

def _node_label(graph: AssetGraph, nid: str) -> str:
    node = graph.nodes.get(nid)
    if not node:
        return nid
    if node.kind == "host":
        return "host:%s" % node.host
    if node.kind == "service":
        return "port:%d(%s)" % (node.port, node.tags[0] if node.tags else node.port)
    return node.url or nid


def bfs_to_crown_jewel(graph: AssetGraph, scores: Dict[str, float],
                       crown_jewels: Sequence[str],
                       start_nodes: Optional[Sequence[str]] = None,
                       top_n: int = 5) -> List[Dict]:
    """Ranked shortest paths from the proven attack surface to each crown jewel."""
    if not crown_jewels:
        return []

    if start_nodes is not None:
        starts = list(start_nodes)
    else:
        proven = [nid for nid, node in graph.nodes.items()
                  if node.kind == "endpoint"
                  and any(e.startswith("finding:") for e in node.evidence)]
        starts = proven if proven else [
            nid for nid, node in graph.nodes.items() if node.kind == "host"
        ]

    paths = graph.bfs(starts, list(crown_jewels), max_depth=8)
    ranked = []
    for path in paths:
        avg_value = sum(scores.get(nid, 0.0) for nid in path) / float(len(path))
        conf = graph.path_confidence(path)
        ranked.append({
            "nodes": list(path),
            "target": path[-1],
            "hops": len(path) - 1,
            "avg_value": round(avg_value, 2),
            "confidence": conf,
            "score": round(avg_value * (0.5 + conf) / 1.5, 2),
            "path_string": " -> ".join(_node_label(graph, nid) for nid in path),
        })
    ranked.sort(key=lambda x: -x["score"])
    return ranked[:top_n]


# ---------------------------------------------------------------------------
# Report section
# ---------------------------------------------------------------------------

def _recommendations(graph: AssetGraph, chains: List[Dict], diff: Dict) -> List[str]:
    recs: List[str] = []
    if diff.get("expected_high_value", 0) and not diff.get("confirmed_on_high_value", 0):
        recs.append("No predicted high-value endpoint has confirmed findings; re-test or expand coverage.")
    if diff.get("crown_jewel_reached"):
        recs.append("Crown jewel reached with confirmed findings: %s" % ", ".join(
            diff["crown_jewel_reached"]))
    for ch in chains[:3]:
        recs.append("Chain -> %s (%d hops): %s" % (
            ch["target"], ch["hops"], ch["path_string"]))
    if not chains:
        recs.append("No path to a crown jewel from current surface; consider protocol/lateral pivots.")
    if graph.summary().get("connected_components", 0) > 1:
        recs.append("Multiple disconnected asset components; pivot opportunities may exist between hosts.")
    return recs


def build_pipeline_report(graph: AssetGraph, scores: Dict[str, float],
                          crown_jewels: Sequence[str], chains: List[Dict],
                          diff: Dict, target: str = "") -> Dict:
    top_assets = []
    for nid, val in sorted(scores.items(), key=lambda x: -x[1])[:10]:
        node = graph.nodes[nid]
        top_assets.append({
            "id": nid,
            "kind": node.kind,
            "value": val,
            "url": node.url,
            "host": node.host,
            "port": node.port,
            "tags": node.tags[:6],
        })
    return {
        "target": target,
        "asset_graph": graph.summary(),
        "crown_jewels": list(crown_jewels),
        "top_assets": top_assets,
        "attack_chains": chains,
        "differential": diff,
        "recommendations": _recommendations(graph, chains, diff),
    }


def run_pipeline(state: Dict, target: str = "",
                 crown_jewels: Optional[Sequence[str]] = None,
                 weights: Optional[Dict[str, float]] = None,
                 top_chains: int = 5) -> Dict:
    """End-to-end pipeline: recon state -> ranked asset graph + crown-jewel chains."""
    graph = build_asset_graph(state, target)
    jewels = infer_crown_jewels(state, target, override=crown_jewels)
    scores = score_assets(graph, state, weights=weights)
    chains = bfs_to_crown_jewel(graph, scores, jewels, top_n=top_chains)
    diff = differential_verify(graph, scores, jewels, state)
    return build_pipeline_report(graph, scores, jewels, chains, diff, target=target)
