import re, json, copy
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("constraint_graph")


@dataclass
class Constraint:
    type: str
    description: str
    params: List[str] = field(default_factory=list)
    expression: Optional[str] = None
    severity: str = "medium"


@dataclass
class Relationship:
    source_param: str
    target_param: str
    relation: str
    confidence: float = 0.5


class ConstraintGraph:
    def __init__(self):
        self.constraints: List[Constraint] = []
        self.relationships: List[Relationship] = []
        self._param_values: Dict[str, List[str]] = {}
        self._param_names: Set[str] = set()
        self._tested_params: Set[str] = set()

    def ingest_request(self, url: str, body: Optional[str],
                       params: Dict[str, str] = None):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for k, vals in qs.items():
            for v in vals:
                self._add_param_value(k, v)
        if body:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    for k, v in data.items():
                        self._add_param_value(k, str(v))
            except (json.JSONDecodeError, ValueError):
                for m in re.finditer(r'([\w_]+)=([^&\s"]+)', body):
                    self._add_param_value(m.group(1), m.group(2))
        if params:
            for k, v in params.items():
                self._add_param_value(k, v)

    def ingest_response(self, status: int, body: str):
        if status not in (200, 201):
            return
        try:
            data = json.loads(body)
            self._extract_from_json(data, "")
        except (json.JSONDecodeError, ValueError):
            self._extract_params_from_html(body)

    def _add_param_value(self, name: str, value: str):
        name = name.strip()
        value = value.strip()
        if not name or not value:
            return
        if name not in self._param_values:
            self._param_values[name] = []
        if value not in self._param_values[name][:20]:
            self._param_values[name].append(value)
        self._param_names.add(name)

    def _extract_from_json(self, data: Any, prefix: str):
        if isinstance(data, dict):
            numerical_fields = {"price", "amount", "total", "cost", "fee",
                                "discount", "quantity", "qty", "count",
                                "balance", "credit", "limit", "max", "min"}
            for k, v in data.items():
                self._param_names.add(k)
                if isinstance(v, (int, float)) and k.lower() in numerical_fields:
                    self._add_param_value(k, str(v))
                elif isinstance(v, str):
                    self._add_param_value(k, v)
                self._extract_from_json(v, f"{prefix}.{k}" if prefix else k)
        elif isinstance(data, list) and len(data) > 0:
            for item in data[:5]:
                self._extract_from_json(item, prefix)

    def _extract_params_from_html(self, html: str):
        for m in re.finditer(r'name=["\']([\w_]+)["\']\s*value=["\']([^"\']*)["\']',
                             html, re.IGNORECASE):
            self._add_param_value(m.group(1), m.group(2))
        for m in re.finditer(r'["\']([\w_]+)["\']\s*:\s*["\']?([^"\'}\s,]+)',
                             html):
            name = m.group(1)
            val = m.group(2).strip("\"'")
            if len(name) > 1 and len(val) < 100:
                self._add_param_value(name, val)

    def detect_numerical_relationships(self) -> List[Relationship]:
        found = []
        numeric_params = {}
        for name, vals in self._param_values.items():
            nums = []
            for v in vals:
                try:
                    nums.append(float(v))
                except (ValueError, TypeError):
                    pass
            if nums:
                numeric_params[name] = nums

        names = list(numeric_params.keys())
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                a_name, a_vals = names[i], numeric_params[names[i]]
                b_name, b_vals = names[j], numeric_params[names[j]]
                if abs(len(a_vals) - len(b_vals)) > 2:
                    continue
                min_len = min(len(a_vals), len(b_vals))
                for pair_idx in range(min_len):
                    av, bv = a_vals[pair_idx], b_vals[pair_idx]
                    if bv != 0 and abs(av * 2 - bv) < 0.01:
                        found.append(Relationship(
                            a_name, b_name, "a*2=b", 0.8))
                    if bv != 0 and abs(av * bv - 1) < 0.01:
                        found.append(Relationship(
                            a_name, b_name, "a*b=1", 0.8))
                for off in range(1, len(a_vals)):
                    pass
        self.relationships.extend(found)
        return found

    def detect_constraints(self) -> List[Constraint]:
        constraints = []
        price_like = {"price", "amount", "total", "cost", "fee", "charge"}
        quantity_like = {"qty", "quantity", "count"}
        limit_like = {"limit", "max", "min", "cap"}

        found_price = self._param_names & price_like
        found_qty = self._param_names & quantity_like
        found_limit = self._param_names & limit_like

        if found_price:
            p = list(found_price)[0]
            constraints.append(Constraint(
                type="price_tamper",
                description=f"Parameter '{p}' may control pricing",
                params=[p],
                severity="high"))
            self._add_mutation_suggestion(p, ["0", "-1", "999999", "0.01"])

        if found_price and found_qty:
            constraints.append(Constraint(
                type="price_qty_mismatch",
                description=f"Price ({','.join(found_price)}) and quantity "
                            f"({','.join(found_qty)}) detected—test total calc",
                params=list(found_price | found_qty),
                severity="high"))

        for param in self._param_names:
            if "percent" in param.lower() or "discount" in param.lower():
                constraints.append(Constraint(
                    type="percentage_abuse",
                    description=f"Percentage/discount param '{param}'",
                    params=[param],
                    severity="high"))
                self._add_mutation_suggestion(param,
                    ["100", "-100", "9999", "0", "1e10"])

            if any(k in param.lower() for k in ("admin", "role", "is_",
                                                  "permission", "group")):
                constraints.append(Constraint(
                    type="mass_assignment",
                    description=f"Privilege-related param '{param}'",
                    params=[param],
                    severity="critical"))

        self.constraints = constraints
        return constraints

    def _add_mutation_suggestion(self, param: str, values: List[str]):
        if not hasattr(self, '_mutation_suggestions'):
            self._mutation_suggestions: Dict[str, List[str]] = {}
        self._mutation_suggestions.setdefault(param, [])
        for v in values:
            if v not in self._mutation_suggestions[param]:
                self._mutation_suggestions[param].append(v)

    def get_mutation_suggestions(self) -> Dict[str, List[str]]:
        return getattr(self, '_mutation_suggestions', {})

    def summary(self) -> Dict:
        return {
            "params_discovered": len(self._param_names),
            "param_values": {k: v[:5] for k, v in self._param_values.items()},
            "constraints": [{"type": c.type, "desc": c.description,
                            "params": c.params, "severity": c.severity}
                           for c in self.constraints],
            "relationships": [{"a": r.source_param, "b": r.target_param,
                              "relation": r.relation, "confidence": r.confidence}
                             for r in self.relationships],
            "mutation_suggestions": self.get_mutation_suggestions(),
        }


class ConstraintBreaker:
    def __init__(self, graph: ConstraintGraph):
        self.graph = graph

    def generate_break_tests(self, url: str, param: str) -> List[Dict]:
        tests = []
        suggestions = self.graph.get_mutation_suggestions()
        if param in suggestions:
            for val in suggestions[param]:
                tests.append({
                    "technique": "constraint_break",
                    "param": param,
                    "value": val,
                    "url": url,
                    "rationale": f"Suggested mutation for '{param}'",
                })
        param_lower = param.lower()
        if param_lower in ("price", "amount", "total", "cost", "fee"):
            for tactic in [
                ("numeric_overflow", "999999999"),
                ("negative", "-1"),
                ("decimal_injection", "0.01"),
                ("zero", "0"),
                ("negative_large", "-999999"),
                ("scientific", "1e10"),
                ("null", "null"),
                ("string_injection", "true"),
            ]:
                tests.append({
                    "technique": "price_manipulation",
                    "variant": tactic[0],
                    "param": param,
                    "value": tactic[1],
                    "url": url,
                })
        if any(k in param_lower for k in ("qty", "quantity", "count")):
            for tactic in [
                ("negative", "-1"),
                ("zero", "0"),
                ("overflow", "999999"),
                ("fraction", "0.5"),
                ("string", "null"),
            ]:
                tests.append({
                    "technique": "quantity_abuse",
                    "variant": tactic[0],
                    "param": param,
                    "value": tactic[1],
                    "url": url,
                })
        return tests


def check(url: str, param: str = None, sess=None, timeout: float = 10.0) -> Dict:
    import requests
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    result = {
        "vulnerable": False,
        "findings": [],
        "graph": {},
    }
    graph = ConstraintGraph()
    try:
        r = sess.get(url, timeout=timeout)
        graph.ingest_request(url, None)
        graph.ingest_response(r.status_code, r.text)
    except Exception:
        pass
    graph.detect_numerical_relationships()
    graph.detect_constraints()
    result["graph"] = graph.summary()
    if param:
        breaker = ConstraintBreaker(graph)
        tests = breaker.generate_break_tests(url, param)
        result["tests"] = tests
    return result
