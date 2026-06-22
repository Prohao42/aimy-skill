import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

from tools.log_utils import get_logger

logger = get_logger("param_classifier")

@dataclass
class ParameterProfile:
    name: str
    role: str
    confidence: float
    data_type: str
    common_values: List[str] = field(default_factory=list)
    inferred_constraints: List[str] = field(default_factory=list)
    sample_values_seen: Set[str] = field(default_factory=set)
    attack_surfaces: List[str] = field(default_factory=list)


ROLE_PATTERNS = {
    "identifier": [
        (r"^(id|uid|pid|gid|sid|oid)$", 0.95),
        (r"^[\w]+_id$", 0.90),
        (r"^(uuid|guid|hash|slug|code|ref|key)$", 0.85),
        (r"^(article|post|user|order|product|account|item)(Id|ID)$", 0.95),
        (r"^[\w]+_(uuid|guid|hash|code)$", 0.80),
    ],
    "filter": [
        (r"^(q|query|search|filter|s|keyword)$", 0.95),
        (r"^(sort|order|by|order_by|sort_by)$", 0.90),
        (r"^(page|offset|limit|per_page|count|from|to)$", 0.95),
        (r"^(status|state|type|category|tag|group)$", 0.85),
        (r"^(include|exclude|fields|select|expand)$", 0.80),
    ],
    "action": [
        (r"^(action|op|operation|cmd|command|do|task|job)$", 0.90),
        (r"^(method|_method|func|function|fn)$", 0.85),
        (r"^(mode|step|stage|phase)$", 0.75),
        (r"^(process|workflow|transition)$", 0.70),
    ],
    "auth": [
        (r"^(token|access_token|refresh_token|api_key|apikey)$", 0.95),
        (r"^(session|session_id|sid|sess)$", 0.90),
        (r"^(jwt|bearer|auth|authorization)$", 0.95),
        (r"^(password|passwd|pass|secret|credential)$", 0.95),
        (r"^(csrf|_csrf|csrf_token|_token|authenticity_token)$", 0.90),
    ],
    "config": [
        (r"^(lang|locale|language|tz|timezone)$", 0.85),
        (r"^(format|response_format|output|view)$", 0.80),
        (r"^(version|v|api_version)$", 0.80),
        (r"^(debug|verbose|pretty)$", 0.85),
        (r"^(callback|jsonp|_callback)$", 0.90),
    ],
    "content": [
        (r"^(title|name|label|headline)$", 0.80),
        (r"^(content|body|text|description|summary)$", 0.85),
        (r"^(url|link|href|src|image|avatar)$", 0.75),
        (r"^(email|phone|address|website)$", 0.80),
        (r"^(note|comment|message|reply)$", 0.75),
    ],
    "financial": [
        (r"^(price|amount|cost|fee|total|subtotal)$", 0.95),
        (r"^(discount|coupon|promo|voucher|code)$", 0.90),
        (r"^(balance|credit|debit|payment|charge)$", 0.90),
        (r"^(quantity|count|num|number|qty)$", 0.80),
        (r"^(currency|symbol|unit)$", 0.75),
    ],
    "boolean": [
        (r"^(is_|has_|can_|does_|should_|enable|disable)", 0.80),
        (r"^(active|enabled|disabled|visible|hidden|deleted)$", 0.90),
        (r"^(flag|toggle|switch|on|off)$", 0.80),
        (r"^(admin|verified|confirmed|approved|published)$", 0.85),
    ],
}

TYPE_INFERENCE = [
    (r"^\d+$", "integer"),
    (r"^[\d.]+$", "float"),
    (r"^[\w.+-]+@[\w-]+\.\w+$", "email"),
    (r"^\d{4}-\d{2}-\d{2}", "date"),
    (r"^(true|false|0|1)$", "boolean"),
    (r"^[\da-f]{8,}$", "hash"),
    (r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$", "jwt"),
]


class ParamClassifier:
    def __init__(self):
        self._profiles: Dict[str, ParameterProfile] = {}

    def classify(self, name: str, sample_value: str = "",
                 url_path: str = "", method: str = "GET") -> ParameterProfile:
        cached = self._profiles.get(name)
        if cached:
            if sample_value and sample_value not in cached.sample_values_seen:
                cached.sample_values_seen.add(sample_value)
            return cached

        role, confidence = self._match_role(name)
        data_type = self._infer_type(sample_value)
        constraints = self._infer_constraints(name, url_path, method)
        surfaces = self._attack_surfaces(role, name, data_type)

        profile = ParameterProfile(
            name=name,
            role=role,
            confidence=confidence,
            data_type=data_type,
            common_values=[],
            inferred_constraints=constraints,
            sample_values_seen={sample_value} if sample_value else set(),
            attack_surfaces=surfaces,
        )
        self._profiles[name] = profile
        return profile

    def classify_batch(self, params: Dict[str, str],
                       url_path: str = "",
                       method: str = "GET") -> List[ParameterProfile]:
        return [
            self.classify(k, v, url_path, method)
            for k, v in params.items()
        ]

    def _match_role(self, name: str) -> Tuple[str, float]:
        best_role = "unknown"
        best_conf = 0.0

        for role, patterns in ROLE_PATTERNS.items():
            for pattern, confidence in patterns:
                if re.search(pattern, name):
                    if confidence > best_conf:
                        best_conf = confidence
                        best_role = role
                        break

        return best_role, best_conf

    def _infer_type(self, value: str) -> str:
        if not value:
            return "unknown"
        for pattern, dtype in TYPE_INFERENCE:
            if re.match(pattern, value):
                return dtype
        return "text"

    def _infer_constraints(self, name: str, url_path: str,
                           method: str) -> List[str]:
        constraints = []

        if re.search(r"id$|_id$", name, re.I):
            constraints.append("likely_numeric_or_uuid")
        if method in ("POST", "PUT", "PATCH"):
            constraints.append("writable")
        if method == "GET":
            constraints.append("readable")
        if name in ("page", "limit", "offset", "per_page"):
            constraints.append("bounded")
        if name in ("sort", "order", "order_by"):
            constraints.append("enum:asc,desc")
        if re.search(r"(password|secret|token|key)", name, re.I):
            constraints.append("write_only")

        return constraints

    def _attack_surfaces(self, role: str, name: str,
                         data_type: str) -> List[str]:
        surfaces = []

        if role == "identifier":
            surfaces.append("idor")
            surfaces.append("bola")
            if data_type in ("integer", "hash"):
                surfaces.append("enumeration")
        if role == "filter":
            surfaces.append("sqli")
            surfaces.append("nosqli")
            surfaces.append("injection")
        if role == "action":
            surfaces.append("command_injection")
            surfaces.append("ssrf")
            surfaces.append("path_traversal")
        if role == "auth":
            surfaces.append("token_manipulation")
            surfaces.append("auth_bypass")
        if role == "config":
            surfaces.append("ssrf" if "callback" in name.lower() else "injection")
        if role == "financial":
            surfaces.append("price_manipulation")
            surfaces.append("integer_overflow")
        if role == "boolean":
            surfaces.append("authorization_bypass")
        if role == "content":
            if data_type == "email":
                surfaces.append("email_injection")
            surfaces.append("xss")
            surfaces.append("ssti")

        return surfaces

    def get_profile(self, name: str) -> Optional[ParameterProfile]:
        return self._profiles.get(name)

    def clear(self):
        self._profiles.clear()
