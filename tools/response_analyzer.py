import re
import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse

from tools.log_utils import get_logger

logger = get_logger("response_analyzer")

SENSITIVE_FIELD_PATTERNS = {
    "credential": re.compile(
        r"(password|passwd|secret|token|apikey|api_key|auth|credential)", re.I
    ),
    "pii": re.compile(
        r"(email|ssn|phone|address|birth|id_card|credit_card|cvv|pin)", re.I
    ),
    "financial": re.compile(r"(price|amount|balance|payment|salary|fee|discount)", re.I),
    "identifier": re.compile(
        r"(id$|_id|uuid|guid|hash|slug|code|key|ref)", re.I
    ),
    "role": re.compile(
        r"(role|permission|group|level|type|status|is_admin|is_active)", re.I
    ),
    "timestamp": re.compile(
        r"(created_at|updated_at|timestamp|date|time|expires|ttl)", re.I
    ),
}


@dataclass
class FieldAnalysis:
    path: str
    name: str
    value_type: str
    sample_value: Any
    is_sensitive: bool = False
    sensitivity_type: str = ""
    is_nullable: bool = False
    is_collection: bool = False
    value_range: Optional[Dict] = None


@dataclass
class ResponseAnalysis:
    status: int
    content_type: str
    body_length: int
    is_json: bool = False
    is_html: bool = False
    is_error: bool = False
    error_type: str = ""
    fields: List[FieldAnalysis] = field(default_factory=list)
    sensitive_fields: List[str] = field(default_factory=list)
    data_structure: Dict = field(default_factory=dict)
    inferred_resource: str = ""
    pagination: Optional[Dict] = None
    endpoints_linked: List[str] = field(default_factory=list)


class ResponseAnalyzer:
    def __init__(self):
        self._cache: Dict[str, ResponseAnalysis] = {}

    def analyze(self, url: str, status: int, headers: Dict,
                body: str) -> ResponseAnalysis:
        ct = headers.get("Content-Type", "")
        body_len = len(body)

        analysis = ResponseAnalysis(
            status=status,
            content_type=ct,
            body_length=body_len,
            is_json="json" in ct,
            is_html="html" in ct,
            is_error=status >= 400,
            error_type=self._classify_error(status, body),
        )

        if analysis.is_json and body:
            analysis = self._analyze_json(analysis, body, url)
        elif analysis.is_html and body:
            analysis = self._analyze_html(analysis, body)

        analysis.inferred_resource = self._infer_resource(url)
        self._cache[url] = analysis
        return analysis

    def _analyze_json(self, analysis: ResponseAnalysis, body: str,
                      url: str) -> ResponseAnalysis:
        try:
            data = json.loads(body)
            analysis.data_structure = self._infer_structure(data)

            if isinstance(data, list):
                analysis.pagination = {"type": "list", "count": len(data)}
                if data:
                    analysis.fields = self._extract_fields(data[0], "$")
            elif isinstance(data, dict):
                analysis.fields = self._extract_fields(data, "$")
                analysis.pagination = self._detect_pagination(data)
                analysis.endpoints_linked = self._extract_endpoints(data, url)
            else:
                analysis.fields = [FieldAnalysis(
                    path="$", name="root",
                    value_type=type(data).__name__,
                    sample_value=str(data)[:100],
                )]

            analysis.sensitive_fields = [
                f.path for f in analysis.fields if f.is_sensitive
            ]
        except json.JSONDecodeError:
            pass

        return analysis

    def _analyze_html(self, analysis: ResponseAnalysis, body: str) -> ResponseAnalysis:
        fields = []

        for m in re.finditer(
            r'<input[^>]*name=["\']([^"\']+)["\']', body, re.I
        ):
            fields.append(FieldAnalysis(
                path=f"form.input.{m.group(1)}",
                name=m.group(1),
                value_type="html_input",
                sample_value="",
                is_nullable=True,
            ))

        for m in re.finditer(
            r'data-([\w-]+)=["\']([^"\']*)["\']', body, re.I
        ):
            fields.append(FieldAnalysis(
                path=f"data.{m.group(1)}",
                name=m.group(1),
                value_type="data_attr",
                sample_value=m.group(2)[:50],
            ))

        analysis.fields = fields

        error_matches = re.findall(
            r'(error|warning|alert|message|notice)["\']?\s*[:=]\s*["\']?([^"\'<>{}\[\]|]+)',
            body, re.I
        )
        if error_matches:
            analysis.is_error = True

        return analysis

    def _extract_fields(self, data: Any, path: str,
                        depth: int = 0) -> List[FieldAnalysis]:
        if depth > 5:
            return []

        fields = []
        if isinstance(data, dict):
            for key, val in data.items():
                child_path = f"{path}.{key}"
                f = FieldAnalysis(
                    path=child_path,
                    name=str(key),
                    value_type=self._type_of(val),
                    sample_value=self._sample(val),
                    is_nullable=val is None,
                    is_collection=isinstance(val, (list, set, tuple)),
                )

                for sens_type, pattern in SENSITIVE_FIELD_PATTERNS.items():
                    if pattern.search(key):
                        f.is_sensitive = True
                        f.sensitivity_type = sens_type
                        break

                fields.append(f)
                if isinstance(val, dict):
                    fields.extend(self._extract_fields(val, child_path, depth + 1))
                elif isinstance(val, list) and val and isinstance(val[0], dict):
                    fields.extend(
                        self._extract_fields(val[0], f"{child_path}[]", depth + 1)
                    )

        return fields

    def _type_of(self, val: Any) -> str:
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "boolean"
        if isinstance(val, int):
            return "integer"
        if isinstance(val, float):
            return "float"
        if isinstance(val, str):
            if re.match(r"^\d{4}-\d{2}-\d{2}", val):
                return "date"
            if re.match(r"^\d{4}-\d{2}-\d{2}T", val):
                return "datetime"
            if re.match(r"^[\w-]+@[\w-]+\.\w+", val):
                return "email"
            if len(val) > 100:
                return "text(long)"
            return "text"
        if isinstance(val, list):
            return f"list[{len(val)}]"
        if isinstance(val, dict):
            return f"object[{len(val)}]"
        return type(val).__name__

    def _sample(self, val: Any, max_len: int = 80) -> str:
        if val is None:
            return "null"
        s = str(val)
        return s[:max_len] + "..." if len(s) > max_len else s

    def _infer_structure(self, data: Any) -> Dict:
        if isinstance(data, dict):
            return {k: self._infer_structure(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self._infer_structure(data[0])] if data else ["unknown"]
        if isinstance(data, bool):
            return "boolean"
        if isinstance(data, int):
            return "number"
        if isinstance(data, float):
            return "number"
        return "string"

    def _detect_pagination(self, data: Dict) -> Optional[Dict]:
        for key in ("page", "pages", "offset", "limit", "total", "count",
                     "has_more", "next_page", "next", "per_page"):
            if key in data:
                return {"field": key, "value": data[key]}
        return None

    def _extract_endpoints(self, data: Dict, base_url: str) -> List[str]:
        endpoints = []
        for key in ("url", "link", "href", "next", "prev", "self",
                     "first", "last"):
            if key in data and isinstance(data[key], str):
                endpoints.append(data[key])
        for key in ("items", "data", "results", "records"):
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, dict):
                        for link_key in ("url", "link", "href", "id"):
                            if link_key in item:
                                val = item[link_key]
                                if isinstance(val, str) and val.startswith("/"):
                                    endpoints.append(val)
        return endpoints

    @staticmethod
    def _classify_error(status: int, body: str) -> str:
        if status == 401:
            return "unauthorized"
        if status == 403:
            return "forbidden"
        if status == 404:
            return "not_found"
        if status == 405:
            return "method_not_allowed"
        if status == 500:
            return "internal_error"
        if status == 502:
            return "bad_gateway"
        if status == 429:
            return "rate_limited"
        if status >= 400:
            if "sql" in body.lower() or "mysql" in body.lower():
                return "sql_error"
            if "stack trace" in body.lower() or "exception" in body.lower():
                return "exception"
            if "traceback" in body.lower():
                return "traceback"
            return f"http_{status}"
        return ""

    @staticmethod
    def _infer_resource(url: str) -> str:
        parsed = urlparse(url)
        parts = [p for p in parsed.path.split("/") if p]
        for part in reversed(parts):
            if not re.match(r"^[\d{8}\-]{2,}$", part) and not part.isdigit():
                return part
            return parts[-2] if len(parts) >= 2 else ""
        return ""
