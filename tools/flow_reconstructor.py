import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

from tools.log_utils import get_logger

logger = get_logger("flow_reconstructor")


@dataclass
class ResourceModel:
    name: str
    path_pattern: str
    methods: List[str]
    id_param: str = ""
    parent_resource: str = ""
    relationships: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    sensitive_fields: List[str] = field(default_factory=list)
    auth_required: bool = False
    is_collection: bool = False


@dataclass
class AuthBoundary:
    url: str
    type: str
    methods_available: List[str] = field(default_factory=list)


@dataclass
class BusinessFlow:
    resources: Dict[str, ResourceModel] = field(default_factory=dict)
    auth_boundaries: List[AuthBoundary] = field(default_factory=list)
    workflows: List[Dict] = field(default_factory=list)
    inferred_relationships: List[Tuple[str, str]] = field(default_factory=list)


class FlowReconstructor:
    def __init__(self):
        self.flow = BusinessFlow()

    def ingest_crawl_result(self, crawl_result: Dict):
        endpoints = crawl_result.get("endpoints", {})
        for path, info in endpoints.items():
            self._process_endpoint(path, info)

        api_list = crawl_result.get("api_endpoints", [])
        for api_path in api_list:
            if api_path not in endpoints:
                self._process_api_path(api_path)

        spa_crawl = crawl_result.get("spa_crawl", {})
        if spa_crawl:
            for api_route in spa_crawl.get("api_routes", []):
                if api_route not in self.flow.resources:
                    self._process_api_path(api_route)
                    self.flow.resources[api_route].is_collection = True

    def ingest_response_analysis(self, url: str, analysis):
        path = urlparse(url).path
        resource = self._find_resource(path)
        if resource and analysis:
            resource.fields = list(set(
                resource.fields + [f.name for f in analysis.fields]
            ))
            resource.sensitive_fields = list(set(
                resource.sensitive_fields + analysis.sensitive_fields
            ))

    def _process_endpoint(self, path: str, info: Dict):
        parsed = urlparse(info.get("url", path))
        clean_path = parsed.path.rstrip("/") or "/"
        methods = info.get("methods", ["GET"])

        resource = self._path_to_resource(clean_path)
        resource.methods = list(set(resource.methods + methods))
        resource.is_collection = not self._has_id_param(clean_path)

        for p in info.get("params", []):
            if p not in resource.fields:
                resource.fields.append(p)

    def _process_api_path(self, path: str):
        resource = self._path_to_resource(path)
        resource.is_collection = not self._has_id_param(path)

    def _path_to_resource(self, path: str) -> ResourceModel:
        if path in self.flow.resources:
            return self.flow.resources[path]

        parts = [p for p in path.split("/") if p]
        resource_name = self._infer_resource_name(parts)
        id_param = self._find_id_param(parts)
        parent = self._find_parent(parts)

        model = ResourceModel(
            name=resource_name,
            path_pattern=path,
            methods=["GET"],
            id_param=id_param,
            parent_resource=parent,
        )
        self.flow.resources[path] = model

        if parent:
            parent_path = "/" + "/".join(
                parts[:parts.index(id_param) - 1] if id_param in parts
                else parts[:-1]
            ).lstrip("/")
            if parent_path:
                rel = (parent_path, path)
                if rel not in self.flow.inferred_relationships:
                    self.flow.inferred_relationships.append(rel)

        return model

    def _find_resource(self, path: str) -> Optional[ResourceModel]:
        exact = self.flow.resources.get(path)
        if exact:
            return exact
        for p, r in self.flow.resources.items():
            if self._path_matches(p, path):
                return r
        return None

    def _path_matches(self, pattern: str, path: str) -> bool:
        p_parts = pattern.strip("/").split("/")
        path_parts = path.strip("/").split("/")
        if len(p_parts) != len(path_parts):
            return False
        for p, a in zip(p_parts, path_parts):
            if p.startswith(":") or re.match(r"^[\d{8}\-]{2,}$", p):
                continue
            if p != a:
                return False
        return True

    def detect_auth_boundaries(self, sess):
        from tools.response_analyzer import ResponseAnalyzer
        analyzer = ResponseAnalyzer()

        for path, resource in self.flow.resources.items():
            url = f"http://localhost{path}"
            try:
                r = sess.get(url, timeout=5)
                analysis = analyzer.analyze(url, r.status_code,
                                             dict(r.headers), r.text)
                if r.status_code in (401, 403):
                    self.flow.auth_boundaries.append(
                        AuthBoundary(url=url, type="unauthorized" if r.status_code == 401 else "forbidden")
                    )
                    resource.auth_required = True
                elif r.status_code == 200:
                    resource.auth_required = False
                    self.ingest_response_analysis(url, analysis)
            except Exception:
                pass

    @staticmethod
    def _infer_resource_name(parts: List[str]) -> str:
        for part in reversed(parts):
            if not re.match(r"^[\d{8}\-]{2,}$", part) and not part.isdigit():
                return part
        return parts[-1] if parts else "root"

    @staticmethod
    def _find_id_param(parts: List[str]) -> str:
        for i, part in enumerate(parts):
            if part.isdigit() or re.match(r"^[\da-f-]{36}$", part):
                return parts[i - 1] + "_id" if i > 0 else "id"
            if part.startswith(":") or part.startswith("{"):
                return part.lstrip(":{")
        return ""

    @staticmethod
    def _find_parent(parts: List[str]) -> str:
        for i, part in enumerate(parts):
            if part.isdigit() and i > 0:
                return parts[i - 1]
        return ""

    @staticmethod
    def _has_id_param(path: str) -> bool:
        parts = path.strip("/").split("/")
        for part in parts:
            if part.isdigit() or re.match(r"^[\da-f-]{36}$", part):
                return True
            if part.startswith(":") or part.startswith("{"):
                return True
        return False
