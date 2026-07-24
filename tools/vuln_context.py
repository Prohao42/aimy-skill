import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("vuln_context")


@dataclass
class VulnContext:
    dbms: Optional[str] = None
    os_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    waf_name: Optional[str] = None
    waf_bypasses: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    discovered_endpoints: List[str] = field(default_factory=list)
    discovered_params: List[str] = field(default_factory=list)
    admin_cookies: List[str] = field(default_factory=list)
    debug_endpoints: List[str] = field(default_factory=list)
    has_auth_bypass: bool = False
    has_file_upload: bool = False
    has_admin_panel: bool = False
    has_graphql: bool = False
    has_debug_mode: bool = False
    ssrf_cloud_creds: List[str] = field(default_factory=list)
    lfi_readable_paths: List[str] = field(default_factory=list)
    sqli_safe_chars: List[str] = field(default_factory=list)
    ssti_engine: Optional[str] = None
    discovered_versions: Dict[str, str] = field(default_factory=dict)

    def merge(self, other: "VulnContext"):
        self.dbms = self.dbms or other.dbms
        self.os_type = self.os_type or other.os_type
        self.cloud_provider = self.cloud_provider or other.cloud_provider
        self.waf_name = self.waf_name or other.waf_name
        self.ssti_engine = self.ssti_engine or other.ssti_engine
        self.has_auth_bypass = self.has_auth_bypass or other.has_auth_bypass
        self.has_file_upload = self.has_file_upload or other.has_file_upload
        self.has_admin_panel = self.has_admin_panel or other.has_admin_panel
        self.has_graphql = self.has_graphql or other.has_graphql
        self.has_debug_mode = self.has_debug_mode or other.has_debug_mode
        self.waf_bypasses = list(set(self.waf_bypasses + other.waf_bypasses))
        self.frameworks = list(set(self.frameworks + other.frameworks))
        self.discovered_endpoints = list(set(self.discovered_endpoints + other.discovered_endpoints))
        self.discovered_params = list(set(self.discovered_params + other.discovered_params))
        self.admin_cookies = list(set(self.admin_cookies + other.admin_cookies))
        self.debug_endpoints = list(set(self.debug_endpoints + other.debug_endpoints))
        self.ssrf_cloud_creds = list(set(self.ssrf_cloud_creds + other.ssrf_cloud_creds))
        self.lfi_readable_paths = list(set(self.lfi_readable_paths + other.lfi_readable_paths))
        self.sqli_safe_chars = list(set(self.sqli_safe_chars + other.sqli_safe_chars))
        self.discovered_versions.update(other.discovered_versions)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v}


class ContextMemory:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.context = VulnContext()
                    cls._instance._storage = None
                    cls._instance._auto_save = True
        return cls._instance

    def __init__(self):
        pass

    def set_storage(self, storage, auto_save: bool = True):
        self._storage = storage
        self._auto_save = auto_save

    def restore(self, fields: Dict[str, Any]):
        with self._lock:
            for k, v in fields.items():
                if hasattr(self.context, k) and v is not None:
                    existing = getattr(self.context, k)
                    if isinstance(existing, list) and isinstance(v, list):
                        setattr(self.context, k, list(set(existing + v)))
                    elif isinstance(existing, dict) and isinstance(v, dict):
                        existing.update(v)
                    elif not existing:
                        setattr(self.context, k, v)

    def update(self, **kwargs):
        with self._lock:
            changed = {}
            for k, v in kwargs.items():
                if hasattr(self.context, k) and v is not None:
                    existing = getattr(self.context, k)
                    if isinstance(existing, list):
                        if isinstance(v, list):
                            new_val = list(set(existing + v))
                            setattr(self.context, k, new_val)
                            if new_val != existing:
                                changed[k] = new_val
                        else:
                            new_val = list(set(existing + [v]))
                            setattr(self.context, k, new_val)
                            if new_val != existing:
                                changed[k] = new_val
                    elif isinstance(existing, dict):
                        old = dict(existing)
                        existing.update(v)
                        if existing != old:
                            changed[k] = dict(existing)
                    else:
                        if v != existing:
                            setattr(self.context, k, v)
                            changed[k] = v
            if changed and self._storage and self._auto_save:
                try:
                    self._storage.save_vuln_context(changed)
                except Exception as e:
                    logger.debug("storage save vuln_context: %s", e)

    def get(self) -> VulnContext:
        with self._lock:
            return self.context

    def get_dict(self) -> dict:
        with self._lock:
            return self.context.to_dict()

    def payload_hint(self, vuln_type: str) -> Optional[str]:
        c = self.context
        if vuln_type == "sqli":
            if c.dbms:
                return c.dbms
        if vuln_type == "ssti":
            if c.ssti_engine:
                return c.ssti_engine
        if vuln_type == "ssrf":
            if c.cloud_provider:
                return c.cloud_provider
        if vuln_type == "lfi":
            if c.os_type:
                return "windows" if "windows" in (c.os_type or "").lower() else "linux"
        return None

    def suggest_waf_bypass(self) -> Optional[str]:
        if not self.context.waf_name:
            return None
        if self.context.waf_bypasses:
            return self.context.waf_bypasses[-1]
        return None

    def has_admin_access(self) -> bool:
        return bool(self.context.admin_cookies) or self.context.has_auth_bypass

    def has_cloud_creds(self) -> bool:
        return bool(self.context.ssrf_cloud_creds)

    def best_exploit_path(self) -> List[str]:
        c = self.context
        paths = []
        if c.ssrf_cloud_creds:
            paths.append("ssrf_to_cloud_pwn")
        if c.lfi_readable_paths and "log" in " ".join(c.lfi_readable_paths):
            paths.append("lfi_log_poison_rce")
        if c.sqli_safe_chars:
            paths.append("sqli_to_os_shell")
        if c.has_admin_panel and c.has_auth_bypass:
            paths.append("auth_bypass_to_admin")
        if c.has_debug_mode:
            paths.append("debug_to_rce")
        return paths
