"""
Context Memory: Shared state system for cross-module intelligence sharing.

Remembers discovered information and reuses it across detection modules:
  - Database type discovered → subsequent SQLi uses matching dialect
  - Web framework identified → subsequent SSTI uses matching payloads
  - WAF fingerprint detected → subsequent bypasses use matching strategies
  - Credentials recovered → subsequent tests use found credentials
  - Internal services discovered → subsequent scans test those services

Memory is session-scoped and thread-safe.
"""
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("context_memory")


@dataclass
class MemoryEntry:
    key: str
    value: any
    source: str
    confidence: float
    timestamp: float
    ttl: float = 3600.0
    tags: List[str] = field(default_factory=list)

    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "age_seconds": round(time.time() - self.timestamp, 1),
            "tags": self.tags,
        }


class ContextMemory:
    """
    Thread-safe context memory for cross-module intelligence sharing.

    Usage:
        memory = ContextMemory()
        
        # Store discovered info
        memory.set("dbms", "MySQL 8.0", source="sqli_detector", confidence=0.90)
        memory.set("framework", "Spring Boot", source="tech_fingerprint", confidence=0.85)
        memory.set("waf", "Cloudflare", source="waf_bypass", confidence=0.80)
        memory.set("creds", {"user": "admin", "pass": "123456"}, source="auth_bypass")
        
        # Retrieve for use in other modules
        dbms = memory.get("dbms")
        framework = memory.get("framework")
        waf = memory.get("waf")
        creds = memory.get("creds")
        
        # Get suggestions for payload generation
        suggestions = memory.get_suggestions("sqli")
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._store: Dict[str, MemoryEntry] = {}
        self._history: List[Dict] = []
        self._lock = threading.RLock()
        self._learnt_rules: Dict[str, List[Dict]] = defaultdict(list)
        self._storage = None
        self._auto_save = True

    def set_storage(self, storage, auto_save: bool = True):
        self._storage = storage
        self._auto_save = auto_save

    def restore(self, entries: Dict[str, dict]):
        with self._lock:
            for key, data in entries.items():
                entry = MemoryEntry(
                    key=key,
                    value=data["value"],
                    source=data.get("source", "restored"),
                    confidence=data.get("confidence", 0.8),
                    timestamp=data.get("timestamp", time.time()),
                    ttl=data.get("ttl", 3600.0),
                    tags=data.get("tags", []),
                )
                existing = self._store.get(key)
                if existing and existing.confidence > entry.confidence:
                    continue
                self._store[key] = entry

    def set(self, key: str, value: any, source: str = "unknown",
            confidence: float = 0.80, ttl: float = 3600.0,
            tags: List[str] = None) -> None:
        with self._lock:
            entry = MemoryEntry(
                key=key, value=value, source=source,
                confidence=confidence, timestamp=time.time(),
                ttl=ttl, tags=tags or [],
            )
            existing = self._store.get(key)
            if existing and existing.confidence > confidence:
                logger.debug("Memory: keeping higher confidence for %s (%.2f > %.2f)",
                           key, existing.confidence, confidence)
                return
            self._store[key] = entry
            self._history.append({
                "action": "set", "key": key, "source": source,
                "confidence": confidence, "time": time.time(),
            })
            self._auto_learn(key, value, source, confidence)
            if self._storage and self._auto_save:
                try:
                    tags = entry.tags if hasattr(entry, 'tags') else None
                    self._storage.save_context(key, value, source, confidence, tags)
                except Exception as e:
                    logger.debug("storage save: %s", e)
            logger.debug("Memory: set %s = %s (source=%s, conf=%.2f)", key, str(value)[:80], source, confidence)

    def get(self, key: str, default: any = None) -> any:
        with self._lock:
            entry = self._store.get(key)
            if entry and not entry.is_expired():
                return entry.value
            if entry:
                del self._store[key]
            return default

    def get_entry(self, key: str) -> Optional[MemoryEntry]:
        with self._lock:
            entry = self._store.get(key)
            if entry and not entry.is_expired():
                return entry
            return None

    def has(self, key: str) -> bool:
        with self._lock:
            entry = self._store.get(key)
            return entry is not None and not entry.is_expired()

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._history.clear()

    def cleanup(self) -> int:
        with self._lock:
            expired = [k for k, v in self._store.items() if v.is_expired()]
            for k in expired:
                del self._store[k]
            return len(expired)

    def all_keys(self) -> List[str]:
        with self._lock:
            return [k for k, v in self._store.items() if not v.is_expired()]

    def snapshot(self) -> Dict[str, any]:
        with self._lock:
            return {
                k: v.to_dict() for k, v in self._store.items()
                if not v.is_expired()
            }

    def get_suggestions(self, module_type: str) -> Dict[str, any]:
        with self._lock:
            suggestions = {}

            if module_type == "sqli":
                dbms = self.get("dbms")
                if dbms:
                    suggestions["dbms"] = dbms
                    suggestions["dialect"] = self._dbms_to_dialect(dbms)
                waf = self.get("waf")
                if waf:
                    suggestions["waf"] = waf
                    suggestions["bypass_strategy"] = self._waf_to_strategy(waf)
                creds = self.get("db_creds")
                if creds:
                    suggestions["use_credentials"] = creds

            elif module_type == "ssti":
                framework = self.get("framework")
                if framework:
                    suggestions["framework"] = framework
                    suggestions["template_engine"] = self._framework_to_engine(framework)
                lang = self.get("language")
                if lang:
                    suggestions["language"] = lang

            elif module_type == "ssrf":
                cloud = self.get("cloud_provider")
                if cloud:
                    suggestions["cloud_provider"] = cloud
                    suggestions["metadata_url"] = self._cloud_metadata_url(cloud)
                internal_services = self.get("internal_services")
                if internal_services:
                    suggestions["internal_targets"] = internal_services

            elif module_type == "cmdi":
                os_type = self.get("os_type")
                if os_type:
                    suggestions["os"] = os_type
                    suggestions["shell"] = "cmd" if os_type == "windows" else "bash"

            elif module_type == "lfi":
                os_type = self.get("os_type")
                if os_type:
                    suggestions["os"] = os_type
                web_root = self.get("web_root")
                if web_root:
                    suggestions["web_root"] = web_root
                php_version = self.get("php_version")
                if php_version:
                    suggestions["php_version"] = php_version
                    suggestions["wrappers"] = self._php_wrappers(php_version)

            elif module_type == "auth":
                creds = self.get("creds")
                if creds:
                    suggestions["credentials"] = creds
                session = self.get("session_token")
                if session:
                    suggestions["session"] = session

            elif module_type == "exploit":
                creds = self.get("creds")
                if creds:
                    suggestions["credentials"] = creds
                ssh_keys = self.get("ssh_keys")
                if ssh_keys:
                    suggestions["ssh_keys"] = ssh_keys
                cloud_creds = self.get("cloud_creds")
                if cloud_creds:
                    suggestions["cloud_credentials"] = cloud_creds

            return suggestions

    def _auto_learn(self, key: str, value: any, source: str, confidence: float) -> None:
        if key == "dbms" and isinstance(value, str):
            self._learnt_rules["sqli_dialect"].append({
                "trigger": value, "action": "use_dialect",
                "dialect": self._dbms_to_dialect(value),
            })
        elif key == "framework" and isinstance(value, str):
            self._learnt_rules["ssti_engine"].append({
                "trigger": value, "action": "use_engine",
                "engine": self._framework_to_engine(value),
            })
        elif key == "waf" and isinstance(value, str):
            self._learnt_rules["waf_bypass"].append({
                "trigger": value, "action": "use_strategy",
                "strategy": self._waf_to_strategy(value),
            })
        elif key == "os_type":
            self._learnt_rules["os_specific"].append({
                "trigger": value, "action": "use_os_payloads",
                "os": value,
            })

    def _dbms_to_dialect(self, dbms: str) -> str:
        dbms_lower = dbms.lower()
        if "mysql" in dbms_lower:
            return "mysql"
        elif "postgres" in dbms_lower or "psql" in dbms_lower:
            return "postgresql"
        elif "mssql" in dbms_lower or "sql server" in dbms_lower:
            return "mssql"
        elif "oracle" in dbms_lower:
            return "oracle"
        elif "sqlite" in dbms_lower:
            return "sqlite"
        elif "mongodb" in dbms_lower or "mongo" in dbms_lower:
            return "mongodb"
        return "generic"

    def _waf_to_strategy(self, waf: str) -> str:
        waf_lower = waf.lower()
        if "cloudflare" in waf_lower:
            return "cloudflare_bypass"
        elif "akamai" in waf_lower:
            return "akamai_bypass"
        elif "modsecurity" in waf_lower or "modsec" in waf_lower:
            return "modsec_bypass"
        elif "aws" in waf_lower or "waf" in waf_lower:
            return "aws_waf_bypass"
        elif "imperva" in waf_lower or "incapsula" in waf_lower:
            return "imperva_bypass"
        elif "f5" in waf_lower or "bigip" in waf_lower:
            return "f5_bypass"
        return "generic_bypass"

    def _framework_to_engine(self, framework: str) -> str:
        fw_lower = framework.lower()
        if "spring" in fw_lower:
            return "spel"
        elif "django" in fw_lower:
            return "django_template"
        elif "flask" in fw_lower or "jinja" in fw_lower:
            return "jinja2"
        elif "laravel" in fw_lower or "blade" in fw_lower:
            return "blade"
        elif "thinkphp" in fw_lower:
            return "thinkphp"
        elif "express" in fw_lower or "ejs" in fw_lower:
            return "ejs"
        elif "handlebars" in fw_lower:
            return "handlebars"
        elif "pug" in fw_lower or "jade" in fw_lower:
            return "pug"
        elif "freemarker" in fw_lower:
            return "freemarker"
        elif "velocity" in fw_lower:
            return "velocity"
        elif "thymeleaf" in fw_lower:
            return "thymeleaf"
        return "generic"

    def _cloud_metadata_url(self, cloud: str) -> str:
        cloud_lower = cloud.lower()
        if "aws" in cloud_lower:
            return "http://169.254.169.254/latest/meta-data/"
        elif "gcp" in cloud_lower or "google" in cloud_lower:
            return "http://metadata.google.internal/computeMetadata/v1/"
        elif "azure" in cloud_lower:
            return "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        elif "alibaba" in cloud_lower or "aliyun" in cloud_lower:
            return "http://100.100.100.200/latest/meta-data/"
        elif "tencent" in cloud_lower or "qcloud" in cloud_lower:
            return "http://metadata.tencentyun.com/latest/meta-data/"
        return "http://169.254.169.254/latest/meta-data/"

    def _php_wrappers(self, version: str) -> List[str]:
        wrappers = [
            "php://filter/convert.base64-encode/resource=",
            "php://input",
            "php://stdin",
        ]
        try:
            major = int(version.split(".")[0])
            minor = int(version.split(".")[1]) if len(version.split(".")) > 1 else 0
            if major >= 7 and minor >= 4:
                wrappers.append("php://temp")
            if major >= 7 and minor >= 2:
                wrappers.append("php://fd/3")
        except (ValueError, IndexError):
            pass
        return wrappers

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "total_entries": len(self._store),
                "active_entries": len([v for v in self._store.values() if not v.is_expired()]),
                "expired_entries": len([v for v in self._store.values() if v.is_expired()]),
                "history_size": len(self._history),
                "learnt_rules": {
                    k: len(v) for k, v in self._learnt_rules.items()
                },
                "keys": self.all_keys(),
            }


def get_memory() -> ContextMemory:
    return ContextMemory()
