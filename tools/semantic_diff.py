import re
import json
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field

from tools.log_utils import get_logger

logger = get_logger("semantic_diff")

NOISE_KEYS = {
    "timestamp", "ts", "_ts", "nonce", "nonce_str", "rand", "random",
    "trace_id", "traceId", "request_id", "requestId", "span_id",
    "elapsed", "took", "processing_time", "server_time",
    "sign", "signature", "_sign", "hash", "_hash",
}

NOISE_VALUES = re.compile(
    r"^\d{10,}$|^[\da-f]{8,}$|^\d{4}-\d{2}-\d{2}T|^[A-Za-z0-9+/]{20,}={0,2}$"
)


@dataclass
class DiffEntry:
    path: str
    type: str
    left_value: Any = None
    right_value: Any = None
    is_noise: bool = False
    significance: str = "unknown"


@dataclass
class SemanticDiffResult:
    has_meaningful_diff: bool = False
    diff_entries: List[DiffEntry] = field(default_factory=list)
    noise_entries: List[DiffEntry] = field(default_factory=list)
    status_diff: Optional[Tuple[int, int]] = None
    length_diff: int = 0
    structural_changes: List[str] = field(default_factory=list)
    summary: str = ""


class SemanticDiffEngine:
    def __init__(self):
        self._sensitive_keys = {
            "password", "secret", "token", "api_key", "apikey",
            "credit_card", "ssn", "cvv", "pin", "auth",
        }

    def diff_json(self, left: str, right: str,
                  label_a: str = "left",
                  label_b: str = "right") -> SemanticDiffResult:
        result = SemanticDiffResult()

        try:
            left_data = json.loads(left) if left else {}
            right_data = json.loads(right) if right else {}
        except json.JSONDecodeError:
            result.has_meaningful_diff = True
            result.summary = "non-json response"
            return result

        if type(left_data) != type(right_data):
            result.has_meaningful_diff = True
            result.structural_changes.append(
                f"type_mismatch: {type(left_data).__name__} vs {type(right_data).__name__}"
            )
            result.summary = "type mismatch"
            return result

        all_keys = set()
        self._collect_keys(left_data, "", all_keys)
        self._collect_keys(right_data, "", all_keys)

        for key_path in sorted(all_keys):
            lv = self._get_nested(left_data, key_path)
            rv = self._get_nested(right_data, key_path)
            if lv == rv:
                continue

            entry = DiffEntry(
                path=key_path,
                type=self._value_type(lv) if lv is not None else "null",
                left_value=self._trunc(lv),
                right_value=self._trunc(rv),
            )

            key_name = key_path.split(".")[-1]
            if key_name in NOISE_KEYS or NOISE_VALUES.match(str(lv or "")):
                entry.is_noise = True
                entry.significance = "noise"
                result.noise_entries.append(entry)
            elif key_name in self._sensitive_keys:
                entry.is_noise = False
                entry.significance = "critical"
                result.diff_entries.append(entry)
                result.has_meaningful_diff = True
            elif lv is None or rv is None:
                entry.significance = "high"
                result.diff_entries.append(entry)
                result.has_meaningful_diff = True
            elif isinstance(lv, (int, float)) and isinstance(rv, (int, float)):
                pct = abs(lv - rv) / max(abs(lv), abs(rv), 1) * 100
                if pct > 10:
                    entry.significance = "medium"
                    result.diff_entries.append(entry)
                    result.has_meaningful_diff = True
                else:
                    entry.significance = "low"
                    result.noise_entries.append(entry)
            elif isinstance(lv, str) and len(lv) > 50 and isinstance(rv, str) and len(rv) > 50:
                if len(lv) != len(rv):
                    entry.significance = "low"
                    result.noise_entries.append(entry)
            else:
                entry.significance = "medium"
                result.diff_entries.append(entry)
                result.has_meaningful_diff = True

        self._build_summary(result, label_a, label_b)
        return result

    def diff_text(self, left: str, right: str,
                  label_a: str = "left",
                  label_b: str = "right") -> SemanticDiffResult:
        result = SemanticDiffResult()
        result.length_diff = abs(len(left) - len(right))
        if result.length_diff > 0:
            result.has_meaningful_diff = True

        left_hash = hashlib.md5(left.encode()).hexdigest()[:16]
        right_hash = hashlib.md5(right.encode()).hexdigest()[:16]
        if left_hash != right_hash:
            result.has_meaningful_diff = True

        diff_ratio = result.length_diff / max(len(left), len(right), 1)
        if diff_ratio < 0.02:
            result.summary = f"minor length diff ({result.length_diff}B)"
        elif diff_ratio < 0.1:
            result.summary = f"moderate length diff ({result.length_diff}B)"
        else:
            result.summary = f"major length diff ({result.length_diff}B)"

        return result

    def _collect_keys(self, data: Any, prefix: str, result: Set[str]):
        if isinstance(data, dict):
            for k, v in data.items():
                path = f"{prefix}.{k}" if prefix else k
                result.add(path)
                self._collect_keys(v, path, result)
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            self._collect_keys(data[0], f"{prefix}[]", result)

    def _get_nested(self, data: Any, path: str) -> Any:
        parts = path.replace("[]", "").split(".")
        current = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and current:
                current = current[0]
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            else:
                return None
        return current

    def _value_type(self, val: Any) -> str:
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "boolean"
        if isinstance(val, int):
            return "integer"
        if isinstance(val, float):
            return "float"
        if isinstance(val, str):
            return "string"
        if isinstance(val, list):
            return "list"
        if isinstance(val, dict):
            return "object"
        return type(val).__name__

    def _trunc(self, val: Any, max_len: int = 80) -> str:
        if val is None:
            return "null"
        s = str(val)
        return s[:max_len] + "..." if len(s) > max_len else s

    def _build_summary(self, result: SemanticDiffResult,
                       label_a: str, label_b: str):
        parts = []
        if result.status_diff:
            parts.append(f"status {result.status_diff[0]} vs {result.status_diff[1]}")
        meaningful = len(result.diff_entries)
        noise = len(result.noise_entries)
        if meaningful:
            parts.append(f"{meaningful} meaningful diffs")
        if noise:
            parts.append(f"{noise} noise fields ignored")
        result.summary = ", ".join(parts) if parts else "identical"
