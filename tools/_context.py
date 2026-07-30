import threading
import time
from typing import Any, Dict, List, Optional

import requests

from tools._session import make_session
from tools.log_utils import get_logger

logger = get_logger("context")


class ScanContext:
    def __init__(self, target: str, sess: Optional[requests.Session] = None,
                 timeout: float = 10.0, threads: int = 10):
        self.target = target.rstrip("/")
        self.sess = sess or make_session()
        self.timeout = timeout
        self.threads = threads
        self._start_time = time.time()
        self._findings: Dict[str, Dict] = {}
        self._state: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._cross_context: Dict[str, List[str]] = {}
        self._tech_stack: List[str] = []

    def add_finding(self, key: str, finding: Dict):
        with self._lock:
            self._findings[key] = finding

    def get_findings(self) -> Dict[str, Dict]:
        with self._lock:
            return dict(self._findings)

    def findings_count(self) -> int:
        with self._lock:
            return len(self._findings)

    def set_state(self, key: str, value: Any):
        with self._lock:
            self._state[key] = value

    def get_state(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._state.get(key, default)

    def elapsed(self) -> float:
        return time.time() - self._start_time

    def share_finding(self, skill: str, finding_type: str, detail: Dict):
        with self._lock:
            key = f"{skill}:{finding_type}"
            self._cross_context.setdefault(key, []).append(detail)

    def get_shared(self, skill: str = "", finding_type: str = "") -> List[Dict]:
        with self._lock:
            results = []
            for k, v in self._cross_context.items():
                if (not skill or k.startswith(skill)) and (not finding_type or finding_type in k):
                    results.extend(v)
            return results

    def get_param_targets_from_ssrf(self) -> List[str]:
        ssrf_params = self.get_shared("ssrf_detector", "ssrf")
        targets = []
        for entry in ssrf_params:
            if isinstance(entry, dict):
                targets.append(entry.get("param", ""))
        return targets

    def set_tech_stack(self, techs: List[str]):
        with self._lock:
            self._tech_stack = techs

    def get_tech_stack(self) -> List[str]:
        with self._lock:
            return list(self._tech_stack)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "timeout": self.timeout,
            "threads": self.threads,
            "elapsed": self.elapsed(),
            "findings_count": self.findings_count(),
            "findings": self.get_findings(),
            "state": dict(self._state),
            "tech_stack": self._tech_stack,
            "cross_context_keys": list(self._cross_context.keys()),
        }
