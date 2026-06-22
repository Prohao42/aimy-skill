import json, re, time, hashlib, copy
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from urllib.parse import urlparse, parse_qs, urlencode
from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("workflow_tracer")


class StepRole(Enum):
    INIT = auto()
    AUTH = auto()
    READ = auto()
    CREATE = auto()
    UPDATE = auto()
    DELETE = auto()
    CONFIRM = auto()
    REDIRECT = auto()


@dataclass
class TraceStep:
    index: int
    method: str
    url: str
    params: Dict[str, str]
    body: Optional[str]
    response_status: int
    response_body: str
    response_headers: Dict[str, str]
    role: StepRole = StepRole.READ
    extract: Dict[str, str] = field(default_factory=dict)
    timestamp: float = 0.0

    @property
    def signature(self) -> str:
        key = f"{self.method}|{self.url.split('?')[0]}|{self.response_status}"
        return hashlib.md5(key.encode()).hexdigest()[:12]


@dataclass
class WorkflowTrace:
    name: str
    steps: List[TraceStep] = field(default_factory=list)
    identity_label: str = ""
    base_url: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_step(self, step: TraceStep):
        self.steps.append(step)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "steps": [
                {"index": s.index, "method": s.method, "url": s.url,
                 "status": s.response_status, "role": s.role.name,
                 "extract": s.extract}
                for s in self.steps
            ],
            "identity": self.identity_label,
            "urls": [s.url.split("?")[0] for s in self.steps],
            "total_steps": len(self.steps),
        }


class WorkflowTracer:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.active_trace: Optional[WorkflowTrace] = None
        self.traces: Dict[str, WorkflowTrace] = {}
        self._step_index = 0

    def start_trace(self, name: str, identity_label: str = ""):
        self.active_trace = WorkflowTrace(
            name=name, identity_label=identity_label,
            base_url=self.base_url,
        )
        self._step_index = 0

    def record(self, method: str, url: str,
               params: Dict[str, str] = None,
               body: str = None,
               response_status: int = 0,
               response_body: str = "",
               response_headers: Dict[str, str] = None,
               role: StepRole = StepRole.READ) -> Optional[TraceStep]:
        if self.active_trace is None:
            return None
        step = TraceStep(
            index=self._step_index,
            method=method.upper(),
            url=url,
            params=params or {},
            body=body,
            response_status=response_status,
            response_body=response_body,
            response_headers=response_headers or {},
            role=role,
            timestamp=time.time(),
        )
        self.active_trace.add_step(step)
        self._step_index += 1
        return step

    def end_trace(self, name: str = None) -> Optional[WorkflowTrace]:
        if self.active_trace is None:
            return None
        if name:
            self.active_trace.name = name
        self.traces[self.active_trace.name] = self.active_trace
        trace = self.active_trace
        self.active_trace = None
        return trace

    def get_trace(self, name: str) -> Optional[WorkflowTrace]:
        return self.traces.get(name)

    def list_traces(self) -> Dict[str, int]:
        return {n: len(t.steps) for n, t in self.traces.items()}


class WorkflowDeviator:
    def __init__(self, trace: WorkflowTrace):
        self.trace = trace
        self.base_url = trace.base_url

    def find_resource_ids(self) -> List[Tuple[str, str, int]]:
        found = []
        for s in self.trace.steps:
            for key, val in s.extract.items():
                if key in ("id", "user_id", "order_id", "uuid",
                           "token", "session"):
                    found.append((key, val, s.index))
            if s.response_status in (200, 201) and len(s.response_body) < 50000:
                try:
                    data = json.loads(s.response_body)
                    if isinstance(data, dict):
                        for id_key in ("id", "uuid", "token", "order_id",
                                       "user_id", "account_id", "ref"):
                            if id_key in data:
                                found.append((id_key, str(data[id_key]), s.index))
                    elif isinstance(data, list) and len(data) > 0:
                        for item in data[:3]:
                            if isinstance(item, dict):
                                for id_key in ("id", "uuid"):
                                    if id_key in item:
                                        found.append((id_key, str(item[id_key]),
                                                     s.index))
                except (json.JSONDecodeError, ValueError):
                    for m in re.finditer(r'"id"\s*:\s*"([^"]+)"', s.response_body):
                        found.append(("id", m.group(1), s.index))
        return found

    def generate_skip_steps(self, target_step_index: int) -> List[Dict]:
        tests = []
        for s in self.trace.steps:
            if s.index > target_step_index:
                continue
            direct_url = self.trace.steps[target_step_index].url
            tests.append({
                "technique": "skip_intermediate",
                "description": f"Jump from step {s.index} to step {target_step_index}",
                "from_step": s.index,
                "from_url": s.url,
                "target_url": direct_url,
                "expected_auth": target_step_index > 0,
            })
        return tests

    def generate_role_swap(self, target_step_index: int,
                           resource_owner: str) -> List[Dict]:
        step = self.trace.steps[target_step_index]
        tests = []
        for id_key, id_val, _ in self.find_resource_ids():
            swapped_url = step.url.replace(id_val, f"{id_val}_other")
            tests.append({
                "technique": "role_swap_idor",
                "resource_id": id_val,
                "resource_owner": resource_owner,
                "original_url": step.url,
                "swapped_url": swapped_url,
                "step_index": target_step_index,
                "step_role": step.role.name,
            })
        parts = urlparse(step.url)
        qs = parse_qs(parts.query)
        for param, values in qs.items():
            for val in values:
                if any(k in param.lower() for k in ("id", "user", "account",
                                                      "order", "owner")):
                    tests.append({
                        "technique": "role_swap_param",
                        "param": param,
                        "original_value": val,
                        "suggested_swap": str(int(val) + 1) if val.isdigit() else f"{val}_other",
                        "step_index": target_step_index,
                    })
        return tests

    def generate_replay(self) -> List[Dict]:
        tests = []
        auth_steps = [s for s in self.trace.steps
                      if s.role in (StepRole.AUTH, StepRole.CREATE,
                                    StepRole.UPDATE, StepRole.DELETE)]
        for i in range(len(auth_steps)):
            for j in range(i + 1, len(auth_steps)):
                tests.append({
                    "technique": "replay_old_step",
                    "description": f"Replay step {auth_steps[i].index} ({auth_steps[i].role.name}) "
                                   f"after step {auth_steps[j].index}",
                    "old_step_index": auth_steps[i].index,
                    "old_url": auth_steps[i].url,
                    "old_method": auth_steps[i].method,
                    "current_step_index": auth_steps[j].index,
                })
        return tests


class StateProbe:
    def __init__(self, sess):
        self.sess = sess
        self._state_snapshots: Dict[str, str] = {}

    def snapshot(self, key: str, url: str) -> Optional[int]:
        try:
            r = self.sess.get(url, timeout=10)
            self._state_snapshots[key] = r.text
            return len(r.text)
        except Exception as e:
            logger.debug("snapshot %s: %s", key, e)
            return None

    def compare(self, key_a: str, key_b: str) -> Dict:
        a = self._state_snapshots.get(key_a)
        b = self._state_snapshots.get(key_b)
        if a is None or b is None:
            return {"error": "snapshot not found", "identical": False}
        return {
            "key_a": key_a, "key_b": key_b,
            "identical": a == b,
            "len_a": len(a), "len_b": len(b),
        }

    def assert_state_unchanged(self, before: str, after: str) -> bool:
        return self._state_snapshots.get(before) == self._state_snapshots.get(after)


def trace_workflow(sess, base_url: str, steps: List[Dict]) -> WorkflowTrace:
    tracer = WorkflowTracer(base_url)
    as_role = {"GET": StepRole.READ, "POST": StepRole.CREATE,
               "PUT": StepRole.UPDATE, "PATCH": StepRole.UPDATE,
               "DELETE": StepRole.DELETE}
    tracer.start_trace("manual")
    for s in steps:
        method = s.get("method", "GET").upper()
        url = s.get("url", "")
        if not url.startswith("http"):
            url = f"{base_url.rstrip('/')}/{url.lstrip('/')}"
        data = s.get("data")
        try:
            r = getattr(sess, method.lower())(url, json=data if isinstance(data, dict) else None,
                                               data=data if isinstance(data, str) else None,
                                               timeout=10)
        except Exception as e:
            logger.debug("trace step %s %s: %s", method, url, e)
            continue
        params = {}
        q = urlparse(url).query
        if q:
            params = {k: v[0] if len(v) == 1 else v
                      for k, v in parse_qs(q).items()}
        tracer.record(method, url, params=params,
                      body=json.dumps(data) if data else None,
                      response_status=r.status_code,
                      response_body=r.text,
                      response_headers=dict(r.headers),
                      role=as_role.get(method, StepRole.READ))
        time.sleep(0.2)
    return tracer.end_trace("manual") or WorkflowTrace(name="manual")


def check(base_url: str, sess=None, timeout: float = 10.0) -> Dict:
    import requests
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    result = {
        "vulnerable": False,
        "findings": [],
        "traces": [],
    }
    return result
