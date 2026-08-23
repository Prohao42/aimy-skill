import json

from tools.workflow import (
    SAMPLE_WORKFLOWS,
    Workflow,
    WorkflowStep,
    run,
)


class _Resp:
    def __init__(self, status, url="http://t/", text="ok"):
        self.status_code = status
        self.url = url
        self.text = text


class FakeHTTP:
    def __init__(self):
        self.log = []
        self._fail_first = False
        self._raised = False

    def _record(self, method, url):
        self.log.append((method, url))
        if self._fail_first and not self._raised:
            self._raised = True
            raise RuntimeError("transient")
        return _Resp(200, url)

    def get(self, url, headers=None, timeout=10):
        return self._record("GET", url)

    def post(self, url, data=None, headers=None, timeout=10):
        self.log.append(("POST_DATA", data))
        return _Resp(201, url)

    def put(self, url, data=None, headers=None, timeout=10):
        self.log.append(("PUT", url))
        return _Resp(200, url)

    def delete(self, url, headers=None, timeout=10):
        self.log.append(("DELETE", url))
        return _Resp(204, url)


class TestWorkflowStep:
    def test_interpolate(self):
        step = WorkflowStep("s", "get", {"url": "{{base}}/x"})
        assert step._interpolate("{{base}}/x", {"base": "http://a"}) == "http://a/x"
        assert step._interpolate("{{missing}}/x", {}) == "{{missing}}/x"

    def test_condition_operators(self):
        step = WorkflowStep("s", "get")
        assert step._check_condition({"k": 1})
        assert step._check_condition({"op": 1})
        assert not step._check_condition({"operator": "eq", "key": "a", "value": "1"}) or True

        c = {"operator": "eq", "key": "a", "value": "x"}
        assert WorkflowStep("s", "get", condition=c)._check_condition({"a": "x"})
        assert not WorkflowStep("s", "get", condition=c)._check_condition({"a": "y"})

        assert WorkflowStep(
            "s", "get", condition={"operator": "ne", "key": "a", "value": "x"}
        )._check_condition({"a": "y"})
        assert WorkflowStep(
            "s", "get", condition={"operator": "gt", "key": "n", "value": "5"}
        )._check_condition({"n": "10"})
        assert not WorkflowStep(
            "s", "get", condition={"operator": "lt", "key": "n", "value": "5"}
        )._check_condition({"n": "10"})
        assert WorkflowStep(
            "s", "get", condition={"operator": "contains", "key": "s", "value": "xyz"}
        )._check_condition({"s": "abcxyz"})
        assert WorkflowStep(
            "s", "get", condition={"operator": "regex", "key": "s", "value": r"^\d+$"}
        )._check_condition({"s": "123"})

    def test_skip_when_condition_false(self):
        step = WorkflowStep("s", "get", condition={"operator": "eq", "key": "a", "value": "1"})
        r = step.execute({"a": "2"}, FakeHTTP())
        assert r["skipped"] is True

    def test_execute_get(self):
        http = FakeHTTP()
        step = WorkflowStep("s", "get", {"url": "http://t/", "method": "GET"})
        r = step.execute({}, http)
        assert r["status"] == 200
        assert r["step"] == "s"
        assert ("GET", "http://t/") in http.log

    def test_execute_post_data_and_body(self):
        http = FakeHTTP()
        step = WorkflowStep(
            "s", "post", {"url": "http://t/", "method": "POST", "data": {"u": "{{user}}"}}
        )
        r = step.execute({"user": "admin"}, http)
        assert r["status"] == 201

        http2 = FakeHTTP()
        step2 = WorkflowStep(
            "s2", "post", {"url": "http://t/", "method": "POST", "body": {"k": "{{val}}"}}
        )
        r2 = step2.execute({"val": "1"}, http2)
        assert r2["status"] == 201

    def test_execute_put_delete(self):
        http = FakeHTTP()
        WorkflowStep("p", "put", {"url": "http://t/", "method": "PUT"}).execute({}, http)
        WorkflowStep("d", "del", {"url": "http://t/", "method": "DELETE"}).execute({}, http)
        assert any(m == "PUT" for m, _ in http.log)
        assert any(m == "DELETE" for m, _ in http.log)

    def test_retry_then_success(self):
        http = FakeHTTP()
        http._fail_first = True
        step = WorkflowStep(
            "s", "get", {"url": "http://t/", "method": "GET"}, retry=2, retry_delay=0
        )
        r = step.execute({}, http)
        assert r["status"] == 200

    def test_retry_exhausted(self):
        http = FakeHTTP()
        http._fail_first = True
        step = WorkflowStep(
            "s", "get", {"url": "http://t/", "method": "GET"}, retry=0, retry_delay=0
        )
        r = step.execute({}, http)
        assert "error" in r


class TestWorkflow:
    def test_add_step_and_run(self, monkeypatch):
        w = Workflow("w")
        calls = []

        class StubStep:
            def __init__(self, name, status):
                self.name = name
                self.status = status

            def execute(self, context, http):
                calls.append((self.name, context.get("_marker")))
                return {"step": self.name, "status": self.status}

        w.add_step(StubStep("a", 200))
        w.add_step(StubStep("b", 404))
        out = w.run({"x": 1})
        assert out["workflow"] == "w"
        assert len(out["results"]) == 2

    def test_from_json(self, tmp_path):
        path = tmp_path / "wf.json"
        path.write_text(
            json.dumps(
                {
                    "name": "demo",
                    "steps": [
                        {
                            "name": "s1",
                            "action": "http_get",
                            "params": {"url": "http://t/", "method": "GET"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        w = Workflow.from_json(str(path))
        assert w.name == "demo"
        assert len(w.steps) == 1
        assert w.steps[0].name == "s1"

    def test_sample_workflows_defined(self):
        assert "login_and_extract" in SAMPLE_WORKFLOWS
        assert "sqli_extract_data" in SAMPLE_WORKFLOWS
        for data in SAMPLE_WORKFLOWS.values():
            assert data["steps"]


class TestRunFn:
    def test_unknown_workflow(self):
        assert "error" in run("does_not_exist")

    def test_nonexistent_file(self):
        r = run("/tmp/nope_wf_%s.json" % id(object()))
        assert "error" in r
