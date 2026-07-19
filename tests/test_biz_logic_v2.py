import pytest
from unittest.mock import patch, MagicMock
from tools.biz_logic_v2 import (
    run_authz_scan,
    run_workflow_scan,
    run_race_scan,
    run_constraint_scan,
    check,
)


class TestRunAuthzScan:
    @patch("tools.biz_logic_v2.DeviationOracle")
    @patch("tools.biz_logic_v2.SessionMatrix")
    def test_basic_flow(self, MockMatrix, MockOracle):
        mock_matrix = MagicMock()
        MockMatrix.return_value = mock_matrix
        mock_matrix.authenticate_all.return_value = {"admin": True}
        mock_matrix.list.return_value = [{"label": "admin", "role": "admin"}]

        mock_oracle = MagicMock()
        MockOracle.return_value = mock_oracle
        mock_oracle.run.return_value = {"vulnerable": True, "findings": ["x"]}

        result = run_authz_scan(
            "http://test.com",
            [{"username": "admin", "password": "pass", "role": "admin"}],
        )
        assert result["vulnerable"] is True
        assert result["findings"] == ["x"]
        assert result["auth_results"] == {"admin": True}

    @patch("tools.biz_logic_v2.DeviationOracle")
    @patch("tools.biz_logic_v2.SessionMatrix")
    def test_default_auth_url(self, MockMatrix, MockOracle):
        mock_matrix = MagicMock()
        MockMatrix.return_value = mock_matrix
        mock_matrix.authenticate_all.return_value = {}
        mock_matrix.list.return_value = []

        mock_oracle = MagicMock()
        MockOracle.return_value = mock_oracle
        mock_oracle.run.return_value = {"vulnerable": False}

        run_authz_scan("http://test.com/api", [])
        MockMatrix.assert_called_once_with("http://test.com/api")

    @patch("tools.biz_logic_v2.DeviationOracle")
    @patch("tools.biz_logic_v2.SessionMatrix")
    def test_custom_auth_url(self, MockMatrix, MockOracle):
        mock_matrix = MagicMock()
        MockMatrix.return_value = mock_matrix
        mock_matrix.authenticate_all.return_value = {}
        mock_matrix.list.return_value = []

        mock_oracle = MagicMock()
        MockOracle.return_value = mock_oracle
        mock_oracle.run.return_value = {"vulnerable": False}

        run_authz_scan("http://test.com", [], auth_url="http://custom/login")
        MockMatrix.assert_called_once_with("http://test.com")
        mock_matrix.authenticate_all.assert_called_once_with(
            "http://custom/login", timeout=10.0
        )

    @patch("tools.biz_logic_v2.DeviationOracle")
    @patch("tools.biz_logic_v2.SessionMatrix")
    def test_multiple_identities(self, MockMatrix, MockOracle):
        mock_matrix = MagicMock()
        MockMatrix.return_value = mock_matrix
        mock_matrix.authenticate_all.return_value = {"a": True, "b": False}
        mock_matrix.list.return_value = ["a", "b"]

        mock_oracle = MagicMock()
        MockOracle.return_value = mock_oracle
        mock_oracle.run.return_value = {"vulnerable": False}

        run_authz_scan("http://test.com", [
            {"label": "a", "username": "a", "password": "a", "role": "admin"},
            {"label": "b", "username": "b", "password": "b", "role": "user"},
        ])
        assert mock_matrix.register.call_count == 2

    @patch("tools.biz_logic_v2.DeviationOracle")
    @patch("tools.biz_logic_v2.SessionMatrix")
    def test_no_identities(self, MockMatrix, MockOracle):
        mock_matrix = MagicMock()
        MockMatrix.return_value = mock_matrix
        mock_matrix.authenticate_all.return_value = {}
        mock_matrix.list.return_value = []

        mock_oracle = MagicMock()
        MockOracle.return_value = mock_oracle
        mock_oracle.run.return_value = {"vulnerable": False}

        result = run_authz_scan("http://test.com", [])
        MockMatrix.assert_called_once_with("http://test.com")
        mock_matrix.register.assert_not_called()

    @patch("tools.biz_logic_v2.DeviationOracle")
    @patch("tools.biz_logic_v2.SessionMatrix")
    def test_identity_uses_username_as_label_fallback(self, MockMatrix, MockOracle):
        mock_matrix = MagicMock()
        MockMatrix.return_value = mock_matrix
        mock_matrix.authenticate_all.return_value = {}
        mock_matrix.list.return_value = []

        mock_oracle = MagicMock()
        MockOracle.return_value = mock_oracle
        mock_oracle.run.return_value = {"vulnerable": False}

        run_authz_scan("http://test.com", [
            {"username": "u1", "password": "p1", "role": "user"},
        ])
        mock_matrix.register.assert_called_once_with(
            label="u1", username="u1", password="p1", role="user"
        )


class TestRunWorkflowScan:
    @patch("tools.biz_logic_v2.trace_workflow")
    def test_no_vulnerabilities(self, mock_trace):
        mock_trace_obj = MagicMock()
        mock_trace_obj.steps = []
        mock_trace_obj.to_dict.return_value = {}
        mock_trace.return_value = mock_trace_obj

        with patch("tools.biz_logic_v2.WorkflowDeviator") as MockDeviator:
            mock_deviator = MagicMock()
            MockDeviator.return_value = mock_deviator
            mock_deviator.generate_skip_steps.return_value = []
            mock_deviator.generate_replay.return_value = []
            mock_deviator.find_resource_ids.return_value = []

            result = run_workflow_scan("http://test.com", [], sess=MagicMock())
            assert result["vulnerable"] is False
            assert result["findings"] == []

    @patch("tools.biz_logic_v2.trace_workflow")
    def test_skip_step_detected(self, mock_trace):
        mock_trace_obj = MagicMock()
        mock_trace_obj.steps = [{"url": "http://test.com/s1"}, {"url": "http://test.com/s2"}]
        mock_trace_obj.to_dict.return_value = {}
        mock_trace.return_value = mock_trace_obj

        with patch("tools.biz_logic_v2.WorkflowDeviator") as MockDeviator:
            mock_deviator = MagicMock()
            MockDeviator.return_value = mock_deviator
            mock_deviator.generate_skip_steps.return_value = [
                {"target_url": "http://test.com/s2", "description": "skip step 1"},
            ]
            mock_deviator.generate_replay.return_value = []
            mock_deviator.find_resource_ids.return_value = []

            mock_sess = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_sess.get.return_value = mock_resp

            result = run_workflow_scan("http://test.com", [{"step": "a"}], sess=mock_sess)
            assert result["vulnerable"] is True
            assert len(result["findings"]) == 1
            assert result["findings"][0]["type"] == "workflow_bypass"

    @patch("tools.biz_logic_v2.trace_workflow")
    def test_skip_step_not_accessible(self, mock_trace):
        mock_trace_obj = MagicMock()
        mock_trace_obj.steps = [{"url": "http://test.com/s1"}]
        mock_trace_obj.to_dict.return_value = {}
        mock_trace.return_value = mock_trace_obj

        with patch("tools.biz_logic_v2.WorkflowDeviator") as MockDeviator:
            mock_deviator = MagicMock()
            MockDeviator.return_value = mock_deviator
            mock_deviator.generate_skip_steps.return_value = [
                {"target_url": "http://test.com/admin", "description": "skip to admin"},
            ]
            mock_deviator.generate_replay.return_value = []
            mock_deviator.find_resource_ids.return_value = []

            mock_sess = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_sess.get.return_value = mock_resp

            result = run_workflow_scan("http://test.com", [], sess=mock_sess)
            assert result["vulnerable"] is False

    @patch("tools.biz_logic_v2.trace_workflow")
    def test_replay_detected(self, mock_trace):
        mock_trace_obj = MagicMock()
        mock_trace_obj.steps = [{"url": "http://test.com/s1"}]
        mock_trace_obj.to_dict.return_value = {}
        mock_trace.return_value = mock_trace_obj

        with patch("tools.biz_logic_v2.WorkflowDeviator") as MockDeviator:
            mock_deviator = MagicMock()
            MockDeviator.return_value = mock_deviator
            mock_deviator.generate_skip_steps.return_value = []
            mock_deviator.generate_replay.return_value = [
                {"old_url": "http://test.com/s1", "description": "replay"},
            ]
            mock_deviator.find_resource_ids.return_value = []

            mock_sess = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_sess.get.return_value = mock_resp

            result = run_workflow_scan("http://test.com", [], sess=mock_sess)
            assert result["vulnerable"] is True
            assert result["findings"][0]["type"] == "state_replay"

    @patch("tools.biz_logic_v2.trace_workflow")
    def test_resource_ids_extracted(self, mock_trace):
        mock_trace_obj = MagicMock()
        mock_trace_obj.steps = [{"url": "http://test.com/s1"}]
        mock_trace_obj.to_dict.return_value = {}
        mock_trace.return_value = mock_trace_obj

        with patch("tools.biz_logic_v2.WorkflowDeviator") as MockDeviator:
            mock_deviator = MagicMock()
            MockDeviator.return_value = mock_deviator
            mock_deviator.generate_skip_steps.return_value = []
            mock_deviator.generate_replay.return_value = []
            mock_deviator.find_resource_ids.return_value = [
                ("id", "42", 0), ("uid", "99", 0),
            ]

            result = run_workflow_scan("http://test.com", [{"step": "a"}], sess=MagicMock())
            assert result["vulnerable"] is True
            assert len(result["findings"]) == 2
            assert result["findings"][0]["type"] == "idor_candidate"


class TestRunRaceScan:
    @patch("tools.biz_logic_v2.RaceProfiler")
    def test_race_window_found(self, MockProfiler):
        mock_profiler = MagicMock()
        MockProfiler.return_value = mock_profiler
        mock_window = MagicMock()
        mock_window.concurrency = 10
        mock_window.elapsed_ms = 5.0
        mock_window.duplicate_success = True
        mock_window.state_mismatch = False
        mock_window.integrity_violated = False
        mock_window.resource_created_twice = False
        mock_profiler.detect_windows.return_value = {
            "window_found": True,
            "windows": [mock_window],
        }

        result = run_race_scan("http://test.com", param="id")
        assert result["vulnerable"] is True
        assert len(result["windows"]) == 1

    @patch("tools.biz_logic_v2.RaceProfiler")
    def test_no_race_window(self, MockProfiler):
        mock_profiler = MagicMock()
        MockProfiler.return_value = mock_profiler
        mock_profiler.detect_windows.return_value = {
            "window_found": False,
            "windows": [],
        }

        result = run_race_scan("http://test.com", param="id")
        assert result["vulnerable"] is False

    @patch("tools.biz_logic_v2.RaceProfiler")
    def test_default_param_body(self, MockProfiler):
        mock_profiler = MagicMock()
        MockProfiler.return_value = mock_profiler
        mock_profiler.detect_windows.return_value = {
            "window_found": False, "windows": [],
        }

        run_race_scan("http://test.com")
        mock_profiler.detect_windows.assert_called_once()
        args = mock_profiler.detect_windows.call_args
        assert args[0][0] == "http://test.com"
        assert args[0][1] is None

    @patch("tools.biz_logic_v2.RaceProfiler")
    def test_custom_concurrency(self, MockProfiler):
        mock_profiler = MagicMock()
        MockProfiler.return_value = mock_profiler
        mock_profiler.detect_windows.return_value = {
            "window_found": False, "windows": [],
        }

        result = run_race_scan("http://test.com", concurrency=50)
        assert result["vulnerable"] is False


class TestRunConstraintScan:
    @patch("tools.biz_logic_v2.ConstraintGraph")
    def test_no_constraints(self, MockGraph):
        mock_graph = MagicMock()
        MockGraph.return_value = mock_graph
        mock_graph.detect_constraints.return_value = []
        mock_graph.summary.return_value = {}

        result = run_constraint_scan("http://test.com")
        assert result["vulnerable"] is False
        assert result["findings"] == []

    @patch("tools.biz_logic_v2.ConstraintGraph")
    def test_constraints_detected(self, MockGraph):
        mock_graph = MagicMock()
        MockGraph.return_value = mock_graph
        mock_constraint = MagicMock()
        mock_constraint.type = "numeric_relationship"
        mock_constraint.description = "price > 0 constraint"
        mock_constraint.params = ["price"]
        mock_constraint.severity = "medium"
        mock_graph.detect_numerical_relationships.return_value = None
        mock_graph.detect_constraints.return_value = [mock_constraint]
        mock_graph.summary.return_value = {"nodes": 5}

        result = run_constraint_scan("http://test.com", param="price", sess=MagicMock())
        assert result["vulnerable"] is True
        assert len(result["constraints"]) == 1
        assert result["constraints"][0]["type"] == "numeric_relationship"

    @patch("tools.biz_logic_v2.ConstraintGraph")
    @patch("tools.biz_logic_v2.ConstraintBreaker")
    def test_constraint_breaker_findings(self, MockBreaker, MockGraph):
        mock_graph = MagicMock()
        MockGraph.return_value = mock_graph
        mock_graph.detect_constraints.return_value = []
        mock_graph.summary.return_value = {}

        mock_breaker = MagicMock()
        MockBreaker.return_value = mock_breaker
        mock_breaker.generate_break_tests.return_value = [
            {"technique": "negate", "param": "qty", "value": "-1", "variant": "int"},
        ]

        result = run_constraint_scan("http://test.com", param="qty", sess=MagicMock())
        assert result["vulnerable"] is True
        assert len(result["findings"]) == 1

    @patch("tools.biz_logic_v2.ConstraintGraph")
    def test_request_exception_handled(self, MockGraph):
        mock_graph = MagicMock()
        MockGraph.return_value = mock_graph
        mock_graph.detect_constraints.return_value = []
        mock_graph.summary.return_value = {}

        mock_sess = MagicMock()
        mock_sess.get.side_effect = Exception("Timeout")

        result = run_constraint_scan("http://test.com", sess=mock_sess)
        assert result["vulnerable"] is False


class TestCheck:
    @patch("tools.biz_logic_v2.run_constraint_scan")
    @patch("tools.biz_logic_v2.run_race_scan")
    def test_both_not_vulnerable(self, mock_race, mock_constraint):
        mock_constraint.return_value = {"vulnerable": False, "data": "c"}
        mock_race.return_value = {"vulnerable": False, "data": "r"}

        result = check("http://test.com", "id")
        assert result["vulnerable"] is False
        assert result["checks"]["constraints"]["data"] == "c"
        assert result["checks"]["race"]["data"] == "r"

    @patch("tools.biz_logic_v2.run_constraint_scan")
    @patch("tools.biz_logic_v2.run_race_scan")
    def test_constraint_vulnerable(self, mock_race, mock_constraint):
        mock_constraint.return_value = {"vulnerable": True, "findings": ["x"]}
        mock_race.return_value = {"vulnerable": False}

        result = check("http://test.com", "id")
        assert result["vulnerable"] is True

    @patch("tools.biz_logic_v2.run_constraint_scan")
    @patch("tools.biz_logic_v2.run_race_scan")
    def test_race_vulnerable(self, mock_race, mock_constraint):
        mock_constraint.return_value = {"vulnerable": False}
        mock_race.return_value = {"vulnerable": True, "windows": ["w"]}

        result = check("http://test.com", "id")
        assert result["vulnerable"] is True

    @patch("tools.biz_logic_v2.run_constraint_scan")
    @patch("tools.biz_logic_v2.run_race_scan")
    def test_both_vulnerable(self, mock_race, mock_constraint):
        mock_constraint.return_value = {"vulnerable": True}
        mock_race.return_value = {"vulnerable": True}

        result = check("http://test.com", "id")
        assert result["vulnerable"] is True

    @patch("tools.biz_logic_v2.run_constraint_scan")
    @patch("tools.biz_logic_v2.run_race_scan")
    def test_custom_timeout(self, mock_race, mock_constraint):
        mock_constraint.return_value = {"vulnerable": False}
        mock_race.return_value = {"vulnerable": False}

        check("http://test.com", "id", timeout=30.0)
        mock_constraint.assert_called_once_with(
            "http://test.com", "id", None, 30.0
        )
        mock_race.assert_called_once_with(
            "http://test.com", "id", sess=None, timeout=30.0
        )
