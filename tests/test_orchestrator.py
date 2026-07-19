import time
import pytest
from unittest.mock import patch, MagicMock, Mock, PropertyMock
from tools.false_positive_filter import FalsePositiveFilter


class MockResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.elapsed = 0.1


class TestTestSinglePoint:
    """Test the _test_single_point method with confidence and FPF integration."""

    @pytest.fixture(autouse=True)
    def _cleanup_detectors(self):
        from tools.orchestrator import ALL_DETECTORS
        saved = ALL_DETECTORS.copy()
        yield
        ALL_DETECTORS.clear()
        ALL_DETECTORS.update(saved)

    def _make_orchestrator(self):
        from tools.orchestrator import Orchestrator, ALL_DETECTORS
        o = Orchestrator("http://target.test")
        o._lock = __import__("threading").Lock()
        o.state["filtered_findings"] = []
        o._backtrack_findings = []
        o._chain_cache = {}
        o.profiler = MagicMock()
        return o

    def _register_test_detector(self, o, name="test_vuln", mock_det=None):
        """Register a mock detector function in ALL_DETECTORS."""
        from tools.orchestrator import ALL_DETECTORS
        if mock_det is None:
            mock_det = lambda url, param, sess, timeout, waf, oob: self._detector()
        ALL_DETECTORS[name] = mock_det

    def _detector(self, vulnerable=True, confidence=0.8, votes=None, evidence=None):
        return {
            "vulnerable": vulnerable,
            "type": "test_vuln",
            "confidence_score": confidence,
            "confidence_votes": votes or [],
            "evidence": evidence or ["test evidence", "test evidence 2"],
        }

    def test_confidence_merging_detector_higher(self):
        """Native detector confidence is higher than oracle, so final = native."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.85)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.4,
            "confidence_votes": [],
            "evidence": ["oracle evidence", "oracle evidence 2"],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 1
        assert result[0]["confidence_score"] == 0.85
        assert result[0]["detector_confidence"] == 0.85

    def test_confidence_merging_oracle_higher(self):
        """Oracle confidence is higher than native, so final = oracle."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.4)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.9,
            "confidence_votes": ["oob_callback:0.95"],
            "evidence": ["OOB callback", "OOB evidence"],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 1
        assert result[0]["confidence_score"] == 0.9
        assert result[0]["detector_confidence"] == 0.4

    def test_false_positive_low_confidence_skipped(self):
        """Low confidence findings are filtered and stored in state."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.1)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.1,
            "confidence_votes": [],
            "evidence": ["weak signal"],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0
        assert len(o.state["filtered_findings"]) == 1
        assert o.state["filtered_findings"][0]["filtered"] is True
        assert "low_confidence" in o.state["filtered_findings"][0].get("filter_reason", "")

    def test_high_confidence_passes_filter(self):
        """High confidence findings pass through FPF."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.85)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.85,
            "confidence_votes": ["bool_multi_confirmed:0.75"],
            "evidence": ["sqli: error", "time_delay: 3.2s"],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 1
        assert result[0]["filtered"] is False
        assert len(o.state["filtered_findings"]) == 0

    def test_non_vulnerable_skipped(self):
        """Detector returning vulnerable=False generates no finding."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(vulnerable=False)
        self._register_test_detector(o, "test_vuln", mock_det)

        o._budget_ok = MagicMock(return_value=True)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0

    def test_oracle_not_verified_skipped(self):
        """Oracle returning verified=False skips the finding."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.8)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": False,
            "confidence_score": 0.0,
            "confidence_votes": [],
            "evidence": [],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0

    def test_evidence_passed_through(self):
        """Evidence from detector reaches the finding."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(evidence=["sqli: error based", "sqli: time based"])
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.8,
            "confidence_votes": ["bool_diff:0.5"],
            "evidence": ["sqli: error based", "sqli: time based"],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result[0]["evidence"]) >= 2

    def test_confidence_votes_passed_through(self):
        """Confidence votes from detector or oracle reach the finding."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(votes=["output_indicator:0.70"])
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.7,
            "confidence_votes": ["output_indicator:0.70"],
            "evidence": ["evidence 1", "evidence 2"],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result[0]["confidence_votes"]) > 0

    def test_error_page_finding_filtered(self):
        """Finding with error page content gets filtered."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.8)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.8,
            "confidence_votes": [],
            "evidence": ["test"],
            "response_text": "<title>404 Not Found</title><h1>Error 404</h1>",
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0
        assert len(o.state["filtered_findings"]) == 1

    def test_backtrack_chain_skipped_for_filtered(self):
        """Chain backtracking is not called for filtered findings."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.1)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.1,
            "confidence_votes": [],
            "evidence": [],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)
        o._maybe_backtrack_chain = MagicMock(return_value={"success": True})

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        o._maybe_backtrack_chain.assert_not_called()

    def test_backtrack_chain_called_for_unfiltered(self):
        """Chain backtracking is called for unfiltered high-confidence findings."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.85)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.85,
            "confidence_votes": ["bool_diff:0.5"],
            "evidence": ["sqli: error", "sqli: evidence 2"],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        o._test_single_point(
            {"url": "http://target.test/page", "param": "id"},
            ["test_vuln"],
        )

        o._maybe_backtrack_chain.assert_called_once()

    def test_timestamp_in_finding(self):
        """Finding includes a timestamp field."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.8)
        self._register_test_detector(o, "test_vuln", mock_det)
        before = time.time()

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.8,
            "confidence_votes": [],
            "evidence": ["test 1", "test 2"],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert before <= result[0]["timestamp"] <= time.time() + 1

    def test_vulnerable_field_overridden_by_fpf(self):
        """FPF sets vulnerable=False on filtered finding."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.1)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.1,
            "confidence_votes": [],
            "evidence": [],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0
        assert o.state["filtered_findings"][0]["vulnerable"] is False

    def test_cross_verify_called_when_vulnerable(self):
        """_cross_verify is invoked when detector finds vulnerable."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.8)
        self._register_test_detector(o, "test_vuln", mock_det)

        o._budget_ok = MagicMock(return_value=True)
        cross_mock = MagicMock(side_effect=lambda a, b, c, d, e, f: f)
        o._cross_verify = cross_mock
        o.oracle.verify = MagicMock(return_value={"verified": True, "confidence_score": 0.8, "confidence_votes": [], "evidence": []})
        o._maybe_backtrack_chain = MagicMock(return_value=None)

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        cross_mock.assert_called_once()

    def test_cross_verify_not_called_when_not_vulnerable(self):
        """_cross_verify is skipped when detector returns not vulnerable."""
        o = self._make_orchestrator()

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(vulnerable=False)
        self._register_test_detector(o, "test_vuln", mock_det)

        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock()

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        o._cross_verify.assert_not_called()

    def test_detector_exception_handled(self):
        """Exception in detector is caught and logged, does not crash."""
        o = self._make_orchestrator()

        def mock_det(*args, **kwargs):
            raise ValueError("detector crash")
        self._register_test_detector(o, "test_vuln", mock_det)

        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock()
        o.oracle = MagicMock()

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0

    def test_unknown_detector_skipped(self):
        """Unknown detector type in active_detectors is skipped."""
        o = self._make_orchestrator()
        o._budget_ok = MagicMock(return_value=True)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["nonexistent_detector"],
        )

        assert len(result) == 0

    def test_thread_lock_prevents_race(self):
        """Threading lock is acquired for shared state modifications."""
        o = self._make_orchestrator()
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.1)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.1,
            "confidence_votes": [],
            "evidence": [],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert o._lock.locked() is False

    def test_multiple_detectors_run(self):
        """Multiple detectors in active list each get called."""
        o = self._make_orchestrator()
        call_count = []

        def mock_det1(url, param, sess, timeout, waf, oob):
            call_count.append(1)
            return self._detector(vulnerable=False)
        def mock_det2(url, param, sess, timeout, waf, oob):
            call_count.append(1)
            return self._detector(vulnerable=False)
        def mock_det3(url, param, sess, timeout, waf, oob):
            call_count.append(1)
            return self._detector(vulnerable=False)
        self._register_test_detector(o, "test_vuln", mock_det1)
        self._register_test_detector(o, "test_vuln2", mock_det2)
        self._register_test_detector(o, "test_vuln3", mock_det3)

        o._budget_ok = MagicMock(return_value=True)

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln", "test_vuln2", "test_vuln3"],
        )

        assert len(call_count) == 3

    def test_lock_initialized_in_init(self):
        """_lock is initialized in Orchestrator.__init__."""
        o = self._make_orchestrator()
        assert hasattr(o, '_lock')
        o.state["filtered_findings"] = []

        def mock_det(url, param, sess, timeout, waf, oob):
            return self._detector(confidence=0.1)
        self._register_test_detector(o, "test_vuln", mock_det)

        o.oracle.verify = MagicMock(return_value={
            "verified": True,
            "confidence_score": 0.1,
            "confidence_votes": [],
            "evidence": [],
        })
        o._budget_ok = MagicMock(return_value=True)
        o._cross_verify = MagicMock(side_effect=lambda a, b, c, d, e, f: f)

        o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(o.state["filtered_findings"]) == 1

    def test_budget_exhausted_skips(self):
        """When budget is exhausted, no tests run."""
        o = self._make_orchestrator()
        o._budget_ok = MagicMock(return_value=False)

        result = o._test_single_point(
            {"url": "http://target.test/page", "param": "q"},
            ["test_vuln"],
        )

        assert len(result) == 0


class TestOrchestratorIntegration:
    """Integration-level tests for the Orchestrator."""

    @patch("tools.orchestrator.fingerprint_tech", return_value={})
    @patch("tools.orchestrator.scan_ports", return_value={})
    @patch("tools.orchestrator.check_git_leak", return_value={})
    @patch("tools.orchestrator.fuzz_directories", return_value={"interesting": []})
    def test_phase_recon_runs(self, *mocks):
        from tools.orchestrator import Orchestrator
        o = Orchestrator("http://target.test", time_budget=600)
        result = o.phase_recon()
        assert "target" in result
        assert result["target"] == "http://target.test"

    @patch("tools.orchestrator.ALL_DETECTORS", {})
    def test_phase_detect_no_points(self):
        from tools.orchestrator import Orchestrator
        o = Orchestrator("http://target.test", time_budget=600)
        crawl_result = o.phase_crawl()
        o.state["phases"]["crawl"] = crawl_result
        o.state["phases"]["param_mine"] = {}
        # Run _select_detectors with empty state
        o.last_hypotheses = []

        with patch.object(o, '_run_kali_recon'):
            result = o.phase_detect()

        assert isinstance(result, dict)

    @patch("tools.orchestrator.build_attack_plan")
    def test_phase_attack_plan_empty(self, mock_plan):
        mock_plan.return_value = {"phases": [], "risk_score": 0}
        from tools.orchestrator import Orchestrator
        o = Orchestrator("http://target.test", time_budget=600)
        o.state["phases"]["recon"] = {"technologies": {}, "open_ports": {}, "git_leak": {}, "directories": {}}
        result = o.phase_attack_plan()
        assert "phases" in result

    def test_select_detectors_default_order(self):
        from tools.orchestrator import Orchestrator, ALL_DETECTORS
        o = Orchestrator("http://target.test", time_budget=600)
        o.last_hypotheses = []
        result = o._select_detectors()
        assert len(result) == len(ALL_DETECTORS)
        assert result[0] == "sql_injection"

    @patch("tools.orchestrator.fingerprint_tech", return_value={})
    @patch("tools.orchestrator.scan_ports", return_value={})
    @patch("tools.orchestrator.check_git_leak", return_value={})
    @patch("tools.orchestrator.fuzz_directories", return_value={"interesting": []})
    def test_recon_stores_state(self, *mocks):
        from tools.orchestrator import Orchestrator
        o = Orchestrator("http://target.test", time_budget=600)
        o.phase_recon()
        assert "recon" in o.state["phases"]

    def test_build_test_points_with_crawl_data(self):
        """Build test points from crawl data with one endpoint + param."""
        from tools.orchestrator import Orchestrator
        o = Orchestrator("http://target.test", time_budget=600)
        o.state["phases"]["recon"] = {"technologies": {"technologies": [{"id": "php"}]}, "open_ports": {}, "git_leak": {}, "directories": {}}
        o.state["phases"]["crawl"] = {
            "endpoints": {"/page.php": {"url": "http://target.test/page.php", "methods": ["GET"], "params": ["id"]}},
            "parameters": ["id"],
            "js_api_endpoints": [],
        }
        o.state["phases"]["param_mine"] = {}
        points = o._build_test_points()
        assert len(points) > 0
        assert any("id" in p.get("param", "") for p in points)

    def test_budget_tracking(self):
        from tools.orchestrator import Orchestrator
        o = Orchestrator("http://target.test", time_budget=600)
        o._start_time = time.time() - 100
        remaining = o._budget_remaining()
        assert 495 < remaining <= 600


class TestFalsePositiveFilter:
    """Verify FPF integration with orchestrator findings."""

    def test_fpf_filters_low_confidence(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": True,
            "confidence_score": 0.1,
            "evidence": ["weak test"],
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is True
        assert "low_confidence" in result["filter_reason"]

    def test_fpf_passes_high_confidence(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": True,
            "confidence_score": 0.85,
            "evidence": ["sqli: error", "time_delay: 3.2s"],
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is False

    def test_fpf_filters_insufficient_evidence(self):
        fpf = FalsePositiveFilter()
        fpf.set_threshold(min_evidence=3)
        finding = {
            "vulnerable": True,
            "confidence_score": 0.85,
            "evidence": ["sqli: error"],
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is True
        assert "insufficient_evidence" in result["filter_reason"]

    def test_fpf_filters_error_page(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": True,
            "confidence_score": 0.85,
            "evidence": ["sqli: error"],
            "response_text": "<title>404 Not Found</title>",
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is True
        assert "error_page" in result["filter_reason"]

    def test_fpf_filter_sets_vulnerable_false(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": True,
            "confidence_score": 0.1,
            "evidence": ["test"],
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["vulnerable"] is False

    def test_fpf_not_vulnerable_not_filtered(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": False,
            "confidence_score": 0.0,
            "evidence": [],
            "timestamp": time.time(),
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is False

    def test_fpf_batch_filter(self):
        fpf = FalsePositiveFilter()
        results = [
            {"vulnerable": True, "confidence_score": 0.1, "evidence": ["test"], "timestamp": time.time()},
            {"vulnerable": True, "confidence_score": 0.85, "evidence": ["a", "b"], "timestamp": time.time()},
            {"vulnerable": True, "confidence_score": 0.9, "evidence": ["a", "b", "c"], "timestamp": time.time()},
        ]
        out = fpf.filter(results)
        assert len(out) == 2

    def test_stale_data_filtered(self):
        fpf = FalsePositiveFilter()
        finding = {
            "vulnerable": True,
            "confidence_score": 0.85,
            "evidence": ["sqli: error"],
            "timestamp": time.time() - 7200,
        }
        result = fpf.filter_single(finding)
        assert result["filtered"] is True
        assert "stale_data" in result["filter_reason"]


class TestBenchmarkHelpers:
    """Test helper utilities used by orchestrator."""

    def test_skip_params_defined(self):
        from tools.orchestrator import SKIP_PARAMS
        assert "submit" in SKIP_PARAMS
        assert "button" in SKIP_PARAMS

    def test_detector_risk_order_has_all(self):
        from tools.orchestrator import DETECTOR_RISK_ORDER, ALL_DETECTORS
        for d in ALL_DETECTORS:
            assert d in DETECTOR_RISK_ORDER, "%s missing from DETECTOR_RISK_ORDER" % d

    def test_all_detectors_lambdas_are_callable(self):
        """Every entry in ALL_DETECTORS is a callable function."""
        from tools.orchestrator import ALL_DETECTORS
        for name, fn in ALL_DETECTORS.items():
            assert callable(fn), "%s entry is not callable" % name
