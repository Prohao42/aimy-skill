import re

import responses

from tools.param_classifier import ParameterProfile
from tools.smart_fuzzer import (
    ROLE_FUZZ_STRATEGIES,
    LearningFuzzer,
    ResponseFingerprint,
    SmartFuzzer,
)


class TestSmartFuzzer:
    def _profile(self, role="content"):
        return ParameterProfile(name="q", role=role, confidence=0.9, data_type="string")

    @responses.activate
    def test_fuzz_point_sqli_detection(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/api/search\?.*"),
            body="You have an error in your SQL syntax near '1'",
            status=200,
        )
        fz = SmartFuzzer()
        results = fz.fuzz_point("http://test.com/api/search", "q", sample_value="term")
        assert results
        assert any(r.vulnerable and r.attack_type == "sqli" for r in results)

    @responses.activate
    def test_fuzz_point_no_findings(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/api/search\?.*"),
            body="no results",
            status=200,
        )
        fz = SmartFuzzer()
        results = fz.fuzz_point("http://test.com/api/search", "q")
        assert results == [] or all(not r.vulnerable for r in results)

    def test_check_sqli_error_match(self):
        fz = SmartFuzzer()
        res = fz._check_sqli(
            _make_result(),
            "You have an error in your SQL syntax near '1' at line 1",
            {"status": 200, "length": 10},
        )
        assert res is not None
        assert res.attack_type == "sqli"
        assert res.vulnerable
        assert res.confidence == "high"

    def test_check_sqli_length_diff(self):
        fz = SmartFuzzer()
        baseline = {"status": 200, "length": 100}
        res = fz._check_sqli(_make_result(), "A" * 500, baseline)
        assert res is not None
        assert res.vulnerable
        assert res.confidence == "medium"

    def test_reflection_check(self):
        fz = SmartFuzzer()
        assert fz._check_reflection("<script>alert(1)</script>", "foo <script>alert(1)</script>")
        assert not fz._check_reflection("<script>alert(1)</script>", "foo &lt;script&gt;alert(1)")
        assert not fz._check_reflection("payload", "nothing here")

    def test_infer_role_from_context(self):
        fz = SmartFuzzer()
        assert fz._infer_role_from_context("user_id", "http://x.test/api/users") == "identifier"
        assert fz._infer_role_from_context("q", "http://x.test/api/search") == "filter"
        assert fz._infer_role_from_context("token", "http://x.test/api/login") == "auth"
        assert fz._infer_role_from_context("price", "http://x.test/api/order") == "financial"
        assert fz._infer_role_from_context("foo", "http://x.test/anything") == "content"

    def test_strategy_fallback(self):
        profile = self._profile("unknown_role")
        strategies = ROLE_FUZZ_STRATEGIES.get(profile.role) or ROLE_FUZZ_STRATEGIES["content"]
        assert strategies["label"] == "XSS / SSTI"


def _make_result():
    from tools.smart_fuzzer import FuzzResult

    return FuzzResult(
        param="id",
        role="filter",
        attack_type="sqli",
        payload="test",
        before_length=100,
        after_length=500,
    )


class TestResponseFingerprint:
    class _Resp:
        def __init__(self, status, text, headers=None):
            self.status_code = status
            self.text = text
            self.headers = headers or {}

    def test_from_response(self):
        fp = ResponseFingerprint.from_response(self._Resp(200, "hello world\n" * 3))
        assert fp.status == 200
        assert fp.line_count == 3
        assert fp.word_count > 0
        assert fp.hash_prefix

    def test_server_error_flag(self):
        fp = ResponseFingerprint.from_response(self._Resp(500, "boom"))
        assert fp.has_error
        assert fp.error_type == "server_error"

    def test_diff_score_status_change(self):
        a = ResponseFingerprint(200, 100, 1, 10, "aaaabbbb")
        b = ResponseFingerprint(404, 100, 1, 10, "aaaabbbb")
        assert a.diff_score(b) >= 3.0

    def test_diff_score_blocked_status_penalty(self):
        a = ResponseFingerprint(200, 100, 1, 10, "aaaabbbb")
        b = ResponseFingerprint(
            200,
            100,
            1,
            10,
            "aaaabbbb",
        )
        blocked = ResponseFingerprint(403, 100, 1, 10, "aaaabbbb")
        assert a.diff_score(b) < a.diff_score(blocked)


class TestLearningFuzzer:
    @responses.activate
    def test_fuzz_param_finds_interesting(self):
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/api\?.*"),
            body="a" * 500,
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/api$"),
            body="a" * 100,
            status=200,
        )
        fz = LearningFuzzer(sess=__import__("requests").Session(), timeout=5)
        hits = fz.fuzz_param("http://t.test/api", "q", ["x", "y"], "generic")
        assert hits

    @responses.activate
    def test_learn_and_refine(self):
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/api\?.*"),
            body="b" * 300,
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(r"http://t\.test/api$"),
            body="b" * 50,
            status=200,
        )
        fz = LearningFuzzer(sess=__import__("requests").Session(), timeout=5)
        out = fz.learn_and_refine("http://t.test/api", ["id"], {"injection": ["' OR 1=1--", "1"]})
        assert "findings" in out
        assert "top_params" in out
        assert "high_confidence" in out

    def test_top_params_ordering(self):
        fz = LearningFuzzer(sess=None)
        fz._param_scores = {"a": 1.0, "b": 5.0, "c": 2.0}
        assert fz.top_params(2) == ["b", "c"]
        assert fz.top_params() == ["b", "c", "a"]

    def test_top_findings_threshold(self):
        fz = LearningFuzzer(sess=None)
        fz._interesting = [
            {"param": "a", "diff_score": 4.5},
            {"param": "b", "diff_score": 2.0},
        ]
        out = fz.top_findings(threshold=3.0)
        assert len(out) == 1
        assert out[0]["param"] == "a"
