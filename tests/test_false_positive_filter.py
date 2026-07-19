import pytest
from tools.false_positive_filter import FalsePositiveFilter, filter_results, filter_single_result


class TestFalsePositiveFilter:
    def test_low_confidence_filtered(self):
        r = {"vulnerable": True, "evidence": ["sqli: error"], "confidence_score": 0.1}
        fpf = FalsePositiveFilter()
        out = fpf.filter_single(r)
        assert out["filtered"] is True
        assert "low_confidence" in out["filter_reason"]

    def test_high_confidence_passes(self):
        r = {"vulnerable": True, "evidence": ["time_delay", "bool_diff"], "confidence_score": 0.85}
        fpf = FalsePositiveFilter()
        out = fpf.filter_single(r)
        assert out["filtered"] is False

    def test_insufficient_evidence_filtered(self):
        r = {"vulnerable": True, "evidence": [], "confidence_score": 0.8}
        fpf = FalsePositiveFilter()
        fpf.set_threshold(min_evidence=1)
        out = fpf.filter_single(r)
        assert out["filtered"] is True
        assert "insufficient_evidence" in out["filter_reason"]

    def test_error_page_filtered(self):
        r = {"vulnerable": True, "evidence": ["sqli"], "confidence_score": 0.8,
             "response_text": "<title>404 Not Found</title><h1>Error 404</h1>"}
        fpf = FalsePositiveFilter()
        out = fpf.filter_single(r)
        assert out["filtered"] is True
        assert "error_page" in out["filter_reason"]

    def test_short_response_filtered(self):
        r = {"vulnerable": True, "evidence": ["xss: alert"], "confidence_score": 0.8,
             "response_text": "ok"}
        fpf = FalsePositiveFilter()
        out = fpf.filter_single(r)
        assert out["filtered"] is True
        assert "error_page" in out["filter_reason"]

    def test_noise_keywords_filtered(self):
        r = {"vulnerable": True, "evidence": ["xss: test"], "confidence_score": 0.8,
             "response_text": "This is a test page. Example content here. Default placeholder demo sample text for testing under construction."}
        fpf = FalsePositiveFilter()
        out = fpf.filter_single(r)
        assert out["filtered"] is True

    def test_stale_data_filtered(self):
        import time
        r = {"vulnerable": True, "evidence": ["time_delay"], "confidence_score": 0.8,
             "timestamp": time.time() - 7200}
        fpf = FalsePositiveFilter()
        out = fpf.filter_single(r)
        assert out["filtered"] is True
        assert "stale_data" in out["filter_reason"]

    def test_fresh_data_not_stale(self):
        import time
        r = {"vulnerable": True, "evidence": ["time_delay", "sqli_error"], "confidence_score": 0.8,
             "timestamp": time.time() - 100}
        fpf = FalsePositiveFilter()
        out = fpf.filter_single(r)
        assert out["filtered"] is False

    def test_batch_filter(self):
        results = [
            {"vulnerable": True, "evidence": ["a"], "confidence_score": 0.1},
            {"vulnerable": True, "evidence": ["a", "b"], "confidence_score": 0.85},
            {"vulnerable": True, "evidence": ["a", "b", "c"], "confidence_score": 0.9},
        ]
        out = filter_results(results)
        assert len(out) == 2

    def test_batch_filter_single_convenience(self):
        r = {"vulnerable": True, "evidence": ["a"], "confidence_score": 0.05}
        out = filter_single_result(r)
        assert out["filtered"] is True

    def test_not_vulnerable_not_filtered(self):
        r = {"vulnerable": False, "evidence": [], "confidence_score": 0.0}
        fpf = FalsePositiveFilter()
        out = fpf.filter_single(r)
        assert out["filtered"] is False

    def test_custom_threshold(self):
        r = {"vulnerable": True, "evidence": ["xss"], "confidence_score": 0.5}
        fpf = FalsePositiveFilter()
        fpf.set_threshold(min_confidence=0.6)
        out = fpf.filter_single(r)
        assert out["filtered"] is True

    def test_raw_response_check(self):
        r = {"vulnerable": True, "evidence": ["ssrf"], "confidence_score": 0.8,
             "raw_response": {"text": "<title>404 Not Found</title>"}}
        fpf = FalsePositiveFilter()
        out = fpf.filter_single(r)
        assert out["filtered"] is True


class TestConfidenceVoter:
    def test_empty_voter(self):
        from tools.verification_oracle import ConfidenceVoter
        v = ConfidenceVoter()
        assert v.score == 0.0
        assert v.level.value == "low"

    def test_single_vote(self):
        from tools.verification_oracle import ConfidenceVoter
        v = ConfidenceVoter()
        v.add_vote("test", 0.8)
        assert abs(v.score - 0.8) < 0.01

    def test_multiple_votes_high_confidence(self):
        from tools.verification_oracle import ConfidenceVoter
        v = ConfidenceVoter()
        v.add_vote("a", 0.9)
        v.add_vote("b", 0.85)
        v.add_vote("c", 0.8)
        assert v.level.value in ("high", "confirmed")

    def test_vote_status_code(self):
        from tools.verification_oracle import ConfidenceVoter, ConfidenceLevel
        mock_resp = type("MockResp", (), {"status_code": 500})()
        w = ConfidenceVoter.vote_status_code(mock_resp, 200)
        assert w == 0.5

    def test_vote_length_diff(self):
        from tools.verification_oracle import ConfidenceVoter
        w = ConfidenceVoter.vote_length_diff(500, 100)
        assert w == 0.7

    def test_vote_body_hash(self):
        from tools.verification_oracle import ConfidenceVoter
        w = ConfidenceVoter.vote_body_hash("abc", "def")
        assert w == 0.6

    def test_vote_body_hash_same(self):
        from tools.verification_oracle import ConfidenceVoter
        w = ConfidenceVoter.vote_body_hash("abc", "abc")
        assert w == 0.0

    def test_vote_time_elapsed(self):
        from tools.verification_oracle import ConfidenceVoter
        w = ConfidenceVoter.vote_time_elapsed(10.0, 2.0, 5.0)
        assert w > 0.8

    def test_vote_evidence_keywords(self):
        from tools.verification_oracle import ConfidenceVoter
        w = ConfidenceVoter.vote_evidence_keywords("root admin sql error", ["root", "admin", "sql", "error"])
        assert w == 0.9

    def test_vote_oob_callback(self):
        from tools.verification_oracle import ConfidenceVoter
        assert ConfidenceVoter.vote_oob_callback(True) == 0.95
        assert ConfidenceVoter.vote_oob_callback(False) == 0.0

    def test_vote_multiple_payloads(self):
        from tools.verification_oracle import ConfidenceVoter
        w = ConfidenceVoter.vote_multiple_payloads(3, 5)
        assert w == 0.8

    def test_vote_multiple_payloads_low(self):
        from tools.verification_oracle import ConfidenceVoter
        w = ConfidenceVoter.vote_multiple_payloads(1, 5)
        assert w == 0.2

    def test_evidence(self):
        from tools.verification_oracle import ConfidenceVoter
        v = ConfidenceVoter()
        v.add_vote("src_a", 0.75)
        assert v.evidence() == ["src_a:0.75"]
