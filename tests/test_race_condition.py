import responses

from tools.race_condition import RaceConditionTester, check


class TestRaceAnalysis:
    def test_repeated_success_status_differs_from_baseline(self):
        responses = [
            {"i": i, "status": 200, "len": 20, "body": "ok", "elapsed_ms": 5} for i in range(2)
        ]
        result = RaceConditionTester()._analyze_round(responses, 400, 20, "error")
        assert result["vulnerable"] is True
        assert result["type"] == "status_differential"

    def test_length_variance_is_detected(self):
        responses = [
            {"i": 0, "status": 200, "len": 100, "body": "a" * 100, "elapsed_ms": 5},
            {"i": 1, "status": 200, "len": 300, "body": "b" * 300, "elapsed_ms": 5},
        ]
        result = RaceConditionTester()._analyze_round(responses, 200, 100, "a" * 100)
        assert result["vulnerable"] is True
        assert result["type"] == "length_variance"

    def test_identical_idempotent_responses_are_not_a_race(self):
        responses = [
            {"i": i, "status": 200, "len": 2, "body": "ok", "elapsed_ms": 5} for i in range(20)
        ]
        result = RaceConditionTester()._analyze_round(responses, 200, 2, "ok")
        assert result["vulnerable"] is False


class TestRaceCheck:
    @responses.activate
    def test_post_method_and_payload_are_used(self):
        seen = []

        def callback(request):
            seen.append((request.method, request.body))
            return (200, {}, "ok")

        responses.add_callback(responses.POST, "http://test.com/api/claim", callback=callback)
        result = check(
            "http://test.com/api/claim",
            "coupon",
            post_body=True,
            post_data={"coupon": "SAVE10", "Submit": "Submit"},
        )
        assert result["rounds_tested"] == 3
        assert seen
        assert all(method == "POST" for method, _ in seen)
        assert all("coupon=SAVE10" in body for _, body in seen)

    @responses.activate
    def test_no_race_with_failure_responses(self):
        responses.add(
            responses.POST,
            "http://test.com/api/claim",
            body='{"error":"already claimed"}',
            status=400,
        )
        result = check("http://test.com/api/claim", "coupon", post_body=True)
        assert result["vulnerable"] is False
        assert result["rounds_tested"] == 3
