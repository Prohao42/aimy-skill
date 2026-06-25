import pytest
import responses
from tools.race_condition import check


class TestRaceCondition:
    @responses.activate
    def test_race_detection(self):
        def callback(request):
            import json
            data = json.loads(request.body)
            return (200, {}, json.dumps({"status": "ok", "balance": 100}))

        responses.add_callback(
            responses.POST,
            'http://test.com/api/claim',
            callback=callback,
        )
        result = check('http://test.com/api/claim', 'coupon')
        assert result is not None

    @responses.activate
    def test_no_race(self):
        responses.add(
            responses.POST, 'http://test.com/api/claim',
            body='{"error":"already claimed"}', status=400,
        )
        result = check('http://test.com/api/claim', 'coupon')
        assert result is not None
