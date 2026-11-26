"""Offline dual-session BOLA/info-disclosure decision tests."""

from tools.dual_session import DualSessionManager


class _Response:
    def __init__(self, status=200, text="ok"):
        self.status_code = status
        self.text = text


class _Session:
    def __init__(self, response):
        self._response = response

    def get(self, *args, **kwargs):
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def _manager(low, high):
    return DualSessionManager(_Session(low), _Session(high))


def test_public_endpoint_same_response_is_not_info_disclosure():
    result = _manager(_Response(), _Response()).test_point("http://t/api/public", "id")
    assert result["bola_detected"] is False
    assert result["info_disclosure"] is False
    assert result["evidence"] == []


def test_protected_endpoint_same_response_is_bola_and_disclosure():
    result = _manager(_Response(), _Response()).test_point("http://t/api/user/1", "id")
    assert result["bola_detected"] is True
    assert result["info_disclosure"] is True
    assert any("BOLA" in item for item in result["evidence"])


def test_low_privilege_success_high_denied_is_access_control_bypass():
    result = _manager(_Response(200, "data"), _Response(403, "denied")).test_point(
        "http://t/api/user/1", "id"
    )
    assert result["access_control_bypass"] is True
    assert result["bola_detected"] is False


def test_low_request_error_is_returned_without_high_request():
    result = _manager(RuntimeError("boom"), _Response()).test_point("http://t/api/user/1", "id")
    assert "boom" in result["low_error"]
    assert result["high_status"] is None
