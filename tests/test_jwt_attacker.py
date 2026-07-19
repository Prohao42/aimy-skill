import pytest
import responses
from tools.jwt_attacker import check


class TestJWTAttacker:
    @responses.activate
    def test_jwt_found(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        responses.add(
            responses.GET,
            "http://test.com/api",
            json={"token": token},
            status=200,
        )
        result = check("http://test.com/api")
        assert isinstance(result, dict)

    @responses.activate
    def test_jwt_not_found(self):
        responses.add(
            responses.GET,
            "http://test.com/page",
            body="no token here",
            status=200,
        )
        result = check("http://test.com/page")
        assert result.get("vulnerable", False) is False

    @responses.activate
    def test_jwt_none_algorithm(self):
        token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        responses.add(
            responses.GET,
            "http://test.com/api",
            json={"token": token},
            status=200,
        )
        result = check("http://test.com/api")
        assert isinstance(result, dict)

    @responses.activate
    def test_jwt_weak_secret(self):
        responses.add(
            responses.GET,
            "http://test.com/api",
            json={"token": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.5"},
            status=200,
        )
        result = check("http://test.com/api")
        assert isinstance(result, dict)
