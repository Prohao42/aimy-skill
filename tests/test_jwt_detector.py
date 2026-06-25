import re
import json
import base64
import pytest
import responses
from tools.jwt_detector import (
    check, decode_jwt_payload, decode_jwt_header,
    check_jwt_none, check_jwt_weak_secret,
)


def _make_b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')


class TestJWTDecode:
    def test_decode_valid_token(self):
        hdr = _make_b64({"alg": "HS256", "typ": "JWT"})
        pld = _make_b64({"sub": "123", "role": "admin"})
        token = f"{hdr}.{pld}.signature"
        assert decode_jwt_payload(token) == {"sub": "123", "role": "admin"}
        assert decode_jwt_header(token) == {"alg": "HS256", "typ": "JWT"}

    def test_decode_invalid_token(self):
        assert decode_jwt_payload("not.a.token") is None
        assert decode_jwt_header("invalid") is None


class TestCheckJwtNone:
    def test_alg_none_token_generated(self):
        result = check_jwt_none(sess=None, url=None)
        assert 'token' in result
        assert result['header']['alg'] == 'none'

    @responses.activate
    def test_alg_none_accepted(self):
        responses.add(
            responses.GET, 'http://test.com/admin',
            body='admin panel', status=200,
        )
        import requests
        sess = requests.Session()
        result = check_jwt_none(sess, 'http://test.com/admin')
        assert result['vulnerable'] is True


class TestCheckJwtWeakSecret:
    def test_weak_secret_found(self):
        test_secret = "supersecret"
        hdr = _make_b64({"alg": "HS256"})
        pld = _make_b64({"sub": "user"})
        import hmac, hashlib
        sig = hmac.new(test_secret.encode(), f"{hdr}.{pld}".encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
        token = f"{hdr}.{pld}.{sig_b64}"
        result = check_jwt_weak_secret(token)
        assert result['vulnerable'] is True
        assert result['found_secret'] == test_secret

    def test_no_weak_secret(self):
        hdr = _make_b64({"alg": "HS256"})
        pld = _make_b64({"sub": "user"})
        import hmac, hashlib
        sig = hmac.new(b"unknown_secret_12345", f"{hdr}.{pld}".encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
        token = f"{hdr}.{pld}.{sig_b64}"
        result = check_jwt_weak_secret(token)
        assert result['vulnerable'] is False


class TestJWTCheck:
    @responses.activate
    def test_jwt_found_in_body(self):
        token_hdr = _make_b64({"alg": "HS256"})
        token_pld = _make_b64({"sub": "admin", "role": "admin"})
        token = f"{token_hdr}.{token_pld}.signature"
        responses.add(
            responses.GET, 'http://test.com/page',
            body=f'<html>token: {token}</html>', status=200,
        )
        result = check('http://test.com/page')
        assert result['vulnerable'] is True
        assert len(result['tokens_found']) > 0

    @responses.activate
    def test_no_jwt_found(self):
        responses.add(
            responses.GET, 'http://test.com/static',
            body='<html>no tokens here</html>', status=200,
        )
        responses.add(
            responses.GET, re.compile(r'http://test\.com/static.*'),
            body='unauthorized', status=401,
        )
        result = check('http://test.com/static')
        assert result['vulnerable'] is False
