"""Offline SAML response inspection tests."""

import base64
import re
import zlib

import responses

from tools.saml_sso import check

NS = (
    'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
)


def _b64(xml, compress=False):
    raw = xml.encode()
    if compress:
        raw = zlib.compress(raw)[2:-4]
    return base64.b64encode(raw).decode()


def _response(assertion_body, signed=False, compressed=False):
    signature = b"<ds:Signature><ds:SignedInfo/></ds:Signature>" if signed else b""
    xml = (
        "<samlp:Response %s><saml:Assertion>"
        "%s<saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>"
        "%s</saml:Assertion></samlp:Response>" % (NS, assertion_body, signature.decode())
    ).encode()
    if compressed:
        payload = zlib.compress(xml)[2:-4]
    else:
        payload = xml
    return base64.b64encode(payload).decode()


def _add_redirect(token):
    def callback(request):
        return (302, {"Location": "http://idp.test/acs?SAMLResponse=%s" % token}, "")

    responses.add_callback(
        responses.GET,
        re.compile(r"http://idp\.test/sso\?.*SAML.*"),
        callback=callback,
    )


@responses.activate
def test_unsigned_response_is_high_severity():
    responses.add(responses.GET, "http://idp.test/sso", body="login", status=200)
    _add_redirect(_response('<saml:Conditions NotOnOrAfter="2099-01-01T00:00:00Z"/>'))
    result = check("http://idp.test/sso")
    assert result["vulnerable"] is True
    assert any(item["severity"] == "high" for item in result["findings"])


@responses.activate
def test_signed_response_with_conditions_is_not_vulnerable():
    responses.add(responses.GET, "http://idp.test/sso", body="login", status=200)
    _add_redirect(
        _response(
            '<saml:Conditions NotOnOrAfter="2099-01-01T00:00:00Z"/>'
            "<saml:AttributeStatement><saml:Attribute/></saml:AttributeStatement>",
            signed=True,
        )
    )
    result = check("http://idp.test/sso")
    assert result["vulnerable"] is False
    assert not [f for f in result["findings"] if f["severity"] == "high"]


@responses.activate
def test_signed_assertion_without_conditions_is_replay_risk():
    responses.add(responses.GET, "http://idp.test/sso", body="login", status=200)
    _add_redirect(_response("", signed=True))
    result = check("http://idp.test/sso")
    assert result["vulnerable"] is True
    assert any("Conditions" in item["issue"] for item in result["findings"])


@responses.activate
def test_deflated_response_is_decoded():
    responses.add(responses.GET, "http://idp.test/sso", body="login", status=200)
    _add_redirect(
        _response('<saml:Conditions NotOnOrAfter="2099-01-01T00:00:00Z"/>', compressed=True)
    )
    result = check("http://idp.test/sso")
    assert result["vulnerable"] is True
    assert any(item["issue"].startswith("SAML Response without") for item in result["findings"])


@responses.activate
def test_invalid_saml_payload_does_not_raise():
    responses.add(responses.GET, "http://idp.test/sso", body="login", status=200)
    _add_redirect("not-base64!")
    result = check("http://idp.test/sso")
    assert result["vulnerable"] is False
    assert not [f for f in result["findings"] if f["severity"] == "high"]


@responses.activate
def test_no_saml_redirect_returns_empty():
    responses.add(responses.GET, "http://idp.test/sso", body="login", status=200)
    responses.add(
        responses.GET,
        re.compile(r"http://idp\.test/sso\?.*"),
        body="login",
        status=200,
    )
    result = check("http://idp.test/sso")
    assert result == {"vulnerable": False, "findings": []}
