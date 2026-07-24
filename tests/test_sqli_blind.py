import re

import requests
import responses

from tools.sqli_blind import BlindInjector, ResponseClassifier, check


def _make_session():
    s = requests.Session()
    s.verify = False
    return s


_calibrate_bodies = ["user exists", "access denied"]


def _calibrate_callback(req):
    return (200, {}, _calibrate_bodies.pop(0))


class TestResponseClassifier:
    @responses.activate
    def test_calibrate_success(self):
        responses.add_callback(
            responses.GET,
            re.compile(r".*test\.com.*"),
            callback=_calibrate_callback,
        )

        clf = ResponseClassifier(_make_session(), 10.0)
        ok = clf.calibrate("http://test.com/page", "id", "' AND 1=1-- ", "' AND 1=2-- ")
        assert ok is True
        assert clf.calibrated is True
        assert clf.true_len == len("user exists")
        assert clf.false_len == len("access denied")

    @responses.activate
    def test_is_true_returns_true(self):
        clf = ResponseClassifier(_make_session(), 10.0)
        clf.calibrated = True
        clf.true_len = 11
        clf.true_text = "user exists"
        clf.false_len = 14
        clf.false_text = "access denied"

        responses.add(responses.GET, re.compile(r".*"), body="user exists", status=200)
        result = clf.is_true("http://test.com/page", "id", "' AND 1=1-- ")
        assert result is True

    @responses.activate
    def test_is_true_returns_false(self):
        clf = ResponseClassifier(_make_session(), 10.0)
        clf.calibrated = True
        clf.true_len = 11
        clf.true_text = "user exists"
        clf.false_len = 14
        clf.false_text = "access denied"

        responses.add(responses.GET, re.compile(r".*"), body="access denied", status=200)
        result = clf.is_true("http://test.com/page", "id", "' AND 1=2-- ")
        assert result is False

    @responses.activate
    def test_is_true_not_calibrated(self):
        clf = ResponseClassifier(_make_session(), 10.0)
        result = clf.is_true("http://test.com/page", "id", "payload")
        assert result is None

    @responses.activate
    def test_is_true_ambiguous(self):
        clf = ResponseClassifier(_make_session(), 10.0)
        clf.calibrated = True
        clf.true_len = 12
        clf.false_len = 12
        clf.true_text = "some content"
        clf.false_text = "some content"

        responses.add(responses.GET, re.compile(r".*"), body="some content", status=200)
        result = clf.is_true("http://test.com/page", "id", "' AND 1=1-- ")
        assert result is None

    @responses.activate
    def test_calibrate_with_baseline(self):
        responses.add(responses.GET, re.compile(r".*"), body="normal page", status=200)

        clf = ResponseClassifier(_make_session(), 10.0)
        ok = clf.calibrate_with_baseline("http://test.com/page", "id", _make_session(), 10.0)
        assert ok is True
        assert clf.baseline_len == len("normal page")

    @responses.activate
    def test_network_error_is_true_returns_none(self):
        clf = ResponseClassifier(_make_session(), 10.0)
        clf.calibrated = True
        clf.true_len = 11
        clf.true_text = "user exists"
        clf.false_len = 14
        clf.false_text = "access denied"

        result = clf.is_true("http://test.com/page", "id", "payload")
        assert result is None


class TestBlindInjector:
    @responses.activate
    def test_auto_detect_dbms_mysql_by_error(self):
        responses.add(responses.GET, re.compile(r".*"), body="MySQL syntax error", status=200)

        injector = BlindInjector(_make_session(), timeout=5.0)
        dbms = injector._auto_detect_dbms("http://test.com/page", "id")
        assert dbms == "mysql"

    @responses.activate
    def test_auto_detect_dbms_mssql_by_error(self):
        responses.add(responses.GET, re.compile(r".*"),
                       body="Microsoft SQL Server error", status=200)

        injector = BlindInjector(_make_session(), timeout=5.0)
        dbms = injector._auto_detect_dbms("http://test.com/page", "id")
        assert dbms == "mssql"

    @responses.activate
    def test_auto_detect_dbms_postgres_by_error(self):
        responses.add(responses.GET, re.compile(r".*"),
                       body="PostgreSQL psql error", status=200)

        injector = BlindInjector(_make_session(), timeout=5.0)
        dbms = injector._auto_detect_dbms("http://test.com/page", "id")
        assert dbms == "postgresql"

    @responses.activate
    def test_auto_detect_dbms_oracle_by_error(self):
        responses.add(responses.GET, re.compile(r".*"),
                       body="ORA-00911: invalid character", status=200)

        injector = BlindInjector(_make_session(), timeout=5.0)
        dbms = injector._auto_detect_dbms("http://test.com/page", "id")
        assert dbms == "oracle"

    @responses.activate
    def test_auto_detect_dbms_returns_none_without_signals(self):
        responses.add(responses.GET, re.compile(r".*"), body="hello world", status=200)

        injector = BlindInjector(_make_session(), timeout=1.0, sleep_time=3)
        dbms = injector._auto_detect_dbms("http://test.com/page", "id")
        assert dbms is None

    @responses.activate
    def test_measure_baseline(self):
        responses.add(responses.GET, re.compile(r".*"), body="ok", status=200)

        injector = BlindInjector(_make_session(), timeout=5.0)
        baseline = injector._measure_baseline("http://test.com/page", "id")
        assert baseline > 0

    @responses.activate
    def test_extract_via_error_mysql(self):
        body = "XPATH syntax error: '~5.7'"
        responses.add(responses.GET, re.compile(r".*"), body=body, status=200)

        injector = BlindInjector(_make_session(), timeout=5.0)
        injector.dbms = "mysql"
        val = injector._extract_via_error("http://test.com/page", "id", "@@version")
        assert val is not None
        assert "5.7" in val

    @responses.activate
    def test_extract_via_error_no_pattern(self):
        responses.add(responses.GET, re.compile(r".*"), body="some error", status=500)

        injector = BlindInjector(_make_session(), timeout=5.0)
        injector.dbms = "mssql"
        val = injector._extract_via_error("http://test.com/page", "id", "@@version")
        assert val is None

    @responses.activate
    def test_extract_via_error_unknown_dbms(self):
        injector = BlindInjector(_make_session(), timeout=5.0)
        injector.dbms = "unknown_dbms"
        val = injector._extract_via_error("http://test.com/page", "id", "VERSION()")
        assert val is None


class TestCheckFunction:
    @responses.activate
    def test_check_returns_dict_with_required_keys(self):
        responses.add(responses.GET, re.compile(r".*"), body="normal", status=200)

        result = check("http://test.com/page", "id", timeout=2.0)
        assert "vulnerable" in result
        assert "confidence_score" in result
        assert "confidence" in result
        assert "confidence_votes" in result
        assert isinstance(result["confidence_score"], float)

    @responses.activate
    def test_check_waf_auto_detect(self):
        responses.add(responses.GET, re.compile(r".*"), body="normal", status=200)

        result = check("http://test.com/page", "id", timeout=2.0, auto_detect_waf=True)
        assert "waf_detected" in result


class TestConfidenceIntegration:
    @responses.activate
    def test_extract_via_error_adds_confidence(self):
        body = "XPATH syntax error: '~8.0'"
        responses.add(responses.GET, re.compile(r".*"), body=body, status=200)

        injector = BlindInjector(_make_session(), timeout=5.0)
        injector.dbms = "mysql"
        result = {
            "vulnerable": False, "dbms": "mysql", "technique": None,
            "data": {}, "error": None, "waf_detected": None,
        }
        val = injector._extract_via_error("http://test.com/page", "id", "@@version")
        if val:
            result["vulnerable"] = True
            result["technique"] = "error"
            result["data"]["version"] = val

        result = injector._compute_confidence(result)
        assert result["confidence"] != "low"
        assert result["confidence_score"] > 0
        assert len(result["confidence_votes"]) > 0

    @responses.activate
    def test_check_confidence_fields_default(self):
        responses.add(responses.GET, re.compile(r".*"), body="ok", status=200)

        result = check("http://test.com/page", "id", timeout=2.0)
        assert "confidence_score" in result
        assert "confidence" in result
        assert "confidence_votes" in result
