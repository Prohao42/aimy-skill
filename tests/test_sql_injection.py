import re
import pytest
import requests
import responses
from tools.sql_injection import check, _extract_dbms as guess_dbms
from tools.http_client import build_url
from tools.response_profiler import ResponseProfiler, CLEAN_VALUE


class TestBuildUrl:
    def test_basic_url(self):
        result = build_url("http://example.com/page", "id", "1' OR '1'='1")
        assert "id=1%27+OR+%271%27%3D%271" in result

    def test_existing_query(self):
        result = build_url("http://example.com/page?foo=bar", "id", "test")
        assert "foo=bar" in result
        assert "id=test" in result

    def test_special_chars(self):
        result = build_url("http://example.com/", "q", "hello world&test")
        assert "hello+world" in result
        assert "%26test" in result


class TestGuessDbms:
    def test_mysql(self):
        assert guess_dbms("MySQLSyntaxErrorException") == "MySQL"

    def test_postgres(self):
        assert guess_dbms("PSQLException") == "PostgreSQL"

    def test_oracle(self):
        assert guess_dbms("ORA-00933") == "Oracle"

    def test_sqlite(self):
        assert guess_dbms("SQLite3::SQLException") == "SQLite"

    def test_mssql(self):
        assert guess_dbms("SqlException") == "MSSQL"

    def test_unknown(self):
        assert guess_dbms("nothing here") is None


class TestSqlInjectionCheck:
    @responses.activate
    def test_error_based_detection(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            body="You have an error in your SQL syntax... MySQL",
            status=200,
        )

        result = check("http://test.com/page", "id")
        assert result["vulnerable"] is True
        assert result["type"] == "error"

    @responses.activate
    def test_time_based_detection(self):
        import time

        def delayed_callback(request):
            time.sleep(3)
            return (200, {}, "ok")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*SLEEP.*"),
            callback=delayed_callback,
        )
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            body="normal",
            status=200,
        )

        result = check("http://test.com/page", "id")
        assert result["vulnerable"] is True
        assert result["type"] == "time"

    @responses.activate
    def test_no_vulnerability(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            body="normal page content",
            status=200,
        )

        result = check("http://test.com/page", "id")
        assert result["vulnerable"] is False


class TestSqlInjectionPost:
    @responses.activate
    def test_post_error_based(self):
        responses.add(
            responses.POST,
            url="http://test.com/login",
            body="ORA-00933: SQL command not properly ended",
            status=200,
        )

        result = check("http://test.com/login", "user", post_body=True, post_data={"user": "1", "pass": "x"})
        assert result["vulnerable"] is True
        assert result["type"] == "error"
