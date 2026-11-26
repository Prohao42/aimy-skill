import re

import responses

from tools.http_client import build_url
from tools.sql_injection import _extract_dbms as guess_dbms
from tools.sql_injection import check


class TestUnionReflectionGuard:
    """UNION 反射守卫: 回显输入 != SQL 注入."""

    @responses.activate
    def test_echo_endpoint_is_not_union_sqli(self):
        """端点原样回显 payload 时, UNION marker 全部"出现"但无 SQL 执行."""
        from urllib.parse import unquote_plus

        def cb(request):
            q = unquote_plus(request.url.split("?", 1)[1]) if "?" in request.url else ""
            val = q.split("=", 1)[1] if "=" in q else ""
            return (200, {}, "<html><body>%s</body></html>" % val)

        responses.add_callback(responses.GET, re.compile(r"http://test\.com/page\?.*"), callback=cb)
        result = check("http://test.com/page", "q")
        assert result["vulnerable"] is False

    @responses.activate
    def test_error_based_sets_confidence(self):
        """错误型 SQLi 命中时必须带 confidence_score (>0), 否则下游 FPF 丢弃."""
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            body="You have an error in your SQL syntax near '' at line 1",
            status=200,
        )
        result = check("http://test.com/page", "id")
        assert result["vulnerable"] is True
        assert result["confidence_score"] > 0
        assert result["confidence"] in ("medium", "high")


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
            if "SLEEP" in request.url.upper():
                time.sleep(3)
            return (200, {}, "ok")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            callback=delayed_callback,
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

        result = check(
            "http://test.com/login", "user", post_body=True, post_data={"user": "1", "pass": "x"}
        )
        assert result["vulnerable"] is True
        assert result["type"] == "error"
