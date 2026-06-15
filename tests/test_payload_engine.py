import pytest
from tools.payload_engine import generate, generate_sqli_error


class TestPayloadGenerate:
    def test_sqli_error_returns_payloads(self):
        results = generate("sqli", "error", "string")
        assert len(results) > 0
        for r in results:
            assert "payload" in r

    def test_sqli_boolean_true_returns_payloads(self):
        results = generate("sqli", "boolean_true", "string")
        assert len(results) > 0

    def test_sqli_boolean_false_returns_payloads(self):
        results = generate("sqli", "boolean_false", "string")
        assert len(results) > 0

    def test_sqli_time_mysql_contains_sleep(self):
        results = generate("sqli", "time_mysql", "all")
        assert len(results) > 0
        assert any("SLEEP" in r["payload"].upper() for r in results)

    def test_sqli_union_contains_union(self):
        results = generate("sqli", "union", "all")
        assert len(results) > 0
        assert all("UNION" in r["payload"].upper() for r in results)

    def test_sqli_error_contains_quote(self):
        results = generate("sqli", "error", "string")
        assert len(results) > 0
        all_text = " ".join(r["payload"] for r in results)
        has_quote = "'" in all_text
        has_hex_quote = "%27" in all_text
        assert has_quote or has_hex_quote, "no quote or hex-encoded quote found"

    def test_xss_html_returns_payloads(self):
        results = generate("xss", "html", "all")
        assert len(results) > 0
        assert any("script" in r["payload"] for r in results)

    def test_xss_attr_returns_payloads(self):
        results = generate("xss", "attr", "all")
        assert len(results) > 0

    def test_xss_js_returns_payloads(self):
        results = generate("xss", "js", "all")
        assert len(results) > 0

    def test_xss_angular_returns_payloads(self):
        results = generate("xss", "angular", "all")
        assert len(results) > 0

    def test_cmdi_output_contains_id(self):
        results = generate("cmdi", "output", "all")
        assert len(results) > 0
        texts = [r["payload"] for r in results]
        assert any("id" in t for t in texts)

    def test_cmdi_time_contains_sleep_or_ping(self):
        results = generate("cmdi", "time", "all")
        assert len(results) > 0
        texts = " ".join(r["payload"] for r in results)
        assert any(kw in texts for kw in ("sleep", "ping"))

    def test_lfi_traversal_contains_passwd(self):
        results = generate("lfi", "traversal", "all")
        assert len(results) > 0
        assert any("etc/passwd" in r["payload"] for r in results)

    def test_lfi_php_wrappers_contains_php(self):
        results = generate("lfi", "php_wrappers", "all")
        assert len(results) > 0
        assert any("php://" in r["payload"] for r in results)

    def test_ssti_detect_contains_operator(self):
        results = generate("ssti", "detect", "all")
        assert len(results) > 0
        texts = " ".join(r["payload"] for r in results)
        assert "999999" in texts or "config" in texts

    def test_ssti_blind_contains_os(self):
        results = generate("ssti", "blind", "all")
        assert len(results) > 0
        assert any("popen" in r["payload"] or "os." in r["payload"] for r in results)

    def test_nosqli_boolean_returns_payloads(self):
        results = generate("nosqli", "boolean", "string")
        assert len(results) > 0

    def test_nosqli_where_time_contains_sleep(self):
        results = generate("nosqli", "where_time", "string")
        assert len(results) > 0
        assert any("sleep" in r["payload"].lower() for r in results)

    def test_nosqli_json_contains_operator(self):
        results = generate("nosqli", "json", "json")
        assert len(results) > 0
        assert any("$" in r["payload"] for r in results)

    def test_nosqli_boolean_filtered_by_context(self):
        results = generate("nosqli", "boolean", "numeric")
        assert len(results) == 0

    def test_generate_sqli_error_helper(self):
        payloads = generate_sqli_error("string")
        assert len(payloads) > 0
        assert all(isinstance(p, str) for p in payloads)

    def test_waf_strategy_affects_output(self):
        none_results = generate("sqli", "error", "string", waf_name=None)
        cf_results = generate("sqli", "error", "string", waf_name="cloudflare")
        assert len(none_results) > 0
        assert len(cf_results) > 0

    def test_payload_not_double_encoded(self):
        results = generate("sqli", "error", "string")
        for r in results:
            assert "%25" not in r["payload"], "payload should not be double-URL-encoded"

    def test_seed_groups_has_all_keys(self):
        assert len(generate("sqli", "error", "string")) > 0
        assert len(generate("xss", "html", "all")) > 0
        assert len(generate("cmdi", "output", "all")) > 0
        assert len(generate("lfi", "traversal", "all")) > 0
        assert len(generate("ssti", "detect", "all")) > 0
        assert len(generate("nosqli", "boolean", "string")) > 0

    def test_max_payloads_limit(self):
        results = generate("sqli", "error", "string", max_payloads=5)
        assert len(results) <= 5

    def test_unknown_group_returns_empty(self):
        results = generate("nonexistent", "foo", "all")
        assert results == []
