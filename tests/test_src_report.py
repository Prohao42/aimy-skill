from tools.src_report import SRC_VULN_TEMPLATES, src_report, src_report_markdown


class TestSrcReport:
    def test_boolean_template(self):
        f = {"type": "boolean", "url": "http://x.com/p", "param": "id",
             "vector": "1 AND 1=1", "evidence": ["diff=200"]}
        r = src_report(f)
        assert r["vuln_type"] == "boolean"
        assert r["severity"] == "高危"
        assert "CWE-89" in r["cwe"]
        assert r["description"]
        assert any("1 AND 1=1" in s for s in r["reproduction_steps"])
        assert r["fix_suggestion"]

    def test_unknown_type_falls_back(self):
        r = src_report({"type": "weird", "url": "http://x.com"})
        assert r["vuln_type"] == "weird"
        assert r["description"]

    def test_markdown_output(self):
        r = src_report({"type": "xss", "url": "http://x.com", "param": "q"})
        md = src_report_markdown(r)
        assert "## " in md
        assert "复现步骤" in md
        assert "修复建议" in md
        assert "危害等级" in md

    def test_all_templates_valid(self):
        for name, tpl in SRC_VULN_TEMPLATES.items():
            assert tpl["title"] and tpl["description"] and tpl["fix"], name
