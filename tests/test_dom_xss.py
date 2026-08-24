import re

import requests
import responses

from tools.dom_xss import _analyze_scripts, check


class TestDomXss:
    @responses.activate
    def test_innerhtml_hash_sink_detected(self):
        html = (
            "<html><body>"
            "<div id='out'></div>"
            "<script>document.getElementById('out').innerHTML = location.hash;</script>"
            "</body></html>"
        )
        responses.add(
            responses.GET,
            "http://test.com/app",
            body=html,
            status=200,
        )
        sess = requests.Session()
        result = check("http://test.com/app", sess=sess, timeout=5)
        assert result["vulnerable"] is True
        sinks = [f["sink"] for f in result["findings"]]
        assert "innerHTML" in sinks
        assert any(f["source"] == "location.hash" for f in result["findings"])

    @responses.activate
    def test_no_sinks(self):
        responses.add(
            responses.GET,
            "http://test.com/app",
            body="<html><script>var x = 1 + 2;</script></html>",
            status=200,
        )
        sess = requests.Session()
        result = check("http://test.com/app", sess=sess, timeout=5)
        assert result["vulnerable"] is False

    def test_analyze_scripts_direct(self):
        scripts = ["var x = document.URL; el.innerHTML = x;"]
        findings = _analyze_scripts(scripts)
        assert findings
        assert findings[0]["sink"] == "innerHTML"
        assert findings[0]["source"] == "document.URL"


class TestFrameworkSinks:
    @responses.activate
    def test_vue_vhtml(self):
        html = ("<div id='app'><div v-html='userInput'></div></div>"
                "<script>var userInput = location.hash;</script>")
        responses.add(responses.GET, "http://test.com/vue", body=html, status=200)
        sess = requests.Session()
        result = check("http://test.com/vue", sess=sess, timeout=5)
        assert result["vulnerable"] is True
        assert any(f["sink"] == "vue v-html" for f in result["findings"])

    @responses.activate
    def test_react_dangerously_set_inner_html(self):
        html = ("<script>"
                "var d = location.hash;"
                "React.createElement('div', {dangerouslySetInnerHTML: {__html: d}});"
                "</script>")
        responses.add(responses.GET, "http://test.com/react", body=html, status=200)
        sess = requests.Session()
        result = check("http://test.com/react", sess=sess, timeout=5)
        assert result["vulnerable"] is True
        assert any("dangerouslySetInnerHTML" in f["sink"] for f in result["findings"])

    @responses.activate
    def test_jquery_html(self):
        html = ("<script>"
                "$('#out').html(location.hash);"
                "</script>")
        responses.add(responses.GET, "http://test.com/jquery", body=html, status=200)
        sess = requests.Session()
        result = check("http://test.com/jquery", sess=sess, timeout=5)
        assert result["vulnerable"] is True
        assert any("jquery" in f["sink"] for f in result["findings"])

    def test_safe_sink_not_flagged(self):
        # textContent is not an XSS sink
        scripts = ["el.textContent = location.hash;"]
        findings = _analyze_scripts(scripts)
        dangerous = [f for f in findings if f["sink"] in {
            "innerHTML", "outerHTML", "document.write", "eval"}]
        assert not dangerous
