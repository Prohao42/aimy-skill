import os
import tempfile

from tools.reporter import generate_html, save_report, to_json


class TestReporter:
    def test_to_json_handles_datetime_and_bytes(self):
        from datetime import datetime
        data = {"when": datetime(2024, 1, 1), "raw": b"abc", "n": 1}
        out = to_json(data)
        assert "2024-01-01" in out
        assert "abc" in out

    def test_generate_html(self):
        report = {
            "target": "http://example.com",
            "elapsed_seconds": 1.5,
            "summary": {"vulnerabilities": 2, "by_type": {"sqli": 2}, "critical": False},
            "recon": {"pages_crawled": 3},
        }
        html = generate_html(report)
        assert "<!DOCTYPE html>" in html
        assert "example.com" in html
        assert "SQLI" in html

    def test_save_report_writes_json_and_html(self):
        report = {"target": "http://x.test", "elapsed_seconds": 1.0,
                  "summary": {"vulnerabilities": 1, "by_type": {"xss": 1}, "critical": True}}
        with tempfile.TemporaryDirectory() as d:
            paths = save_report(report, d)
            assert paths.get("json") and paths.get("html")
            assert os.path.isfile(paths["json"])
            assert os.path.isfile(paths["html"])
            with open(paths["json"], encoding="utf-8") as f:
                assert "x.test" in f.read()
