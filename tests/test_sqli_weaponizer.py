import re
import urllib.parse

import requests
import responses

from tools.sqli_weaponizer import _probe_column_count, check


def _param_from(request):
    q = urllib.parse.parse_qs(request.url.split("?", 1)[1])
    return q.get("id", [""])[0]


class TestSqliWeaponizer:
    @responses.activate
    def test_probe_column_count_union_works(self):
        def callback(request):
            v = _param_from(request)
            if re.search(r"UNION SELECT NULL,NULL,NULL", v):
                return (200, {}, "<html>normal response</html>")
            if re.search(r"UNION SELECT NULL,NULL", v):
                return (200, {}, "<html>different number of columns error</html>")
            if "UNION SELECT" in v:
                return (200, {}, "<html>different number of columns error</html>")
            return (200, {}, "page")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            callback=callback,
        )
        sess = requests.Session()
        cols = _probe_column_count("http://test.com/page", "id", sess, 5)
        assert cols == 3

    @responses.activate
    def test_check_union_reflection_extracts_database(self):
        def callback(request):
            v = _param_from(request)
            if "RFLCT_" in v:
                m = re.search(r"'RFLCT_(\d+)'", v)
                return (200, {}, "<html>RFLCT_%s</html>" % m.group(1))
            if "DATABASE()" in v:
                return (200, {}, "<html>testdb</html>")
            if re.search(r"UNION SELECT NULL,NULL,NULL", v):
                return (200, {}, "<html>normal response</html>")
            if "UNION SELECT" in v:
                return (200, {}, "<html>different number of columns error</html>")
            return (200, {}, "page")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            callback=callback,
        )
        sess = requests.Session()
        result = check("http://test.com/page", "id", sess, 5)
        assert result["column_count"] == 3
        assert result["vulnerable"] is True
        assert result["type"] == "union"
        values = " ".join(str(d) for d in result["data"])
        assert "testdb" in values

    @responses.activate
    def test_check_always_probes_columns(self):
        def callback(request):
            v = _param_from(request)
            if re.search(r"UNION SELECT NULL,NULL,NULL", v):
                return (200, {}, "<html>200 OK</html>")
            return (500, {}, "error")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/page\?.*"),
            callback=callback,
        )
        sess = requests.Session()
        result = check("http://test.com/page", "id", sess, 5)
        assert result["column_count"] == 3
        assert "data" in result

    @responses.activate
    def test_blind_boolean_extraction(self):
        """Boolean-blind extraction of the database name (no UNION)."""
        def callback(request):
            v = _param_from(request)
            if "UNION SELECT" in v:
                return (500, {}, "error")
            if "ASCII(SUBSTRING((SELECT DATABASE())," in v:
                m = re.search(r"\)\)>(\d+)", v)
                ascii_gt = int(m.group(1))
                db = "testdb"
                pos_m = re.search(r"SUBSTRING\(\(SELECT DATABASE\(\)\),(\d+),1\)", v)
                pos = int(pos_m.group(1)) if pos_m else 1
                ch = ord(db[pos - 1]) if pos <= len(db) else 0
                if ch > ascii_gt:
                    return (200, {}, "x" * 200 + "true")
                return (200, {}, "false")
            if "1=1" in v:
                return (200, {}, "x" * 200 + "true")
            return (200, {}, "false")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/blind\?.*"),
            callback=callback,
        )
        sess = requests.Session()
        result = check("http://test.com/blind", "id", sess, 5)
        assert result["vulnerable"] is True
        values = " ".join(str(d) for d in result["data"])
        assert "testdb" in values

    @responses.activate
    def test_blind_union_extraction(self):
        """Blind UNION extraction: IF(cond,1,2) row-presence oracle, 1 column."""
        def callback(request):
            v = _param_from(request)
            if re.search(r"UNION SELECT NULL,NULL", v):
                return (200, {}, "<html>different number of columns error</html>")
            if "IF((" in v and "1=1" in v:
                return (200, {}, "x" * 100 + "extra row")
            if "IF((" in v and "1=2" in v:
                return (200, {}, "x")
            if "IF((" in v:
                m = re.search(r"SUBSTRING\(\(SELECT DATABASE\(\)\),(\d+),1\)\)>(\d+)", v)
                if m:
                    pos, ascii_gt = int(m.group(1)), int(m.group(2))
                    db = "testdb"
                    ch = ord(db[pos - 1]) if pos <= len(db) else 0
                    if ch > ascii_gt:
                        return (200, {}, "x" * 100 + "true")
                return (200, {}, "x")
            if re.search(r"UNION SELECT NULL", v):
                return (200, {}, "<html>normal</html>")
            return (200, {}, "<html>normal</html>")

        responses.add_callback(
            responses.GET,
            re.compile(r"http://test\.com/bu\?.*"),
            callback=callback,
        )
        sess = requests.Session()
        result = check("http://test.com/bu", "id", sess, 5)
        assert result["vulnerable"] is True
        values = " ".join(str(d) for d in result["data"])
        assert "testdb" in values
