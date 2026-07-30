import json
import re

import pytest
import requests
import responses

from tools.sqli_weaponizer import check, _probe_column_count


class TestSqliWeaponizer:
    @responses.activate
    def test_probe_column_count_union_works(self):
        responses.get(
            re.compile(r".*UNION SELECT NULL,NULL,NULL--.*"),
            body="<html>normal response</html>",
            status=200,
        )
        responses.get(
            re.compile(r".*UNION SELECT NULL,NULL--.*"),
            body="<html>The used SELECT statements have a different number of columns</html>",
            status=200,
        )
        sess = requests.Session()
        cols = _probe_column_count("http://test.com/page", "id", sess, 5)
        assert cols == 3

    @responses.activate
    def test_check_union_extract(self):
        responses.get(
            re.compile(r".*UNION SELECT NULL,NULL,NULL--.*"),
            body="<html>normal response 200 OK</html>",
            status=200,
        )
        responses.get(
            re.compile(r".*DATABASE\(\)--.*"),
            body="<html>testdb</html>",
            status=200,
        )
        sess = requests.Session()
        result = check("http://test.com/page", "id", sess, 5)
        assert "column_count" in result

    @responses.activate
    def test_check_always_probes_columns(self):
        responses.get(
            re.compile(r".*UNION SELECT NULL,NULL,NULL.*"),
            body="<html>200 OK</html>",
            status=200,
        )
        responses.get(re.compile(r".*"), body="error", status=500)
        sess = requests.Session()
        result = check("http://test.com/page", "id", sess, 5)
        assert result["column_count"] == 3
        assert "data" in result
