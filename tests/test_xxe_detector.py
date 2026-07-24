import re
from unittest.mock import patch

import requests
import responses

from tools.xxe_detector import XXEDetector


class TestXXEDetector:
    @responses.activate
    def test_xxe_file_read_detected(self):
        sess = requests.Session()
        responses.add(
            responses.POST,
            re.compile(".*"),
            body="root:x:0:0:root:/root:/bin/bash",
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(".*"),
            body="root:x:0:0:root:/root:/bin/bash",
            status=200,
        )
        detector = XXEDetector(sess=sess)
        result = detector.check("http://test.com/api/xml", "data")
        assert result["vulnerable"] is True
        assert result["vuln_type"] == "xxe"
        assert result["confidence"] > 0

    @responses.activate
    def test_xxe_error_based(self):
        sess = requests.Session()
        responses.add(
            responses.GET,
            re.compile(".*"),
            body="xml error: entity not defined",
            status=200,
        )
        responses.add(
            responses.POST,
            re.compile(".*"),
            body="xml error: entity not defined",
            status=200,
        )
        detector = XXEDetector(sess=sess)
        result = detector.check("http://test.com/xml", "data")
        assert result["vulnerable"] is True

    @responses.activate
    def test_no_xxe(self):
        sess = requests.Session()
        responses.add(
            responses.GET,
            re.compile(".*"),
            body="normal page content",
            status=200,
        )
        responses.add(
            responses.POST,
            re.compile(".*"),
            body="normal page content",
            status=200,
        )
        detector = XXEDetector(sess=sess)
        with patch("socket.getaddrinfo", side_effect=OSError("no such domain")):
            result = detector.check("http://test.com/page", "q")
        assert result["vulnerable"] is False

    @responses.activate
    def test_svg_upload_xxe(self):
        sess = requests.Session()
        responses.add(
            responses.POST,
            re.compile(".*"),
            body="root:x:0:0",
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(".*"),
            body="root:x:0:0",
            status=200,
        )
        detector = XXEDetector(sess=sess)
        result = detector.check("http://test.com/upload")
        assert result["vulnerable"] is True

    @responses.activate
    def test_xinclude_xxe(self):
        sess = requests.Session()
        responses.add(
            responses.POST,
            re.compile(".*"),
            body="root:x:0:0",
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(".*"),
            body="root:x:0:0",
            status=200,
        )
        detector = XXEDetector(sess=sess)
        result = detector.check("http://test.com/api")
        assert result["vulnerable"] is True

    @responses.activate
    def test_soap_xxe(self):
        sess = requests.Session()
        responses.add(
            responses.POST,
            re.compile(".*"),
            body="root:x:0:0",
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(".*"),
            body="root:x:0:0",
            status=200,
        )
        detector = XXEDetector(sess=sess)
        result = detector.check("http://test.com/soap")
        assert result["vulnerable"] is True

    @responses.activate
    def test_xslt_injection(self):
        sess = requests.Session()
        responses.add(
            responses.POST,
            re.compile(".*"),
            body="root:x:0:0",
            status=200,
        )
        responses.add(
            responses.GET,
            re.compile(".*"),
            body="root:x:0:0",
            status=200,
        )
        detector = XXEDetector(sess=sess)
        result = detector.check("http://test.com/transform")
        assert result["vulnerable"] is True
