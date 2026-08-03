from tools.service_mapping import (
    DEFAULT_CREDS,
    SERVICE_CVES,
    default_creds,
    extract_version,
    map_family,
    map_open_ports,
    map_service,
    match_cves,
)


class TestFamily:
    def test_service_name(self):
        assert map_family("MySQL", 0) == "mysql"
        assert map_family("redis", 0) == "redis"
        assert map_family("Microsoft-ds", 0) == "smb"
        assert map_family("Elasticsearch", 0) == "elasticsearch"
        assert map_family("", 0) == "generic"

    def test_port_fallback(self):
        assert map_family("unknown", 9200) == "elasticsearch"
        assert map_family("unknown", 61616) == "activemq"
        assert map_family("unknown", 9999) == "generic"


class TestVersion:
    def test_extract(self):
        assert extract_version("SSH-2.0-OpenSSH_7.2p2") == "7.2p2"
        assert extract_version("220 (vsFTPd 2.3.4)") == "2.3.4"
        assert extract_version("nothing here") == ""

    def test_window(self):
        assert match_cves("Tomcat", "Apache Tomcat/8.5.11", port=0)
        old = {c["cve"] for c in match_cves("Tomcat", "Apache Tomcat/9.0.50", port=0)}
        assert "CVE-2017-12615" not in old
        assert "CVE-2020-1938" in old


class TestCves:
    def test_vsftpd_backdoor(self):
        out = match_cves("FTP", "220 (vsFTPd 2.3.4)")
        assert any(c["cve"] == "CVE-2011-2523" for c in out)

    def test_ghostcat(self):
        out = match_cves("http-proxy", "Apache-Coyote/1.1", port=8080)
        assert any(c["cve"] == "CVE-2020-1938" for c in out)

    def test_weblogic_critical(self):
        out = match_cves("weblogic", "WebLogic Server 12.2.1")
        assert any(c["cve"] == "CVE-2020-14882" for c in out)

    def test_no_match_returns_empty(self):
        assert match_cves("generic", "hello world") == []


class TestCreds:
    def test_known_defaults(self):
        assert {"user": "root", "pass": "root"} in default_creds("MySQL")
        assert {"user": "guest", "pass": "guest"} in default_creds("RabbitMQ")
        assert {"user": "tomcat", "pass": "tomcat"} in default_creds("Tomcat")

    def test_unknown_service_no_creds(self):
        assert default_creds("totally-unknown") == []

    def test_tables_populated(self):
        assert len(SERVICE_CVES) > 10
        assert len(DEFAULT_CREDS) > 10


class TestMapService:
    def test_full_mapping(self):
        out = map_service("FTP", "220 (vsFTPd 2.3.4)")
        assert out["family"] == "ftp"
        assert out["version"] == "2.3.4"
        assert any(c["cve"] == "CVE-2011-2523" for c in out["cves"])
        assert out["default_credentials"]
        assert out["risk"] == "critical"

    def test_low_risk_plain_service(self):
        out = map_service("ssh", "SSH-2.0-OpenSSH_9.6")
        assert out["risk"] == "low"


class TestMapOpenPorts:
    def test_consumes_recon(self):
        state = {
            "phases": {
                "recon": {
                    "open_ports": {
                        "open_ports": [
                            {"port": 21, "service": "FTP",
                             "banner": "220 (vsFTPd 2.3.4)", "state": "open"},
                            {"port": 22, "service": "SSH",
                             "banner": "SSH-2.0-OpenSSH_9.6", "state": "open"},
                            {"port": 9999, "service": "", "state": "open"},
                        ]
                    }
                }
            }
        }
        out = map_open_ports(state)
        assert out["mapped"] == 2
        assert out["with_cves"] == 1
        assert any(s["family"] == "ftp" for s in out["services"])

    def test_empty_state(self):
        assert map_open_ports({})["mapped"] == 0
