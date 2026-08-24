from unittest import mock

from tools import batch_recon


class TestBatchRecon:
    def test_run_basic(self, tmp_path):
        hosts = tmp_path / "hosts.txt"
        hosts.write_text("1.2.3.4\n5.6.7.8\n")
        with mock.patch.object(batch_recon, "_scan_ports", side_effect=[[80, 443], [22]]):
            with mock.patch.object(batch_recon, "_probe_web", side_effect=[
                [{"url": "http://1.2.3.4/", "status": 200, "server": "nginx",
                  "title": "Login", "has_login": True}],
                [],
            ]):
                r = batch_recon.run(str(hosts), ports="22,80,443")
        assert r["targets"] == 2
        assert len(r["alive"]) == 2
        assert len(r["web"]) == 1
        assert r["web"][0]["ip"] == "1.2.3.4"
        assert r["high_priority"][0]["ip"] == "1.2.3.4"
        assert r["high_priority"][0]["has_login_web"] is True

    def test_db_port_high_priority(self, tmp_path):
        hosts = tmp_path / "hosts.txt"
        hosts.write_text("1.2.3.4\n")
        with mock.patch.object(batch_recon, "_scan_ports", return_value=[6379]):
            with mock.patch.object(batch_recon, "_probe_web", return_value=[]):
                r = batch_recon.run(str(hosts), ports="6379")
        assert r["high_priority"][0]["db_services"] == ["Redis"]

    def test_unauth_link(self, tmp_path):
        hosts = tmp_path / "hosts.txt"
        hosts.write_text("1.2.3.4\n")
        fake_unauth = mock.Mock(return_value={
            "scanned": 1, "vulnerable": 1,
            "findings": [{"ip": "1.2.3.4", "port": 6379, "unauth": True, "version": "8.0"}],
            "honeypots": [],
        })
        with mock.patch.object(batch_recon, "_scan_ports", return_value=[6379]):
            with mock.patch.object(batch_recon, "_probe_web", return_value=[]):
                with mock.patch.object(batch_recon, "unauth_check", fake_unauth):
                    r = batch_recon.run(str(hosts), ports="6379", unauth=True)
        assert r["unauth"]["vulnerable"] == 1
        fake_unauth.assert_called_once()
