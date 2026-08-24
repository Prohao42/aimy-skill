from tools.reverse_shell import (
    WEBSHELLS,
    generate_webshell,
    run,
)


class TestReverseShell:
    def test_generate_shells_covers_major_languages(self):
        r = run(lhost="10.0.0.1", lport=4444)
        names = [s["name"] for s in r["shells"]]
        for lang in ("bash_tcp", "python_tcp", "php_tcp", "nc_tcp",
                     "perl_tcp", "ruby_tcp", "node_tcp", "powershell_tcp",
                     "golang_tcp", "awk_tcp", "lua_tcp", "socat_tty"):
            assert lang in names, lang
        assert r["listeners"]
        assert r["msfvenom"]

    def test_shell_command_contains_host_port(self):
        r = run(lhost="192.168.1.10", lport=9999)
        bash = next(s for s in r["shells"] if s["name"] == "bash_tcp")
        assert "192.168.1.10" in bash["command"]
        assert "9999" in bash["command"]

    def test_webshell_types(self):
        assert "php_cmd" in WEBSHELLS
        assert "aspx_cmd" in WEBSHELLS
        assert "jsp_cmd" in WEBSHELLS
        r = generate_webshell("php_cmd", "b64")
        assert r["code"]
        assert "encoded" in r
        assert r["paths"]

    def test_generate_webshell_unknown_type_falls_back(self):
        r = generate_webshell("php_cmd")
        assert r["type"] == "php_cmd"
