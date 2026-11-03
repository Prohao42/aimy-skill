"""Wordlist generation and bundled dictionary tests."""

import os
import subprocess
import sys
from pathlib import Path

from tools import wordgen

ROOT = Path(__file__).resolve().parents[1]
# Pin the child process to UTF-8: the harness decodes with encoding="utf-8",
# so a cp936 child (Windows default) would produce undecodable bytes.
ENV = dict(
    os.environ,
    NO_PROXY="127.0.0.1,localhost",
    PYTHONIOENCODING="utf-8",
    PYTHONUTF8="1",
)


class TestGenerate:
    def test_casing_variants(self):
        variants = wordgen.casing_variants("AliBaba")
        assert "AliBaba" in variants
        assert "Alibaba" in variants
        assert "ALIBABA" in variants
        assert "alibaba" in variants

    def test_leet_substitutions(self):
        assert wordgen.apply_leet("password") == "p@$$w0rd"
        assert wordgen.apply_leet("mud") == "mud"  # nothing to map

    def test_keywords_produce_suffixed_candidates(self):
        words = wordgen.generate_wordlist(
            ["target"],
            years=[2024],
            max_suffix=2,
            leet=False,
        )
        assert "target" in words
        assert "Target" in words
        assert "TARGET" in words
        assert "target0" in words
        assert "target2" in words
        assert "target2024" in words
        assert "target!" in words

    def test_leet_variants_included_by_default(self):
        words = wordgen.generate_wordlist(["pass"], max_suffix=0, leet=True)
        assert "p@$$" in words

    def test_dedup_preserves_order(self):
        words = wordgen.generate_wordlist(["dup"], max_suffix=0, leet=False)
        assert len(words) == len(set(words))

    def test_domains_produce_email_forms(self):
        words = wordgen.generate_wordlist(
            ["admin"],
            domains=["corp.com"],
            max_suffix=0,
            leet=False,
        )
        assert "admin@corp.com" in words


class TestBundled:
    def test_bundled_loads(self):
        assert len(wordgen.load_bundled("top_passwords")) >= 50
        assert "123456" in wordgen.load_bundled("top_passwords")
        assert "admin" in wordgen.load_bundled("top_users")
        assert len(wordgen.load_bundled("top_passwords_cn")) >= 30

    def test_bundled_names(self):
        names = wordgen.list_bundled()
        assert {"top_users", "top_passwords", "top_passwords_cn"} <= set(names)

    def test_sum_bundled(self):
        total, names = wordgen.sum_bundled()
        assert total > 100
        assert len(names) == 3


class TestMerge:
    def test_merge_dedupes(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("admin\nroot\nadmin\n", encoding="utf-8")
        b.write_text("root\ntest\n", encoding="utf-8")
        out = tmp_path / "merged.txt"
        words = wordgen.merge_wordlists([str(a), str(b)], str(out))
        assert words == ["admin", "root", "test"]
        assert out.read_text(encoding="utf-8").splitlines() == ["admin", "root", "test"]


class TestCli:
    def test_wordgen_cli_end_to_end(self, tmp_path):
        out = tmp_path / "dict.txt"
        proc = subprocess.run(
            [
                sys.executable,
                "main.py",
                "--json",
                "wordgen",
                "--keywords",
                "acme",
                "--max-suffix",
                "2",
                "--years",
                "2024",
                "--out",
                str(out),
            ],
            cwd=str(ROOT),
            capture_output=True,
            encoding="utf-8",
            timeout=60,
            env=ENV,
        )
        assert proc.returncode == 0, proc.stderr
        assert out.exists()
        produced = out.read_text(encoding="utf-8").splitlines()
        assert "acme" in produced
        assert "acme2024" in produced

    def test_wordgen_bundled_cli(self):
        proc = subprocess.run(
            [sys.executable, "main.py", "--json", "wordgen", "--list-bundled"],
            cwd=str(ROOT),
            capture_output=True,
            encoding="utf-8",
            timeout=60,
            env=ENV,
        )
        assert proc.returncode == 0, proc.stderr
        import json

        payload = json.loads(proc.stdout)
        assert payload["total"] > 100
        assert "top_passwords" in payload["bundled"]

    def test_wordgen_requires_input(self):
        proc = subprocess.run(
            [sys.executable, "main.py", "--json", "wordgen"],
            cwd=str(ROOT),
            capture_output=True,
            encoding="utf-8",
            timeout=60,
            env=ENV,
        )
        assert proc.returncode == 1
        import json

        payload = json.loads(proc.stdout)
        assert payload["code"] == "invalid_args"
