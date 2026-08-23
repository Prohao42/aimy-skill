from tools.semantic_diff import NOISE_KEYS, NOISE_VALUES, SemanticDiffEngine


class TestDiffJson:
    def setup_method(self):
        self.engine = SemanticDiffEngine()

    def test_identical_json(self):
        r = self.engine.diff_json('{"a": 1, "b": "x"}', '{"a": 1, "b": "x"}')
        assert not r.has_meaningful_diff
        assert r.diff_entries == []
        assert r.summary == "identical"

    def test_non_json(self):
        r = self.engine.diff_json("<html>", "not json")
        assert r.has_meaningful_diff
        assert r.summary == "non-json response"

    def test_type_mismatch(self):
        r = self.engine.diff_json("[1, 2]", '{"a": 1}')
        assert r.has_meaningful_diff
        assert r.structural_changes
        assert r.summary == "type mismatch"

    def test_noise_key_ignored(self):
        left = '{"timestamp": 1234567890, "a": 1}'
        right = '{"timestamp": 9999999999, "a": 1}'
        r = self.engine.diff_json(left, right)
        assert not r.has_meaningful_diff
        assert r.noise_entries
        assert r.noise_entries[0].is_noise

    def test_noise_value_ignored(self):
        left = '{"token": "abcdef1234567890", "a": 1}'
        right = '{"token": "fedcba0987654321", "a": 1}'
        r = self.engine.diff_json(left, right)
        assert not r.has_meaningful_diff

    def test_sensitive_key_critical(self):
        left = '{"password": "oldpass", "a": 1}'
        right = '{"password": "newpass", "a": 1}'
        r = self.engine.diff_json(left, right)
        assert r.has_meaningful_diff
        entry = r.diff_entries[0]
        assert entry.significance == "critical"
        assert entry.path == "password"

    def test_numeric_medium_diff(self):
        left = '{"price": 100}'
        right = '{"price": 5000}'
        r = self.engine.diff_json(left, right)
        assert r.has_meaningful_diff
        assert r.diff_entries[0].significance == "medium"

    def test_small_numeric_is_noise(self):
        left = '{"price": 100}'
        right = '{"price": 105}'
        r = self.engine.diff_json(left, right)
        assert not r.has_meaningful_diff
        assert r.noise_entries

    def test_missing_field_is_high(self):
        left = '{"a": 1, "b": "x"}'
        right = '{"a": 1}'
        r = self.engine.diff_json(left, right)
        assert r.has_meaningful_diff
        assert any(e.path == "b" and e.significance == "high" for e in r.diff_entries)

    def test_summary_counts(self):
        left = '{"a": 1, "ts": 100, "b": "x"}'
        right = '{"a": 9999, "ts": 200, "b": "y"}'
        r = self.engine.diff_json(left, right)
        assert "meaningful" in r.summary
        assert "noise" in r.summary


class TestDiffText:
    def setup_method(self):
        self.engine = SemanticDiffEngine()

    def test_identical(self):
        r = self.engine.diff_text("hello", "hello")
        assert not r.has_meaningful_diff
        assert r.length_diff == 0

    def test_length_diff(self):
        r = self.engine.diff_text("hello world", "hi")
        assert r.has_meaningful_diff
        assert r.length_diff == 9
        assert "major" in r.summary

    def test_moderate_diff(self):
        r = self.engine.diff_text("a" * 100, "a" * 95)
        assert "moderate" in r.summary

    def test_minor_diff(self):
        r = self.engine.diff_text("a" * 100, "a" * 99)
        assert "minor" in r.summary


class TestHelpers:
    def test_noise_keys_covered(self):
        assert "timestamp" in NOISE_KEYS
        assert "request_id" in NOISE_KEYS

    def test_noise_values_regex(self):
        assert NOISE_VALUES.match("1234567890123")
        assert NOISE_VALUES.match("a1b2c3d4e5f60718")
        assert NOISE_VALUES.match("2024-01-01T12:00:00Z")
        assert not NOISE_VALUES.match("short")

    def test_nested_list_keys(self):
        engine = SemanticDiffEngine()
        left = '{"items": [{"id": 1, "name": "a"}]}'
        right = '{"items": [{"id": 1, "name": "b"}]}'
        r = engine.diff_json(left, right)
        assert r.has_meaningful_diff
        assert any("name" in e.path for e in r.diff_entries)
