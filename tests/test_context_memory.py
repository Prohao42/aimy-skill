import pytest
from tools.context_memory import ContextMemory


class TestContextMemory:
    def setup_method(self):
        ContextMemory._instance = None

    def test_singleton(self):
        m1 = ContextMemory()
        m2 = ContextMemory()
        assert m1 is m2

    def test_set_get(self):
        m = ContextMemory()
        m.set("credential_admin", {"user": "admin", "pass": "password123"})
        val = m.get("credential_admin")
        assert val is not None
        assert val["user"] == "admin"

    def test_has(self):
        m = ContextMemory()
        m.set("key1", "value1")
        assert m.has("key1") is True
        assert m.has("nonexistent") is False

    def test_delete(self):
        m = ContextMemory()
        m.set("key1", "value1")
        m.delete("key1")
        assert m.has("key1") is False

    def test_clear(self):
        m = ContextMemory()
        m.set("key1", "value1")
        m.set("key2", "value2")
        m.clear()
        assert m.all_keys() == []

    def test_cleanup(self):
        m = ContextMemory()
        m.set("temp_key", {"data": "temp"}, ttl=1)
        import time
        time.sleep(1.1)
        cleaned = m.cleanup()
        assert cleaned >= 0

    def test_snapshot(self):
        m = ContextMemory()
        m.set("key1", "value1")
        snap = m.snapshot()
        assert "key1" in snap

    def test_get_suggestions(self):
        m = ContextMemory()
        m.set("dbms", "mysql")
        suggestions = m.get_suggestions("sqli")
        assert isinstance(suggestions, dict)

    def test_get_stats(self):
        m = ContextMemory()
        m.set("key1", "value1")
        stats = m.get_stats()
        assert "total_entries" in stats
        assert stats["total_entries"] >= 1

    def test_all_keys(self):
        m = ContextMemory()
        m.set("a", 1)
        m.set("b", 2)
        keys = m.all_keys()
        assert len(keys) >= 2
