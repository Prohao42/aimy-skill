import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("storage")

STORAGE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def _ensure_dir():
    os.makedirs(STORAGE_DIR, exist_ok=True)


def db_path(name: str = "default") -> str:
    _ensure_dir()
    return os.path.join(STORAGE_DIR, f"session_{name}.db")


class SessionStore:
    _instances: Dict[str, "SessionStore"] = {}
    _lock = threading.Lock()

    def __new__(cls, name: str = "default"):
        with cls._lock:
            if name not in cls._instances:
                cls._instances[name] = super().__new__(cls)
                cls._instances[name]._initialized = False
            return cls._instances[name]

    def __init__(self, name: str = "default"):
        if self._initialized:
            return
        self._initialized = True
        self.name = name
        self.path = db_path(name)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()
        logger.info("SessionStore '%s' at %s", name, self.path)

    def _init_schema(self):
        c = self._conn
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                created_at REAL,
                updated_at REAL,
                mode TEXT,
                report TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS context_kv (
                session_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT,
                confidence REAL DEFAULT 0.8,
                timestamp REAL,
                tags TEXT,
                PRIMARY KEY (session_id, key)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                session_id INTEGER NOT NULL,
                finding_id TEXT NOT NULL,
                vuln_type TEXT,
                url TEXT,
                param TEXT,
                payload TEXT,
                severity TEXT DEFAULT 'medium',
                confidence REAL DEFAULT 0.5,
                detail TEXT,
                created_at REAL,
                PRIMARY KEY (session_id, finding_id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS phase_state (
                session_id INTEGER NOT NULL,
                phase TEXT NOT NULL,
                state TEXT,
                updated_at REAL,
                PRIMARY KEY (session_id, phase)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS vuln_context (
                session_id INTEGER NOT NULL,
                field TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (session_id, field)
            )
        """)
        self._conn.commit()

    def _ensure_session(self, target: str = "", mode: str = "") -> int:
        cur = self._conn.cursor()
        rows = cur.execute("SELECT id FROM sessions ORDER BY id DESC LIMIT 1").fetchall()
        if rows:
            sid = rows[0]["id"]
            if target:
                cur.execute("UPDATE sessions SET target=?, updated_at=? WHERE id=?",
                            (target, time.time(), sid))
            return sid
        cur.execute("INSERT INTO sessions (target, created_at, updated_at, mode) VALUES (?, ?, ?, ?)",
                    (target, time.time(), time.time(), mode))
        self._conn.commit()
        return cur.lastrowid

    def session_id(self) -> int:
        return self._ensure_session()

    # === Context KV ===
    def save_context(self, key: str, value: Any, source: str = "unknown",
                     confidence: float = 0.8, tags: Optional[List[str]] = None,
                     session_id: Optional[int] = None):
        sid = session_id or self._ensure_session()
        v = json.dumps(value) if not isinstance(value, str) else value
        tags_json = json.dumps(tags or [])
        self._conn.execute("""
            INSERT OR REPLACE INTO context_kv (session_id, key, value, source, confidence, timestamp, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (sid, key, v, source, confidence, time.time(), tags_json))
        self._conn.commit()

    def load_all_context(self, session_id: Optional[int] = None) -> Dict[str, Dict]:
        sid = session_id or self._ensure_session()
        rows = self._conn.execute(
            "SELECT key, value, source, confidence, timestamp, tags FROM context_kv WHERE session_id=?",
            (sid,)
        ).fetchall()
        result = {}
        for r in rows:
            try:
                v = json.loads(r["value"])
            except (json.JSONDecodeError, TypeError):
                v = r["value"]
            result[r["key"]] = {
                "value": v,
                "source": r["source"],
                "confidence": r["confidence"],
                "timestamp": r["timestamp"],
                "tags": json.loads(r["tags"]) if r["tags"] else [],
            }
        return result

    # === Findings ===
    def save_finding(self, finding_id: str, vuln_type: str, url: str,
                     param: str = "", payload: str = "", severity: str = "medium",
                     confidence: float = 0.5, detail: Optional[Dict] = None,
                     session_id: Optional[int] = None):
        sid = session_id or self._ensure_session()
        self._conn.execute("""
            INSERT OR REPLACE INTO findings (session_id, finding_id, vuln_type, url, param,
                payload, severity, confidence, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (sid, finding_id, vuln_type, url, param, payload, severity,
              confidence, json.dumps(detail or {}), time.time()))
        self._conn.commit()

    def load_findings(self, session_id: Optional[int] = None, vuln_type: Optional[str] = None) -> List[Dict]:
        sid = session_id or self._ensure_session()
        q = "SELECT * FROM findings WHERE session_id=?"
        params = [sid]
        if vuln_type:
            q += " AND vuln_type=?"
            params.append(vuln_type)
        rows = self._conn.execute(q, params).fetchall()
        result = []
        for r in rows:
            entry = dict(r)
            try:
                entry["detail"] = json.loads(entry["detail"]) if entry["detail"] else {}
            except (json.JSONDecodeError, TypeError):
                entry["detail"] = {}
            result.append(entry)
        return result

    # === Phase State ===
    def save_phase(self, phase: str, state: Any, session_id: Optional[int] = None):
        sid = session_id or self._ensure_session()
        s = json.dumps(state) if not isinstance(state, str) else state
        self._conn.execute("""
            INSERT OR REPLACE INTO phase_state (session_id, phase, state, updated_at)
            VALUES (?, ?, ?, ?)
        """, (sid, phase, s, time.time()))
        self._conn.commit()

    def load_phase(self, phase: str, session_id: Optional[int] = None) -> Optional[Any]:
        sid = session_id or self._ensure_session()
        row = self._conn.execute(
            "SELECT state FROM phase_state WHERE session_id=? AND phase=?",
            (sid, phase)
        ).fetchone()
        if row:
            try:
                return json.loads(row["state"])
            except (json.JSONDecodeError, TypeError):
                return row["state"]
        return None

    def load_all_phases(self, session_id: Optional[int] = None) -> Dict[str, Any]:
        sid = session_id or self._ensure_session()
        rows = self._conn.execute(
            "SELECT phase, state FROM phase_state WHERE session_id=?", (sid,)
        ).fetchall()
        result = {}
        for r in rows:
            try:
                result[r["phase"]] = json.loads(r["state"])
            except (json.JSONDecodeError, TypeError):
                result[r["phase"]] = r["state"]
        return result

    # === VulnContext ===
    def save_vuln_context(self, fields: Dict[str, Any], session_id: Optional[int] = None):
        sid = session_id or self._ensure_session()
        for k, v in fields.items():
            if v is None:
                continue
            if isinstance(v, (list, dict)):
                val = json.dumps(v)
            else:
                val = str(v)
            self._conn.execute("""
                INSERT OR REPLACE INTO vuln_context (session_id, field, value)
                VALUES (?, ?, ?)
            """, (sid, k, val))
        self._conn.commit()

    def load_vuln_context(self, session_id: Optional[int] = None) -> Dict[str, Any]:
        sid = session_id or self._ensure_session()
        rows = self._conn.execute(
            "SELECT field, value FROM vuln_context WHERE session_id=?", (sid,)
        ).fetchall()
        result = {}
        for r in rows:
            try:
                result[r["field"]] = json.loads(r["value"])
            except (json.JSONDecodeError, TypeError):
                result[r["field"]] = r["value"]
        return result

    # === Session management ===
    def list_sessions(self) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT id, target, created_at, updated_at, mode FROM sessions ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def load_report(self, session_id: Optional[int] = None) -> Optional[Dict]:
        sid = session_id or self._ensure_session()
        row = self._conn.execute(
            "SELECT report FROM sessions WHERE id=?", (sid,)
        ).fetchone()
        if row and row["report"]:
            try:
                return json.loads(row["report"])
            except (json.JSONDecodeError, TypeError):
                return None
        return None

    def close(self):
        self._conn.commit()
        self._conn.close()

    def __del__(self):
        try:
            self._conn.close()
        except Exception:
            pass
