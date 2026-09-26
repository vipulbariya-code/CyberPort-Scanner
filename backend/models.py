"""
models.py
---------
SQLite data access layer for CyberPort Scanner.

Uses plain sqlite3 (no heavy ORM) for a lightweight, transparent
persistence layer that's easy to audit — appropriate for a security
education tool where clarity matters.
"""

import sqlite3
import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone


class Database:
    """Thin wrapper around sqlite3 with schema management and query helpers."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._shared_conn = None
        if self.db_path == ":memory:" or "mode=memory" in self.db_path:
            # Use unique shared cache URI so in-memory DB persists across connections in this Database instance
            if self.db_path == ":memory:":
                self.db_path = f"file:cyberport_mem_{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._shared_conn = sqlite3.connect(self.db_path, uri=True)
            self._shared_conn.execute("PRAGMA foreign_keys = ON")
        else:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_schema()

    @contextmanager
    def get_connection(self):
        """Context-managed connection ensures commits/closes are never skipped."""
        # WAL and a busy timeout reduce transient "database is locked"
        # errors while the web process and background scan thread overlap.
        is_uri = self.db_path.startswith("file:")
        conn = sqlite3.connect(self.db_path, timeout=15, uri=is_uri)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if not is_uri:
            conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 10000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self):
        with self.get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    target TEXT NOT NULL,
                    resolved_ip TEXT,
                    start_port INTEGER NOT NULL,
                    end_port INTEGER NOT NULL,
                    total_ports_scanned INTEGER NOT NULL DEFAULT 0,
                    open_ports_count INTEGER NOT NULL DEFAULT 0,
                    closed_ports_count INTEGER NOT NULL DEFAULT 0,
                    duration_seconds REAL NOT NULL DEFAULT 0,
                    open_ports_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'completed',
                    created_at TEXT NOT NULL
                )
                """
            )
            scan_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(scans)").fetchall()
            }
            if "user_id" not in scan_columns:
                conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE")

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans (user_id)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans (user_id, created_at DESC)"
            )

    # ---------------------------------------------------------------
    # Write operations
    # ---------------------------------------------------------------
    def create_user(self, username, email, password_hash):
        with self.get_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, password_hash, datetime.now(timezone.utc).isoformat()),
            )
            return cursor.lastrowid

    def get_user_by_email(self, email):
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT id, username, email, password_hash FROM users WHERE email = ? COLLATE NOCASE",
                (email,),
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_email_or_username(self, identifier):
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT id, username, email, password_hash FROM users
                WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE
                LIMIT 1
                """,
                (identifier, identifier),
            ).fetchone()
            return dict(row) if row else None

    def create_scan(self, user_id, target, resolved_ip, start_port, end_port,
                     total_ports_scanned, open_ports, duration_seconds,
                     status="completed"):
        open_ports_count = len(open_ports)
        closed_ports_count = max(total_ports_scanned - open_ports_count, 0)
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (
                    user_id, target, resolved_ip, start_port, end_port,
                    total_ports_scanned, open_ports_count, closed_ports_count,
                    duration_seconds, open_ports_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id, target, resolved_ip, start_port, end_port,
                    total_ports_scanned, open_ports_count, closed_ports_count,
                    duration_seconds, json.dumps(open_ports), status,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            return cursor.lastrowid

    def delete_scan(self, scan_id, user_id):
        with self.get_connection() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
            return cursor.rowcount > 0

    def clear_history(self, user_id):
        with self.get_connection() as conn:
            conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))

    # ---------------------------------------------------------------
    # Read operations
    # ---------------------------------------------------------------
    def get_scan(self, scan_id, user_id):
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id)
            ).fetchone()
            return self._row_to_dict(row) if row else None

    def list_scans(self, user_id, page=1, page_size=10, search=None):
        page = max(1, page)
        offset = (page - 1) * page_size
        with self.get_connection() as conn:
            if search:
                # Escape LIKE special characters %, _, \
                escaped = (
                    search.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                like = f"%{escaped}%"
                rows = conn.execute(
                    """
                    SELECT * FROM scans
                    WHERE user_id = ? AND (target LIKE ? ESCAPE '\\' OR resolved_ip LIKE ? ESCAPE '\\')
                    ORDER BY created_at DESC LIMIT ? OFFSET ?
                    """,
                    (user_id, like, like, page_size, offset),
                ).fetchall()
                total = conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE user_id = ? AND (target LIKE ? ESCAPE '\\' OR resolved_ip LIKE ? ESCAPE '\\')",
                    (user_id, like, like),
                ).fetchone()[0]
            else:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (user_id, page_size, offset),
                ).fetchall()
                total = conn.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,)).fetchone()[0]

            return {
                "items": [self._row_to_dict(r) for r in rows],
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": max(1, (total + page_size - 1) // page_size),
            }

    def get_dashboard_stats(self, user_id):
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) as total_scans,
                    COALESCE(SUM(open_ports_count), 0) as total_open_ports,
                    COALESCE(SUM(closed_ports_count), 0) as total_closed_ports,
                    COALESCE(AVG(duration_seconds), 0) as avg_duration
                FROM scans WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            last_scan = conn.execute(
                "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
                (user_id,),
            ).fetchone()

            return {
                "total_scans": row["total_scans"] if row else 0,
                "total_open_ports": row["total_open_ports"] if row else 0,
                "total_closed_ports": row["total_closed_ports"] if row else 0,
                "last_scan": self._row_to_dict(last_scan) if last_scan else None,
                "avg_duration": round(row["avg_duration"], 2) if row else 0,
            }

    def get_public_stats(self):
        """Aggregate stats across all scans for public display without leaking targets."""
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) as total_scans,
                    COALESCE(SUM(open_ports_count), 0) as total_open_ports,
                    COALESCE(SUM(closed_ports_count), 0) as total_closed_ports,
                    COALESCE(AVG(duration_seconds), 0) as avg_duration
                FROM scans
                """
            ).fetchone()
            return {
                "total_scans": row["total_scans"] if row else 0,
                "total_open_ports": row["total_open_ports"] if row else 0,
                "total_closed_ports": row["total_closed_ports"] if row else 0,
                "last_scan": None,
                "avg_duration": round(row["avg_duration"], 2) if row else 0,
            }

    @staticmethod
    def _row_to_dict(row):
        d = dict(row)
        raw_json = d.pop("open_ports_json", "[]") or "[]"
        try:
            d["open_ports"] = json.loads(raw_json)
        except (ValueError, TypeError):
            d["open_ports"] = []
        return d
