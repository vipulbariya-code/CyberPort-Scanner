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
from contextlib import contextmanager
from datetime import datetime


class Database:
    """Thin wrapper around sqlite3 with schema management and query helpers."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_schema()

    @contextmanager
    def get_connection(self):
        """Context-managed connection ensures commits/closes are never skipped."""
        # WAL and a short busy timeout reduce transient "database is locked"
        # errors while the web process and background scan thread overlap.
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
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
                conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans (user_id)")

    # ---------------------------------------------------------------
    # Write operations
    # ---------------------------------------------------------------
    def create_user(self, username, email, password_hash):
        with self.get_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, password_hash, datetime.utcnow().isoformat()),
            )
            return cursor.lastrowid

    def get_user_by_email(self, email):
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT id, username, email, password_hash FROM users WHERE email = ?", (email,)
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
                    datetime.utcnow().isoformat(),
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
                like = f"%{search}%"
                rows = conn.execute(
                    """
                    SELECT * FROM scans
                    WHERE user_id = ? AND (target LIKE ? OR resolved_ip LIKE ?)
                    ORDER BY created_at DESC LIMIT ? OFFSET ?
                    """,
                    (user_id, like, like, page_size, offset),
                ).fetchall()
                total = conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE user_id = ? AND (target LIKE ? OR resolved_ip LIKE ?)",
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
            total_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,)).fetchone()[0]
            open_sum = conn.execute(
                "SELECT COALESCE(SUM(open_ports_count), 0) FROM scans WHERE user_id = ?", (user_id,)
            ).fetchone()[0]
            closed_sum = conn.execute(
                "SELECT COALESCE(SUM(closed_ports_count), 0) FROM scans WHERE user_id = ?", (user_id,)
            ).fetchone()[0]
            last_scan = conn.execute(
                "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 1", (user_id,)
            ).fetchone()
            avg_duration = conn.execute(
                "SELECT COALESCE(AVG(duration_seconds), 0) FROM scans WHERE user_id = ?", (user_id,)
            ).fetchone()[0]

            return {
                "total_scans": total_scans,
                "total_open_ports": open_sum,
                "total_closed_ports": closed_sum,
                "last_scan": self._row_to_dict(last_scan) if last_scan else None,
                "avg_duration": round(avg_duration, 2),
            }

    @staticmethod
    def _row_to_dict(row):
        d = dict(row)
        d["open_ports"] = json.loads(d.pop("open_ports_json", "[]"))
        return d
