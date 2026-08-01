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
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
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
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC)"
            )

    # ---------------------------------------------------------------
    # Write operations
    # ---------------------------------------------------------------
    def create_scan(self, target, resolved_ip, start_port, end_port,
                     total_ports_scanned, open_ports, duration_seconds,
                     status="completed"):
        open_ports_count = len(open_ports)
        closed_ports_count = max(total_ports_scanned - open_ports_count, 0)
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (
                    target, resolved_ip, start_port, end_port,
                    total_ports_scanned, open_ports_count, closed_ports_count,
                    duration_seconds, open_ports_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target, resolved_ip, start_port, end_port,
                    total_ports_scanned, open_ports_count, closed_ports_count,
                    duration_seconds, json.dumps(open_ports), status,
                    datetime.utcnow().isoformat(),
                ),
            )
            return cursor.lastrowid

    def delete_scan(self, scan_id):
        with self.get_connection() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cursor.rowcount > 0

    def clear_history(self):
        with self.get_connection() as conn:
            conn.execute("DELETE FROM scans")

    # ---------------------------------------------------------------
    # Read operations
    # ---------------------------------------------------------------
    def get_scan(self, scan_id):
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            return self._row_to_dict(row) if row else None

    def list_scans(self, page=1, page_size=10, search=None):
        offset = (page - 1) * page_size
        with self.get_connection() as conn:
            if search:
                like = f"%{search}%"
                rows = conn.execute(
                    """
                    SELECT * FROM scans
                    WHERE target LIKE ? OR resolved_ip LIKE ?
                    ORDER BY created_at DESC LIMIT ? OFFSET ?
                    """,
                    (like, like, page_size, offset),
                ).fetchall()
                total = conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE target LIKE ? OR resolved_ip LIKE ?",
                    (like, like),
                ).fetchone()[0]
            else:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (page_size, offset),
                ).fetchall()
                total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

            return {
                "items": [self._row_to_dict(r) for r in rows],
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": max(1, (total + page_size - 1) // page_size),
            }

    def get_dashboard_stats(self):
        with self.get_connection() as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            open_sum = conn.execute(
                "SELECT COALESCE(SUM(open_ports_count), 0) FROM scans"
            ).fetchone()[0]
            closed_sum = conn.execute(
                "SELECT COALESCE(SUM(closed_ports_count), 0) FROM scans"
            ).fetchone()[0]
            last_scan = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            avg_duration = conn.execute(
                "SELECT COALESCE(AVG(duration_seconds), 0) FROM scans"
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
