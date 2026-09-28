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
import hashlib
import secrets
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

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_prefix TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    revoked_at TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys (user_id)"
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

    def update_scan(self, scan_id, user_id=None, status="completed",
                    total_ports_scanned=None, open_ports=None, duration_seconds=None):
        with self.get_connection() as conn:
            fields = ["status = ?"]
            values = [status]
            if total_ports_scanned is not None:
                fields.append("total_ports_scanned = ?")
                values.append(total_ports_scanned)
            if open_ports is not None:
                open_ports_count = len(open_ports)
                total = total_ports_scanned if total_ports_scanned is not None else open_ports_count
                closed_ports_count = max(total - open_ports_count, 0)
                fields.append("open_ports_count = ?")
                values.append(open_ports_count)
                fields.append("closed_ports_count = ?")
                values.append(closed_ports_count)
                fields.append("open_ports_json = ?")
                values.append(json.dumps(open_ports))
            if duration_seconds is not None:
                fields.append("duration_seconds = ?")
                values.append(duration_seconds)

            where = "WHERE id = ?"
            values.append(scan_id)
            if user_id is not None:
                where += " AND user_id = ?"
                values.append(user_id)

            cursor = conn.execute(f"UPDATE scans SET {', '.join(fields)} {where}", values)
            return cursor.rowcount > 0

    def count_active_scans(self, user_id):
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE user_id = ? AND status = 'running'",
                (user_id,),
            ).fetchone()
            return row[0] if row else 0

    # ---------------------------------------------------------------
    # API Key operations
    # ---------------------------------------------------------------
    def create_api_key(self, user_id, name="Default Key"):
        clean_name = (name or "Default Key").strip()[:64] or "Default Key"
        # Generate cryptographically secure random key
        # Format: cps_live_<32 url-safe chars> (256-bit entropy)
        raw_key = f"cps_live_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        prefix = f"{raw_key[:12]}...{raw_key[-4:]}"
        masked_key = f"{raw_key[:12]}••••••••{raw_key[-4:]}"
        created_at = datetime.now(timezone.utc).isoformat()

        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO api_keys (user_id, name, key_hash, key_prefix, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, clean_name, key_hash, prefix, created_at),
            )
            key_id = cursor.lastrowid
            return {
                "id": key_id,
                "user_id": user_id,
                "name": clean_name,
                "api_key": raw_key,
                "masked_key": masked_key,
                "key_prefix": prefix,
                "created_at": created_at,
                "last_used_at": None,
                "revoked_at": None,
            }

    def get_api_key_by_hash(self, key_hash):
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT ak.id, ak.user_id, ak.name, ak.key_hash, ak.key_prefix,
                       ak.created_at, ak.last_used_at, ak.revoked_at,
                       u.username, u.email
                FROM api_keys ak
                JOIN users u ON ak.user_id = u.id
                WHERE ak.key_hash = ?
                """,
                (key_hash,),
            ).fetchone()
            return dict(row) if row else None

    def touch_api_key(self, key_id):
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), key_id),
            )

    def list_api_keys(self, user_id):
        with self.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, user_id, name, key_prefix, created_at, last_used_at, revoked_at
                FROM api_keys
                WHERE user_id = ?
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()
            keys = []
            for r in rows:
                d = dict(r)
                d["masked_key"] = d["key_prefix"].replace("...", "••••••••")
                d["is_active"] = d["revoked_at"] is None
                keys.append(d)
            return keys

    def revoke_api_key(self, key_id, user_id):
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE api_keys
                SET revoked_at = ?
                WHERE id = ? AND user_id = ? AND revoked_at IS NULL
                """,
                (datetime.now(timezone.utc).isoformat(), key_id, user_id),
            )
            return cursor.rowcount > 0

    def get_api_key(self, key_id, user_id):
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT id, user_id, name, key_prefix, created_at, last_used_at, revoked_at
                FROM api_keys
                WHERE id = ? AND user_id = ?
                """,
                (key_id, user_id),
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["masked_key"] = d["key_prefix"].replace("...", "••••••••")
            d["is_active"] = d["revoked_at"] is None
            return d

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
