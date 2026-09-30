"""
models.py
---------
Data access layer for CyberPort Scanner.

Supports dual backends:
1. PostgreSQL (production via DATABASE_URL)
2. SQLite (local development and automated testing via DATABASE_PATH or :memory:)

Uses a lightweight, transparent DB-API layer without a heavy ORM.
"""

import sqlite3
import json
import os
import re
import uuid
import hashlib
import secrets
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timezone

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except Exception:
    HAS_PSYCOPG2 = False

try:
    import pg8000.dbapi
    HAS_PG8000 = True
except Exception:
    HAS_PG8000 = False


class DatabaseIntegrityError(sqlite3.IntegrityError):
    """
    Unified integrity error raised on unique constraint or foreign key violations.
    Inherits from sqlite3.IntegrityError so existing exception handlers catch it transparently.
    """
    pass


class DBRow(dict):
    """
    Row wrapper that supports both dict key lookup (row['email'])
    and integer index lookup (row[0]), matching sqlite3.Row behavior.
    """
    def __init__(self, mapping=None, seq=None):
        if mapping:
            super().__init__(mapping)
        else:
            super().__init__()
        self._seq = tuple(seq) if seq is not None else (tuple(self.values()) if mapping else ())

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._seq[key]
        return super().__getitem__(key)


def _sql_to_postgres(sql: str) -> str:
    """
    Safely translates SQLite SQL parameter placeholders '?' to PostgreSQL '%s'.
    Only transforms '?' that appear outside single/double-quoted string literals.
    """
    out = []
    in_single = False
    in_double = False
    i = 0
    n = len(sql)
    while i < n:
        c = sql[i]
        if c == "'" and not in_double:
            if in_single and i + 1 < n and sql[i + 1] == "'":
                out.append("''")
                i += 2
                continue
            in_single = not in_single
            out.append(c)
        elif c == '"' and not in_single:
            in_double = not in_double
            out.append(c)
        elif c == '?' and not in_single and not in_double:
            out.append('%s')
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _mask_credentials(text: str) -> str:
    """Removes passwords from database connection strings in error messages to prevent credential leaks."""
    if not text:
        return text
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:********@", str(text))


class PGCursorWrapper:
    """Wraps PostgreSQL cursor to safely translate parameters and return dict/index accessible rows."""
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql, params=None):
        pg_sql = _sql_to_postgres(sql)
        if params is not None:
            self._cursor.execute(pg_sql, params)
        else:
            self._cursor.execute(pg_sql)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        if isinstance(row, dict):
            return DBRow(row, tuple(row.values()))
        cols = [c[0] for c in self._cursor.description]
        return DBRow(dict(zip(cols, row)), row)

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not rows:
            return []
        if isinstance(rows[0], dict):
            return [DBRow(r, tuple(r.values())) for r in rows]
        cols = [c[0] for c in self._cursor.description]
        return [DBRow(dict(zip(cols, r)), r) for r in rows]

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        return getattr(self._cursor, "lastrowid", None)

    def close(self):
        try:
            self._cursor.close()
        except Exception:
            pass


class PGConnectionWrapper:
    """Wraps PostgreSQL connection to provide convenience methods matching sqlite3.Connection."""
    def __init__(self, conn):
        self._conn = conn
        self._cursors = []

    def execute(self, sql, params=None):
        cur = self._conn.cursor()
        self._cursors.append(cur)
        wrapper = PGCursorWrapper(cur)
        wrapper.execute(sql, params)
        return wrapper

    def commit(self):
        self._conn.commit()

    def rollback(self):
        try:
            self._conn.rollback()
        except Exception:
            pass

    def close(self):
        for c in self._cursors:
            try:
                c.close()
            except Exception:
                pass
        self._cursors.clear()
        try:
            self._conn.close()
        except Exception:
            pass


class Database:
    """
    Unified database access layer with schema management and query helpers.
    Automatically connects to PostgreSQL when db_path is a postgres URL,
    or falls back to SQLite for local development and in-memory test suites.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._shared_conn = None
        self.is_postgres = bool(
            self.db_path
            and (
                self.db_path.startswith("postgresql://")
                or self.db_path.startswith("postgres://")
            )
        )

        if self.is_postgres:
            if self.db_path.startswith("postgres://"):
                self.db_path = self.db_path.replace("postgres://", "postgresql://", 1)
        elif self.db_path == ":memory:" or "mode=memory" in self.db_path:
            # Use unique shared cache URI so in-memory DB persists across connections in this Database instance
            if self.db_path == ":memory:":
                self.db_path = f"file:cyberport_mem_{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._shared_conn = sqlite3.connect(self.db_path, uri=True)
            self._shared_conn.execute("PRAGMA foreign_keys = ON")
        else:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

        self._init_schema()

    def _connect_postgres(self):
        """Establish a PostgreSQL connection using psycopg2 (fast native) or pg8000 (pure-Python fallback)."""
        if HAS_PSYCOPG2:
            try:
                return psycopg2.connect(
                    self.db_path,
                    cursor_factory=psycopg2.extras.RealDictCursor,
                    connect_timeout=10,
                )
            except Exception as exc:
                if not HAS_PG8000:
                    sanitized = _mask_credentials(str(exc))
                    raise RuntimeError(f"PostgreSQL connection failed: {sanitized}") from None

        if HAS_PG8000:
            try:
                parsed = urllib.parse.urlparse(self.db_path)
                query_params = urllib.parse.parse_qs(parsed.query)
                ssl_mode = query_params.get("sslmode", [""])[0].lower()
                use_ssl = ssl_mode in ("require", "verify-ca", "verify-full") or "sslmode=require" in self.db_path
                return pg8000.dbapi.connect(
                    user=urllib.parse.unquote(parsed.username or ""),
                    password=urllib.parse.unquote(parsed.password or ""),
                    host=parsed.hostname or "localhost",
                    port=parsed.port or 5432,
                    database=parsed.path.lstrip("/"),
                    ssl_context=True if use_ssl else None,
                    timeout=10,
                )
            except Exception as exc:
                sanitized = _mask_credentials(str(exc))
                raise RuntimeError(f"PostgreSQL connection failed: {sanitized}") from None

        raise RuntimeError("No PostgreSQL driver available. Please install psycopg2-binary or pg8000.")

    @contextmanager
    def get_connection(self):
        """Context-managed connection ensuring commits, rollbacks, and cleanup are never skipped."""
        if self.is_postgres:
            raw_conn = self._connect_postgres()
            conn = PGConnectionWrapper(raw_conn)
            try:
                yield conn
                conn.commit()
            except Exception as exc:
                conn.rollback()
                err_str = _mask_credentials(str(exc))
                err_type_name = type(exc).__name__
                if "IntegrityError" in err_type_name or "UniqueViolation" in err_type_name or "unique constraint" in err_str.lower():
                    raise DatabaseIntegrityError(err_str) from None
                raise
            finally:
                conn.close()
        else:
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
            except Exception as exc:
                conn.rollback()
                if isinstance(exc, sqlite3.IntegrityError):
                    raise DatabaseIntegrityError(str(exc)) from exc
                raise
            finally:
                conn.close()

    def _init_schema(self):
        with self.get_connection() as conn:
            if self.is_postgres:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) NOT NULL UNIQUE,
                        email VARCHAR(255) NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        created_at VARCHAR(50) NOT NULL
                    )
                    """
                )
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users (LOWER(username))")
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (LOWER(email))")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scans (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        target VARCHAR(255) NOT NULL,
                        resolved_ip VARCHAR(255),
                        start_port INTEGER NOT NULL,
                        end_port INTEGER NOT NULL,
                        total_ports_scanned INTEGER NOT NULL DEFAULT 0,
                        open_ports_count INTEGER NOT NULL DEFAULT 0,
                        closed_ports_count INTEGER NOT NULL DEFAULT 0,
                        duration_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
                        open_ports_json TEXT NOT NULL DEFAULT '[]',
                        status VARCHAR(50) NOT NULL DEFAULT 'completed',
                        created_at VARCHAR(50) NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans (user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans (user_id, created_at DESC)")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS api_keys (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        name VARCHAR(255) NOT NULL,
                        key_hash VARCHAR(64) NOT NULL UNIQUE,
                        key_prefix VARCHAR(50) NOT NULL,
                        created_at VARCHAR(50) NOT NULL,
                        last_used_at VARCHAR(50),
                        revoked_at VARCHAR(50)
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys (user_id)")
            else:
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

                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans (user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans (user_id, created_at DESC)")

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
                conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys (user_id)")

    # ---------------------------------------------------------------
    # Write operations
    # ---------------------------------------------------------------
    def create_user(self, username, email, password_hash):
        created_at = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            if self.is_postgres:
                cursor = conn.execute(
                    """
                    INSERT INTO users (username, email, password_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    RETURNING id
                    """,
                    (username, email, password_hash, created_at),
                )
                row = cursor.fetchone()
                return row["id"] if isinstance(row, dict) else row[0]
            else:
                cursor = conn.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, email, password_hash, created_at),
                )
                return cursor.lastrowid

    def get_user_by_email(self, email):
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT id, username, email, password_hash FROM users WHERE LOWER(email) = LOWER(?)",
                (email,),
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_email_or_username(self, identifier):
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT id, username, email, password_hash FROM users
                WHERE LOWER(email) = LOWER(?) OR LOWER(username) = LOWER(?)
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
        created_at = datetime.now(timezone.utc).isoformat()
        ports_json = json.dumps(open_ports)

        with self.get_connection() as conn:
            if self.is_postgres:
                cursor = conn.execute(
                    """
                    INSERT INTO scans (
                        user_id, target, resolved_ip, start_port, end_port,
                        total_ports_scanned, open_ports_count, closed_ports_count,
                        duration_seconds, open_ports_json, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING id
                    """,
                    (
                        user_id, target, resolved_ip, start_port, end_port,
                        total_ports_scanned, open_ports_count, closed_ports_count,
                        duration_seconds, ports_json, status, created_at,
                    ),
                )
                row = cursor.fetchone()
                return row["id"] if isinstance(row, dict) else row[0]
            else:
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
                        duration_seconds, ports_json, status, created_at,
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
        raw_key = f"cps_live_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        prefix = f"{raw_key[:12]}...{raw_key[-4:]}"
        masked_key = f"{raw_key[:12]}••••••••{raw_key[-4:]}"
        created_at = datetime.now(timezone.utc).isoformat()

        with self.get_connection() as conn:
            if self.is_postgres:
                cursor = conn.execute(
                    """
                    INSERT INTO api_keys (user_id, name, key_hash, key_prefix, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    RETURNING id
                    """,
                    (user_id, clean_name, key_hash, prefix, created_at),
                )
                row = cursor.fetchone()
                key_id = row["id"] if isinstance(row, dict) else row[0]
            else:
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
                "avg_duration": round(float(row["avg_duration"]), 2) if row else 0,
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
                "avg_duration": round(float(row["avg_duration"]), 2) if row else 0,
            }

    @staticmethod
    def _row_to_dict(row):
        if row is None:
            return None
        d = dict(row)
        raw_json = d.pop("open_ports_json", "[]") or "[]"
        try:
            d["open_ports"] = json.loads(raw_json)
        except (ValueError, TypeError):
            d["open_ports"] = []
        return d
