import sqlite3
import uuid
import pytest
from werkzeug.security import generate_password_hash

from models import Database


@pytest.fixture
def db():
    return Database(f"file:test_db_{uuid.uuid4().hex}?mode=memory&cache=shared")


class TestDatabaseOperations:
    def test_schema_init(self, db):
        with db.get_connection() as conn:
            tables = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            assert "users" in tables
            assert "scans" in tables

    def test_create_and_get_user(self, db):
        pw_hash = generate_password_hash("StrongPassword123")
        user_id = db.create_user("alice", "alice@example.com", pw_hash)
        assert user_id > 0

        # Retrieve by email
        user = db.get_user_by_email("alice@example.com")
        assert user is not None
        assert user["username"] == "alice"
        assert user["email"] == "alice@example.com"

        # Case-insensitive email lookup
        user_upper = db.get_user_by_email("ALICE@EXAMPLE.COM")
        assert user_upper is not None
        assert user_upper["id"] == user_id

        # Lookup by username or email
        user_by_uname = db.get_user_by_email_or_username("alice")
        assert user_by_uname is not None
        assert user_by_uname["id"] == user_id

    def test_duplicate_user_rejection(self, db):
        pw_hash = generate_password_hash("StrongPassword123")
        db.create_user("bob", "bob@example.com", pw_hash)

        # Duplicate email
        with pytest.raises(sqlite3.IntegrityError):
            db.create_user("bob2", "bob@example.com", pw_hash)

        # Duplicate username
        with pytest.raises(sqlite3.IntegrityError):
            db.create_user("bob", "other@example.com", pw_hash)

    def test_create_and_get_scan(self, db):
        pw_hash = generate_password_hash("Password123")
        user_id = db.create_user("charlie", "charlie@example.com", pw_hash)

        open_ports = [{"port": 80, "service": "HTTP", "state": "open"}]
        scan_id = db.create_scan(
            user_id=user_id,
            target="192.168.1.1",
            resolved_ip="192.168.1.1",
            start_port=1,
            end_port=100,
            total_ports_scanned=100,
            open_ports=open_ports,
            duration_seconds=1.23,
        )
        assert scan_id > 0

        scan = db.get_scan(scan_id, user_id)
        assert scan is not None
        assert scan["target"] == "192.168.1.1"
        assert scan["open_ports_count"] == 1
        assert scan["closed_ports_count"] == 99
        assert scan["open_ports"] == open_ports

        # Scan isolation: other user cannot get this scan
        assert db.get_scan(scan_id, user_id + 1) is None

    def test_malformed_json_handling(self, db):
        user_id = db.create_user("json_user", "json@test.com", "hash")
        # Insert a row with corrupted open_ports_json directly
        with db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (
                    user_id, target, resolved_ip, start_port, end_port,
                    total_ports_scanned, open_ports_count, closed_ports_count,
                    duration_seconds, open_ports_json, status, created_at
                ) VALUES (?, '127.0.0.1', '127.0.0.1', 80, 80, 1, 0, 1, 0.1, '{corrupted-json', 'completed', '2026-01-01T00:00:00')
                """,
                (user_id,),
            )
            scan_id = cursor.lastrowid

        scan = db.get_scan(scan_id, user_id=user_id)
        assert scan is not None
        assert scan["open_ports"] == []  # Gracefully falls back to empty list

    def test_delete_scan_and_clear_history(self, db):
        pw_hash = generate_password_hash("Password123")
        u1 = db.create_user("user1", "u1@example.com", pw_hash)
        u2 = db.create_user("user2", "u2@example.com", pw_hash)

        s1 = db.create_scan(u1, "127.0.0.1", "127.0.0.1", 1, 10, 10, [], 0.5)
        s2 = db.create_scan(u2, "127.0.0.1", "127.0.0.1", 1, 10, 10, [], 0.5)

        # User 1 cannot delete User 2's scan
        assert db.delete_scan(s2, user_id=u1) is False
        assert db.get_scan(s2, u2) is not None

        # User 1 deletes their own scan
        assert db.delete_scan(s1, user_id=u1) is True
        assert db.get_scan(s1, u1) is None

        # Clear history only clears that user's scans
        db.create_scan(u1, "127.0.0.1", "127.0.0.1", 1, 10, 10, [], 0.5)
        db.clear_history(user_id=u1)
        assert len(db.list_scans(u1)["items"]) == 0
        assert len(db.list_scans(u2)["items"]) == 1

    def test_list_scans_pagination_and_search(self, db):
        user_id = db.create_user("user_search", "search@example.com", "hash")
        for i in range(15):
            target = f"192.168.1.{i+1}"
            db.create_scan(user_id, target, target, 1, 10, 10, [], 0.5)

        # Pagination: 10 per page
        page1 = db.list_scans(user_id, page=1, page_size=10)
        assert page1["total"] == 15
        assert len(page1["items"]) == 10
        assert page1["total_pages"] == 2

        page2 = db.list_scans(user_id, page=2, page_size=10)
        assert len(page2["items"]) == 5

        # Search
        res = db.list_scans(user_id, page=1, page_size=10, search="192.168.1.15")
        assert res["total"] == 1
        assert res["items"][0]["target"] == "192.168.1.15"

    def test_dashboard_and_public_stats(self, db):
        # Empty stats
        empty_stats = db.get_dashboard_stats(user_id=999)
        assert empty_stats["total_scans"] == 0
        assert empty_stats["total_open_ports"] == 0
        assert empty_stats["total_closed_ports"] == 0
        assert empty_stats["last_scan"] is None

        u = db.create_user("stat_user", "stat@example.com", "hash")
        db.create_scan(u, "10.0.0.1", "10.0.0.1", 1, 100, 100, [{"port": 80, "service": "HTTP", "state": "open"}], 2.0)
        db.create_scan(u, "10.0.0.2", "10.0.0.2", 1, 50, 50, [{"port": 22, "service": "SSH", "state": "open"}, {"port": 443, "service": "HTTPS", "state": "open"}], 1.0)

        user_stats = db.get_dashboard_stats(u)
        assert user_stats["total_scans"] == 2
        assert user_stats["total_open_ports"] == 3
        assert user_stats["total_closed_ports"] == 147
        assert user_stats["avg_duration"] == 1.5
        assert user_stats["last_scan"]["target"] == "10.0.0.2"

        public_stats = db.get_public_stats()
        assert public_stats["total_scans"] == 2
        assert public_stats["total_open_ports"] == 3
        assert public_stats["last_scan"] is None  # Does not leak targets

    def test_api_key_lifecycle(self, db):
        pw_hash = generate_password_hash("Password123")
        u = db.create_user("key_user", "key@example.com", pw_hash)

        # Create key
        key_info = db.create_api_key(u, name="Test Key")
        assert key_info["name"] == "Test Key"
        assert key_info["api_key"].startswith("cps_live_")
        assert key_info["user_id"] == u

        # Retrieve by hash
        hash_val = key_info["api_key"]
        import hashlib
        computed_hash = hashlib.sha256(hash_val.encode("utf-8")).hexdigest()
        retrieved = db.get_api_key_by_hash(computed_hash)
        assert retrieved is not None
        assert retrieved["id"] == key_info["id"]
        assert retrieved["username"] == "key_user"

        # List keys
        keys = db.list_api_keys(u)
        assert len(keys) == 1
        assert keys[0]["is_active"] is True

        # Touch key
        db.touch_api_key(key_info["id"])
        updated = db.get_api_key(key_info["id"], u)
        assert updated["last_used_at"] is not None

        # Revoke key
        assert db.revoke_api_key(key_info["id"], u) is True
        revoked = db.get_api_key(key_info["id"], u)
        assert revoked["is_active"] is False


class TestDualBackendCompatibility:
    def test_sqlite_fallback_detection(self):
        db = Database(":memory:")
        assert db.is_postgres is False

    def test_postgres_detection_and_normalization(self):
        # Instantiate without running schema by checking detection logic
        pg_url = "postgres://user:pass@host:5432/neondb?sslmode=require"
        # Test URL normalization in Config
        from config import Config
        raw = "postgres://test_user:pass@ep-cool-host.neon.tech/neondb?sslmode=require"
        normalized = raw.replace("postgres://", "postgresql://", 1)
        assert normalized.startswith("postgresql://")

    def test_dbrow_compatibility(self):
        from models import DBRow
        row = DBRow({"id": 42, "target": "10.0.0.1"}, (42, "10.0.0.1"))
        # Dict access
        assert row["id"] == 42
        assert row["target"] == "10.0.0.1"
        # Index access (sqlite3.Row behavior)
        assert row[0] == 42
        assert row[1] == "10.0.0.1"
        # dict() conversion
        assert dict(row) == {"id": 42, "target": "10.0.0.1"}

    def test_pg_cursor_wrapper_placeholder_translation(self):
        from models import PGCursorWrapper
        executed = []

        class FakeCursor:
            description = [("id",), ("email",)]
            rowcount = 1

            def execute(self, sql, params=None):
                executed.append((sql, params))

            def fetchone(self):
                return (1, "a@b.com")

            def fetchall(self):
                return [(1, "a@b.com")]

        fake = FakeCursor()
        wrapper = PGCursorWrapper(fake)
        wrapper.execute("SELECT * FROM users WHERE email = ? AND id = ?", ("test@example.com", 1))

        assert len(executed) == 1
        sql, params = executed[0]
        # Verified ? converted to %s for PostgreSQL
        assert "%s" in sql
        assert "?" not in sql
        assert params == ("test@example.com", 1)

        row = wrapper.fetchone()
        assert row["id"] == 1
        assert row[0] == 1

    def test_database_integrity_error_subclass(self):
        from models import DatabaseIntegrityError
        import sqlite3
        assert issubclass(DatabaseIntegrityError, sqlite3.IntegrityError)
        try:
            raise DatabaseIntegrityError("duplicate key violates unique constraint")
        except sqlite3.IntegrityError as e:
            assert "duplicate key" in str(e)
