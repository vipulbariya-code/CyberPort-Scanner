"""
test_api_v1.py
--------------
Comprehensive automated test suite for CyberPort Scanner REST API v1.

Tests cover:
- API health
- API authentication (Bearer, X-API-Key, invalid key, revoked key, missing key)
- API key generation & masking
- API key ownership & revocation
- Scan creation, validation, and lifecycle
- Scan status and open ports reporting
- Scan history & pagination
- Scan deletion
- IDOR protection across users
- User statistics
- Educational port information lookups
- Target safety restrictions (private only, 1024-port cap, invalid octets)
- Rate limiting & concurrent scan limits
- Standardized JSON error response schemas
- OpenAPI 3.0 specification & documentation routes
"""

import pytest
import time
from unittest.mock import patch
from werkzeug.security import generate_password_hash


@pytest.fixture
def auth_user(app):
    """Create a test user and an active API key."""
    with app.app_context():
        user_id = app.db.create_user("api_dev", "dev@example.com", generate_password_hash("DevSecret123"))
        key_data = app.db.create_api_key(user_id, name="Test Key")
        return {
            "user_id": user_id,
            "username": "api_dev",
            "api_key": key_data["api_key"],
            "key_id": key_data["id"],
            "masked_key": key_data["masked_key"]
        }


@pytest.fixture
def auth_headers(auth_user):
    """Authorization header dictionary for auth_user."""
    return {"Authorization": f"Bearer {auth_user['api_key']}"}


@pytest.fixture
def second_user(app):
    """Create a second distinct user and API key for IDOR testing."""
    with app.app_context():
        user_id = app.db.create_user("second_dev", "dev2@example.com", generate_password_hash("DevSecret456"))
        key_data = app.db.create_api_key(user_id, name="User2 Key")
        return {
            "user_id": user_id,
            "username": "second_dev",
            "api_key": key_data["api_key"],
            "key_id": key_data["id"]
        }


class TestHealthEndpoint:
    def test_health_check(self, client):
        res = client.get("/api/v1/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["service"] == "CyberPort Scanner API"
        assert data["version"] == "v1"
        assert data["status"] == "healthy"


class TestAPIAuthentication:
    def test_missing_api_key(self, client):
        res = client.get("/api/v1/stats")
        assert res.status_code == 401
        data = res.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "UNAUTHORIZED"

    def test_malformed_authorization_header(self, client):
        res = client.get("/api/v1/stats", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert res.status_code == 401
        data = res.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "UNAUTHORIZED"

    def test_empty_bearer_token(self, client):
        res = client.get("/api/v1/stats", headers={"Authorization": "Bearer "})
        assert res.status_code == 401
        data = res.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "UNAUTHORIZED"

    def test_invalid_api_key(self, client):
        res = client.get("/api/v1/stats", headers={"Authorization": "Bearer cps_live_invalid_key_hash_12345"})
        assert res.status_code == 401
        data = res.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "INVALID_API_KEY"

    def test_revoked_api_key(self, client, auth_user, app):
        with app.app_context():
            app.db.revoke_api_key(auth_user["key_id"], auth_user["user_id"])

        res = client.get("/api/v1/stats", headers={"Authorization": f"Bearer {auth_user['api_key']}"})
        assert res.status_code == 401
        data = res.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "REVOKED_API_KEY"

    def test_valid_bearer_auth(self, client, auth_headers):
        res = client.get("/api/v1/stats", headers=auth_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "stats" in data

    def test_x_api_key_header_fallback(self, client, auth_user):
        res = client.get("/api/v1/stats", headers={"X-API-Key": auth_user["api_key"]})
        assert res.status_code == 200
        assert res.get_json()["success"] is True


class TestAPIKeyLifecycle:
    def test_generate_api_key(self, client, auth_user, auth_headers):
        res = client.post("/api/v1/keys", headers=auth_headers, json={"name": "Automation Runner"})
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert "key" in data
        assert data["key"]["name"] == "Automation Runner"
        assert data["key"]["api_key"].startswith("cps_live_")
        assert "warning" in data
        assert "displayed only once" in data["warning"]

    def test_generate_api_key_default_name(self, client, auth_headers):
        res = client.post("/api/v1/keys", headers=auth_headers, json={})
        assert res.status_code == 201
        data = res.get_json()
        assert data["key"]["name"] == "Default Key"

    def test_generate_api_key_name_length_limit(self, client, auth_headers):
        long_name = "x" * 70
        res = client.post("/api/v1/keys", headers=auth_headers, json={"name": long_name})
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "INVALID_NAME"

    def test_list_api_keys_masks_secret(self, client, auth_headers):
        res = client.get("/api/v1/keys", headers=auth_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert len(data["keys"]) >= 1
        for k in data["keys"]:
            # Full raw key must NOT be present in list response
            assert "api_key" not in k
            assert "masked_key" in k
            assert "••••••••" in k["masked_key"]
            assert "key_hash" not in k  # hash not exposed in API

    def test_api_key_ownership_and_revocation(self, client, auth_user, second_user):
        # User 1 tries to revoke User 2's key
        res = client.delete(
            f"/api/v1/keys/{second_user['key_id']}",
            headers={"Authorization": f"Bearer {auth_user['api_key']}"}
        )
        assert res.status_code == 404
        assert res.get_json()["error"]["code"] == "KEY_NOT_FOUND"

        # User 1 revokes own key
        res_ok = client.delete(
            f"/api/v1/keys/{auth_user['key_id']}",
            headers={"Authorization": f"Bearer {auth_user['api_key']}"}
        )
        assert res_ok.status_code == 200
        assert res_ok.get_json()["success"] is True


class TestScanCreationAndValidation:
    def test_malformed_json_body(self, client, auth_headers):
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            data="not-json",
            content_type="application/json"
        )
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "MALFORMED_JSON"

    def test_missing_target(self, client, auth_headers):
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"start_port": 1, "end_port": 10}
        )
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "INVALID_TARGET"

    def test_invalid_target_characters(self, client, auth_headers):
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"target": "192.168.1.1; rm -rf /", "start_port": 1, "end_port": 10}
        )
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "INVALID_TARGET"

    def test_invalid_ipv4_octets(self, client, auth_headers):
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"target": "999.999.999.999", "start_port": 1, "end_port": 10}
        )
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "INVALID_TARGET"

    def test_non_integer_ports(self, client, auth_headers):
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"target": "127.0.0.1", "start_port": "abc", "end_port": 100}
        )
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "INVALID_PORTS"

    def test_reversed_port_range(self, client, auth_headers):
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"target": "127.0.0.1", "start_port": 100, "end_port": 10}
        )
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "INVALID_PORTS"

    def test_out_of_bounds_port(self, client, auth_headers):
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"target": "127.0.0.1", "start_port": 0, "end_port": 100}
        )
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "INVALID_PORTS"

    def test_port_range_too_large(self, client, auth_headers):
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"target": "127.0.0.1", "start_port": 1, "end_port": 2000}
        )
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "PORT_RANGE_TOO_LARGE"

    def test_public_target_rejected(self, client, auth_headers):
        # Default safety: PRIVATE_TARGETS_ONLY is True
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"target": "8.8.8.8", "start_port": 53, "end_port": 53}
        )
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "TARGET_NOT_ALLOWED"

    def test_unspecified_multicast_target_rejected(self, client, auth_headers):
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"target": "224.0.0.1", "start_port": 80, "end_port": 80}
        )
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "TARGET_NOT_ALLOWED"

    def test_successful_scan_creation(self, client, auth_headers):
        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"target": "127.0.0.1", "start_port": 80, "end_port": 82}
        )
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert "scan_id" in data
        assert data["status"] == "running"
        assert data["total_ports"] == 3
        assert data["target"] == "127.0.0.1"


class TestScanStatusHistoryAndIDOR:
    def test_get_scan_results(self, client, auth_user, auth_headers, app):
        with app.app_context():
            scan_id = app.db.create_scan(
                user_id=auth_user["user_id"],
                target="192.168.1.10",
                resolved_ip="192.168.1.10",
                start_port=20,
                end_port=25,
                total_ports_scanned=6,
                open_ports=[{"port": 22, "service": "SSH", "state": "open"}],
                duration_seconds=0.45,
                status="completed"
            )

        res = client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        scan = data["scan"]
        assert scan["id"] == scan_id
        assert scan["target"] == "192.168.1.10"
        assert scan["status"] == "completed"
        assert len(scan["open_ports"]) == 1
        assert scan["open_ports"][0]["port"] == 22
        assert scan["open_ports"][0]["service"] == "SSH"

    def test_get_nonexistent_scan(self, client, auth_headers):
        res = client.get("/api/v1/scans/99999", headers=auth_headers)
        assert res.status_code == 404
        assert res.get_json()["error"]["code"] == "SCAN_NOT_FOUND"

    def test_idor_protection_view_scan(self, client, auth_user, second_user, app):
        with app.app_context():
            # User 1 creates scan
            u1_scan_id = app.db.create_scan(
                user_id=auth_user["user_id"],
                target="10.0.0.5",
                resolved_ip="10.0.0.5",
                start_port=80,
                end_port=80,
                total_ports_scanned=1,
                open_ports=[],
                duration_seconds=0.1
            )

        # User 2 attempts to view User 1's scan
        res = client.get(
            f"/api/v1/scans/{u1_scan_id}",
            headers={"Authorization": f"Bearer {second_user['api_key']}"}
        )
        assert res.status_code == 404
        assert res.get_json()["error"]["code"] == "SCAN_NOT_FOUND"

    def test_idor_protection_delete_scan(self, client, auth_user, second_user, app):
        with app.app_context():
            u1_scan_id = app.db.create_scan(
                user_id=auth_user["user_id"],
                target="10.0.0.6",
                resolved_ip="10.0.0.6",
                start_port=80,
                end_port=80,
                total_ports_scanned=1,
                open_ports=[],
                duration_seconds=0.1
            )

        # User 2 attempts to delete User 1's scan
        res = client.delete(
            f"/api/v1/scans/{u1_scan_id}",
            headers={"Authorization": f"Bearer {second_user['api_key']}"}
        )
        assert res.status_code == 404
        assert res.get_json()["error"]["code"] == "SCAN_NOT_FOUND"

        # Verify scan still exists in database
        with app.app_context():
            assert app.db.get_scan(u1_scan_id, auth_user["user_id"]) is not None

    def test_delete_own_scan(self, client, auth_user, auth_headers, app):
        with app.app_context():
            scan_id = app.db.create_scan(
                user_id=auth_user["user_id"],
                target="10.0.0.7",
                resolved_ip="10.0.0.7",
                start_port=80,
                end_port=80,
                total_ports_scanned=1,
                open_ports=[],
                duration_seconds=0.1
            )

        del_res = client.delete(f"/api/v1/scans/{scan_id}", headers=auth_headers)
        assert del_res.status_code == 200
        assert del_res.get_json()["success"] is True

        # Ensure subsequent get returns 404
        get_res = client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
        assert get_res.status_code == 404

    def test_scan_history_pagination(self, client, auth_user, auth_headers, app):
        with app.app_context():
            for i in range(1, 26):
                app.db.create_scan(
                    user_id=auth_user["user_id"],
                    target=f"192.168.1.{i}",
                    resolved_ip=f"192.168.1.{i}",
                    start_port=80,
                    end_port=80,
                    total_ports_scanned=1,
                    open_ports=[],
                    duration_seconds=0.1
                )

        # Page 1, per_page 10
        res = client.get("/api/v1/scans?page=1&per_page=10", headers=auth_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert len(data["scans"]) == 10
        assert data["pagination"]["page"] == 1
        assert data["pagination"]["per_page"] == 10
        assert data["pagination"]["total_items"] == 25
        assert data["pagination"]["total_pages"] == 3
        assert data["pagination"]["has_next"] is True
        assert data["pagination"]["has_prev"] is False

        # Page 3
        res3 = client.get("/api/v1/scans?page=3&per_page=10", headers=auth_headers)
        assert res3.status_code == 200
        data3 = res3.get_json()
        assert len(data3["scans"]) == 5
        assert data3["pagination"]["has_next"] is False
        assert data3["pagination"]["has_prev"] is True


class TestStatsEndpoint:
    def test_user_statistics(self, client, auth_user, auth_headers, app):
        with app.app_context():
            app.db.create_scan(
                user_id=auth_user["user_id"],
                target="192.168.1.1",
                resolved_ip="192.168.1.1",
                start_port=80,
                end_port=82,
                total_ports_scanned=3,
                open_ports=[{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}],
                duration_seconds=0.5
            )

        res = client.get("/api/v1/stats", headers=auth_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["stats"]["total_scans"] >= 1
        assert data["stats"]["open_ports"] >= 2


class TestPortInformationEndpoint:
    def test_known_port_lookup(self, client, auth_headers):
        res = client.get("/api/v1/ports/443", headers=auth_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["port"] == 443
        assert data["protocol"] == "TCP"
        assert data["service"] == "HTTPS"
        assert "TLS" in data["description"] or "SSL" in data["description"]

    def test_ssh_port_lookup(self, client, auth_headers):
        res = client.get("/api/v1/ports/22", headers=auth_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["port"] == 22
        assert data["service"] == "SSH"

    def test_unindexed_port_lookup(self, client, auth_headers):
        res = client.get("/api/v1/ports/54321", headers=auth_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["port"] == 54321
        assert "Dynamic / Private Port" in data.get("category", "") or "Private" in data.get("description", "")

    def test_invalid_port_bounds(self, client, auth_headers):
        res_zero = client.get("/api/v1/ports/0", headers=auth_headers)
        assert res_zero.status_code == 400
        assert res_zero.get_json()["error"]["code"] == "INVALID_PORT"

        res_huge = client.get("/api/v1/ports/70000", headers=auth_headers)
        assert res_huge.status_code == 400
        assert res_huge.get_json()["error"]["code"] == "INVALID_PORT"

    def test_non_integer_port_lookup(self, client, auth_headers):
        res = client.get("/api/v1/ports/https", headers=auth_headers)
        assert res.status_code == 400
        assert res.get_json()["error"]["code"] == "INVALID_PORT"


class TestRateLimitingAndConcurrency:
    def test_concurrent_scan_limit(self, client, auth_user, auth_headers, app):
        # Insert ongoing scans in 'running' status up to limit (2 in base config, 5 in testing)
        with app.app_context():
            app.config["MAX_CONCURRENT_SCANS_PER_USER"] = 2
            app.db.create_scan(
                user_id=auth_user["user_id"], target="127.0.0.1", resolved_ip="127.0.0.1",
                start_port=1, end_port=10, total_ports_scanned=0, open_ports=[],
                duration_seconds=0.0, status="running"
            )
            app.db.create_scan(
                user_id=auth_user["user_id"], target="127.0.0.1", resolved_ip="127.0.0.1",
                start_port=11, end_port=20, total_ports_scanned=0, open_ports=[],
                duration_seconds=0.0, status="running"
            )

        res = client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json={"target": "127.0.0.1", "start_port": 21, "end_port": 30}
        )
        assert res.status_code == 429
        data = res.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "CONCURRENT_SCAN_LIMIT"


class TestOpenAPIAndDocsRoutes:
    def test_openapi_spec_structure(self, client):
        res = client.get("/api/v1/openapi.json")
        assert res.status_code == 200
        data = res.get_json()
        assert data["openapi"].startswith("3.0")
        assert "paths" in data
        assert "/scans" in data["paths"]
        assert "/health" in data["paths"]
        assert "/ports/{port}" in data["paths"]
        assert "/stats" in data["paths"]
        assert "/keys" in data["paths"]

    def test_docs_page_serves(self, client):
        res = client.get("/api/docs")
        assert res.status_code == 200
        assert b"Interactive API Explorer" in res.data
        assert b"openapi.json" in res.data
