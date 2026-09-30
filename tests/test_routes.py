import io
import csv
import json
import pytest
from werkzeug.security import generate_password_hash


class TestPageRoutes:
    def test_public_pages(self, client):
        for route in ("/", "/about", "/contact", "/login", "/signup", "/api/docs"):
            res = client.get(route)
            assert res.status_code == 200

    def test_health_endpoint(self, client):
        res = client.get("/health")
        assert res.status_code == 200
        assert res.headers["Content-Type"].startswith("application/json")
        data = res.get_json()
        assert data == {"status": "ok"}

    def test_protected_pages_redirect_unauthenticated(self, client):
        for route in ("/dashboard", "/scanner", "/history", "/developer"):
            res = client.get(route)
            assert res.status_code == 302
            assert "/login" in res.headers["Location"]

    def test_authenticated_pages(self, client, app):
        with app.app_context():
            uid = app.db.create_user("auth_page_user", "auth_pages@example.com", generate_password_hash("Secret12345"))
        with client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["username"] = "auth_page_user"

        for route in ("/dashboard", "/scanner", "/history", "/developer"):
            res = client.get(route)
            assert res.status_code == 200

    def test_loading_screen_and_performance_elements(self, client):
        res = client.get("/login")
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        # Loading screen branding & structure
        assert 'id="loading-screen"' in html
        assert "CYBERPORT_SCANNER" in html
        assert "initializing secure session" in html
        # No-JS fallback
        assert "<noscript>" in html
        assert "#loading-screen { display: none !important; }" in html
        # Safe inline fallback timer
        assert "hideLoader" in html or "setTimeout" in html
        # Resource hints
        assert 'rel="preconnect" href="https://fonts.gstatic.com"' in html
        assert 'rel="preconnect" href="https://cdnjs.cloudflare.com"' in html
        # Non-blocking Chart.js
        assert 'chart.umd.min.js" defer' in html

    def test_404_error_page(self, client):
        res = client.get("/nonexistent-route-404")
        assert res.status_code == 404
        assert b"Not Found" in res.data

    def test_api_404_returns_json(self, client):
        res = client.get("/api/nonexistent-endpoint")
        assert res.status_code == 404
        data = res.get_json()
        assert data["success"] is False
        assert "not found" in data["error"].lower()


class TestSecurityHeaders:
    def test_headers_present(self, client):
        res = client.get("/")
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" in res.headers
        assert "Permissions-Policy" in res.headers


class TestAuthenticationAndSessions:
    def test_signup_validation(self, client):
        # Invalid username
        res = client.post("/signup", data={"username": "a", "email": "a@b.com", "password": "password123", "confirm_password": "password123"})
        assert b"Username must be 3" in res.data

        # Invalid email
        res = client.post("/signup", data={"username": "valid_user", "email": "bademail", "password": "password123", "confirm_password": "password123"})
        assert b"Enter a valid email" in res.data

        # Mismatched passwords
        res = client.post("/signup", data={"username": "valid_user", "email": "u@b.com", "password": "password123", "confirm_password": "password456"})
        assert b"Passwords do not match" in res.data

        # Short password
        res = client.post("/signup", data={"username": "valid_user", "email": "u@b.com", "password": "short", "confirm_password": "short"})
        assert b"Password must be at least 8" in res.data

    def test_successful_signup_and_login_flow(self, client):
        # Signup
        res = client.post("/signup", data={
            "username": "tester",
            "email": "tester@example.com",
            "password": "Password123",
            "confirm_password": "Password123",
        }, follow_redirects=True)
        assert res.status_code == 200
        assert b"Account created" in res.data

        # Access dashboard now that session is set
        dash_res = client.get("/dashboard")
        assert dash_res.status_code == 200

        # Logout
        logout_res = client.post("/logout", follow_redirects=True)
        assert b"logged out" in logout_res.data

        # Verify logged out
        assert client.get("/dashboard").status_code == 302

        # Login with email
        login_res = client.post("/login", data={
            "email": "tester@example.com",
            "password": "Password123",
        }, follow_redirects=True)
        assert login_res.status_code == 200
        assert client.get("/dashboard").status_code == 200

        # Logout again
        client.post("/logout")

        # Login with username instead of email
        login_u_res = client.post("/login", data={
            "email": "tester",
            "password": "Password123",
        }, follow_redirects=True)
        assert login_u_res.status_code == 200
        assert client.get("/dashboard").status_code == 200

    def test_open_redirect_prevention(self, client, app):
        with app.app_context():
            app.db.create_user("redir_user", "redir@example.com", generate_password_hash("Password123"))

        # Attempt protocol-relative URL open redirect
        res = client.post("/login?next=//attacker.com", data={
            "email": "redir@example.com",
            "password": "Password123",
        })
        assert res.status_code == 302
        assert "//attacker.com" not in res.headers["Location"]
        assert "/dashboard" in res.headers["Location"]

        # Clear session for next attempt
        client.post("/logout")

        # Attempt backslash URL open redirect
        res2 = client.post("/login?next=/\\attacker.com", data={
            "email": "redir@example.com",
            "password": "Password123",
        })
        assert res2.status_code == 302
        assert "/\\attacker.com" not in res2.headers["Location"]
        assert "/dashboard" in res2.headers["Location"]

        # Clear session for next attempt
        client.post("/logout")

        # Legitimate relative path
        res3 = client.post("/login?next=/history", data={
            "email": "redir@example.com",
            "password": "Password123",
        })
        assert res3.status_code == 302
        assert res3.headers["Location"] == "/history"


class TestCSRFProtection:
    def test_csrf_rejection_when_missing(self, csrf_client):
        # POST without CSRF token
        res = csrf_client.post("/login", data={"email": "a@b.com", "password": "pass"})
        assert res.status_code == 302  # redirected with flash message

        # API POST without CSRF token
        api_res = csrf_client.post("/api/scan/start", json={"target": "127.0.0.1"})
        assert api_res.status_code == 403
        data = api_res.get_json()
        assert data["success"] is False
        assert "CSRF" in data["error"]

    def test_csrf_acceptance_with_valid_token(self, csrf_client):
        # Fetch page to generate token in session
        res = csrf_client.get("/login")
        assert res.status_code == 200

        with csrf_client.session_transaction() as sess:
            token = sess.get("_csrf_token")
            assert token is not None

        # Post with valid header token
        api_res = csrf_client.post(
            "/api/scan/start",
            headers={"X-CSRF-Token": token},
            json={"target": "127.0.0.1"},
        )
        # Should proceed to normal auth check (401 because not logged in), not CSRF 403!
        assert api_res.status_code == 401


class TestScanAPIAndAuthorization:
    def test_unauthenticated_api_rejection(self, client):
        assert client.post("/api/scan/start", json={}).status_code == 401
        assert client.get("/api/scan/status/fake-id").status_code == 401
        assert client.get("/api/history").status_code == 401
        assert client.delete("/api/history/1").status_code == 401

    def test_scan_start_validation(self, client, app):
        # Create and login user
        with app.app_context():
            uid = app.db.create_user("scanner_user", "scan@example.com", generate_password_hash("Pass12345"))
        with client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["username"] = "scanner_user"

        # Missing authorization check
        res = client.post("/api/scan/start", json={"target": "127.0.0.1", "start_port": 80, "end_port": 80})
        assert res.status_code == 400
        assert "authorized" in res.get_json()["error"].lower()

        # Public target rejected by default (PRIVATE_TARGETS_ONLY)
        res_pub = client.post("/api/scan/start", json={
            "target": "8.8.8.8", "start_port": 80, "end_port": 80, "authorized": True
        })
        assert res_pub.status_code == 400
        assert "private-network or localhost" in res_pub.get_json()["error"].lower()

        # Valid localhost target
        res_valid = client.post("/api/scan/start", json={
            "target": "127.0.0.1", "start_port": 80, "end_port": 82, "authorized": True
        })
        assert res_valid.status_code == 200
        data = res_valid.get_json()
        assert data["success"] is True
        assert "job_id" in data
        assert data["total_ports"] == 3

    def test_job_isolation(self, client, app):
        with app.app_context():
            u1 = app.db.create_user("user_a", "ua@example.com", "hash")
            u2 = app.db.create_user("user_b", "ub@example.com", "hash")

        # Start scan as user 1
        with client.session_transaction() as sess:
            sess["user_id"] = u1
            sess["username"] = "user_a"

        res = client.post("/api/scan/start", json={
            "target": "127.0.0.1", "start_port": 80, "end_port": 80, "authorized": True
        })
        job_id = res.get_json()["job_id"]

        # Switch to user 2
        with client.session_transaction() as sess:
            sess["user_id"] = u2
            sess["username"] = "user_b"

        # User 2 cannot access user 1's scan status
        status_res = client.get(f"/api/scan/status/{job_id}")
        assert status_res.status_code == 404

        # User 2 cannot cancel user 1's scan
        cancel_res = client.post(f"/api/scan/cancel/{job_id}")
        assert cancel_res.status_code == 404


class TestHistoryAndCSVExport:
    def test_history_authorization_and_export(self, client, app):
        with app.app_context():
            u1 = app.db.create_user("u1", "u1@test.com", "hash")
            u2 = app.db.create_user("u2", "u2@test.com", "hash")
            s1 = app.db.create_scan(
                u1, "192.168.1.5", "192.168.1.5", 80, 80, 1,
                [{"port": 80, "service": "HTTP", "state": "open"}], 0.5
            )

        # Log in as user 2
        with client.session_transaction() as sess:
            sess["user_id"] = u2
            sess["username"] = "u2"

        # User 2 cannot export User 1's scan
        export_fail = client.get(f"/api/history/{s1}/export")
        assert export_fail.status_code == 404

        # User 2 cannot delete User 1's scan
        del_fail = client.delete(f"/api/history/{s1}")
        assert del_fail.status_code == 404

        # Log in as owner (user 1)
        with client.session_transaction() as sess:
            sess["user_id"] = u1
            sess["username"] = "u1"

        # User 1 can export their scan
        export_ok = client.get(f"/api/history/{s1}/export")
        assert export_ok.status_code == 200
        assert export_ok.headers["Content-Type"].startswith("text/csv")
        csv_text = export_ok.data.decode("utf-8")
        assert "192.168.1.5" in csv_text
        assert "HTTP" in csv_text

    def test_csv_formula_injection_sanitization(self, client, app):
        with app.app_context():
            u = app.db.create_user("csv_u", "csv@test.com", "hash")
            # Injected target string starting with '='
            s = app.db.create_scan(
                u, "=cmd|'/C calc'!A0", "127.0.0.1", 80, 80, 1,
                [{"port": 80, "service": "+calc", "state": "-open"}], 0.1
            )

        with client.session_transaction() as sess:
            sess["user_id"] = u

        res = client.get(f"/api/history/{s}/export")
        assert res.status_code == 200
        content = res.data.decode("utf-8")
        # Ensure values starting with formula triggers are prefixed with single quote
        assert "'=cmd|'/C calc'!A0" in content
        assert "'+calc" in content
        assert "'-open" in content


class TestStatsEndpoint:
    def test_stats_public_access(self, client):
        # Unauthenticated guest requesting /api/stats gets aggregate stats (no 401)
        res = client.get("/api/stats")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "total_scans" in data["data"]
        assert data["data"]["last_scan"] is None  # no leaking of user details
