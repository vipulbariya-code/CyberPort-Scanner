import io
import csv
import json
import xml.etree.ElementTree as ET
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

    def test_history_pagination_deletion_fallback_contract(self, client, app):
        with app.app_context():
            u = app.db.create_user("page_user", "page@test.com", "hash")
            scan_ids = []
            # Create 11 scans so page 1 has 10 and page 2 has 1
            for i in range(11):
                s = app.db.create_scan(
                    u, f"192.168.1.{i}", f"192.168.1.{i}", 80, 80, 1,
                    [{"port": 80, "service": "HTTP", "state": "open"}], 0.1
                )
                scan_ids.append(s)

        with client.session_transaction() as sess:
            sess["user_id"] = u
            sess["username"] = "page_user"

        # Verify initial 2 pages
        p1 = client.get("/api/history?page=1").get_json()["data"]
        p2 = client.get("/api/history?page=2").get_json()["data"]
        assert len(p1["items"]) == 10
        assert len(p2["items"]) == 1
        assert p1["total"] == 11
        assert p1["total_pages"] == 2
        assert p2["total_pages"] == 2

        # Delete the single item on page 2 (most recently created scan)
        last_scan_id = scan_ids[-1]
        del_res = client.delete(f"/api/history/{last_scan_id}")
        assert del_res.status_code == 200

        # Querying page 2 now returns 0 items and total_pages=1 (demonstrating empty page condition)
        p2_after = client.get("/api/history?page=2").get_json()["data"]
        assert len(p2_after["items"]) == 0
        assert p2_after["total"] == 10
        assert p2_after["total_pages"] == 1

        # Querying previous page 1 returns the remaining 10 items
        p1_after = client.get("/api/history?page=1").get_json()["data"]
        assert len(p1_after["items"]) == 10
        assert p1_after["total"] == 10
        assert p1_after["total_pages"] == 1

        # Verify static/js/history.js has the BUG-05 pagination recovery logic
        import os
        js_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "js", "history.js")
        with open(js_path, "r", encoding="utf-8") as f:
            js_code = f.read()

        assert "!data.items.length && currentPage > 1" in js_code
        assert "targetPage" in js_code
        assert "loadHistory(Math.max(1, targetPage))" in js_code


class TestStatsEndpoint:
    def test_stats_public_access(self, client):
        # Unauthenticated guest requesting /api/stats gets aggregate stats (no 401)
        res = client.get("/api/stats")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "total_scans" in data["data"]
        assert data["data"]["last_scan"] is None  # no leaking of user details


class TestScannedPortsUIAndResults:
    def test_dashboard_page_has_scanned_ports_ui(self, client, app):
        with app.app_context():
            uid = app.db.create_user("dash_user", "dash@test.com", "hash")
        with client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["username"] = "dash_user"

        res = client.get("/dashboard")
        assert res.status_code == 200
        html = res.data.decode("utf-8")

        assert "Scanned Ports" in html
        assert 'id="no-open-ports-alert"' in html
        assert 'id="scan-error-alert"' in html
        assert 'data-status-filter="all"' in html
        assert 'data-status-filter="open"' in html
        assert 'data-status-filter="closed"' in html
        assert 'data-status-filter="filtered"' in html
        assert "Status" in html
        assert "Service" in html
        assert 'id="summary-scanned"' in html

    def test_scan_job_completion_returns_scanned_ports(self, client, app):
        import time
        with app.app_context():
            uid = app.db.create_user("scan_res_user", "scanres@test.com", "hash")
        with client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["username"] = "scan_res_user"

        res = client.post("/api/scan/start", json={
            "target": "127.0.0.1", "start_port": 65530, "end_port": 65532, "authorized": True
        })
        assert res.status_code == 200
        job_id = res.get_json()["job_id"]

        # Wait for scan job to complete
        for _ in range(30):
            time.sleep(0.1)
            status_res = client.get(f"/api/scan/status/{job_id}")
            assert status_res.status_code == 200
            data = status_res.get_json()
            if data.get("status") == "completed":
                break

        assert data["status"] == "completed"
        result = data.get("result", {})
        assert "scanned_ports" in result
        assert len(result["scanned_ports"]) == 3
        ports = [p["port"] for p in result["scanned_ports"]]
        assert ports == [65530, 65531, 65532]
        for p in result["scanned_ports"]:
            assert "port" in p
            assert "service" in p
            assert "status" in p
            assert p["status"] in ("OPEN", "CLOSED", "FILTERED", "ERROR")
            assert "state" in p


class TestSafeReferrerRedirects:
    """Regression tests for BUG-02: Safe redirect handling for Referer headers."""

    def test_csrf_redirect_with_no_referer(self, csrf_client):
        res = csrf_client.post("/login", data={"email": "test@example.com", "password": "pass"})
        assert res.status_code == 302
        assert res.headers["Location"] == "/"

    def test_csrf_redirect_with_same_origin_referer(self, csrf_client):
        # Full same-origin absolute URL
        res = csrf_client.post(
            "/login",
            data={"email": "test@example.com", "password": "pass"},
            headers={"Referer": "http://localhost/dashboard"},
        )
        assert res.status_code == 302
        assert res.headers["Location"] == "/dashboard"

        # Local relative path with query string
        res_rel = csrf_client.post(
            "/login",
            data={"email": "test@example.com", "password": "pass"},
            headers={"Referer": "/history?target=127.0.0.1"},
        )
        assert res_rel.status_code == 302
        assert res_rel.headers["Location"] == "/history?target=127.0.0.1"

    def test_csrf_redirect_with_external_https_referer(self, csrf_client):
        res = csrf_client.post(
            "/login",
            data={"email": "test@example.com", "password": "pass"},
            headers={"Referer": "https://evil.example/malicious"},
        )
        assert res.status_code == 302
        assert res.headers["Location"] == "/"
        assert "evil.example" not in res.headers["Location"]

    def test_csrf_redirect_with_external_http_referer(self, csrf_client):
        res = csrf_client.post(
            "/login",
            data={"email": "test@example.com", "password": "pass"},
            headers={"Referer": "http://evil.example/steal-session"},
        )
        assert res.status_code == 302
        assert res.headers["Location"] == "/"
        assert "evil.example" not in res.headers["Location"]

    def test_csrf_redirect_with_protocol_relative_referer(self, csrf_client):
        res = csrf_client.post(
            "/login",
            data={"email": "test@example.com", "password": "pass"},
            headers={"Referer": "//evil.example/exploit"},
        )
        assert res.status_code == 302
        assert res.headers["Location"] == "/"
        assert "evil.example" not in res.headers["Location"]

    def test_csrf_redirect_with_malformed_and_suspicious_referer(self, csrf_client):
        suspicious_referrers = [
            "/\\evil.example",
            "\\\\evil.example",
            "/%5cevil.example",
            "http://localhost@evil.example/test",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "http://evil.example:8080/dashboard",
            "https://evil.example.org",
        ]
        for ref in suspicious_referrers:
            res = csrf_client.post(
                "/login",
                data={"email": "test@example.com", "password": "pass"},
                headers={"Referer": ref},
            )
            assert res.status_code == 302
            assert res.headers["Location"] == "/", f"Failed to reject suspicious Referer: {ref}"

    def test_csrf_failure_returns_expected_status_and_message(self, csrf_client):
        # Browser request redirected with flash message
        res = csrf_client.post(
            "/login",
            data={"email": "test@example.com", "password": "pass"},
            follow_redirects=True,
        )
        assert res.status_code == 200
        assert b"security token expired" in res.data.lower()

        # API endpoint returns 403 JSON error
        api_res = csrf_client.post("/api/scan/start", json={"target": "127.0.0.1"})
        assert api_res.status_code == 403
        data = api_res.get_json()
        assert data["success"] is False
        assert "csrf" in data["error"].lower()

    def test_ratelimit_429_handler_safe_redirect(self, app):
        from flask import abort

        # Register a non-API test route that triggers a 429 error
        @app.route("/test-browser-ratelimit")
        def trigger_browser_ratelimit():
            abort(429)

        test_client = app.test_client()

        # 1. External Referer is rejected and redirected to fallback
        res_ext = test_client.get(
            "/test-browser-ratelimit",
            headers={"Referer": "https://evil.example/phish"},
        )
        assert res_ext.status_code == 302
        assert res_ext.headers["Location"] == "/"

        # 2. Same-origin Referer is safely allowed
        res_safe = test_client.get(
            "/test-browser-ratelimit",
            headers={"Referer": "http://localhost/dashboard"},
        )
        assert res_safe.status_code == 302
        assert res_safe.headers["Location"] == "/dashboard"

        # 3. No Referer falls back to "/"
        res_none = test_client.get("/test-browser-ratelimit")
        assert res_none.status_code == 302
        assert res_none.headers["Location"] == "/"

        # 4. Flashed message appears on destination page
        res_follow = test_client.get("/test-browser-ratelimit", follow_redirects=True)
        assert res_follow.status_code == 200
        assert b"too many requests" in res_follow.data.lower()

    def test_get_safe_redirect_target_helper(self, app):
        from app import get_safe_redirect_target

        with app.test_request_context("/", headers={"Host": "localhost:5000"}):
            # Safe relative paths
            assert get_safe_redirect_target("/dashboard") == "/dashboard"
            assert get_safe_redirect_target("/history?tab=recent") == "/history?tab=recent"
            assert get_safe_redirect_target("/developer") == "/developer"

            # Same-origin absolute URLs
            assert get_safe_redirect_target("http://localhost:5000/dashboard") == "/dashboard"
            assert get_safe_redirect_target("http://localhost:5000/history?p=1") == "/history?p=1"

            # Missing / empty
            assert get_safe_redirect_target(None) == "/"
            assert get_safe_redirect_target("") == "/"
            assert get_safe_redirect_target("   ") == "/"

            # External schemes and domains
            assert get_safe_redirect_target("https://evil.example") == "/"
            assert get_safe_redirect_target("http://evil.example/dashboard") == "/"
            assert get_safe_redirect_target("//evil.example") == "/"
            assert get_safe_redirect_target("http://evil.example:5000") == "/"

            # Evasions and attacks
            assert get_safe_redirect_target("/\\evil.example") == "/"
            assert get_safe_redirect_target("\\\\evil.example") == "/"
            assert get_safe_redirect_target("http://localhost:5000@evil.example") == "/"
            assert get_safe_redirect_target("javascript:alert(1)") == "/"
            assert get_safe_redirect_target("data:text/html,abc") == "/"
            assert get_safe_redirect_target("/dashboard\r\nLocation: http://evil.com") == "/"


class TestSitemapAndRobots:
    """Regression tests for BUG-04: protected /developer excluded from sitemap and disallowed in robots.txt."""

    def test_sitemap_excludes_protected_developer_route(self, client):
        res = client.get("/sitemap.xml")
        assert res.status_code == 200
        assert "application/xml" in res.headers.get("Content-Type", "")

        root = ET.fromstring(res.data)
        locs = [elem.text for elem in root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]

        # /developer is NOT present in the sitemap
        assert not any("/developer" in loc for loc in locs)

        # Public /api/docs remains present
        assert any("/api/docs" in loc for loc in locs)

        # Existing public sitemap URLs remain unchanged
        assert any(loc.endswith(".com/") for loc in locs)
        assert any("/about" in loc for loc in locs)
        assert any("/contact" in loc for loc in locs)
        assert len(locs) == 4

    def test_robots_txt_disallows_developer_and_preserves_public_docs(self, client):
        res = client.get("/robots.txt")
        assert res.status_code == 200
        assert "text/plain" in res.headers.get("Content-Type", "")
        content = res.get_data(as_text=True)

        # robots.txt contains the correct /developer disallow rule
        assert "Disallow: /developer\n" in content
        assert "Allow: /developer\n" not in content

        # robots.txt still contains the sitemap URL
        assert "Sitemap: https://cyberport-scanner.onrender.com/sitemap.xml" in content

        # robots.txt does NOT accidentally contain a broad Disallow: /api/
        assert "Disallow: /api/\n" not in content
        assert "Disallow: /api\n" not in content

        # Public routes explicitly allowed
        assert "Allow: /\n" in content
        assert "Allow: /about\n" in content
        assert "Allow: /contact\n" in content
        assert "Allow: /api/docs\n" in content

    def test_route_access_controls(self, client):
        # /developer itself remains protected and requires login
        dev_res = client.get("/developer")
        assert dev_res.status_code == 302
        assert "/login" in dev_res.headers.get("Location", "")

        # /api/docs remains publicly accessible
        docs_res = client.get("/api/docs")
        assert docs_res.status_code == 200
