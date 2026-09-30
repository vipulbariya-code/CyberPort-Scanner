"""
test_loading_improvements.py
-----------------------------
Verification tests for loading screen improvements, /health endpoint,
and public/authenticated navigation.
"""

import pytest
from werkzeug.security import generate_password_hash


class TestLoadingAndHealthEnhancements:
    def test_health_endpoint_contract(self, client):
        """Verifies GET /health returns 200, fast JSON, no auth/csrf needed."""
        res = client.get("/health")
        assert res.status_code == 200
        assert res.headers["Content-Type"].startswith("application/json")
        data = res.get_json()
        assert data == {"status": "ok"}

    def test_all_public_pages_render(self, client):
        """Verifies all public pages return 200 with valid content."""
        routes = ["/", "/about", "/contact", "/api/docs", "/login", "/signup"]
        for route in routes:
            res = client.get(route)
            assert res.status_code == 200, f"Route {route} failed with {res.status_code}"
            assert len(res.data) > 0

    def test_loading_screen_safety_and_accessibility(self, client):
        """Verifies loading screen has accessibility attributes, noscript fallback, and safety timeout."""
        res = client.get("/about")
        assert res.status_code == 200
        html = res.get_data(as_text=True)

        # 1. Branding elements present
        assert 'id="loading-screen"' in html
        assert "CYBERPORT_SCANNER" in html
        assert "initializing secure session" in html
        assert 'aria-live="polite"' in html

        # 2. No-JS fallback style prevents trapped users when JS is disabled
        assert "<noscript>" in html
        assert "#loading-screen { display: none !important; }" in html

        # 3. Inline safety timer fallback prevents trapped users on network stalls
        assert "hideLoader" in html
        assert "setTimeout(hideLoader" in html

        # 4. Resource hints
        assert 'rel="preconnect" href="https://fonts.gstatic.com"' in html
        assert 'rel="preconnect" href="https://cdnjs.cloudflare.com"' in html

        # 5. Non-blocking script loading
        assert 'chart.umd.min.js" defer' in html

    def test_scanner_auth_and_execution_guardrails(self, client, app):
        """Verifies scanner functionality, authorization requirement, and lifecycle."""
        # Unauthenticated access rejected
        for route in ["/scanner", "/dashboard", "/history", "/developer"]:
            res = client.get(route)
            assert res.status_code == 302
            assert "/login" in res.headers["Location"]

        # Authenticate user
        with app.app_context():
            uid = app.db.create_user("guardrail_user", "guardrail@example.com", generate_password_hash("Password123!"))

        with client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["username"] = "guardrail_user"

        # Authenticated access succeeds
        for route in ["/scanner", "/dashboard", "/history", "/developer"]:
            res = client.get(route)
            assert res.status_code == 200

        # Scan launch validation: unauthorized target rejected
        bad_res = client.post("/api/scan/start", json={
            "target": "127.0.0.1", "start_port": 80, "end_port": 80, "authorized": False
        })
        assert bad_res.status_code == 400

        # Start authorized scan
        start_res = client.post("/api/scan/start", json={
            "target": "127.0.0.1", "start_port": 80, "end_port": 82, "authorized": True
        })
        assert start_res.status_code == 200
        job_data = start_res.get_json()
        assert job_data["success"] is True
        job_id = job_data["job_id"]

        # Poll scan status
        status_res = client.get(f"/api/scan/status/{job_id}")
        assert status_res.status_code == 200
        assert status_res.get_json()["success"] is True

        # Cancel scan
        cancel_res = client.post(f"/api/scan/cancel/{job_id}")
        assert cancel_res.status_code == 200
        assert cancel_res.get_json()["success"] is True

        # View history
        history_res = client.get("/api/history")
        assert history_res.status_code == 200
        assert history_res.get_json()["success"] is True
