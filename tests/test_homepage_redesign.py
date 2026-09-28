"""
Tests for the redesigned CyberPort Scanner homepage / landing page.
Verifies all sections, buttons, badges, navigation links, and SEO elements.
"""

import pytest


class TestHomepageRedesign:
    def test_homepage_loads_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "Secure Network Reconnaissance, Built for" in html
        assert "Authorized Testing" in html
        assert "CyberPort Scanner helps security learners" in html

    def test_hero_badges_and_status(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert ("Authorized Security Tool" in html or "AUTHORIZED SECURITY TOOL" in html)
        assert ("Private Targets Only" in html or "PRIVATE TARGETS ONLY" in html)
        assert "Scanner Engine Online" in html

    def test_hero_ctas(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert ('href="/dashboard"' in html or 'href="/scanner"' in html)
        assert "Start Scanning" in html
        assert 'href="/api/docs"' in html
        assert "Explore API" in html

    def test_hero_scanner_mockup(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "192.168.1.10" in html
        assert "SCANNING" in html
        assert "SSH" in html
        assert "HTTP" in html
        assert "HTTPS" in html
        assert "MySQL" in html
        assert "CLOSED" in html
        assert "OPEN" in html

    def test_trust_strip(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "API Key Authentication" in html
        assert "Private Target Protection" in html
        assert "Real-Time Scanning" in html
        assert "Scan History" in html
        assert "CSV Export" in html
        assert "REST API v1" in html

    def test_feature_cards(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "Everything You Need for" in html
        assert "Real-Time Port Scanning" in html
        assert "Service Identification" in html
        assert "Scan History" in html
        assert "Secure REST API" in html
        assert "Developer API Keys" in html
        assert "CSV Export" in html

    def test_workflow_steps(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "01" in html
        assert "Enter Target" in html
        assert "02" in html
        assert "Scan" in html
        assert "03" in html
        assert "Analyze Results" in html

    def test_security_first_section(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "Security" in html
        assert "Comes First" in html
        assert "Private Target Restrictions" in html
        assert "RFC 1918 &amp; Loopback Protection" in html
        assert "API Key Authentication" in html
        assert "Rate Limiting &amp; Concurrency" in html
        assert "User-Level Access Control" in html
        assert "Consistent Error Handling" in html

    def test_developer_rest_api_section(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "Build With" in html
        assert "curl -X POST" in html
        assert "/api/v1/scans" in html
        assert "View API Documentation" in html
        assert "Developer Portal" in html
        assert 'href="/api/docs"' in html
        assert 'href="/developer"' in html

    def test_cli_visual(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "cyberport-scanner --target" in html
        assert "Scan completed" in html

    def test_final_cta(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "Ready to Explore Your Network?" in html
        assert "Start Scanning" in html
        assert "Explore API" in html

    def test_navigation_bar(self, client):
        resp = client.get("/")
        html = resp.get_data(as_text=True)
        assert "CyberPort" in html
        assert "Home" in html
        assert "Scanner" in html
        assert "History" in html
        assert "Developer API" in html
        assert "API Docs" in html
