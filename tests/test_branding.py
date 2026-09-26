"""
Tests for CyberPort Scanner branding assets, logo integration, and favicon endpoints.
"""

import os
import xml.etree.ElementTree as ET
from PIL import Image
import pytest


class TestBrandingAssets:
    """Verifies that all branding files exist, have proper dimensions, and valid formats."""

    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    IMAGES_DIR = os.path.join(BASE_DIR, "static", "images")

    EXPECTED_FILES = [
        "cyberport-symbol.svg",
        "cyberport-logo.svg",
        "favicon.svg",
        "favicon.ico",
        "favicon-16x16.png",
        "favicon-32x32.png",
        "apple-touch-icon.png",
        "cyberport-symbol.png",
        "cyberport-logo.png",
        "cyberport-og.png",
    ]

    def test_all_expected_assets_exist(self):
        for filename in self.EXPECTED_FILES:
            filepath = os.path.join(self.IMAGES_DIR, filename)
            assert os.path.exists(filepath), f"Missing brand asset: {filename}"
            assert os.path.getsize(filepath) > 0, f"Empty asset file: {filename}"

    def test_svg_validity(self):
        svg_files = ["cyberport-symbol.svg", "cyberport-logo.svg", "favicon.svg"]
        for filename in svg_files:
            filepath = os.path.join(self.IMAGES_DIR, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            # Verify valid XML structure
            root = ET.fromstring(content)
            assert root.tag.endswith("svg")
            assert "viewBox" in root.attrib

    def test_png_dimensions(self):
        expected_sizes = {
            "favicon-16x16.png": (16, 16),
            "favicon-32x32.png": (32, 32),
            "apple-touch-icon.png": (180, 180),
            "cyberport-symbol.png": (512, 512),
            "cyberport-logo.png": (1040, 240),
            "cyberport-og.png": (1200, 630),
        }
        for filename, (expected_w, expected_h) in expected_sizes.items():
            filepath = os.path.join(self.IMAGES_DIR, filename)
            with Image.open(filepath) as img:
                assert img.size == (expected_w, expected_h), f"{filename} dimensions {img.size} != {(expected_w, expected_h)}"

    def test_ico_validity(self):
        filepath = os.path.join(self.IMAGES_DIR, "favicon.ico")
        with Image.open(filepath) as img:
            assert img.format == "ICO"


class TestBrandingIntegration:
    """Verifies that templates reference the brand assets and routes serve them with 200 OK."""

    def test_base_template_references(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        assert "images/favicon.svg" in html
        assert "images/favicon-32x32.png" in html
        assert "images/favicon-16x16.png" in html
        assert "images/favicon.ico" in html
        assert "images/apple-touch-icon.png" in html
        assert "images/cyberport-og.png" in html
        assert "images/cyberport-symbol.svg" in html
        assert "brand-symbol" in html
        assert "brand-tag" in html

    def test_static_asset_serving(self, client):
        assets = [
            "/static/images/cyberport-symbol.svg",
            "/static/images/cyberport-logo.svg",
            "/static/images/favicon.svg",
            "/static/images/favicon.ico",
            "/static/images/favicon-32x32.png",
            "/static/images/apple-touch-icon.png",
            "/static/images/cyberport-og.png",
        ]
        for url in assets:
            resp = client.get(url)
            assert resp.status_code == 200, f"Failed to serve {url}"
            assert len(resp.data) > 0

    def test_auth_pages_show_brand_symbol(self, client):
        for path in ["/login", "/signup"]:
            resp = client.get(path)
            assert resp.status_code == 200
            html = resp.get_data(as_text=True)
            assert "auth-brand-symbol" in html
            assert "images/cyberport-symbol.svg" in html
