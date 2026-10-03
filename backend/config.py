"""
config.py
---------
Central configuration for the CyberPort Scanner application.
Loads environment-specific settings and keeps secrets out of source code.
"""

import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class Config:
    """Base configuration shared across all environments."""

    # --- Core Flask settings ---
    SECRET_KEY = os.environ.get("SECRET_KEY")
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

    # --- Database ---
    # Production uses DATABASE_URL (PostgreSQL). Local / test fallback to DATABASE_PATH (SQLite).
    _raw_db_url = os.environ.get("DATABASE_URL")
    if _raw_db_url and _raw_db_url.startswith("postgres://"):
        _raw_db_url = _raw_db_url.replace("postgres://", "postgresql://", 1)
    DATABASE_URL = _raw_db_url
    DATABASE_PATH = DATABASE_URL or os.environ.get(
        "DATABASE_PATH", os.path.join(BASE_DIR, "database", "cyberport.db")
    )

    # --- Exports ---
    EXPORTS_DIR = os.path.join(BASE_DIR, "exports")

    # --- Scanner limits (safety / responsible-use guardrails) ---
    # These bounds exist to keep the tool usable for its intended purpose
    # (learning + authorized testing) and to prevent abuse of shared hosting.
    MAX_PORT_RANGE = 1024          # Max number of ports scannable in a single request
    MIN_PORT = 1
    MAX_PORT = 65535
    SOCKET_TIMEOUT = 0.6           # seconds, per-port connect timeout
    MAX_THREADS = 100              # concurrent worker threads for scanning
    # The public web UI is intentionally limited to local/lab networks.
    # Set this to False only for a separately authenticated deployment.
    PRIVATE_TARGETS_ONLY = os.environ.get("PRIVATE_TARGETS_ONLY", "true").lower() == "true"

    # --- Rate limiting ---
    RATE_LIMIT_DEFAULT = "60 per hour"
    RATE_LIMIT_SCAN = "10 per minute"

    # --- REST API settings ---
    RATE_LIMIT_API_DEFAULT = os.environ.get("RATE_LIMIT_API_DEFAULT", "60 per minute")
    RATE_LIMIT_API_SCAN = os.environ.get("RATE_LIMIT_API_SCAN", "10 per minute")
    MAX_CONCURRENT_SCANS_PER_USER = int(os.environ.get("MAX_CONCURRENT_SCANS_PER_USER", 2))

    # --- Pagination ---
    HISTORY_PAGE_SIZE = 10

    # --- Stale scan recovery ---
    # Scans remaining in 'running' status longer than this threshold (seconds)
    # are treated as abandoned/stale (e.g. following worker crash or restart)
    # and recovered to 'failed' so concurrent scan slots are not permanently blocked.
    try:
        _raw_stale_timeout = int(os.environ.get("SCAN_STALE_TIMEOUT_SECONDS", 300))
        SCAN_STALE_TIMEOUT_SECONDS = _raw_stale_timeout if _raw_stale_timeout > 0 else 300
    except (ValueError, TypeError):
        SCAN_STALE_TIMEOUT_SECONDS = 300


class DevelopmentConfig(Config):
    DEBUG = True
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-not-for-production")


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SECRET_KEY = "test-secret-key-for-testing-only"
    DATABASE_PATH = ":memory:"
    RATE_LIMIT_DEFAULT = "1000 per hour"
    RATE_LIMIT_SCAN = "1000 per minute"
    RATE_LIMIT_API_DEFAULT = "1000 per minute"
    RATE_LIMIT_API_SCAN = "1000 per minute"
    MAX_CONCURRENT_SCANS_PER_USER = 5
    SCAN_STALE_TIMEOUT_SECONDS = 300


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}

