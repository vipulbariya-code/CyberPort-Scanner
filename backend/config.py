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
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-this-in-production")
    JSON_SORT_KEYS = False

    # --- Database ---
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "cyberport.db")

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

    # --- Rate limiting ---
    RATE_LIMIT_DEFAULT = "60 per hour"
    RATE_LIMIT_SCAN = "10 per minute"

    # --- Pagination ---
    HISTORY_PAGE_SIZE = 10


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
