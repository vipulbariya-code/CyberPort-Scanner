"""
app.py
------
Application factory + entry point for CyberPort Scanner.

Run locally with:
    python app.py

Educational / authorized-testing use only — see README.md and the
in-app disclaimer for full terms.
"""

import os
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import config_map, ProductionConfig
from models import Database
from routes import main_bp, api_bp


def create_app(env=None):
    # Direct local execution is developer-friendly; WSGI deployments default to
    # production and therefore still require an explicit production secret.
    default_env = "development" if __name__ == "__main__" else "production"
    env = env or os.environ.get("FLASK_ENV", default_env)
    app_config = config_map.get(env, config_map["default"])

    if app_config is ProductionConfig and not app_config.SECRET_KEY:
        raise RuntimeError("SECRET_KEY must be set when FLASK_ENV=production.")

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
    )
    app.config.from_object(app_config)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=not app.config["DEBUG"],
    )

    # --- Database ---
    app.db = Database(app_config.DATABASE_PATH)

    # --- Rate limiting (protects the scan endpoint from abuse) ---
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[app_config.RATE_LIMIT_DEFAULT],
        storage_uri="memory://",
    )
    limiter.limit(app_config.RATE_LIMIT_SCAN)(api_bp)

    # --- Blueprints ---
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    # --- Security headers on every response ---
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
