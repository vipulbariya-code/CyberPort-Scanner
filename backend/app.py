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
import secrets
import hmac
import hashlib
from flask import Flask, request, session, jsonify, render_template, redirect, url_for, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from config import config_map, ProductionConfig
from models import Database
from routes import main_bp, api_bp
from api_v1 import api_v1_bp


def create_app(env=None):
    # WSGI deployments (e.g. Render) set FLASK_ENV=production. Local / test default to development.
    env = env or os.environ.get("FLASK_ENV")
    if not env:
        env = "development"
    app_config = config_map.get(env, config_map["default"])

    if env == "production" and not app_config.SECRET_KEY:
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
        SESSION_COOKIE_SECURE=not app.config.get("DEBUG", False),
    )

    # Enable reverse proxy support (Render/Gunicorn headers)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # --- Database ---
    app.db = Database(app_config.DATABASE_PATH)

    # --- CSRF Protection ---
    def get_csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)
        return session["_csrf_token"]

    @app.context_processor
    def inject_csrf():
        return dict(csrf_token=get_csrf_token)

    @app.before_request
    def check_csrf():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            # Allow skipping in test environments if specifically requested
            if app.config.get("TESTING") and app.config.get("WTF_CSRF_ENABLED") is False:
                return

            # REST API endpoints authenticated via Bearer token or X-API-Key are not subject to browser CSRF
            if request.path.startswith("/api/v1/"):
                auth_header = request.headers.get("Authorization", "").strip()
                x_api_key = request.headers.get("X-API-Key", "").strip()
                if auth_header.startswith("Bearer ") or x_api_key:
                    return

            expected = session.get("_csrf_token")
            # Fetch token from header (AJAX) or form data
            client_token = (
                request.headers.get("X-CSRF-Token")
                or request.headers.get("X-CSRFToken")
                or request.form.get("csrf_token")
            )
            if not client_token and request.is_json:
                data = request.get_json(silent=True) or {}
                client_token = data.get("csrf_token")

            if not expected or not client_token or not hmac.compare_digest(expected, client_token):
                if request.path.startswith("/api/v1/"):
                    return jsonify({
                        "success": False,
                        "error": {
                            "code": "CSRF_ERROR",
                            "message": "Invalid or missing CSRF token."
                        }
                    }), 403
                if request.path.startswith("/api/"):
                    return jsonify({"success": False, "error": "Invalid or missing CSRF token."}), 403
                flash("Your session or security token expired. Please try again.", "error")
                return redirect(request.referrer or url_for("main.home"))

    # --- Rate limiting key function ---
    def get_rate_limit_key():
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            tok = auth_header[7:].strip()
            if tok:
                return f"tok_{hashlib.sha256(tok.encode()).hexdigest()[:16]}"
        x_key = request.headers.get("X-API-Key", "").strip()
        if x_key:
            return f"tok_{hashlib.sha256(x_key.encode()).hexdigest()[:16]}"
        if session.get("user_id"):
            return f"user_{session['user_id']}"
        return get_remote_address()

    # --- Rate limiting (protects scanner endpoints from abuse) ---
    limiter = Limiter(
        get_rate_limit_key,
        app=app,
        default_limits=[app_config.RATE_LIMIT_DEFAULT],
        storage_uri="memory://",
    )
    limiter.limit(app_config.RATE_LIMIT_SCAN)(api_bp)
    limiter.limit(getattr(app_config, "RATE_LIMIT_API_DEFAULT", "60 per minute"))(api_v1_bp)

    # --- Blueprints ---
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(api_v1_bp)

    # --- Consistent Error Handlers ---
    def _v1_error(code, message, status_code):
        return jsonify({
            "success": False,
            "error": {
                "code": code,
                "message": message
            }
        }), status_code

    @app.errorhandler(400)
    def bad_request(e):
        if request.path.startswith("/api/v1/"):
            return _v1_error("BAD_REQUEST", getattr(e, "description", "Bad Request"), 400)
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": getattr(e, "description", "Bad Request")}), 400
        return render_template("404.html"), 400

    @app.errorhandler(401)
    def unauthorized(e):
        if request.path.startswith("/api/v1/"):
            return _v1_error("UNAUTHORIZED", getattr(e, "description", "Authentication required."), 401)
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Authentication required."}), 401
        flash("Please log in to continue.", "error")
        return redirect(url_for("main.login", next=request.path))

    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith("/api/v1/"):
            return _v1_error("FORBIDDEN", getattr(e, "description", "Forbidden"), 403)
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": getattr(e, "description", "Forbidden")}), 403
        flash("You do not have permission to access that resource.", "error")
        return redirect(url_for("main.home"))

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/v1/"):
            return _v1_error("NOT_FOUND", getattr(e, "description", "Resource not found."), 404)
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Resource not found."}), 404
        return render_template("404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        if request.path.startswith("/api/v1/"):
            return _v1_error("METHOD_NOT_ALLOWED", "Method not allowed for this endpoint.", 405)
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Method not allowed."}), 405
        return render_template("404.html"), 405

    @app.errorhandler(422)
    def unprocessable_entity(e):
        if request.path.startswith("/api/v1/"):
            return _v1_error("UNPROCESSABLE_ENTITY", getattr(e, "description", "Unprocessable entity."), 422)
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Unprocessable entity."}), 422
        return render_template("404.html"), 422

    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.path.startswith("/api/v1/"):
            return _v1_error("RATE_LIMIT_EXCEEDED", "Rate limit exceeded. Please wait before making more requests.", 429)
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Rate limit exceeded. Please slow down."}), 429
        flash("Too many requests. Please wait a moment before trying again.", "error")
        return redirect(request.referrer or url_for("main.home"))

    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith("/api/v1/"):
            return _v1_error("INTERNAL_SERVER_ERROR", "An internal server error occurred.", 500)
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "An internal server error occurred."}), 500
        return render_template("404.html"), 500

    # --- Security headers on every response ---
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Content Security Policy safe for all templates and external CDN assets
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

        if not app.config.get("DEBUG", False):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
