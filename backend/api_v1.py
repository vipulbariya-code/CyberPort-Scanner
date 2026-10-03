"""
api_v1.py
---------
REST API v1 blueprint for CyberPort Scanner.

Provides authenticated REST endpoints for:
- Health checking
- Authorized TCP port scanning
- Scan status and result polling
- User scan history with pagination
- Scan deletion (with strict IDOR prevention)
- User scan statistics
- Educational port information lookups
- Secure API key lifecycle management (generate, view masked, revoke)
- OpenAPI 3.0 specification
"""

import hashlib
import hmac
import threading
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, request, jsonify, current_app, g, session

from scanner import (
    PortScanner, validate_target, validate_port_range, resolve_target,
    validate_resolved_target, ValidationError
)
from ports_data import get_port_info

api_v1_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")

# Registry for active scan cancellations
ACTIVE_SCANNERS = {}
ACTIVE_LOCK = threading.Lock()


def register_active_scan(scan_id: int, scanner: PortScanner):
    with ACTIVE_LOCK:
        ACTIVE_SCANNERS[scan_id] = scanner


def unregister_active_scan(scan_id: int):
    with ACTIVE_LOCK:
        ACTIVE_SCANNERS.pop(scan_id, None)


def cancel_active_scan(scan_id: int):
    with ACTIVE_LOCK:
        scanner = ACTIVE_SCANNERS.pop(scan_id, None)
        if scanner:
            scanner.cancel()


def api_error(code: str, message: str, status_code: int = 400):
    """Return a consistent JSON error response."""
    return jsonify({
        "success": False,
        "error": {
            "code": code,
            "message": message
        }
    }), status_code


def _extract_api_key_from_request():
    """Extract raw API key from Authorization header or X-API-Key header."""
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header:
        if not auth_header.startswith("Bearer "):
            return None, "INVALID_FORMAT"
        token = auth_header[7:].strip()
        if not token:
            return None, "EMPTY_TOKEN"
        return token, None

    x_key = request.headers.get("X-API-Key", "").strip()
    if x_key:
        return x_key, None

    return None, "MISSING_KEY"


def api_key_required(view):
    """
    Decorator enforcing first-party API key authentication.
    Validates token presence, cryptographic hash match, and active revocation status.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        raw_key, err = _extract_api_key_from_request()
        if err == "MISSING_KEY":
            return api_error(
                "UNAUTHORIZED",
                "Missing API key. Provide via 'Authorization: Bearer <API_KEY>' header.",
                401
            )
        if err in ("INVALID_FORMAT", "EMPTY_TOKEN") or not raw_key:
            return api_error(
                "UNAUTHORIZED",
                "Invalid Authorization header format. Expected 'Bearer <API_KEY>'.",
                401
            )

        # Hash input key for secure constant-time database lookup
        computed_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        key_record = current_app.db.get_api_key_by_hash(computed_hash)

        if not key_record:
            return api_error("INVALID_API_KEY", "Invalid API key.", 401)

        if key_record.get("revoked_at") is not None:
            return api_error("REVOKED_API_KEY", "This API key has been revoked.", 401)

        # Timing-safe comparison defense-in-depth
        if not hmac.compare_digest(key_record["key_hash"], computed_hash):
            return api_error("INVALID_API_KEY", "Invalid API key.", 401)

        # Record activity
        try:
            current_app.db.touch_api_key(key_record["id"])
        except Exception:
            pass

        # Populate context for request duration
        g.api_key = key_record
        g.api_user = {
            "id": key_record["user_id"],
            "username": key_record["username"],
            "email": key_record["email"]
        }
        g.current_user = g.api_user

        return view(*args, **kwargs)
    return wrapped


def api_key_or_session_required(view):
    """
    Decorator allowing either Bearer API key or active authenticated browser session.
    Used for Developer API key management endpoints.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        raw_key, err = _extract_api_key_from_request()
        if raw_key and err is None:
            computed_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
            key_record = current_app.db.get_api_key_by_hash(computed_hash)
            if not key_record:
                return api_error("INVALID_API_KEY", "Invalid API key.", 401)
            if key_record.get("revoked_at") is not None:
                return api_error("REVOKED_API_KEY", "This API key has been revoked.", 401)
            if not hmac.compare_digest(key_record["key_hash"], computed_hash):
                return api_error("INVALID_API_KEY", "Invalid API key.", 401)

            try:
                current_app.db.touch_api_key(key_record["id"])
            except Exception:
                pass

            g.api_key = key_record
            g.api_user = {
                "id": key_record["user_id"],
                "username": key_record["username"],
                "email": key_record["email"]
            }
            g.current_user = g.api_user
            return view(*args, **kwargs)

        # Fallback to session authentication
        user_id = session.get("user_id")
        if user_id:
            g.api_user = {
                "id": user_id,
                "username": session.get("username", "")
            }
            g.current_user = g.api_user
            return view(*args, **kwargs)

        return api_error(
            "UNAUTHORIZED",
            "Authentication required. Provide an API key via 'Authorization: Bearer <API_KEY>' or log in.",
            401
        )
    return wrapped


def _run_v1_scan_worker(scan_id: int, app, target_ip: str, start_port: int, end_port: int, original_target: str, user_id: int):
    """Background thread executing port scan and recording results to DB."""
    with app.app_context():
        db = current_app.db
        cfg = current_app.config
        scanner = PortScanner(
            target_ip, start_port, end_port,
            timeout=cfg["SOCKET_TIMEOUT"], max_threads=cfg["MAX_THREADS"]
        )
        register_active_scan(scan_id, scanner)
        try:
            result = scanner.run()
            db.update_scan(
                scan_id,
                user_id=user_id,
                status="completed",
                total_ports_scanned=result["total_scanned"],
                open_ports=result["open_ports"],
                duration_seconds=result["duration_seconds"]
            )
        except Exception:
            db.update_scan(
                scan_id,
                user_id=user_id,
                status="failed",
                total_ports_scanned=0,
                open_ports=[],
                duration_seconds=0.0
            )
        finally:
            unregister_active_scan(scan_id)


# =====================================================================
# REST Endpoints
# =====================================================================

@api_v1_bp.route("/health", methods=["GET"])
def health():
    """Check API and system service status."""
    return jsonify({
        "success": True,
        "service": "CyberPort Scanner API",
        "version": "v1",
        "status": "healthy"
    })


@api_v1_bp.route("/scans", methods=["POST"])
@api_key_required
def create_scan():
    """Start an authorized network port scan."""
    if not request.is_json:
        return api_error("MALFORMED_JSON", "Request body must be valid JSON.", 400)
    data = request.get_json(silent=True)
    if data is None:
        return api_error("MALFORMED_JSON", "Request body must be valid JSON.", 400)

    cfg = current_app.config
    db = current_app.db
    user_id = g.api_user["id"]

    # Target validation
    raw_target = data.get("target")
    if not raw_target or not isinstance(raw_target, str) or not raw_target.strip():
        return api_error("INVALID_TARGET", "Target address is required.", 400)

    try:
        target = validate_target(raw_target)
    except ValidationError as e:
        return api_error("INVALID_TARGET", str(e), 400)

    # Port range validation
    start_port_raw = data.get("start_port")
    end_port_raw = data.get("end_port")
    if start_port_raw is None or end_port_raw is None:
        return api_error("INVALID_PORTS", "start_port and end_port are required.", 400)

    try:
        start_port, end_port = validate_port_range(
            start_port_raw, end_port_raw, max_range=cfg["MAX_PORT_RANGE"]
        )
    except ValidationError as e:
        err_msg = str(e)
        if "too large" in err_msg.lower():
            return api_error("PORT_RANGE_TOO_LARGE", err_msg, 400)
        return api_error("INVALID_PORTS", err_msg, 400)

    # DNS Target Resolution
    try:
        resolved_ip = resolve_target(target)
    except ValidationError as e:
        return api_error("RESOLUTION_FAILED", str(e), 400)

    # Safety Guardrail: Private / Localhost restriction
    try:
        validated_ip = validate_resolved_target(
            resolved_ip, private_only=cfg["PRIVATE_TARGETS_ONLY"]
        )
    except ValidationError as e:
        return api_error("TARGET_NOT_ALLOWED", str(e), 400)

    # Concurrency check
    stale_timeout = cfg.get("SCAN_STALE_TIMEOUT_SECONDS", 300)
    active_count = db.count_active_scans(user_id, timeout_seconds=stale_timeout)
    max_concurrent = cfg.get("MAX_CONCURRENT_SCANS_PER_USER", 2)
    if active_count >= max_concurrent:
        return api_error(
            "CONCURRENT_SCAN_LIMIT",
            f"Maximum concurrent scans limit reached ({max_concurrent}). Please wait for active scans to finish.",
            429
        )

    # Create scan row in database with initial running status
    scan_id = db.create_scan(
        user_id=user_id,
        target=target,
        resolved_ip=validated_ip,
        start_port=start_port,
        end_port=end_port,
        total_ports_scanned=0,
        open_ports=[],
        duration_seconds=0.0,
        status="running"
    )

    # Launch background scanning worker
    app_obj = current_app._get_current_object()
    thread = threading.Thread(
        target=_run_v1_scan_worker,
        args=(scan_id, app_obj, validated_ip, start_port, end_port, target, user_id),
        daemon=True
    )
    thread.start()

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "status": "running",
        "target": target,
        "resolved_ip": validated_ip,
        "start_port": start_port,
        "end_port": end_port,
        "total_ports": end_port - start_port + 1,
        "created_at": datetime.now(timezone.utc).isoformat()
    }), 201


@api_v1_bp.route("/scans/<scan_id>", methods=["GET"])
@api_key_required
def get_scan(scan_id):
    """Retrieve scan status and discovered open ports by scan ID."""
    try:
        s_id = int(scan_id)
    except (ValueError, TypeError):
        return api_error("SCAN_NOT_FOUND", "Scan not found.", 404)

    db = current_app.db
    user_id = g.api_user["id"]
    stale_timeout = current_app.config.get("SCAN_STALE_TIMEOUT_SECONDS", 300)
    scan = db.get_scan(s_id, user_id, timeout_seconds=stale_timeout)
    if not scan:
        return api_error("SCAN_NOT_FOUND", "Scan not found.", 404)

    return jsonify({
        "success": True,
        "scan": {
            "id": scan["id"],
            "target": scan["target"],
            "resolved_ip": scan["resolved_ip"],
            "start_port": scan["start_port"],
            "end_port": scan["end_port"],
            "status": scan["status"],
            "open_ports": scan["open_ports"],
            "total_ports_scanned": scan["total_ports_scanned"],
            "open_ports_count": scan["open_ports_count"],
            "closed_ports_count": scan["closed_ports_count"],
            "duration_seconds": scan["duration_seconds"],
            "created_at": scan["created_at"]
        }
    })


@api_v1_bp.route("/scans", methods=["GET"])
@api_key_required
def list_scans():
    """Retrieve authenticated user's scan history with pagination."""
    try:
        page = int(request.args.get("page", 1))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = int(request.args.get("per_page", 20))
    except (ValueError, TypeError):
        per_page = 20

    page = max(1, page)
    per_page = min(max(1, per_page), 100)
    user_id = g.api_user["id"]
    db = current_app.db
    stale_timeout = current_app.config.get("SCAN_STALE_TIMEOUT_SECONDS", 300)

    result = db.list_scans(user_id, page=page, page_size=per_page, timeout_seconds=stale_timeout)
    scans_list = []
    for s in result["items"]:
        scans_list.append({
            "id": s["id"],
            "target": s["target"],
            "resolved_ip": s["resolved_ip"],
            "start_port": s["start_port"],
            "end_port": s["end_port"],
            "status": s["status"],
            "open_ports_count": s["open_ports_count"],
            "closed_ports_count": s["closed_ports_count"],
            "open_ports": s["open_ports"],
            "duration_seconds": s["duration_seconds"],
            "created_at": s["created_at"]
        })

    return jsonify({
        "success": True,
        "scans": scans_list,
        "pagination": {
            "page": result["page"],
            "per_page": result["page_size"],
            "total_items": result["total"],
            "total_pages": result["total_pages"],
            "has_next": result["page"] < result["total_pages"],
            "has_prev": result["page"] > 1
        }
    })


@api_v1_bp.route("/scans/<scan_id>", methods=["DELETE"])
@api_key_required
def delete_scan(scan_id):
    """Delete a scan record belonging to the authenticated user."""
    try:
        s_id = int(scan_id)
    except (ValueError, TypeError):
        return api_error("SCAN_NOT_FOUND", "Scan not found.", 404)

    db = current_app.db
    user_id = g.api_user["id"]
    scan = db.get_scan(s_id, user_id)
    if not scan:
        return api_error("SCAN_NOT_FOUND", "Scan not found.", 404)

    cancel_active_scan(s_id)
    db.delete_scan(s_id, user_id)

    return jsonify({
        "success": True,
        "message": "Scan deleted successfully."
    })


@api_v1_bp.route("/stats", methods=["GET"])
@api_key_required
def get_stats():
    """Retrieve authenticated user's scan statistics."""
    db = current_app.db
    user_id = g.api_user["id"]
    data = db.get_dashboard_stats(user_id)
    return jsonify({
        "success": True,
        "stats": {
            "total_scans": data["total_scans"],
            "open_ports": data["total_open_ports"],
            "closed_ports": data["total_closed_ports"],
            "avg_duration": data["avg_duration"]
        }
    })


@api_v1_bp.route("/ports/<port>", methods=["GET"])
@api_key_required
def get_port_details(port):
    """Retrieve educational technical details for a specified port number."""
    try:
        port_num = int(port)
    except (ValueError, TypeError):
        return api_error("INVALID_PORT", "Port must be an integer between 1 and 65535.", 400)

    try:
        info = get_port_info(port_num)
    except ValueError as e:
        return api_error("INVALID_PORT", str(e), 400)

    return jsonify({
        "success": True,
        "port": info["port"],
        "protocol": info["protocol"],
        "service": info["service"],
        "description": info["description"]
    })


# =====================================================================
# API Key Lifecycle Endpoints
# =====================================================================

@api_v1_bp.route("/keys", methods=["GET"])
@api_key_or_session_required
def list_keys():
    """List all API keys belonging to the authenticated user (masked)."""
    db = current_app.db
    user_id = g.api_user["id"]
    keys = db.list_api_keys(user_id)
    return jsonify({
        "success": True,
        "keys": keys
    })


@api_v1_bp.route("/keys", methods=["POST"])
@api_key_or_session_required
def create_key():
    """Generate a new first-party API key."""
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "Default Key").strip()
    if not name:
        name = "Default Key"
    if len(name) > 64:
        return api_error("INVALID_NAME", "Key name must be 64 characters or fewer.", 400)

    db = current_app.db
    user_id = g.api_user["id"]
    key_info = db.create_api_key(user_id, name=name)

    return jsonify({
        "success": True,
        "key": {
            "id": key_info["id"],
            "name": key_info["name"],
            "api_key": key_info["api_key"],
            "masked_key": key_info["masked_key"],
            "key_prefix": key_info["key_prefix"],
            "created_at": key_info["created_at"]
        },
        "warning": "The full API key is displayed only once. Store it securely."
    }), 201


@api_v1_bp.route("/keys/<key_id>", methods=["DELETE"])
@api_key_or_session_required
def revoke_key(key_id):
    """Revoke an API key belonging to the authenticated user."""
    try:
        k_id = int(key_id)
    except (ValueError, TypeError):
        return api_error("KEY_NOT_FOUND", "API key not found.", 404)

    db = current_app.db
    user_id = g.api_user["id"]
    ok = db.revoke_api_key(k_id, user_id)
    if not ok:
        return api_error("KEY_NOT_FOUND", "API key not found or already revoked.", 404)

    return jsonify({
        "success": True,
        "message": "API key revoked successfully."
    })


# =====================================================================
# OpenAPI Specification
# =====================================================================

@api_v1_bp.route("/openapi.json", methods=["GET"])
def get_openapi_spec():
    """Return OpenAPI 3.0.3 specification for the CyberPort Scanner REST API."""
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "CyberPort Scanner REST API",
            "version": "1.0.0",
            "description": (
                "Official authenticated REST API for CyberPort Scanner. "
                "Enables programmatic TCP connect-scanning, status tracking, "
                "port reconnaissance, and statistics for authorized security testing and education."
            ),
            "contact": {
                "name": "Vipul Bariya",
                "url": "https://github.com/vipulbariya-code/CyberPort-Scanner"
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        "servers": [
            {
                "url": "/api/v1",
                "description": "Current Server (Relative)"
            },
            {
                "url": "https://cyberport-scanner.onrender.com/api/v1",
                "description": "Production Server"
            }
        ],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "API_KEY",
                    "description": "Enter your CyberPort API key starting with 'cps_live_'"
                }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "success": {"type": "boolean", "example": False},
                        "error": {
                            "type": "object",
                            "properties": {
                                "code": {"type": "string", "example": "INVALID_TARGET"},
                                "message": {"type": "string", "example": "Target address is required."}
                            }
                        }
                    }
                },
                "ScanCreateRequest": {
                    "type": "object",
                    "required": ["target", "start_port", "end_port"],
                    "properties": {
                        "target": {"type": "string", "example": "192.168.1.10", "description": "IPv4 address or hostname within private network/localhost"},
                        "start_port": {"type": "integer", "minimum": 1, "maximum": 65535, "example": 1},
                        "end_port": {"type": "integer", "minimum": 1, "maximum": 65535, "example": 100}
                    }
                }
            }
        },
        "paths": {
            "/health": {
                "get": {
                    "summary": "API Service Health",
                    "description": "Returns current health and service version.",
                    "responses": {
                        "200": {"description": "Service is healthy"}
                    }
                }
            },
            "/scans": {
                "post": {
                    "summary": "Start Port Scan",
                    "description": "Initiate an authorized background TCP port scan.",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanCreateRequest"}
                            }
                        }
                    },
                    "responses": {
                        "201": {"description": "Scan started"},
                        "400": {"description": "Validation error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                        "401": {"description": "Unauthorized"},
                        "429": {"description": "Rate limit or concurrent scan limit exceeded"}
                    }
                },
                "get": {
                    "summary": "List User Scans",
                    "description": "Returns authenticated user's scan history with pagination.",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
                        {"name": "per_page", "in": "query", "schema": {"type": "integer", "default": 20}}
                    ],
                    "responses": {
                        "200": {"description": "List of user scans"},
                        "401": {"description": "Unauthorized"}
                    }
                }
            },
            "/scans/{scan_id}": {
                "get": {
                    "summary": "Get Scan Results",
                    "description": "Retrieve scan status and discovered open ports by scan ID.",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"name": "scan_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "responses": {
                        "200": {"description": "Scan details"},
                        "401": {"description": "Unauthorized"},
                        "404": {"description": "Scan not found"}
                    }
                },
                "delete": {
                    "summary": "Delete Scan",
                    "description": "Delete a scan record belonging to authenticated user.",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"name": "scan_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "responses": {
                        "200": {"description": "Scan deleted"},
                        "401": {"description": "Unauthorized"},
                        "404": {"description": "Scan not found"}
                    }
                }
            },
            "/stats": {
                "get": {
                    "summary": "User Statistics",
                    "description": "Return authenticated user's scan count and open ports discovered.",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {"description": "User statistics"},
                        "401": {"description": "Unauthorized"}
                    }
                }
            },
            "/ports/{port}": {
                "get": {
                    "summary": "Educational Port Information",
                    "description": "Look up standardized protocol, service, and technical description for a given port.",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"name": "port", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "responses": {
                        "200": {"description": "Port educational information"},
                        "400": {"description": "Invalid port number"},
                        "401": {"description": "Unauthorized"}
                    }
                }
            },
            "/keys": {
                "get": {
                    "summary": "List API Keys",
                    "description": "List all active and revoked API keys belonging to the user.",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {"description": "List of masked API keys"},
                        "401": {"description": "Unauthorized"}
                    }
                },
                "post": {
                    "summary": "Generate API Key",
                    "description": "Generate a new first-party API key. Full key returned once.",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "201": {"description": "API key generated successfully"},
                        "401": {"description": "Unauthorized"}
                    }
                }
            },
            "/keys/{key_id}": {
                "delete": {
                    "summary": "Revoke API Key",
                    "description": "Revoke an existing API key.",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"name": "key_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "responses": {
                        "200": {"description": "API key revoked"},
                        "401": {"description": "Unauthorized"},
                        "404": {"description": "API key not found"}
                    }
                }
            }
        }
    }
    return jsonify(spec)
