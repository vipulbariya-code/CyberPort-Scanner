"""
routes.py
---------
All HTTP routes for CyberPort Scanner: page rendering + JSON API.

Scans run in background threads so the UI can poll for live progress
without blocking the Flask worker. Job state lives in an in-memory
dict (`SCAN_JOBS`) — sufficient for a single-instance educational tool;
a production multi-worker deployment would swap this for Redis.
"""

import csv
import io
import os
import threading
import uuid
import re
import sqlite3
from functools import wraps
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint, render_template, request, jsonify, send_file, current_app, abort,
    redirect, url_for, flash, session
)
from werkzeug.security import generate_password_hash, check_password_hash

from models import DatabaseIntegrityError

from scanner import (
    PortScanner, validate_target, validate_port_range, resolve_target,
    validate_resolved_target, ValidationError
)

main_bp = Blueprint("main", __name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")

# In-memory job registry: { job_id: {status, scanned, total, open_count, result, error} }
SCAN_JOBS = {}
JOBS_LOCK = threading.Lock()
JOB_TTL = timedelta(hours=1)


def page_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access the scanner.", "error")
            return redirect(url_for("main.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def api_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"success": False, "error": "Authentication required."}), 401
        return view(*args, **kwargs)
    return wrapped


def _prune_jobs():
    """Drop terminal jobs after a short retention period and cap memory usage."""
    now = datetime.now(timezone.utc)
    expired = [
        job_id for job_id, job in SCAN_JOBS.items()
        if job.get("finished_at") and now - job["finished_at"] > JOB_TTL
    ]
    for job_id in expired:
        SCAN_JOBS.pop(job_id, None)

    # Hard cap on in-memory jobs to avoid memory leaks
    if len(SCAN_JOBS) > 100:
        sorted_jobs = sorted(
            SCAN_JOBS.items(),
            key=lambda item: item[1].get("started_at", ""),
        )
        for old_id, _ in sorted_jobs[: len(SCAN_JOBS) - 100]:
            SCAN_JOBS.pop(old_id, None)


# =====================================================================
# Page routes
# =====================================================================
@main_bp.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@main_bp.route("/robots.txt")
def robots_txt():
    content = (
        "User-agent: *\n"
        "Allow: /\n"
        "Allow: /about\n"
        "Allow: /contact\n"
        "Allow: /api/docs\n"
        "Disallow: /developer\n"
        "Disallow: /dashboard\n"
        "Disallow: /scanner\n"
        "Disallow: /history\n"
        "Disallow: /logout\n"
        "Disallow: /api/v1/\n"
        "Disallow: /api/scan/\n"
        "Disallow: /api/history/\n"
        "Disallow: /api/keys\n"
        "\n"
        "Sitemap: https://cyberport-scanner.onrender.com/sitemap.xml\n"
    )
    return current_app.response_class(content, mimetype="text/plain")


@main_bp.route("/sitemap.xml")
def sitemap_xml():
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        '  <url><loc>https://cyberport-scanner.onrender.com/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n'
        '  <url><loc>https://cyberport-scanner.onrender.com/api/docs</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>\n'
        '  <url><loc>https://cyberport-scanner.onrender.com/about</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>\n'
        '  <url><loc>https://cyberport-scanner.onrender.com/contact</loc><changefreq>monthly</changefreq><priority>0.7</priority></url>\n'
        '</urlset>'
    )
    return current_app.response_class(xml, mimetype="application/xml")


@main_bp.route("/")
def home():
    return render_template("index.html")


@main_bp.route("/scanner")
@main_bp.route("/dashboard")
@page_login_required
def dashboard():
    return render_template("dashboard.html")


@main_bp.route("/history")
@page_login_required
def history():
    return render_template("history.html")


@main_bp.route("/developer")
@page_login_required
def developer():
    return render_template("developer.html")


@main_bp.route("/api/docs")
def api_docs():
    return render_template("api_docs.html")


@main_bp.route("/about")
def about():
    return render_template("about.html")


@main_bp.route("/contact")
def contact():
    return render_template("contact.html")


@main_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user_id"):
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash("Username must be 3–30 letters, numbers, or underscores.", "error")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif len(password) > 128:
            flash("Password must be 128 characters or fewer.", "error")
        elif password != confirm_password:
            flash("Passwords do not match.", "error")
        else:
            try:
                user_id = current_app.db.create_user(
                    username, email, generate_password_hash(password)
                )
            except (sqlite3.IntegrityError, DatabaseIntegrityError):
                flash("That username or email is already registered.", "error")
            else:
                session.clear()
                session.permanent = True
                session["user_id"] = user_id
                session["username"] = username
                flash("Account created. Welcome!", "success")
                return redirect(url_for("main.dashboard"))
    return render_template("signup.html")


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        identifier = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not identifier or not password:
            flash("Email/username and password are required.", "error")
            return render_template("login.html")
        if len(password) > 128:
            flash("Invalid email or password.", "error")
            return render_template("login.html")

        user = current_app.db.get_user_by_email_or_username(identifier)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "error")
        else:
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            next_url = request.args.get("next", "")
            # Prevent open redirects
            if (
                next_url
                and next_url.startswith("/")
                and not next_url.startswith("//")
                and not next_url.startswith("/\\")
            ):
                return redirect(next_url)
            return redirect(url_for("main.dashboard"))
    return render_template("login.html")


@main_bp.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("main.home"))


# =====================================================================
# API routes
# =====================================================================
def _run_scan_job(job_id, app, target_ip, start_port, end_port, original_target, user_id):
    """Executed in a background thread."""
    with app.app_context():
        db = current_app.db
        cfg = current_app.config

        def on_progress(scanned, total, open_count):
            with JOBS_LOCK:
                if job_id in SCAN_JOBS:
                    SCAN_JOBS[job_id].update(
                        scanned=scanned, total=total, open_count=open_count
                    )

        scanner = PortScanner(
            target_ip, start_port, end_port,
            timeout=cfg["SOCKET_TIMEOUT"], max_threads=cfg["MAX_THREADS"],
        )

        with JOBS_LOCK:
            SCAN_JOBS[job_id]["scanner_ref"] = scanner
            if SCAN_JOBS[job_id]["status"] == "cancelled":
                scanner.cancel()

        try:
            result = scanner.run(progress_callback=on_progress)
            with JOBS_LOCK:
                cancelled = SCAN_JOBS.get(job_id, {}).get("status") == "cancelled"
            if cancelled:
                return

            scan_id = db.create_scan(
                user_id=user_id, target=original_target,
                resolved_ip=target_ip,
                start_port=start_port,
                end_port=end_port,
                total_ports_scanned=result["total_scanned"],
                open_ports=result["open_ports"],
                duration_seconds=result["duration_seconds"],
                status="completed",
            )
            with JOBS_LOCK:
                SCAN_JOBS[job_id].update(
                    status="completed", result=result, db_scan_id=scan_id,
                    finished_at=datetime.now(timezone.utc)
                )
        except Exception as exc:  # pragma: no cover - defensive
            with JOBS_LOCK:
                SCAN_JOBS[job_id].update(
                    status="error", error=str(exc), finished_at=datetime.now(timezone.utc)
                )


@api_bp.route("/scan/start", methods=["POST"])
@api_login_required
def start_scan():
    data = request.get_json(silent=True) or {}
    cfg = current_app.config

    try:
        if data.get("authorized") is not True:
            raise ValidationError("Confirm that you are authorized to scan this target.")
        target = validate_target(data.get("target", ""))
        start_port, end_port = validate_port_range(
            data.get("start_port"), data.get("end_port"), max_range=cfg["MAX_PORT_RANGE"]
        )
        resolved_ip = validate_resolved_target(
            resolve_target(target), private_only=cfg["PRIVATE_TARGETS_ONLY"]
        )
    except ValidationError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    job_id = str(uuid.uuid4())
    with JOBS_LOCK:
        _prune_jobs()
        SCAN_JOBS[job_id] = {
            "status": "running",
            "scanned": 0,
            "total": end_port - start_port + 1,
            "open_count": 0,
            "target": target,
            "resolved_ip": resolved_ip,
            "user_id": session["user_id"],
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

    app = current_app._get_current_object()
    thread = threading.Thread(
        target=_run_scan_job,
        args=(job_id, app, resolved_ip, start_port, end_port, target, session["user_id"]),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "success": True,
        "job_id": job_id,
        "resolved_ip": resolved_ip,
        "total_ports": end_port - start_port + 1,
    })


@api_bp.route("/scan/status/<job_id>")
@api_login_required
def scan_status(job_id):
    with JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job or job.get("user_id") != session["user_id"]:
            return jsonify({"success": False, "error": "Job not found."}), 404

        payload = {
            "success": True,
            "status": job["status"],
            "scanned": job["scanned"],
            "total": job["total"],
            "open_count": job["open_count"],
            "target": job.get("target"),
            "resolved_ip": job.get("resolved_ip"),
        }
        if job["status"] == "completed":
            payload["result"] = job["result"]
            payload["db_scan_id"] = job.get("db_scan_id")
        elif job["status"] == "error":
            payload["error"] = job.get("error")

        return jsonify(payload)


@api_bp.route("/scan/cancel/<job_id>", methods=["POST"])
@api_login_required
def cancel_scan(job_id):
    with JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job or job.get("user_id") != session["user_id"]:
            return jsonify({"success": False, "error": "Job not found."}), 404
        scanner_ref = job.get("scanner_ref")
        if scanner_ref:
            scanner_ref.cancel()
        job.update(status="cancelled", finished_at=datetime.now(timezone.utc))
    return jsonify({"success": True})


@api_bp.route("/stats")
def stats():
    # If user is logged in, return their personalized dashboard stats;
    # otherwise, return anonymous platform-wide summary for home page charts.
    user_id = session.get("user_id")
    if user_id:
        data = current_app.db.get_dashboard_stats(user_id)
    else:
        data = current_app.db.get_public_stats()
    return jsonify({"success": True, "data": data})


@api_bp.route("/history")
@api_login_required
def get_history():
    page = request.args.get("page", 1, type=int)
    search = request.args.get("search", "").strip() or None
    page_size = current_app.config["HISTORY_PAGE_SIZE"]
    data = current_app.db.list_scans(session["user_id"], page=page, page_size=page_size, search=search)
    return jsonify({"success": True, "data": data})


@api_bp.route("/history/<int:scan_id>", methods=["DELETE"])
@api_login_required
def delete_history_item(scan_id):
    ok = current_app.db.delete_scan(scan_id, session["user_id"])
    if not ok:
        return jsonify({"success": False, "error": "Scan not found."}), 404
    return jsonify({"success": True})


@api_bp.route("/history", methods=["DELETE"])
@api_login_required
def clear_history():
    current_app.db.clear_history(session["user_id"])
    return jsonify({"success": True})


def _sanitize_csv_cell(value):
    """Mitigate CSV formula injection in spreadsheet applications."""
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


@api_bp.route("/history/<int:scan_id>/export")
@api_login_required
def export_csv(scan_id):
    scan = current_app.db.get_scan(scan_id, session["user_id"])
    if not scan:
        return jsonify({"success": False, "error": "Scan not found or access denied."}), 404

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Target", _sanitize_csv_cell(scan["target"])])
    writer.writerow(["Resolved IP", _sanitize_csv_cell(scan["resolved_ip"])])
    writer.writerow(["Scan Date", _sanitize_csv_cell(scan["created_at"])])
    writer.writerow(["Port Range", _sanitize_csv_cell(f"{scan['start_port']}-{scan['end_port']}")])
    writer.writerow(["Duration (s)", _sanitize_csv_cell(scan["duration_seconds"])])
    writer.writerow([])
    writer.writerow(["Port", "Service", "State"])
    for p in scan["open_ports"]:
        writer.writerow([
            _sanitize_csv_cell(p.get("port", "")),
            _sanitize_csv_cell(p.get("service", "")),
            _sanitize_csv_cell(p.get("state", "")),
        ])

    mem = io.BytesIO(buffer.getvalue().encode("utf-8"))
    safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", str(scan["target"]))[:32]
    filename = f"cyberport_scan_{scan_id}_{safe_target}.csv"
    return send_file(
        mem, mimetype="text/csv", as_attachment=True, download_name=filename
    )


@api_bp.route("/keys", methods=["GET"])
@api_login_required
def get_user_keys():
    keys = current_app.db.list_api_keys(session["user_id"])
    return jsonify({"success": True, "keys": keys})


@api_bp.route("/keys", methods=["POST"])
@api_login_required
def generate_user_key():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "Default Key").strip()[:64] or "Default Key"
    key_info = current_app.db.create_api_key(session["user_id"], name=name)
    return jsonify({
        "success": True,
        "key": key_info,
        "warning": "The full API key is displayed only once. Store it securely."
    }), 201


@api_bp.route("/keys/<int:key_id>", methods=["DELETE"])
@api_login_required
def revoke_user_key(key_id):
    ok = current_app.db.revoke_api_key(key_id, session["user_id"])
    if not ok:
        return jsonify({"success": False, "error": "API key not found or already revoked."}), 404
    return jsonify({"success": True, "message": "API key revoked successfully."})

