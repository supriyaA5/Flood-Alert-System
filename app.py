"""
FloodWatch Community — Complete Flask Application
=================================================
Upgraded from the original CommunityFloodAlert project.
Preserves all existing data and features. Adds:
  - User registration, login, roles (resident / response_team / admin)
  - In-app messaging (inbox, sent, unread counts, replies)
  - Community alert broadcasts
  - SMS / email notification stubs (demo-safe)
  - Report status history
  - File uploads (photo attachments)
  - Admin panel
  - Rate-limited login
  - CSRF protection via Flask-WTF
"""

import os
import re
import math
import hashlib
import sqlite3
import secrets
import mimetypes
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, session, flash, abort, send_from_directory,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DB_NAME = "flood_reports.db"

# File upload config
UPLOAD_FOLDER = os.path.join("static", "uploads")
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Notification config (from env)
TWILIO_SID    = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN  = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM   = os.environ.get("TWILIO_PHONE_NUMBER", "")
SMTP_HOST     = os.environ.get("SMTP_HOST", "")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USERNAME", "")
SMTP_PASS     = os.environ.get("SMTP_PASSWORD", "")
MAIL_FROM     = os.environ.get("MAIL_FROM", "")
DEMO_MODE     = os.environ.get("DEMO_MODE", "true").lower() in ("1", "true", "yes")

# Login rate-limiting (simple in-memory dict — sufficient for demo)
_login_attempts: dict = {}  # ip -> [timestamps]
LOGIN_MAX_ATTEMPTS = 10
LOGIN_WINDOW_SECONDS = 300

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_db():
    """Create all tables and run safe incremental migrations."""
    conn = get_db()

    # ── reports (existing, preserve data) ──────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            location    TEXT    NOT NULL,
            issue       TEXT    NOT NULL,
            severity    TEXT    NOT NULL,
            created_at  TEXT    NOT NULL,
            latitude    REAL,
            longitude   REAL
        )
    """)

    # ── followups (existing) ────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS followups (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id   INTEGER NOT NULL,
            ip_hash     TEXT    NOT NULL,
            created_at  TEXT    NOT NULL,
            UNIQUE(report_id, ip_hash)
        )
    """)

    # ── users ───────────────────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'resident',
            full_name     TEXT,
            phone         TEXT,
            location_area TEXT,
            notify_inapp  INTEGER NOT NULL DEFAULT 1,
            notify_sms    INTEGER NOT NULL DEFAULT 0,
            notify_email  INTEGER NOT NULL DEFAULT 0,
            sms_consent   INTEGER NOT NULL DEFAULT 0,
            email_consent INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    NOT NULL,
            last_login    TEXT
        )
    """)

    # ── report_status_history ───────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS report_status_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id   INTEGER NOT NULL,
            old_status  TEXT,
            new_status  TEXT    NOT NULL,
            changed_by  INTEGER,
            note        TEXT,
            changed_at  TEXT    NOT NULL
        )
    """)

    # ── report_assignments ──────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS report_assignments (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id    INTEGER NOT NULL,
            assigned_to  INTEGER NOT NULL,
            assigned_by  INTEGER,
            assigned_at  TEXT NOT NULL,
            UNIQUE(report_id, assigned_to)
        )
    """)

    # ── report_notes (internal, responders only) ───────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS report_notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id   INTEGER NOT NULL,
            author_id   INTEGER NOT NULL,
            note        TEXT    NOT NULL,
            created_at  TEXT    NOT NULL
        )
    """)

    # ── messages ───────────────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id   INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            subject     TEXT    NOT NULL,
            body        TEXT    NOT NULL,
            report_id   INTEGER,
            parent_id   INTEGER,
            is_read     INTEGER NOT NULL DEFAULT 0,
            sent_at     TEXT    NOT NULL
        )
    """)

    # ── alerts ─────────────────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id       INTEGER NOT NULL,
            title           TEXT    NOT NULL,
            body            TEXT    NOT NULL,
            severity        TEXT    NOT NULL DEFAULT 'Information',
            affected_area   TEXT,
            report_id       INTEGER,
            recipient_group TEXT    NOT NULL DEFAULT 'all',
            sent_at         TEXT    NOT NULL
        )
    """)

    # ── alert_recipients ───────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_recipients (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id   INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            is_read    INTEGER NOT NULL DEFAULT 0,
            read_at    TEXT,
            UNIQUE(alert_id, user_id)
        )
    """)

    # ── notification_log ───────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notification_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id    INTEGER,
            message_id  INTEGER,
            user_id     INTEGER NOT NULL,
            channel     TEXT    NOT NULL,
            status      TEXT    NOT NULL,
            detail      TEXT,
            attempted_at TEXT   NOT NULL
        )
    """)

    # ── Safe migrations for existing tables ────────────────────────────────
    _safe_add_columns(conn, "reports", {
        "status":      "TEXT NOT NULL DEFAULT 'New'",
        "description": "TEXT",
        "reporter_name": "TEXT",
        "contact":     "TEXT",
        "photo_path":  "TEXT",
        "category":    "TEXT",
    })

    _safe_add_columns(conn, "followups", {
        "message": "TEXT",
    })

    # ── Indexes ─────────────────────────────────────────────────────────────
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS idx_reports_severity ON reports(severity)",
        "CREATE INDEX IF NOT EXISTS idx_reports_status   ON reports(status)",
        "CREATE INDEX IF NOT EXISTS idx_reports_created  ON reports(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, is_read)",
        "CREATE INDEX IF NOT EXISTS idx_alert_recipients_user ON alert_recipients(user_id, is_read)",
        "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
    ]:
        conn.execute(idx_sql)

    conn.commit()
    conn.close()


def _safe_add_columns(conn, table: str, columns: dict):
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for col, col_type in columns.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return dict(user) if user else None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please log in.", "warning")
                return redirect(url_for("login", next=request.path))
            if user["role"] not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def _check_login_rate(ip: str) -> bool:
    """Return True if the IP is within allowed attempts."""
    now = datetime.now().timestamp()
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        return False
    attempts.append(now)
    _login_attempts[ip] = attempts
    return True


def _clear_login_rate(ip: str):
    _login_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# Notification helpers (SMS / Email — demo-safe)
# ---------------------------------------------------------------------------

def send_sms_notification(to_phone: str, message: str, user_id: int,
                           alert_id=None, msg_id=None) -> dict:
    """
    Attempt SMS via Twilio if configured and not in demo mode.
    Always logs the attempt. Never claims success unless confirmed.
    """
    if DEMO_MODE or not all([TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM]):
        _log_notification(alert_id, msg_id, user_id, "sms",
                          "demo_skipped", "DEMO_MODE: SMS not sent")
        return {"sent": False, "reason": "DEMO_MODE or credentials not configured"}

    try:
        from twilio.rest import Client
        client = Client(TWILIO_SID, TWILIO_TOKEN)
        msg = client.messages.create(body=message, from_=TWILIO_FROM, to=to_phone)
        sid = msg.sid
        _log_notification(alert_id, msg_id, user_id, "sms", "sent", sid)
        return {"sent": True, "sid": sid}
    except Exception as exc:
        _log_notification(alert_id, msg_id, user_id, "sms", "error", str(exc))
        return {"sent": False, "reason": str(exc)}


def send_email_notification(to_email: str, subject: str, body: str,
                             user_id: int, alert_id=None, msg_id=None) -> dict:
    """
    Attempt email via SMTP if configured and not in demo mode.
    """
    if DEMO_MODE or not all([SMTP_HOST, SMTP_USER, SMTP_PASS, MAIL_FROM]):
        _log_notification(alert_id, msg_id, user_id, "email",
                          "demo_skipped", "DEMO_MODE: Email not sent")
        return {"sent": False, "reason": "DEMO_MODE or credentials not configured"}

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = MAIL_FROM
        msg["To"]      = to_email
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as srv:
            srv.starttls()
            srv.login(SMTP_USER, SMTP_PASS)
            srv.sendmail(MAIL_FROM, to_email, msg.as_string())
        _log_notification(alert_id, msg_id, user_id, "email", "sent", "OK")
        return {"sent": True}
    except Exception as exc:
        _log_notification(alert_id, msg_id, user_id, "email", "error", str(exc))
        return {"sent": False, "reason": str(exc)}


def _log_notification(alert_id, msg_id, user_id, channel, status, detail):
    conn = get_db()
    conn.execute(
        """INSERT INTO notification_log
           (alert_id, message_id, user_id, channel, status, detail, attempted_at)
           VALUES (?,?,?,?,?,?,?)""",
        (alert_id, msg_id, user_id, channel, status, detail,
         datetime.now().strftime("%d-%m-%Y %I:%M %p")),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Risk assessment (unchanged from original, kept transparent)
# ---------------------------------------------------------------------------

def _haversine_km(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2
         + math.cos(math.radians(lat1))
         * math.cos(math.radians(lat2))
         * math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def assess_risk(reports):
    now = datetime.now()
    reasons = []
    cluster_warning = False

    active = [r for r in reports if r.get("status", "New") != "Resolved"]

    def parse_dt(s):
        for fmt in ("%d-%m-%Y %I:%M %p", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except Exception:
                pass
        return None

    recent = [r for r in active
              if (lambda dt: dt and (now - dt) <= timedelta(hours=48))(parse_dt(r.get("created_at", "")))]

    high_count     = sum(1 for r in active if r["severity"] in ("High", "Critical"))
    critical_count = sum(1 for r in active if r["severity"] == "Critical")
    medium_count   = sum(1 for r in active if r["severity"] == "Medium")
    recent_high    = sum(1 for r in recent if r["severity"] in ("High", "Critical"))

    geo_reports = [r for r in active
                   if r["severity"] in ("High", "Critical")
                   and r.get("latitude") is not None and r.get("longitude") is not None]
    for i in range(len(geo_reports)):
        for j in range(i + 1, len(geo_reports)):
            dist = _haversine_km(geo_reports[i]["latitude"], geo_reports[i]["longitude"],
                                  geo_reports[j]["latitude"], geo_reports[j]["longitude"])
            if dist <= 10:
                cluster_warning = True
                break
        if cluster_warning:
            break

    if critical_count >= 1 or recent_high >= 2 or (high_count >= 3) or cluster_warning:
        level = "Danger"
        if critical_count >= 1:
            reasons.append(f"{critical_count} critical-severity report(s) currently active.")
        if recent_high >= 2:
            reasons.append(f"{recent_high} high/critical reports submitted within the last 48 hours.")
        if cluster_warning:
            reasons.append("Multiple high-severity reports are geographically clustered (within 10 km).")
        if high_count >= 3:
            reasons.append(f"{high_count} unresolved high/critical reports in the database.")
    elif high_count >= 1 or medium_count >= 2:
        level = "Warning"
        if high_count >= 1:
            reasons.append(f"{high_count} unresolved high-severity report(s) on record.")
        if medium_count >= 2:
            reasons.append(f"{medium_count} unresolved medium-severity reports found.")
    elif medium_count >= 1:
        level = "Caution"
        reasons.append(f"{medium_count} unresolved medium-severity report(s) noted.")
    else:
        level = "Normal"
        reasons.append("No significant unresolved reports at this time.")

    if not active:
        level = "Normal"
        reasons = ["No active reports in the system."]

    return {
        "level": level,
        "reasons": reasons,
        "cluster_warning": cluster_warning,
        "active_count": len(active),
        "recent_count": len(recent),
    }


def compute_stats(reports):
    total      = len(reports)
    critical   = sum(1 for r in reports if r["severity"] == "Critical")
    high       = sum(1 for r in reports if r["severity"] == "High")
    med        = sum(1 for r in reports if r["severity"] == "Medium")
    low        = sum(1 for r in reports if r["severity"] == "Low")
    unresolved = sum(1 for r in reports if r.get("status", "New") != "Resolved")
    recent_count = 0
    now = datetime.now()
    for r in reports:
        for fmt in ("%d-%m-%Y %I:%M %p", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(r["created_at"], fmt)
                if (now - dt) <= timedelta(hours=48):
                    recent_count += 1
                break
            except Exception:
                pass
    return {
        "total": total, "critical": critical,
        "high": high, "medium": med, "low": low,
        "unresolved": unresolved, "recent": recent_count,
    }


def _attach_followup_counts(reports, conn):
    if not reports:
        return
    followup_rows = conn.execute(
        "SELECT report_id, COUNT(*) as cnt FROM followups GROUP BY report_id"
    ).fetchall()
    followup_map = {row["report_id"]: row["cnt"] for row in followup_rows}
    for r in reports:
        r["followup_count"] = followup_map.get(r["id"], 0)


def _unread_counts(user_id: int) -> dict:
    """Return unread message and alert counts for navbar badge."""
    if not user_id:
        return {"messages": 0, "alerts": 0}
    conn = get_db()
    msg_count = conn.execute(
        "SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND is_read = 0",
        (user_id,),
    ).fetchone()[0]
    alert_count = conn.execute(
        "SELECT COUNT(*) FROM alert_recipients WHERE user_id = ? AND is_read = 0",
        (user_id,),
    ).fetchone()[0]
    conn.close()
    return {"messages": msg_count, "alerts": alert_count}


# ---------------------------------------------------------------------------
# File upload helper
# ---------------------------------------------------------------------------

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------------------------------------------------------------------
# Template context processor — inject user + unread counts globally
# ---------------------------------------------------------------------------

@app.context_processor
def inject_globals():
    user = current_user()
    uid  = user["id"] if user else None
    uc   = _unread_counts(uid)
    return {
        "current_user": user,
        "unread_messages": uc["messages"],
        "unread_alerts": uc["alerts"],
        "demo_mode": DEMO_MODE,
    }


# ---------------------------------------------------------------------------
# ── AUTH ROUTES ─────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if not _check_login_rate(ip):
            flash("Too many login attempts. Please wait a few minutes.", "error")
            return render_template("auth/login.html", active_page="login")

        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("auth/login.html", active_page="login")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (username, username),
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            _clear_login_rate(ip)
            session["user_id"] = user["id"]
            session.permanent = True
            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.now().strftime("%d-%m-%Y %I:%M %p"), user["id"]),
            )
            conn.commit()
            conn.close()
            flash(f"Welcome back, {user['full_name'] or user['username']}!", "success")
            return redirect(request.args.get("next") or url_for("home"))
        else:
            conn.close()
            flash("Invalid username or password.", "error")

    return render_template("auth/login.html", active_page="login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == "POST":
        username  = request.form.get("username", "").strip().lower()
        email     = request.form.get("email", "").strip().lower()
        password  = request.form.get("password", "")
        confirm   = request.form.get("confirm_password", "")
        full_name = request.form.get("full_name", "").strip()
        phone     = request.form.get("phone", "").strip()
        location_area = request.form.get("location_area", "").strip()

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not re.match(r"^[a-z0-9_]+$", username):
            errors.append("Username may only contain letters, numbers, and underscores.")
        if not email or "@" not in email:
            errors.append("A valid email address is required.")
        if not password or len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if phone and not re.match(r"^\+?[\d\s\-]{7,15}$", phone):
            errors.append("Phone number format is invalid.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("auth/register.html", active_page="register",
                                   form=request.form)

        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
        ).fetchone()
        if existing:
            conn.close()
            flash("Username or email already registered.", "error")
            return render_template("auth/register.html", active_page="register",
                                   form=request.form)

        pw_hash = generate_password_hash(password, method="pbkdf2:sha256")
        conn.execute(
            """INSERT INTO users (username, email, password_hash, role, full_name,
               phone, location_area, notify_inapp, created_at)
               VALUES (?,?,?,?,?,?,?,1,?)""",
            (username, email, pw_hash, "resident", full_name or username,
             phone or None, location_area or None,
             datetime.now().strftime("%d-%m-%Y %I:%M %p")),
        )
        conn.commit()
        uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        session["user_id"] = uid
        flash("Account created! Welcome to FloodWatch Community.", "success")
        return redirect(url_for("home"))

    return render_template("auth/register.html", active_page="register", form={})


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# ── PROFILE ────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()

    if request.method == "POST":
        full_name   = request.form.get("full_name", "").strip()
        phone       = request.form.get("phone", "").strip()
        location_area = request.form.get("location_area", "").strip()
        notify_inapp  = 1 if request.form.get("notify_inapp") else 0
        notify_sms    = 1 if request.form.get("notify_sms") else 0
        notify_email  = 1 if request.form.get("notify_email") else 0
        sms_consent   = 1 if request.form.get("sms_consent") else 0
        email_consent = 1 if request.form.get("email_consent") else 0

        if phone and not re.match(r"^\+?[\d\s\-]{7,15}$", phone):
            flash("Phone number format is invalid.", "error")
            return redirect(url_for("profile"))

        new_password = request.form.get("new_password", "")
        current_pw   = request.form.get("current_password", "")

        conn = get_db()
        if new_password:
            if len(new_password) < 8:
                flash("New password must be at least 8 characters.", "error")
                conn.close()
                return redirect(url_for("profile"))
            if not check_password_hash(user["password_hash"], current_pw):
                flash("Current password is incorrect.", "error")
                conn.close()
                return redirect(url_for("profile"))
            new_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                         (new_hash, user["id"]))

        conn.execute(
            """UPDATE users SET full_name=?, phone=?, location_area=?,
               notify_inapp=?, notify_sms=?, notify_email=?,
               sms_consent=?, email_consent=? WHERE id=?""",
            (full_name or user["username"], phone or None, location_area or None,
             notify_inapp, notify_sms, notify_email,
             sms_consent, email_consent, user["id"]),
        )
        conn.commit()
        conn.close()
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html", active_page="profile", user=user)


# ---------------------------------------------------------------------------
# ── DASHBOARD ───────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    conn = get_db()
    all_reports = [dict(r) for r in conn.execute(
        "SELECT * FROM reports ORDER BY id DESC"
    ).fetchall()]

    # Latest alerts (for dashboard)
    latest_alerts = [dict(r) for r in conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT 5"
    ).fetchall()]

    # Latest status updates
    recent_updates = [dict(r) for r in conn.execute(
        """SELECT rsh.*, r.location, r.severity FROM report_status_history rsh
           JOIN reports r ON r.id = rsh.report_id
           ORDER BY rsh.id DESC LIMIT 5"""
    ).fetchall()]

    conn.close()

    stats = compute_stats(all_reports)
    risk  = assess_risk(all_reports)

    return render_template(
        "index.html",
        stats=stats, risk=risk,
        latest_alerts=latest_alerts,
        recent_updates=recent_updates,
        active_page="dashboard",
    )


# ---------------------------------------------------------------------------
# ── MAP ─────────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/map")
def live_map():
    conn = get_db()
    all_reports  = [dict(r) for r in conn.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()]
    geo_reports  = [r for r in all_reports if r.get("latitude") and r.get("longitude")]
    conn.close()
    return render_template("map.html", all_reports=all_reports,
                           geo_reports=geo_reports, active_page="map")


# ---------------------------------------------------------------------------
# ── REPORT FLOOD ─────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/report-flood", methods=["GET"])
def report_page():
    return render_template("report.html", active_page="report")


@app.route("/report", methods=["POST"])
def submit_report():
    location      = request.form.get("location", "").strip()
    issue         = request.form.get("issue", "").strip()
    category      = request.form.get("category", issue).strip()
    severity      = request.form.get("severity", "")
    description   = request.form.get("description", "").strip()
    reporter_name = request.form.get("reporter_name", "").strip()
    contact       = request.form.get("contact", "").strip()
    lat_raw       = request.form.get("latitude", "").strip()
    lon_raw       = request.form.get("longitude", "").strip()

    errors = []
    if not location or len(location) < 3:
        errors.append("Location must be at least 3 characters.")
    if not issue:
        errors.append("Please select a problem type.")
    if severity not in ("Low", "Medium", "High", "Critical"):
        errors.append("Please select a valid severity level.")
    if len(description) > 1000:
        errors.append("Description must be 1000 characters or fewer.")

    latitude = longitude = None
    if lat_raw and lon_raw:
        try:
            latitude  = float(lat_raw)
            longitude = float(lon_raw)
            if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
                errors.append("Coordinates are out of valid range.")
                latitude = longitude = None
        except ValueError:
            errors.append("Invalid coordinate format.")
            latitude = longitude = None

    # Photo upload
    photo_path = None
    if "photo" in request.files:
        f = request.files["photo"]
        if f and f.filename:
            if allowed_file(f.filename):
                filename = secure_filename(f.filename)
                unique_name = f"{secrets.token_hex(8)}_{filename}"
                save_path = os.path.join(UPLOAD_FOLDER, unique_name)
                try:
                    f.save(save_path)
                    photo_path = unique_name
                except Exception:
                    errors.append("Photo could not be saved.")
            else:
                errors.append("Photo must be a JPG, PNG, GIF, or WEBP file.")

    if errors:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "errors": errors}), 400
        for e in errors:
            flash(e, "error")
        return redirect(url_for("report_page"))

    conn = get_db()
    conn.execute(
        """INSERT INTO reports
           (location, issue, category, severity, description, reporter_name,
            contact, created_at, latitude, longitude, status, photo_path)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (location, issue, category, severity, description, reporter_name or None,
         contact or None, datetime.now().strftime("%d-%m-%Y %I:%M %p"),
         latitude, longitude, "New", photo_path),
    )
    report_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        """INSERT INTO report_status_history
           (report_id, old_status, new_status, changed_by, note, changed_at)
           VALUES (?,?,?,?,?,?)""",
        (report_id, None, "New",
         session.get("user_id"),
         "Report created", datetime.now().strftime("%d-%m-%Y %I:%M %p")),
    )
    conn.commit()
    conn.close()

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": True,
                        "message": f"Report #{report_id} submitted successfully.",
                        "report_id": report_id})
    flash(f"✅ Report #{report_id} submitted successfully!", "success")
    return redirect(url_for("all_reports"))


# ---------------------------------------------------------------------------
# ── ALL REPORTS ──────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/reports")
def all_reports():
    conn = get_db()
    sev_filter    = request.args.get("severity", "")
    status_filter = request.args.get("status", "")
    search_query  = request.args.get("q", "").strip()

    query  = "SELECT * FROM reports WHERE 1=1"
    params = []

    if sev_filter in ("Low", "Medium", "High", "Critical"):
        query += " AND severity = ?"
        params.append(sev_filter)

    if status_filter in ("New", "Under Review", "In Progress", "Resolved"):
        query += " AND status = ?"
        params.append(status_filter)

    if search_query:
        query += " AND (location LIKE ? OR issue LIKE ? OR description LIKE ?)"
        like = f"%{search_query}%"
        params.extend([like, like, like])

    query += " ORDER BY id DESC"
    reports = [dict(r) for r in conn.execute(query, params).fetchall()]
    _attach_followup_counts(reports, conn)
    conn.close()

    return render_template(
        "reports.html", reports=reports,
        sev_filter=sev_filter, status_filter=status_filter,
        search_query=search_query, active_page="reports",
    )


# ---------------------------------------------------------------------------
# ── COMMUNITY RESPONSE ───────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/community")
def community_response():
    conn = get_db()
    all_rep = [dict(r) for r in conn.execute(
        "SELECT * FROM reports ORDER BY id DESC"
    ).fetchall()]
    _attach_followup_counts(all_rep, conn)

    unresolved   = [r for r in all_rep if r.get("status", "New") != "Resolved"]
    high_priority = [r for r in unresolved if r["severity"] in ("High", "Critical")]
    needs_followup = [r for r in unresolved if r.get("followup_count", 0) > 0]
    geo_unresolved = [r for r in unresolved if r.get("latitude") and r.get("longitude")]

    # Assignments (for logged-in response team)
    assignments = {}
    notes_by_report = {}
    user = current_user()
    if user and user["role"] in ("admin", "response_team"):
        rows = conn.execute(
            """SELECT ra.report_id, u.username, u.full_name
               FROM report_assignments ra
               JOIN users u ON u.id = ra.assigned_to"""
        ).fetchall()
        for row in rows:
            assignments.setdefault(row["report_id"], []).append(
                row["full_name"] or row["username"]
            )
        note_rows = conn.execute(
            """SELECT rn.report_id, rn.note, rn.created_at, u.username
               FROM report_notes rn JOIN users u ON u.id = rn.author_id
               ORDER BY rn.id DESC"""
        ).fetchall()
        for nr in note_rows:
            notes_by_report.setdefault(nr["report_id"], []).append(dict(nr))

    conn.close()
    return render_template(
        "community.html",
        unresolved=unresolved, high_priority=high_priority,
        needs_followup=needs_followup, geo_unresolved=geo_unresolved,
        geo_count=len(geo_unresolved),
        assignments=assignments, notes_by_report=notes_by_report,
        active_page="community",
    )


@app.route("/report/<int:rid>/notes", methods=["POST"])
@role_required("admin", "response_team")
def add_report_note(rid):
    note = request.form.get("note", "").strip()
    if not note:
        return jsonify({"success": False, "error": "Note cannot be empty."}), 400
    conn = get_db()
    if not conn.execute("SELECT id FROM reports WHERE id = ?", (rid,)).fetchone():
        conn.close()
        return jsonify({"success": False, "error": "Report not found."}), 404
    conn.execute(
        """INSERT INTO report_notes (report_id, author_id, note, created_at)
           VALUES (?,?,?,?)""",
        (rid, session["user_id"], note, datetime.now().strftime("%d-%m-%Y %I:%M %p")),
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# ── SAFETY GUIDE ─────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/safety")
def safety():
    return render_template("safety.html", active_page="safety")


# ---------------------------------------------------------------------------
# ── MESSAGES & ALERTS ────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/messages")
@login_required
def messages():
    user = current_user()
    uid  = user["id"]
    conn = get_db()

    inbox = [dict(r) for r in conn.execute(
        """SELECT m.*, u.username as sender_username, u.full_name as sender_name
           FROM messages m JOIN users u ON u.id = m.sender_id
           WHERE m.recipient_id = ?
           ORDER BY m.sent_at DESC""",
        (uid,),
    ).fetchall()]

    sent = [dict(r) for r in conn.execute(
        """SELECT m.*, u.username as rec_username, u.full_name as rec_name
           FROM messages m JOIN users u ON u.id = m.recipient_id
           WHERE m.sender_id = ?
           ORDER BY m.sent_at DESC""",
        (uid,),
    ).fetchall()]

    alerts_list = [dict(r) for r in conn.execute(
        """SELECT a.*, ar.is_read, ar.read_at, u.username as sender_username, u.full_name as sender_name
           FROM alerts a
           JOIN alert_recipients ar ON ar.alert_id = a.id AND ar.user_id = ?
           JOIN users u ON u.id = a.sender_id
           ORDER BY a.sent_at DESC""",
        (uid,),
    ).fetchall()]

    conn.close()
    return render_template(
        "messages.html",
        inbox=inbox, sent=sent, alerts_list=alerts_list,
        active_page="messages",
    )


@app.route("/messages/send", methods=["GET", "POST"])
@login_required
def send_message():
    user = current_user()
    conn = get_db()

    if request.method == "POST":
        recipient_id = request.form.get("recipient_id", "")
        subject      = request.form.get("subject", "").strip()
        body         = request.form.get("body", "").strip()
        report_id    = request.form.get("report_id", "") or None
        parent_id    = request.form.get("parent_id", "") or None

        errors = []
        if not subject:
            errors.append("Subject is required.")
        if not body:
            errors.append("Message body is required.")
        try:
            recipient_id = int(recipient_id)
        except (ValueError, TypeError):
            errors.append("Please select a recipient.")

        if errors:
            users_list = conn.execute(
                "SELECT id, username, full_name, role FROM users WHERE id != ? ORDER BY role, username",
                (user["id"],),
            ).fetchall()
            conn.close()
            return render_template("compose_message.html", errors=errors,
                                   users_list=users_list, active_page="messages",
                                   form=request.form)

        conn.execute(
            """INSERT INTO messages (sender_id, recipient_id, subject, body,
               report_id, parent_id, is_read, sent_at)
               VALUES (?,?,?,?,?,?,0,?)""",
            (user["id"], recipient_id, subject, body,
             int(report_id) if report_id else None,
             int(parent_id) if parent_id else None,
             datetime.now().strftime("%d-%m-%Y %I:%M %p")),
        )
        msg_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # External notifications
        recip = conn.execute("SELECT * FROM users WHERE id = ?", (recipient_id,)).fetchone()
        if recip:
            recip = dict(recip)
            notif_subject = f"[FloodWatch] New message: {subject}"
            notif_body    = f"You have a new message from {user['full_name'] or user['username']}:\n\n{body}"
            if recip.get("notify_sms") and recip.get("sms_consent") and recip.get("phone"):
                send_sms_notification(recip["phone"], notif_body[:160], recip["id"], msg_id=msg_id)
            if recip.get("notify_email") and recip.get("email_consent") and recip.get("email"):
                send_email_notification(recip["email"], notif_subject, notif_body,
                                        recip["id"], msg_id=msg_id)

        conn.commit()
        conn.close()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": True, "message": "Message sent."})
        flash("Message sent successfully.", "success")
        return redirect(url_for("messages"))

    users_list = conn.execute(
        "SELECT id, username, full_name, role FROM users WHERE id != ? ORDER BY role, username",
        (user["id"],),
    ).fetchall()
    conn.close()
    return render_template("compose_message.html", users_list=users_list,
                           active_page="messages", form={})


@app.route("/messages/<int:mid>")
@login_required
def view_message(mid):
    user = current_user()
    conn = get_db()
    msg = conn.execute(
        """SELECT m.*, u.username as sender_username, u.full_name as sender_name
           FROM messages m JOIN users u ON u.id = m.sender_id
           WHERE m.id = ? AND (m.recipient_id = ? OR m.sender_id = ?)""",
        (mid, user["id"], user["id"]),
    ).fetchone()
    if not msg:
        conn.close()
        abort(404)
    msg = dict(msg)

    if msg["recipient_id"] == user["id"] and not msg["is_read"]:
        conn.execute("UPDATE messages SET is_read = 1 WHERE id = ?", (mid,))
        conn.commit()

    # Thread (replies)
    thread = [dict(r) for r in conn.execute(
        """SELECT m.*, u.username as su, u.full_name as sn
           FROM messages m JOIN users u ON u.id = m.sender_id
           WHERE m.parent_id = ? ORDER BY m.sent_at ASC""",
        (mid,),
    ).fetchall()]

    conn.close()
    return render_template("view_message.html", msg=msg, thread=thread, active_page="messages")


@app.route("/messages/read/<int:mid>", methods=["POST"])
@login_required
def mark_message_read(mid):
    conn = get_db()
    conn.execute(
        "UPDATE messages SET is_read = 1 WHERE id = ? AND recipient_id = ?",
        (mid, session["user_id"]),
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# ── ALERTS (Admin broadcast) ─────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/alerts/compose", methods=["GET", "POST"])
@role_required("admin", "response_team")
def compose_alert():
    user = current_user()
    conn = get_db()

    if request.method == "POST":
        title        = request.form.get("title", "").strip()
        body         = request.form.get("body", "").strip()
        severity     = request.form.get("alert_severity", "Information")
        affected_area = request.form.get("affected_area", "").strip()
        report_id    = request.form.get("report_id", "") or None
        recip_group  = request.form.get("recipient_group", "all")

        errors = []
        if not title:
            errors.append("Alert title is required.")
        if not body:
            errors.append("Alert message body is required.")
        if severity not in ("Information", "Advisory", "Warning", "Emergency"):
            errors.append("Invalid severity level.")

        if errors:
            conn.close()
            return jsonify({"success": False, "errors": errors}), 400

        conn.execute(
            """INSERT INTO alerts (sender_id, title, body, severity, affected_area,
               report_id, recipient_group, sent_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (user["id"], title, body, severity, affected_area or None,
             int(report_id) if report_id else None, recip_group,
             datetime.now().strftime("%d-%m-%Y %I:%M %p")),
        )
        alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Determine recipients
        if recip_group == "all":
            recipients = conn.execute("SELECT * FROM users").fetchall()
        elif recip_group == "response_team":
            recipients = conn.execute(
                "SELECT * FROM users WHERE role IN ('response_team','admin')"
            ).fetchall()
        elif recip_group == "residents":
            recipients = conn.execute(
                "SELECT * FROM users WHERE role = 'resident'"
            ).fetchall()
        else:
            # Treat as individual user id
            try:
                rid_int = int(recip_group)
                recipients = conn.execute("SELECT * FROM users WHERE id = ?", (rid_int,)).fetchall()
            except ValueError:
                recipients = conn.execute("SELECT * FROM users").fetchall()

        delivered = 0
        for recip in recipients:
            recip = dict(recip)
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO alert_recipients (alert_id, user_id) VALUES (?,?)",
                    (alert_id, recip["id"]),
                )
                delivered += 1
            except Exception:
                pass

            # External notifications
            notif_msg = f"[FloodWatch ALERT - {severity}] {title}\n{body}"
            if recip.get("notify_sms") and recip.get("sms_consent") and recip.get("phone"):
                send_sms_notification(recip["phone"], notif_msg[:160], recip["id"], alert_id=alert_id)
            if recip.get("notify_email") and recip.get("email_consent") and recip.get("email"):
                send_email_notification(recip["email"], f"[FloodWatch] {title}", notif_msg,
                                        recip["id"], alert_id=alert_id)

        conn.commit()
        conn.close()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({
                "success": True,
                "message": f"Alert sent to {delivered} recipient(s).",
                "alert_id": alert_id, "delivered": delivered,
            })
        flash(f"✅ Alert sent to {delivered} recipient(s).", "success")
        return redirect(url_for("alert_history"))

    # GET
    reports_list = conn.execute(
        "SELECT id, location, severity FROM reports ORDER BY id DESC LIMIT 50"
    ).fetchall()
    users_list = conn.execute(
        "SELECT id, username, full_name, role FROM users ORDER BY role, username"
    ).fetchall()
    conn.close()
    return render_template("compose_alert.html", reports_list=reports_list,
                           users_list=users_list, active_page="messages")


@app.route("/alerts/history")
@role_required("admin", "response_team")
def alert_history():
    conn = get_db()
    alerts = [dict(r) for r in conn.execute(
        """SELECT a.*, u.username as sender_username, u.full_name as sender_name,
           (SELECT COUNT(*) FROM alert_recipients ar WHERE ar.alert_id = a.id) as recipient_count
           FROM alerts a JOIN users u ON u.id = a.sender_id
           ORDER BY a.id DESC"""
    ).fetchall()]
    conn.close()
    return render_template("alert_history.html", alerts=alerts, active_page="messages")


@app.route("/alerts/<int:aid>/read", methods=["POST"])
@login_required
def mark_alert_read(aid):
    conn = get_db()
    conn.execute(
        """UPDATE alert_recipients SET is_read = 1, read_at = ?
           WHERE alert_id = ? AND user_id = ?""",
        (datetime.now().strftime("%d-%m-%Y %I:%M %p"), aid, session["user_id"]),
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# ── ADMIN PANEL ──────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/admin")
@role_required("admin")
def admin_panel():
    conn = get_db()
    users     = [dict(r) for r in conn.execute("SELECT * FROM users ORDER BY id").fetchall()]
    all_rep   = [dict(r) for r in conn.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()]
    stats     = compute_stats(all_rep)
    risk      = assess_risk(all_rep)
    notif_log = [dict(r) for r in conn.execute(
        "SELECT * FROM notification_log ORDER BY id DESC LIMIT 50"
    ).fetchall()]
    conn.close()
    return render_template("admin/panel.html", users=users, all_reports=all_rep,
                           stats=stats, risk=risk, notif_log=notif_log,
                           active_page="admin")


@app.route("/admin/users/<int:uid>/role", methods=["POST"])
@role_required("admin")
def admin_set_role(uid):
    new_role = request.form.get("role", "")
    if new_role not in ("resident", "response_team", "admin"):
        return jsonify({"success": False, "error": "Invalid role."}), 400
    if uid == session.get("user_id"):
        return jsonify({"success": False, "error": "Cannot change your own role here."}), 400
    conn = get_db()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, uid))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_user(uid):
    if uid == session.get("user_id"):
        return jsonify({"success": False, "error": "Cannot delete yourself."}), 400
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/admin/setup", methods=["GET", "POST"])
def admin_setup():
    """First-run admin creation. Disabled once any admin exists."""
    conn = get_db()
    admin_exists = conn.execute(
        "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
    ).fetchone()
    if admin_exists:
        conn.close()
        flash("Administrator already exists. Use the login page.", "info")
        return redirect(url_for("login"))

    if request.method == "POST":
        username  = request.form.get("username", "").strip().lower()
        email     = request.form.get("email", "").strip().lower()
        password  = request.form.get("password", "")
        setup_key = request.form.get("setup_key", "")

        expected_key = os.environ.get("ADMIN_SETUP_KEY", "floodwatch-setup")
        if setup_key != expected_key:
            flash("Invalid setup key.", "error")
            conn.close()
            return render_template("admin/setup.html")

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not email or "@" not in email:
            errors.append("Valid email required.")
        if not password or len(password) < 8:
            errors.append("Password must be at least 8 characters.")

        if errors:
            for e in errors:
                flash(e, "error")
            conn.close()
            return render_template("admin/setup.html")

        pw_hash = generate_password_hash(password, method="pbkdf2:sha256")
        conn.execute(
            """INSERT INTO users (username, email, password_hash, role, full_name,
               notify_inapp, created_at)
               VALUES (?,?,?,'admin',?,1,?)""",
            (username, email, pw_hash, username,
             datetime.now().strftime("%d-%m-%Y %I:%M %p")),
        )
        conn.commit()
        uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        session["user_id"] = uid
        flash("Administrator account created. You are now logged in.", "success")
        return redirect(url_for("admin_panel"))

    conn.close()
    return render_template("admin/setup.html")


# ---------------------------------------------------------------------------
# ── FORM HANDLERS (POST) ─────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/update_status", methods=["POST"])
def update_status():
    report_id  = request.form.get("report_id", "")
    new_status = request.form.get("status", "")
    note       = request.form.get("note", "").strip()

    if new_status not in ("New", "Under Review", "In Progress", "Resolved"):
        return jsonify({"success": False, "error": "Invalid status."}), 400
    try:
        report_id = int(report_id)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid report ID."}), 400

    conn = get_db()
    old = conn.execute("SELECT status FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not old:
        conn.close()
        return jsonify({"success": False, "error": "Report not found."}), 404

    old_status = old["status"]
    conn.execute("UPDATE reports SET status = ? WHERE id = ?", (new_status, report_id))
    conn.execute(
        """INSERT INTO report_status_history
           (report_id, old_status, new_status, changed_by, note, changed_at)
           VALUES (?,?,?,?,?,?)""",
        (report_id, old_status, new_status, session.get("user_id"),
         note or None, datetime.now().strftime("%d-%m-%Y %I:%M %p")),
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/followup", methods=["POST"])
def followup():
    report_id = request.form.get("report_id", "")
    try:
        report_id = int(report_id)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid report ID."}), 400

    ip = request.remote_addr or "unknown"
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]

    conn = get_db()
    if not conn.execute("SELECT id FROM reports WHERE id = ?", (report_id,)).fetchone():
        conn.close()
        return jsonify({"success": False, "error": "Report not found."}), 404

    try:
        conn.execute(
            "INSERT INTO followups (report_id, ip_hash, created_at) VALUES (?,?,?)",
            (report_id, ip_hash, datetime.now().strftime("%d-%m-%Y %I:%M %p")),
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Follow-up flagged."})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "error": "You have already flagged this report."})


# ---------------------------------------------------------------------------
# ── JSON API ─────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    conn = get_db()
    all_reports = [dict(r) for r in conn.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()]
    conn.close()

    stats = compute_stats(all_reports)
    risk  = assess_risk(all_reports)

    now   = datetime.now()
    daily = {}
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).strftime("%d %b")
        daily[day] = 0
    for r in all_reports:
        for fmt in ("%d-%m-%Y %I:%M %p", "%Y-%m-%d %H:%M:%S"):
            try:
                dt  = datetime.strptime(r["created_at"], fmt)
                key = dt.strftime("%d %b")
                if key in daily:
                    daily[key] += 1
                break
            except Exception:
                pass

    return jsonify({
        "stats": stats, "risk": risk,
        "daily_trend": {"labels": list(daily.keys()), "data": list(daily.values())},
    })


@app.route("/api/reports/geo")
def api_reports_geo():
    """GeoJSON-style endpoint for map markers."""
    conn = get_db()
    reports = [dict(r) for r in conn.execute(
        "SELECT id, location, issue, severity, status, created_at, latitude, longitude "
        "FROM reports WHERE latitude IS NOT NULL AND longitude IS NOT NULL ORDER BY id DESC"
    ).fetchall()]
    conn.close()
    return jsonify(reports)


@app.route("/api/unread")
@login_required
def api_unread():
    uc = _unread_counts(session["user_id"])
    return jsonify(uc)


# ---------------------------------------------------------------------------
# Uploaded files
# ---------------------------------------------------------------------------

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(413)
def too_large(e):
    return jsonify({"success": False, "error": "File too large. Maximum is 5 MB."}), 413


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    initialize_db()
    app.run(debug=True)
