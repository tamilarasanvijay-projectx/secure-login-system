"""Secure Login System - Flask + SQLite.

Features:
  * Registration / login with hashed passwords (bcrypt; scrypt fallback if bcrypt is missing)
  * Input validation + parameterized SQL queries (SQL injection protection)
  * Session management with secure cookies and logout
  * CSRF protection, brute-force lockout
  * Optional Two-Factor Authentication (TOTP, works with Google Authenticator / Authy)
"""
import base64
import hmac
import os
import re
import secrets
import sqlite3
import struct
import time
from datetime import timedelta
from functools import wraps
from urllib.parse import quote

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:  # fallback so the app still runs; install bcrypt for the real thing
    bcrypt = None
    HAS_BCRYPT = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "users.db"))
SECRET_FILE = os.path.join(BASE_DIR, ".secret_key")

MAX_FAILED = 5            # failed logins before lockout
LOCK_SECONDS = 300        # lockout length


def load_secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(SECRET_FILE, 0o600)
    with open(SECRET_FILE) as f:
        return f.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",  # set 1 behind HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)


# ----------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT NOT NULL UNIQUE,
               email TEXT NOT NULL UNIQUE,
               password_hash TEXT NOT NULL,
               totp_secret TEXT,
               failed_attempts INTEGER NOT NULL DEFAULT 0,
               locked_until REAL NOT NULL DEFAULT 0,
               created_at REAL NOT NULL
           )"""
    )
    db.commit()
    db.close()


# --------------------------------------------------------- password hashing
def hash_password(password: str) -> str:
    if HAS_BCRYPT:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    return generate_password_hash(password, method="scrypt")


def verify_password(password: str, stored: str) -> bool:
    try:
        if stored.startswith("$2"):
            return HAS_BCRYPT and bcrypt.checkpw(password.encode(), stored.encode())
        return check_password_hash(stored, password)
    except ValueError:
        return False


DUMMY_HASH = hash_password("dummy-password-for-timing")  # equalizes timing for unknown users


# --------------------------------------------------------------------- TOTP
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp_code(secret: str, for_time=None) -> str:
    key = base64.b32decode(secret)
    counter = int((for_time or time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
    offset = digest[-1] & 0x0F
    number = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**6
    return f"{number:06d}"


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        return False
    now = time.time()
    return any(hmac.compare_digest(totp_code(secret, now + drift * 30), code)
               for drift in (-1, 0, 1))


# --------------------------------------------------------------- validation
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


def validate_registration(username, email, password, confirm):
    errors = []
    if not USERNAME_RE.fullmatch(username):
        errors.append("Username must be 3-20 characters: letters, numbers, underscore.")
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        errors.append("Enter a valid email address.")
    if len(password) < 8 or len(password) > 64:
        errors.append("Password must be 8-64 characters.")
    else:
        if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password):
            errors.append("Password needs both upper and lower case letters.")
        if not re.search(r"\d", password):
            errors.append("Password needs at least one number.")
        if not re.search(r"[^A-Za-z0-9]", password):
            errors.append("Password needs at least one symbol.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


# --------------------------------------------------------------------- CSRF
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token.")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ----------------------------------------------------------------- sessions
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def start_session(user_id):
    session.clear()                      # prevents session fixation
    session.permanent = True
    session["user_id"] = user_id
    csrf_token()


# ------------------------------------------------------------------- routes
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        errors = validate_registration(username, email, password, confirm)
        if not errors:
            db = get_db()
            # Parameterized query: user input is never concatenated into SQL.
            exists = db.execute(
                "SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email)
            ).fetchone()
            if exists:
                errors.append("Username or email is already registered.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username, email=email), 400

        db.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username, email, hash_password(password), time.time()),
        )
        db.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", username="", email="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and user["locked_until"] > time.time():
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html"), 429

        ok = verify_password(password, user["password_hash"] if user else DUMMY_HASH)
        if not (user and ok):
            if user:
                attempts = user["failed_attempts"] + 1
                locked = time.time() + LOCK_SECONDS if attempts >= MAX_FAILED else 0
                db.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (0 if locked else attempts, locked, user["id"]),
                )
                db.commit()
            flash("Invalid username or password.", "error")   # generic: no user enumeration
            return render_template("login.html"), 401

        db.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?", (user["id"],))
        db.commit()

        if user["totp_secret"]:
            session.clear()
            session["pending_2fa"] = user["id"]
            session["pending_2fa_time"] = time.time()
            csrf_token()
            return redirect(url_for("verify_2fa"))

        start_session(user["id"])
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/2fa/verify", methods=["GET", "POST"])
def verify_2fa():
    uid = session.get("pending_2fa")
    if not uid or time.time() - session.get("pending_2fa_time", 0) > 300:
        session.clear()
        return redirect(url_for("login"))
    if request.method == "POST":
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if user and user["totp_secret"] and verify_totp(user["totp_secret"], request.form.get("code")):
            start_session(user["id"])
            return redirect(url_for("dashboard"))
        flash("Invalid authentication code.", "error")
        return render_template("verify_2fa.html"), 401
    return render_template("verify_2fa.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if user is None:
        session.clear()
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)


@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = current_user()
    if user["totp_secret"]:
        flash("Two-factor authentication is already enabled.", "success")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        secret = session.get("setup_secret")
        if secret and verify_totp(secret, request.form.get("code")):
            db = get_db()
            db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]))
            db.commit()
            session.pop("setup_secret", None)
            flash("Two-factor authentication enabled.", "success")
            return redirect(url_for("dashboard"))
        flash("That code was not correct. Try again.", "error")
    secret = session.setdefault("setup_secret", new_totp_secret())
    uri = f"otpauth://totp/SecureLogin:{quote(user['username'])}?secret={secret}&issuer=SecureLogin"
    return render_template("setup_2fa.html", secret=secret, uri=uri)


@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    user = current_user()
    if verify_password(request.form.get("password", ""), user["password_hash"]):
        db = get_db()
        db.execute("UPDATE users SET totp_secret = NULL WHERE id = ?", (user["id"],))
        db.commit()
        flash("Two-factor authentication disabled.", "success")
    else:
        flash("Wrong password; 2FA was not changed.", "error")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(debug=False, port=5000)
