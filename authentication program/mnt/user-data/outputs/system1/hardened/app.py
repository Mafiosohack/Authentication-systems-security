"""
SYSTEM 1 — Basic Password Auth + Sessions
HARDENED IMPLEMENTATION

Each fix references the vulnerability it closes (V1–V7).

  F1: bcrypt with salt (work factor 12) — replaces MD5
  F2: Flask-Limiter rate limiting — 10 attempts/minute/IP
  F3: Generic error message — no username enumeration possible
  F4: SECRET_KEY from environment variable
  F5: Cookie flags: HttpOnly, SameSite=Lax (Secure in production)
  F6: session.clear() before login — prevents session fixation
  F7: debug=False

  BONUS:
  F8: Account lockout (5 failures → 5-minute lockout)
  F9: Constant-time comparison (blocks timing-based enumeration)
 F10: Pre-computed dummy hash (uniform response time for missing users)
"""

import os
import time
import secrets
import threading

import bcrypt
from flask import Flask, request, session, redirect, url_for, render_template_string

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _LIMITER_AVAILABLE = True
except ImportError:
    _LIMITER_AVAILABLE = False
    print("[!] flask-limiter not installed — rate limiting disabled.")
    print("    Fix: pip install flask-limiter")

import sqlite3

app = Flask(__name__)

# ── F4: Secret key from environment, never hardcoded ──────────────
_SECRET_KEY = os.environ.get("SECRET_KEY")
if not _SECRET_KEY:
    _SECRET_KEY = secrets.token_hex(32)
    print("[!] SECRET_KEY not in environment — generated ephemeral key.")
    print("    Sessions will not survive a restart. Set SECRET_KEY in .env for production.")
app.secret_key = _SECRET_KEY

# ── F5: Session cookie security flags ─────────────────────────────
app.config["SESSION_COOKIE_HTTPONLY"] = True     # JS cannot read session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # Blocks cross-site POST requests
# app.config["SESSION_COOKIE_SECURE"] = True     # Enforce HTTPS in production

# ── F2: Rate limiting ──────────────────────────────────────────────
if _LIMITER_AVAILABLE:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per hour"],
        storage_uri="memory://"
    )
    # F2: 10 login attempts per minute per IP. Stacked on the /login view below.
    login_rate_limit = limiter.limit("10 per minute")
else:
    # Rate limiting unavailable — decorator becomes a transparent pass-through.
    def login_rate_limit(view):
        return view

# ── F8: Account lockout (in-memory; use Redis in production) ───────
_lock_store: dict = {}
_lock_mutex         = threading.Lock()
LOCKOUT_THRESHOLD   = 5
LOCKOUT_SECONDS     = 300   # 5 minutes

BCRYPT_WORK_FACTOR  = 12    # 2^12 rounds — ~250ms on modern hardware
DB_PATH             = "hardened_users.db"

# ── F10: Pre-computed dummy hash ───────────────────────────────────
# Used when username doesn't exist so bcrypt still runs.
# Ensures response time is identical whether user exists or not.
# Without this, an attacker can enumerate usernames by measuring timing:
#   "user not found" → returns in 0.001s
#   "wrong password" → returns in 0.250s (bcrypt)
_DUMMY_HASH = bcrypt.hashpw(b"dummy_timing_anchor", bcrypt.gensalt(rounds=BCRYPT_WORK_FACTOR))


LOGIN_TEMPLATE = """
<!DOCTYPE html><html>
<head><title>Secure Login</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:80px auto;padding:20px">
  <h2>Login</h2>
  {% if error %}<p style="color:red;font-weight:bold">{{ error }}</p>{% endif %}
  <form method="post" autocomplete="off">
    <label>Username</label><br>
    <input name="username" required style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Password</label><br>
    <input type="password" name="password" required style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <button type="submit" style="padding:8px 20px">Login</button>
  </form>
</body></html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html><html>
<head><title>Dashboard</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:80px auto;padding:20px">
  <h2>Welcome, {{ user }}!</h2>
  <p>Authenticated. Role: {{ role }}</p>
  <a href="/logout">Logout</a>
</body></html>
"""


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            role          TEXT DEFAULT 'user',
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # F1: bcrypt hashes with auto-generated salt per user.
    #     Even if two users share the same password, their hashes differ.
    seed = [
        ("admin", b"admin123", "admin"),
        ("john",  b"password", "user"),
    ]
    for uname, pwd, role in seed:
        try:
            h = bcrypt.hashpw(pwd, bcrypt.gensalt(rounds=BCRYPT_WORK_FACTOR))
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (uname, h, role)
            )
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()
    print("[*] Hardened DB ready.")


# ── Lockout helpers ────────────────────────────────────────────────

def _is_locked(username: str) -> bool:
    with _lock_mutex:
        entry = _lock_store.get(username)
        if not entry:
            return False
        if entry["attempts"] >= LOCKOUT_THRESHOLD:
            if time.time() < entry["locked_until"]:
                return True
            else:
                del _lock_store[username]
        return False


def _record_failure(username: str):
    with _lock_mutex:
        if username not in _lock_store:
            _lock_store[username] = {"attempts": 0, "locked_until": 0}
        _lock_store[username]["attempts"] += 1
        if _lock_store[username]["attempts"] >= LOCKOUT_THRESHOLD:
            _lock_store[username]["locked_until"] = time.time() + LOCKOUT_SECONDS
            print(f"[SECURITY] Locked: {username}")


def _clear_failures(username: str):
    with _lock_mutex:
        _lock_store.pop(username, None)


# ── Routes ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@login_rate_limit
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # F8: Check lockout BEFORE hitting the DB
        if _is_locked(username):
            time.sleep(1)   # Extra friction
            return render_template_string(LOGIN_TEMPLATE,
                error="Invalid credentials. Please try again later."), 429

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        # ── F9 + F10: Constant-time path ──────────────────────────
        # Both branches do a bcrypt.checkpw call of equal cost.
        # An attacker measuring response time cannot distinguish
        # "user not found" from "wrong password".
        if user is None:
            bcrypt.checkpw(password.encode(), _DUMMY_HASH)  # Runs same cost as real check
            _record_failure(username)
            # F3: Single generic message — no username enumeration
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")

        if bcrypt.checkpw(password.encode(), user["password_hash"]):
            _clear_failures(username)
            # F6: Clear session before setting new values — prevents session fixation.
            # An attacker who injected a session ID before login cannot reuse it.
            session.clear()
            session["user"]       = username
            session["role"]       = user["role"]
            session["login_time"] = time.time()
            return redirect(url_for("dashboard"))

        _record_failure(username)
        # F3: Same generic message regardless of which check failed
        return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")

    return render_template_string(LOGIN_TEMPLATE, error=None)



@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    # Optional: absolute session expiry (1 hour)
    if time.time() - session.get("login_time", 0) > 3600:
        session.clear()
        return redirect(url_for("login"))

    return render_template_string(DASHBOARD_TEMPLATE,
                                  user=session["user"],
                                  role=session["role"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    # F7: Debug OFF
    app.run(debug=False, host="0.0.0.0", port=5001)
