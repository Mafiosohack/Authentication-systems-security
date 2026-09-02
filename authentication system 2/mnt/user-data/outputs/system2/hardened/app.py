"""
SYSTEM 2 — Password + TOTP MFA
HARDENED IMPLEMENTATION

Fixes mapped to the vulnerable version's weaknesses:
  F1 (V1): Rate limiting + per-user lockout on TOTP verification
  F2 (V2): Replay protection — each time-step counter usable once
  F3 (V3): Tight window (window=1) — 3 codes max, not 7
  F4 (V4): TOTP secret ENCRYPTED at rest (Fernet/AES) — DB dump is not enough
  F5 (V5): No secret-exposing endpoint; QR shown once at enrollment only
  F6 (V6): Strict flow binding — dashboard requires mfa_passed == True

HONEST LIMITATION (the bridge to System 3):
  None of these fixes stop a real-time phishing relay (Attack 5). A perfectly
  hardened TOTP still hands a valid code to whoever the user is talking to.
  Phishing resistance requires origin-bound credentials => Passkeys/FIDO2.
"""

import os
import time
import threading
import secrets

from flask import Flask, request, session, redirect, url_for, render_template_string
import sqlite3
import bcrypt
import pyotp
from cryptography.fernet import Fernet

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _LIMITER = True
except ImportError:
    _LIMITER = False
    print("[!] flask-limiter not installed: pip install flask-limiter")

app = Flask(__name__)

# Secret key from environment (System 1 lesson carried forward)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# F4: encryption key for TOTP secrets at rest. From env in production.
_FERNET_KEY = os.environ.get("TOTP_FERNET_KEY")
if not _FERNET_KEY:
    _FERNET_KEY = Fernet.generate_key().decode()
    print("[!] TOTP_FERNET_KEY not set — generated ephemeral key (secrets won't")
    print("    survive a restart). Set TOTP_FERNET_KEY in production.")
fernet = Fernet(_FERNET_KEY.encode() if isinstance(_FERNET_KEY, str) else _FERNET_KEY)

DB_PATH = "hardened_mfa.db"

# F3: tight window. 1 => steps -1..+1 => 3 codes (90s). Pairs with replay guard.
TOTP_WINDOW = 1
TIME_STEP = 30

# F1: lockout config
MAX_TOTP_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
PENDING_TTL = 300   # half-login (post-password, pre-TOTP) expires after 5 min

_lock = threading.Lock()
_totp_attempts = {}     # username -> {"attempts": n, "locked_until": ts}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY,
            username        TEXT UNIQUE NOT NULL,
            password_hash   BLOB NOT NULL,
            totp_secret_enc BLOB NOT NULL,   -- F4: encrypted, not plaintext
            last_used_step  INTEGER DEFAULT 0 -- F2: highest consumed counter
        )
    """)
    secret = "JBSWY3DPEHPK3PXP"  # same secret as vuln app, but stored ENCRYPTED
    pw_hash = bcrypt.hashpw(b"SuperSecret123", bcrypt.gensalt(rounds=12))
    enc_secret = fernet.encrypt(secret.encode())   # F4
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, totp_secret_enc) VALUES (?, ?, ?)",
            ("admin", pw_hash, enc_secret)
        )
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()
    print("[*] Hardened MFA DB ready (TOTP secret stored ENCRYPTED).")


if _LIMITER:
    limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")


def _is_locked(username):
    with _lock:
        e = _totp_attempts.get(username)
        if e and e["attempts"] >= MAX_TOTP_ATTEMPTS:
            if time.time() < e["locked_until"]:
                return True
            del _totp_attempts[username]
        return False


def _record_totp_fail(username):
    with _lock:
        e = _totp_attempts.setdefault(username, {"attempts": 0, "locked_until": 0})
        e["attempts"] += 1
        if e["attempts"] >= MAX_TOTP_ATTEMPTS:
            e["locked_until"] = time.time() + LOCKOUT_SECONDS


def _clear_totp_fails(username):
    with _lock:
        _totp_attempts.pop(username, None)


def _matching_step(secret, code, now=None):
    """
    F2 helper: return the time-step counter the code matches within the window,
    or None. Lets us enforce replay protection by comparing against last_used.
    """
    if now is None:
        now = time.time()
    current = int(now // TIME_STEP)
    totp = pyotp.TOTP(secret)
    for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        step = current + offset
        if secrets.compare_digest(totp.at(step * TIME_STEP), code):  # constant-time
            return step
    return None


LOGIN_PAGE = """
<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:380px;margin:60px auto">
<h2>Step 1 — Password</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post">
  <input name="username" placeholder="username" style="width:100%;padding:8px;margin:6px 0"><br>
  <input type="password" name="password" placeholder="password" style="width:100%;padding:8px;margin:6px 0"><br>
  <button style="padding:8px 20px">Continue</button>
</form>
</body></html>
"""

TOTP_PAGE = """
<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:380px;margin:60px auto">
<h2>Step 2 — Enter 6-digit code</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post">
  <input name="code" placeholder="000000" style="width:100%;padding:8px;margin:6px 0"><br>
  <button style="padding:8px 20px">Verify</button>
</form>
</body></html>
"""

DASH_PAGE = """
<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:560px;margin:60px auto">
<h2>Dashboard</h2><p>Welcome, {{ user }}. Fully authenticated (password + TOTP).</p>
<a href="/logout">Logout</a></body></html>
"""


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user["password_hash"]):
            # F6: do NOT mark authenticated here. Only a short-lived PENDING
            #     state that is useless on its own.
            session.clear()
            session["pending_user"] = username
            session["pending_since"] = time.time()
            return redirect(url_for("verify_totp"))

        return render_template_string(LOGIN_PAGE, error="Invalid credentials")
    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/verify-totp", methods=["GET", "POST"])
def verify_totp():
    # F6: must be in the pending (post-password) state, and it must be fresh
    pending = session.get("pending_user")
    if not pending:
        return redirect(url_for("login"))
    if time.time() - session.get("pending_since", 0) > PENDING_TTL:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        # F1: lockout check
        if _is_locked(pending):
            time.sleep(1)
            return render_template_string(TOTP_PAGE, error="Too many attempts. Try later."), 429

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (pending,)).fetchone()

        secret = fernet.decrypt(user["totp_secret_enc"]).decode()  # F4: decrypt
        step = _matching_step(secret, code)                        # F3 window + constant-time

        # F2: replay protection — the matched step must be NEWER than the last
        #     consumed step for this user.
        if step is not None and step > user["last_used_step"]:
            conn.execute("UPDATE users SET last_used_step = ? WHERE username = ?", (step, pending))
            conn.commit()
            conn.close()
            _clear_totp_fails(pending)

            # F6: now (and only now) promote to a fully authenticated session
            session.clear()
            session["user"] = pending
            session["mfa_passed"] = True
            return redirect(url_for("dashboard"))

        conn.close()
        _record_totp_fail(pending)
        # Generic message whether code was wrong OR a replay
        return render_template_string(TOTP_PAGE, error="Invalid code")
    return render_template_string(TOTP_PAGE, error=None)


# F1: apply rate limit to the verification route
if _LIMITER:
    limiter.limit("10 per minute")(verify_totp)


@app.route("/dashboard")
def dashboard():
    # F6: strict — requires the FULL authentication marker, no bypass
    if not (session.get("user") and session.get("mfa_passed")):
        return redirect(url_for("login"))
    return render_template_string(DASH_PAGE, user=session["user"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# NOTE: there is intentionally NO /totp-secret endpoint. The secret is shown
# exactly once during enrollment (out of scope here) and never exposed again.


if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5004)
