"""
System 6 — Account Recovery & Enrollment
PHASE 1: VULNERABLE IMPLEMENTATION

A realistic "forgot password" + registration flow built the way a developer
who skipped security training would build it. Every vulnerability here is REAL
and demonstrable against a running instance — not simulated.

Run:  python vulnerable_account_recovery.py
Then aim the Phase 2 attack scripts at http://127.0.0.1:5000

Recovery flow modeled:
  register -> forgot-password -> (email delivers OTP + reset link) ->
  verify-otp -> reset-password -> login

The "email" is a fake outbox readable at GET /outbox so attacks can observe
what was delivered (stands in for an attacker who can read the victim's mail,
OR — see VULN #4 — an attacker who poisoned the delivery destination).
"""

import sqlite3
import random
import time
from flask import Flask, request, jsonify, g

app = Flask(__name__)
DB = ":memory:"

# A shared in-process outbox standing in for delivered emails.
# Keyed by recipient address. In the real world these go to the user's inbox;
# here we expose them so the demo is observable.
OUTBOX = {}


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db


# NOTE: :memory: is per-connection, so we use a single module-level connection
# to keep state across requests. Fine for a study harness.
_conn = sqlite3.connect(DB, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.executescript(
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0
    );
    CREATE TABLE reset_tokens (
        token TEXT,
        email TEXT,
        otp TEXT,
        created_at REAL
    );
    """
)
# Seed a victim and an admin so takeover / escalation is observable.
_conn.execute(
    "INSERT INTO users (username, email, password, is_admin) VALUES (?,?,?,?)",
    ("victim", "victim@corp.example", "victimPassw0rd!", 0),
)
_conn.execute(
    "INSERT INTO users (username, email, password, is_admin) VALUES (?,?,?,?)",
    ("root", "root@corp.example", "s3cr3t-admin", 1),
)
_conn.commit()


def query(sql, args=(), one=False):
    cur = _conn.execute(sql, args)
    rows = cur.fetchall()
    _conn.commit()
    return (rows[0] if rows else None) if one else rows


# ---------------------------------------------------------------------------
# ENROLLMENT
# ---------------------------------------------------------------------------
@app.post("/register")
def register():
    data = request.get_json(force=True)

    # VULN #1 — USER ENUMERATION AT ENROLLMENT
    # Distinct error messages tell an attacker exactly which usernames/emails
    # already exist. Combined with the recovery flow's enumeration (VULN #2),
    # an attacker can map the entire user base.
    if query("SELECT 1 FROM users WHERE username=?", (data.get("username"),), one=True):
        return jsonify(error="username already taken"), 409
    if query("SELECT 1 FROM users WHERE email=?", (data.get("email"),), one=True):
        return jsonify(error="email already registered"), 409

    # VULN #2 — MASS ASSIGNMENT / OVERPERMISSIVE BINDING
    # The client-supplied JSON is trusted wholesale. Anyone who adds
    # "is_admin": 1 to their signup payload registers as an administrator.
    # No allowlist of settable fields, no email verification before the
    # account is live.
    cols = ", ".join(data.keys())
    placeholders = ", ".join("?" for _ in data)
    _conn.execute(
        f"INSERT INTO users ({cols}) VALUES ({placeholders})", tuple(data.values())
    )
    _conn.commit()
    return jsonify(status="registered", user=data.get("username")), 201


# ---------------------------------------------------------------------------
# RECOVERY — request
# ---------------------------------------------------------------------------
@app.post("/forgot-password")
def forgot_password():
    data = request.get_json(force=True)
    email = data.get("email")
    user = query("SELECT * FROM users WHERE email=?", (email,), one=True)

    # VULN #3 — USER ENUMERATION IN RECOVERY
    # Known vs unknown addresses get different responses (and different
    # timing, since only the known path does DB writes + email build). An
    # attacker can confirm which emails have accounts.
    if not user:
        return jsonify(error="no account with that email"), 404

    # VULN #5 — WEAK, PREDICTABLE SECRETS
    # OTP: 6-digit code from the NON-cryptographic Mersenne-Twister PRNG.
    # Token: derived from the current time. Both are guessable/predictable.
    otp = str(random.randint(0, 999999)).zfill(6)          # not secrets.*
    token = str(int(time.time() * 1000))                    # monotonic, guessable

    # VULN #6 — NO EXPIRY, NO SINGLE-USE (written now; enforced never)
    # created_at is recorded but never checked. Old tokens stay valid forever
    # and are never deleted after a successful reset -> replayable.
    _conn.execute(
        "INSERT INTO reset_tokens (token, email, otp, created_at) VALUES (?,?,?,?)",
        (token, email, otp, time.time()),
    )
    _conn.commit()

    # VULN #4 — HOST HEADER INJECTION IN THE RESET LINK
    # The reset URL is built from the attacker-controllable Host header.
    # Send a forgot-password request for the victim with
    # Host: attacker.example and the poisoned link (carrying the victim's
    # token) is delivered to the victim. If they click, the token is
    # exfiltrated to the attacker's server.
    host = request.headers.get("Host")
    reset_link = f"http://{host}/reset-password?token={token}"

    OUTBOX[email] = {"otp": otp, "reset_link": reset_link, "token": token}
    return jsonify(status="recovery email sent"), 200


# ---------------------------------------------------------------------------
# RECOVERY — verify OTP
# ---------------------------------------------------------------------------
@app.post("/verify-otp")
def verify_otp():
    data = request.get_json(force=True)
    email = data.get("email")
    otp = data.get("otp")

    row = query("SELECT * FROM reset_tokens WHERE email=?", (email,), one=True)
    if not row:
        return jsonify(error="no pending recovery"), 400

    # VULN #7 — NO RATE LIMITING / LOCKOUT ON OTP
    # A 6-digit code is a 10^6 space, but nothing caps attempts. An attacker
    # sprays until it matches. No delay, no lockout, no attempt counter.
    if otp == row["otp"]:
        return jsonify(status="otp verified", token=row["token"]), 200
    return jsonify(error="invalid otp"), 400


# ---------------------------------------------------------------------------
# RECOVERY — reset
# ---------------------------------------------------------------------------
@app.post("/reset-password")
def reset_password():
    data = request.get_json(force=True)
    token = data.get("token")
    new_password = data.get("new_password")

    row = query("SELECT * FROM reset_tokens WHERE token=?", (token,), one=True)
    if not row:
        return jsonify(error="invalid token"), 400

    # VULN #6 (cont.) — token TTL never enforced here either.
    # VULN #8 — BROKEN ACCOUNT BINDING (IDOR)
    # The account to reset is taken from a client-supplied "email" field
    # instead of from the token itself. A valid token for ATTACKER's own
    # account is accepted to reset ANY victim's password, because the code
    # trusts data["email"] over row["email"].
    target_email = data.get("email", row["email"])

    _conn.execute(
        "UPDATE users SET password=? WHERE email=?", (new_password, target_email)
    )
    _conn.commit()
    # Token is NOT deleted -> replayable indefinitely (VULN #6).
    return jsonify(status="password reset", account=target_email), 200


# ---------------------------------------------------------------------------
# Support endpoints
# ---------------------------------------------------------------------------
@app.post("/login")
def login():
    data = request.get_json(force=True)
    user = query(
        "SELECT * FROM users WHERE email=? AND password=?",
        (data.get("email"), data.get("password")),
        one=True,
    )
    if not user:
        return jsonify(error="bad credentials"), 401
    return jsonify(status="ok", username=user["username"], is_admin=bool(user["is_admin"])), 200


@app.get("/outbox")
def outbox():
    # Stand-in for the victim's inbox. Lets attack scripts observe delivery.
    return jsonify(OUTBOX), 200


if __name__ == "__main__":
    # threaded=False keeps the single module-level sqlite connection safe.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=False)
