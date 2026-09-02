"""
SYSTEM 2 — Password + TOTP MFA
VULNERABLE IMPLEMENTATION

Password layer uses bcrypt (carried forward from System 1 — we are NOT
re-demonstrating password weaknesses here). All weaknesses below are in the
TOTP / MFA layer specifically.

Intentional weaknesses (numbered for demo reference):
  V1: No rate limiting on TOTP verification  -> code brute force
  V2: No replay protection                    -> a used code works again
  V3: Excessive time window (window=3)         -> 7 codes valid at once
  V4: TOTP secret stored in plaintext in DB    -> DB dump = permanent bypass
  V5: Enrollment endpoint leaks the secret     -> /totp-secret returns it, no auth
  V6: Broken flow: session marked authenticated after PASSWORD, before TOTP
      -> attacker navigates straight to /dashboard, skipping MFA entirely

DO NOT USE IN PRODUCTION.
"""

from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify
import sqlite3
import bcrypt
import pyotp

app = Flask(__name__)
app.secret_key = "totp-demo-key-not-secret"   # (separate issue; see System 1)

DB_PATH = "vuln_mfa.db"

# V3: dangerously wide acceptance window. window=3 -> steps -3..+3 -> 7 valid
#     codes at any moment -> 7x the attacker's hit chance vs window=0.
TOTP_WINDOW = 3


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
            totp_secret   TEXT NOT NULL          -- V4: plaintext base32 secret
        )
    """)
    # Seed one user. Password hashed with bcrypt; TOTP secret in PLAINTEXT.
    secret = "JBSWY3DPEHPK3PXP"   # fixed for demo so attacks are reproducible
    pw_hash = bcrypt.hashpw(b"SuperSecret123", bcrypt.gensalt(rounds=12))
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
            ("admin", pw_hash, secret)
        )
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()
    print("[*] Vulnerable MFA DB ready.")
    print(f"    user: admin  /  password: SuperSecret123")
    print(f"    TOTP secret (PLAINTEXT in DB): {secret}")
    print(f"    Current code right now: {pyotp.TOTP(secret).now()}")


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
<h2>Dashboard</h2>
<p>Welcome, {{ user }}. MFA stage: {{ stage }}.</p>
<a href="/logout">Logout</a>
</body></html>
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
            # V6: BROKEN FLOW. The session is marked with the user identity here,
            #     at the PASSWORD stage, before TOTP is verified. The "mfa_passed"
            #     flag defaults to absent, but /dashboard below does not strictly
            #     require it -> MFA can be skipped entirely.
            session["user"] = username
            session["mfa_passed"] = False
            return redirect(url_for("verify_totp"))

        return render_template_string(LOGIN_PAGE, error="Invalid credentials")
    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/verify-totp", methods=["GET", "POST"])
def verify_totp():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (session["user"],)).fetchone()
        conn.close()

        totp = pyotp.TOTP(user["totp_secret"])

        # V1: no rate limiting at all -> attacker can submit codes as fast as the
        #     network allows.
        # V2: no replay protection -> a code that already succeeded keeps working
        #     for its whole validity window; no record of consumed codes.
        # V3: TOTP_WINDOW = 3 -> 7 codes valid simultaneously.
        if totp.verify(code, valid_window=TOTP_WINDOW):
            session["mfa_passed"] = True
            return redirect(url_for("dashboard"))

        return render_template_string(TOTP_PAGE, error="Invalid code")
    return render_template_string(TOTP_PAGE, error=None)


@app.route("/dashboard")
def dashboard():
    # V6: only checks that the user passed the PASSWORD stage. It does NOT
    #     enforce session["mfa_passed"] == True. So a user who completed only
    #     step 1 can reach the dashboard by navigating here directly.
    if "user" not in session:
        return redirect(url_for("login"))
    stage = "FULL (password+TOTP)" if session.get("mfa_passed") else "PASSWORD ONLY (MFA skipped!)"
    return render_template_string(DASH_PAGE, user=session["user"], stage=stage)


@app.route("/totp-secret")
def totp_secret():
    # V5: enrollment/debug endpoint that returns the raw TOTP secret with NO
    #     authentication. Real apps leak secrets like this via verbose
    #     enrollment APIs, debug routes, or QR endpoints with no access control.
    username = request.args.get("user", "admin")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "no such user"}), 404
    return jsonify({
        "username": username,
        "totp_secret": user["totp_secret"],
        "provisioning_uri": pyotp.TOTP(user["totp_secret"]).provisioning_uri(
            name=username, issuer_name="VulnerableApp")
    })


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5002)
