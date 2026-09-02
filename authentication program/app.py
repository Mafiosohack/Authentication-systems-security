"""
SYSTEM 1 — Basic Password Auth + Sessions
VULNERABLE IMPLEMENTATION

Intentional weaknesses (numbered for demo reference):
  V1: Unsalted MD5 password hashing
  V2: No rate limiting — unlimited login attempts
  V3: Verbose error messages → username enumeration
  V4: Hardcoded secret key → session forgery
  V5: Session cookie has no HttpOnly / Secure / SameSite flags
  V6: No session regeneration after login → session fixation
  V7: Debug mode on → interactive debugger exposed at /__debugger__

DO NOT USE IN PRODUCTION.
"""

from flask import Flask, request, session, redirect, url_for, render_template_string
import sqlite3
import hashlib

app = Flask(__name__)

# V4: Hardcoded secret key. Anyone who knows this can forge session cookies.
app.secret_key = "secret123"

# V5: Flask default — no cookie flags set at all.

DB_PATH = "vuln_users.db"

LOGIN_TEMPLATE = """
<!DOCTYPE html><html>
<head><title>Login</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:80px auto;padding:20px">
  <h2>Login</h2>
  {% if error %}<p style="color:red;font-weight:bold">{{ error }}</p>{% endif %}
  <form method="post">
    <label>Username</label><br>
    <input name="username" style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Password</label><br>
    <input type="password" name="password" style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <button type="submit" style="padding:8px 20px">Login</button>
  </form>
</body></html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html><html>
<head><title>Dashboard</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:80px auto;padding:20px">
  <h2>Welcome, {{ user }}! [role: {{ role }}]</h2>
  <p>This is protected content. You are authenticated.</p>
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
            id       INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user'
        )
    """)

    # V1: Passwords stored as unsalted MD5.
    # Same hash for same password across every user. Rainbow tables work directly.
    # This is exactly what you extracted from Kioptrix via UNION SELECT.
    seed_users = [
        ("admin",  hashlib.md5(b"admin123").hexdigest(),  "admin"),
        ("john",   hashlib.md5(b"password").hexdigest(),  "user"),
        ("alice",  hashlib.md5(b"123456").hexdigest(),    "user"),
        ("bob",    hashlib.md5(b"qwerty").hexdigest(),    "user"),
    ]
    for uname, phash, role in seed_users:
        try:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (uname, phash, role)
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

    print("[*] Vulnerable DB ready.")
    print(f"    admin  → {hashlib.md5(b'admin123').hexdigest()}  (admin123)")
    print(f"    john   → {hashlib.md5(b'password').hexdigest()}  (password)")
    print(f"    alice  → {hashlib.md5(b'123456').hexdigest()}  (123456)")


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    # V2: Zero rate limiting. Attacker can hammer this at full network speed.
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # V1: MD5, no salt
        pwd_hash = hashlib.md5(password.encode()).hexdigest()

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        # V3: Two distinct error messages.
        #     "User not found"  → username does NOT exist  (attacker learns this)
        #     "Wrong password"  → username DOES exist      (attacker learns this)
        #     This lets attacker enumerate valid usernames before brute-forcing.
        if user is None:
            return render_template_string(LOGIN_TEMPLATE, error="User not found")

        if user["password"] != pwd_hash:
            return render_template_string(LOGIN_TEMPLATE, error="Wrong password")

        # V6: No session.clear() before setting values → session fixation possible.
        session["user"] = username
        session["role"] = user["role"]
        return redirect(url_for("dashboard"))

    return render_template_string(LOGIN_TEMPLATE, error=None)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
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
    # V7: debug=True exposes Werkzeug's interactive debugger.
    #     Visiting /?__debugger__=yes can give RCE in some configs.
    app.run(debug=True, host="0.0.0.0", port=5000)
