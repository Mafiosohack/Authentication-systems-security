"""
vulnerable/auth_server.py   (port 5000)
=======================================
A deliberately INSECURE OAuth 2.0 / OIDC Authorization Server.

Flaws baked in (each tagged `VULN:`):
  V1  /authorize does NOT validate redirect_uri against registration
  V2  /authorize does NOT require or bind a `state` value
  V3  /authorize accepts the flow with NO PKCE (and ignores it if sent)
  V4  /token does NOT mark authorization codes as used  -> replayable
  (The OIDC id_token itself is signed correctly; the *client* fails to
   validate it -- see vulnerable/client_app.py. That keeps attack 5's
   root cause on the validation side, where it belongs.)

Do NOT model real software on this file.
"""
import os
import sqlite3
import sys
import time

from flask import Flask, request, redirect, session, g, jsonify, render_template_string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oauth_engine as eng

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oauth_vuln.db")
ISS = "http://localhost:5000"

app = Flask(__name__)
app.secret_key = os.environ.get("VULN_AS_SECRET_KEY") or os.urandom(32)


# --------------------------------------------------------------------- db
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    c = sqlite3.connect(DB)
    c.executescript("""
        CREATE TABLE users    (username TEXT PRIMARY KEY, password TEXT, email TEXT);
        CREATE TABLE clients  (client_id TEXT PRIMARY KEY, client_secret TEXT,
                               redirect_uri TEXT, is_public INTEGER);
        CREATE TABLE codes    (code TEXT PRIMARY KEY, client_id TEXT, username TEXT,
                               redirect_uri TEXT, scope TEXT, nonce TEXT,
                               code_challenge TEXT, challenge_method TEXT,
                               used INTEGER DEFAULT 0, created REAL);
        CREATE TABLE tokens   (token TEXT PRIMARY KEY, client_id TEXT, username TEXT,
                               scope TEXT, created REAL);
    """)
    # resource owners
    c.execute("INSERT INTO users VALUES (?,?,?)", ("alice", "alicepw", "alice@victim.com"))
    c.execute("INSERT INTO users VALUES (?,?,?)", ("mallory", "mallorypw", "mallory@evil.com"))
    # registered clients
    c.execute("INSERT INTO clients VALUES (?,?,?,?)",
              ("webapp", "webapp-secret-0xDEADBEEF", "http://localhost:5001/callback", 0))
    c.execute("INSERT INTO clients VALUES (?,?,?,?)",
              ("spa", None, "http://localhost:5001/spa-callback", 1))
    c.commit()
    c.close()


# ----------------------------------------------------------------- consent UI
LOGIN_PAGE = """
<h2>AuthServer login (resource owner)</h2>
<form method=post>
  user <input name=username> pass <input name=password type=password>
  <button>login</button>
</form>{{msg}}
"""

CONSENT_PAGE = """
<h2>Authorize {{client_id}}?</h2>
<p>Logged in as <b>{{username}}</b>. Scope: {{scope}}</p>
<form method=get action="/authorize">
  {% for k,v in params.items() %}<input type=hidden name="{{k}}" value="{{v}}">{% endfor %}
  <input type=hidden name="_consent" value="yes">
  <button>Allow</button>
</form>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        row = db().execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (request.form["username"], request.form["password"]),
        ).fetchone()
        if row:
            session["user"] = row["username"]
            nxt = request.args.get("next", "/")
            return redirect(nxt)
        return render_template_string(LOGIN_PAGE, msg="<p>bad creds</p>")
    return render_template_string(LOGIN_PAGE, msg="")


@app.route("/authorize")
def authorize():
    # resource owner must be authenticated to the AS
    if "user" not in session:
        return redirect("/login?next=" + request.full_path)

    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "openid")
    state = request.args.get("state")            # may be None
    nonce = request.args.get("nonce")            # may be None
    code_challenge = request.args.get("code_challenge")           # ignored below
    challenge_method = request.args.get("code_challenge_method")

    client = db().execute("SELECT * FROM clients WHERE client_id=?", (client_id,)).fetchone()
    if not client:
        return "unknown client", 400

    # VULN V1: redirect_uri is whatever the request says. No comparison to
    # the registered value. An attacker can point the code anywhere.
    # (correct behaviour would be: exact-string match against registration)

    # VULN V3: PKCE is neither required nor enforced. code_challenge is read
    # and stored but never verified at the token endpoint.

    if request.args.get("_consent") != "yes":
        params = {k: v for k, v in request.args.items() if k != "_consent"}
        return render_template_string(CONSENT_PAGE, client_id=client_id,
                                      username=session["user"], scope=scope, params=params)

    code = eng.generate_authorization_code()
    db().execute(
        "INSERT INTO codes (code,client_id,username,redirect_uri,scope,nonce,"
        "code_challenge,challenge_method,used,created) VALUES (?,?,?,?,?,?,?,?,0,?)",
        (code, client_id, session["user"], redirect_uri, scope, nonce,
         code_challenge, challenge_method, time.time()),
    )
    db().commit()

    # VULN V2: state is echoed back if present, but never required. A client
    # that omits it gets no CSRF protection and the AS does nothing about it.
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}"
    if state:
        location += f"&state={state}"
    return redirect(location)


@app.route("/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    code_verifier = request.form.get("code_verifier")   # ignored below

    if grant_type != "authorization_code":
        return jsonify(error="unsupported_grant_type"), 400

    row = db().execute("SELECT * FROM codes WHERE code=?", (code,)).fetchone()
    if not row:
        return jsonify(error="invalid_grant"), 400

    client = db().execute("SELECT * FROM clients WHERE client_id=?", (client_id,)).fetchone()
    if not client:
        return jsonify(error="invalid_client"), 400

    # confidential clients authenticate with a secret; public clients don't
    if not client["is_public"] and client_secret != client["client_secret"]:
        return jsonify(error="invalid_client"), 401

    # VULN V3 (cont.): if a code_challenge was registered we should now demand
    # a matching code_verifier. We do not. PKCE is completely ignored.

    # VULN V4: the code is NOT marked used. Replaying this exact request
    # mints fresh tokens every time.
    access_token = eng.generate_access_token()
    db().execute("INSERT INTO tokens VALUES (?,?,?,?,?)",
                 (access_token, client_id, row["username"], row["scope"], time.time()))
    db().commit()

    resp = {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600,
            "scope": row["scope"]}

    # OIDC: issue an id_token when 'openid' scope present.
    if "openid" in (row["scope"] or ""):
        signing_key = client["client_secret"] or "spa-no-secret"
        resp["id_token"] = eng.build_id_token(
            iss=ISS, sub=row["username"], aud=client_id, key=signing_key,
            nonce=row["nonce"], extra={"email": _email(row["username"])},
        )
    return jsonify(resp)


def _email(username):
    r = db().execute("SELECT email FROM users WHERE username=?", (username,)).fetchone()
    return r["email"] if r else None


@app.route("/")
def home():
    return "Vulnerable AuthServer running on :5000"


if __name__ == "__main__":
    init_db()
    print("[vuln-as] DB seeded. Listening on :5000")
    app.run(port=5000, threaded=True)
