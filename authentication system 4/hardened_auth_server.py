"""
hardened/auth_server.py   (port 5100)
=====================================
Hardened OAuth 2.0 / OIDC Authorization Server. Each control cites the
RFC 9700 (Jan 2025) recommendation it implements.

  H1  redirect_uri: EXACT STRING match against registration, at both the
      authorization and token endpoints           (RFC 9700 sec 2.1 / 4.1)
  H3  PKCE: required for public clients; verified whenever a challenge was
      issued                                       (RFC 9700 sec 2.1.1)
  H4  authorization codes are single-use; on reuse the code is invalidated
      AND tokens previously minted from it are revoked  (RFC 9700 sec 4.5)
  state / nonce are echoed/embedded so the client can enforce them.

Note: RFC 9700 recommends PKCE for ALL clients. This server requires it for
public clients and verifies it for confidential clients that send it; the
reference confidential client (hardened/client_app.py) adopts PKCE too, so
universal PKCE is achieved in practice.
"""
import os, sqlite3, sys, time
from flask import Flask, request, redirect, session, g, jsonify, render_template_string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oauth_engine as eng

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oauth_hard.db")
ISS = "http://localhost:5000"

app = Flask(__name__)
app.secret_key = os.environ.get("HARDENED_AS_SECRET_KEY") or os.urandom(32)


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
        CREATE TABLE users   (username TEXT PRIMARY KEY, password TEXT, email TEXT);
        CREATE TABLE clients (client_id TEXT PRIMARY KEY, client_secret TEXT,
                              redirect_uri TEXT, is_public INTEGER);
        CREATE TABLE codes   (code TEXT PRIMARY KEY, client_id TEXT, username TEXT,
                              redirect_uri TEXT, scope TEXT, nonce TEXT,
                              code_challenge TEXT, challenge_method TEXT,
                              used INTEGER DEFAULT 0, created REAL);
        CREATE TABLE tokens  (token TEXT PRIMARY KEY, client_id TEXT, username TEXT,
                              scope TEXT, from_code TEXT, created REAL);
    """)
    c.execute("INSERT INTO users VALUES (?,?,?)", ("alice", "alicepw", "alice@victim.com"))
    c.execute("INSERT INTO users VALUES (?,?,?)", ("mallory", "mallorypw", "mallory@evil.com"))
    c.execute("INSERT INTO clients VALUES (?,?,?,?)",
              ("webapp", "webapp-secret-0xDEADBEEF", "http://localhost:5001/callback", 0))
    c.execute("INSERT INTO clients VALUES (?,?,?,?)",
              ("spa", None, "http://localhost:5001/spa-callback", 1))
    c.commit()
    c.close()


LOGIN_PAGE = """<h2>AuthServer login</h2><form method=post>
user <input name=username> pass <input name=password type=password>
<button>login</button></form>{{msg}}"""

CONSENT_PAGE = """<h2>Authorize {{client_id}}?</h2>
<p>Logged in as <b>{{username}}</b>. Scope: {{scope}}</p>
<form method=get action="/authorize">
{% for k,v in params.items() %}<input type=hidden name="{{k}}" value="{{v}}">{% endfor %}
<input type=hidden name="_consent" value="yes"><button>Allow</button></form>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        row = db().execute("SELECT * FROM users WHERE username=? AND password=?",
                           (request.form["username"], request.form["password"])).fetchone()
        if row:
            session["user"] = row["username"]
            return redirect(request.args.get("next", "/"))
        return render_template_string(LOGIN_PAGE, msg="<p>bad creds</p>")
    return render_template_string(LOGIN_PAGE, msg="")


@app.route("/authorize")
def authorize():
    if "user" not in session:
        return redirect("/login?next=" + request.full_path)

    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "openid")
    state = request.args.get("state")
    nonce = request.args.get("nonce")
    code_challenge = request.args.get("code_challenge")
    challenge_method = request.args.get("code_challenge_method", "S256")

    client = db().execute("SELECT * FROM clients WHERE client_id=?", (client_id,)).fetchone()
    if not client:
        return "unknown client", 400

    # H1: redirect_uri MUST exactly equal the registered value. No prefix,
    # no substring, no normalisation games. (RFC 9700 sec 2.1)
    if redirect_uri != client["redirect_uri"]:
        return "invalid redirect_uri", 400   # do NOT redirect on this error

    # H3: PKCE required for public clients.
    if client["is_public"] and not code_challenge:
        return "PKCE required (code_challenge missing)", 400
    if challenge_method not in ("S256", "plain"):
        return "unsupported code_challenge_method", 400

    if request.args.get("_consent") != "yes":
        params = {k: v for k, v in request.args.items() if k != "_consent"}
        return render_template_string(CONSENT_PAGE, client_id=client_id,
                                      username=session["user"], scope=scope, params=params)

    code = eng.generate_authorization_code()
    db().execute(
        "INSERT INTO codes (code,client_id,username,redirect_uri,scope,nonce,"
        "code_challenge,challenge_method,used,created) VALUES (?,?,?,?,?,?,?,?,0,?)",
        (code, client_id, session["user"], redirect_uri, scope, nonce,
         code_challenge, challenge_method, time.time()))
    db().commit()

    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}"
    if state:
        location += f"&state={state}"
    return redirect(location)


def _revoke_tokens_from_code(code):
    db().execute("DELETE FROM tokens WHERE from_code=?", (code,))


@app.route("/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    redirect_uri = request.form.get("redirect_uri")
    code_verifier = request.form.get("code_verifier")

    if grant_type != "authorization_code":
        return jsonify(error="unsupported_grant_type"), 400

    row = db().execute("SELECT * FROM codes WHERE code=?", (code,)).fetchone()
    if not row:
        return jsonify(error="invalid_grant"), 400

    client = db().execute("SELECT * FROM clients WHERE client_id=?", (client_id,)).fetchone()
    if not client or row["client_id"] != client_id:
        return jsonify(error="invalid_client"), 400

    if not client["is_public"] and client_secret != client["client_secret"]:
        return jsonify(error="invalid_client"), 401

    # H4: single-use. If this code was already consumed, treat reuse as an
    # attack: invalidate and revoke everything it produced. (RFC 9700 sec 4.5)
    if row["used"]:
        _revoke_tokens_from_code(code)
        db().commit()
        return jsonify(error="invalid_grant", detail="code reuse detected; tokens revoked"), 400

    # H1 (cont.): the redirect_uri presented here MUST match the one bound to
    # the code at authorization time.
    if redirect_uri != row["redirect_uri"]:
        return jsonify(error="invalid_grant", detail="redirect_uri mismatch"), 400

    # H3 (cont.): verify PKCE whenever a challenge was issued.
    if row["code_challenge"]:
        if not eng.verify_pkce(code_verifier, row["code_challenge"],
                               row["challenge_method"] or "S256"):
            return jsonify(error="invalid_grant", detail="PKCE verification failed"), 400

    # consume the code
    db().execute("UPDATE codes SET used=1 WHERE code=?", (code,))

    access_token = eng.generate_access_token()
    db().execute("INSERT INTO tokens VALUES (?,?,?,?,?,?)",
                 (access_token, client_id, row["username"], row["scope"], code, time.time()))
    db().commit()

    resp = {"access_token": access_token, "token_type": "Bearer",
            "expires_in": 3600, "scope": row["scope"]}
    if "openid" in (row["scope"] or ""):
        signing_key = client["client_secret"] or "spa-no-secret"
        resp["id_token"] = eng.build_id_token(
            iss=ISS, sub=row["username"], aud=client_id, key=signing_key,
            nonce=row["nonce"], extra={"email": _email(row["username"])})
    return jsonify(resp)


def _email(username):
    r = db().execute("SELECT email FROM users WHERE username=?", (username,)).fetchone()
    return r["email"] if r else None


@app.route("/")
def home():
    return "Hardened AuthServer running on :5100"


if __name__ == "__main__":
    init_db()
    print("[hard-as] DB seeded. Listening on :5000")
    app.run(port=5000, threaded=True)
