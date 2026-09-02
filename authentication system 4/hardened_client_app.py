"""
hardened/client_app.py   (port 5101)
====================================
Hardened OAuth 2.0 / OIDC client (relying party).

  state  generated per flow, stored in session, enforced on callback
         -> defeats login CSRF / code injection      (RFC 6749 sec 10.12)
  PKCE   code_verifier generated, challenge sent, verifier redeemed
         -> binds the code to this client             (RFC 7636 / 9700)
  nonce  generated, sent, and required in the id_token
         -> defeats id_token replay                   (OIDC Core 3.1.3.7)
  id_token verified strictly via oauth_engine.jwt_verify: alg pinned to
         HS256, signature checked, iss/aud/nonce enforced.
"""
import os, sys, requests
from flask import Flask, request, redirect, session, jsonify

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oauth_engine as eng

AS = "http://localhost:5000"
ISS = "http://localhost:5000"
CLIENT_ID = "webapp"
CLIENT_SECRET = "webapp-secret-0xDEADBEEF"
REDIRECT_URI = "http://localhost:5001/callback"

app = Flask(__name__)
app.secret_key = os.environ.get("HARDENED_CLIENT_SECRET_KEY") or os.urandom(32)


@app.route("/")
def home():
    who = session.get("identity", "anonymous")
    return f"<h2>Hardened client</h2>logged in as: <b>{who}</b><br><a href='/login'>login</a>"


@app.route("/login")
def login():
    state = eng.generate_state()
    nonce = eng.generate_nonce()
    verifier = eng.generate_code_verifier()
    challenge = eng.derive_code_challenge(verifier, "S256")

    # bound to THIS user-agent via the server-side session
    session["state"] = state
    session["nonce"] = nonce
    session["code_verifier"] = verifier

    url = (f"{AS}/authorize?response_type=code&client_id={CLIENT_ID}"
           f"&redirect_uri={REDIRECT_URI}&scope=openid"
           f"&state={state}&nonce={nonce}"
           f"&code_challenge={challenge}&code_challenge_method=S256")
    return redirect(url)


@app.route("/callback")
def callback():
    # enforce state: reject anything not tied to a flow this browser started
    if not session.get("state") or request.args.get("state") != session["state"]:
        return "state mismatch -- request rejected", 400
    code = request.args.get("code")
    if not code:
        return "no code", 400

    r = requests.post(f"{AS}/token", data={
        "grant_type": "authorization_code", "code": code,
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": session.get("code_verifier"),
    })
    tokens = r.json()
    if "id_token" not in tokens:
        return jsonify(tokens), 400

    # strict OIDC id_token verification
    try:
        claims = eng.jwt_verify(tokens["id_token"], CLIENT_SECRET,
                                expected_alg="HS256", expected_iss=ISS,
                                expected_aud=CLIENT_ID,
                                expected_nonce=session.get("nonce"))
    except ValueError as e:
        return f"id_token rejected: {e}", 400

    session["identity"] = claims["sub"]
    session["access_token"] = tokens["access_token"]
    # one-time values consumed
    session.pop("state", None); session.pop("nonce", None); session.pop("code_verifier", None)
    return redirect("/")


@app.route("/me")
def me():
    return jsonify(identity=session.get("identity"),
                   access_token=session.get("access_token"))


if __name__ == "__main__":
    print("[hard-client] listening on :5001")
    app.run(port=5001, threaded=True)
