"""
vulnerable/client_app.py   (port 5001)
======================================
A deliberately INSECURE OAuth 2.0 / OIDC client (relying party).

Flaws (tagged `VULN:`):
  V2  no `state` generated or checked        -> login CSRF / code injection
  V3  no PKCE (no code_verifier generated)
  V5a no `nonce` generated or checked        -> id_token replay
  V5b id_token accepted via UNVERIFIED decode -> forged/none-alg tokens pass

The client trusts whatever identity the id_token claims, with no signature,
issuer, audience, or nonce checking. That is the entire point of attack 5.
"""
import os
import sys
import requests
from flask import Flask, request, redirect, session, jsonify

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oauth_engine as eng

AS = "http://localhost:5000"
CLIENT_ID = "webapp"
CLIENT_SECRET = "webapp-secret-0xDEADBEEF"
REDIRECT_URI = "http://localhost:5001/callback"

app = Flask(__name__)
app.secret_key = os.environ.get("VULN_CLIENT_SECRET_KEY") or os.urandom(32)


@app.route("/")
def home():
    who = session.get("identity", "anonymous")
    return f"<h2>Vulnerable client</h2>logged in as: <b>{who}</b><br><a href='/login'>login via AuthServer</a>"


@app.route("/login")
def login():
    # VULN V2/V3/V5a: no state, no PKCE, no nonce. The authorization request
    # carries nothing that binds the eventual response to THIS browser.
    url = (f"{AS}/authorize?response_type=code&client_id={CLIENT_ID}"
           f"&redirect_uri={REDIRECT_URI}&scope=openid")
    return redirect(url)


@app.route("/callback")
def callback():
    code = request.args.get("code")
    # VULN V2: state is never generated, so there is nothing to compare.
    # Any code that lands here is exchanged and trusted.
    if not code:
        return "no code", 400

    r = requests.post(f"{AS}/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
    })
    tokens = r.json()
    if "id_token" not in tokens:
        return jsonify(tokens), 400

    # VULN V5b: identity is read from the id_token with NO verification.
    # No signature check, no alg pinning, no iss/aud/nonce check.
    _, claims = eng.jwt_decode_unverified(tokens["id_token"])
    session["identity"] = claims.get("sub")
    session["access_token"] = tokens["access_token"]
    return redirect("/")


@app.route("/me")
def me():
    return jsonify(identity=session.get("identity"),
                   access_token=session.get("access_token"))


if __name__ == "__main__":
    print("[vuln-client] listening on :5001")
    app.run(port=5001, threaded=True)
