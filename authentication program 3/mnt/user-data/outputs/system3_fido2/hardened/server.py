"""
hardened/server.py   --   runs on http://localhost:5007
========================================================
The same relying party, done correctly, delegating verification to the
production `py_webauthn` library. The fixes, one per vulnerability:

  [FIX A]  challenge is stored per-user, passed as expected_challenge, and
           CONSUMED on use  -> a replayed assertion carries a stale challenge
           that no longer matches, and is rejected.
  [FIX B]  expected_origin is enforced  -> an assertion whose clientDataJSON
           says https://evil.localhost is rejected. THIS is what kills phishing.
  [FIX C]  signCount is tracked; a non-increasing counter is treated as a
           possible cloned authenticator and rejected.
  [FIX D]  bounded reuse for always-zero counters. Synced/platform passkeys
           report signCount=0 forever, and the spec (and py_webauthn) skip the
           monotonic check when both stored and asserted counts are 0. So a
           record that is still at 0 gets a separate budget: after
           ZERO_COUNT_MAX_USES successful zero-count logins the credential is
           retired and the user must re-register. FIX C is untouched.

We still use attestation "none" at registration. As covered in the report,
ignoring attestation is a deliberate, standard choice for consumer login, not a
vulnerability -- so it is NOT in the hardened "fix" list.
"""

import os
import sys
import json
import base64
from flask import Flask, request, jsonify

import webauthn
from webauthn.helpers import exceptions as wa_exc

RP_ID = "demo.localhost"
EXPECTED_ORIGIN = "https://demo.localhost"
PORT = 5007

# [FIX D] how many successful signCount=0 logins a credential may perform while
# its stored counter is also 0, before it is retired.
ZERO_COUNT_MAX_USES = 5

app = Flask(__name__)

users = {}              # username -> {"public_key": bytes, "sign_count": int,
                        #              "zero_count_uses": int, "retired": bool}
issued_challenges = {}  # username -> bytes (single-use)


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@app.post("/register/begin")
def register_begin():
    username = request.json["username"]
    challenge = os.urandom(32)
    issued_challenges[username] = challenge
    return jsonify({
        "challenge": base64.urlsafe_b64encode(challenge).rstrip(b"=").decode(),
        "rp_id": RP_ID,
    })


@app.post("/register/finish")
def register_finish():
    username = request.json["username"]
    credential = request.json["credential"]
    expected = issued_challenges.pop(username, None)
    if expected is None:
        return jsonify({"status": "error", "message": "no challenge issued"}), 400

    try:
        verified = webauthn.verify_registration_response(
            credential=json.dumps(credential),
            expected_challenge=expected,
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,
        )
    except wa_exc.InvalidRegistrationResponse as e:
        return jsonify({"status": "error", "message": f"registration rejected: {e}"}), 400

    users[username] = {
        "public_key": verified.credential_public_key,
        "sign_count": verified.sign_count,
        "zero_count_uses": 0,   # [FIX D] separate from sign_count, never repurposed
        "retired": False,       # [FIX D] set once the zero-count budget is spent
    }
    return jsonify({"status": "registered", "username": username})


@app.post("/login/begin")
def login_begin():
    username = request.json["username"]
    challenge = os.urandom(32)
    issued_challenges[username] = challenge   # overwrites any previous; single-use
    return jsonify({
        "challenge": base64.urlsafe_b64encode(challenge).rstrip(b"=").decode(),
        "rp_id": RP_ID,
    })


@app.post("/login/finish")
def login_finish():
    username = request.json["username"]
    credential = request.json["credential"]
    if username not in users:
        return jsonify({"status": "error", "message": "unknown user"}), 400

    # [FIX A] consume the challenge: pop it so it can never be used twice.
    expected = issued_challenges.pop(username, None)
    if expected is None:
        return jsonify({"status": "error", "message": "no pending challenge (already used?)"}), 401

    stored = users[username]

    # [FIX D] a retired credential is rejected outright. Distinct status and
    # message from "unknown user" (400) and "no pending challenge" (401).
    if stored["retired"]:
        return jsonify({
            "status": "error",
            "message": (f"credential retired: signCount=0 authenticator reached "
                        f"{ZERO_COUNT_MAX_USES} uses; re-register to continue"),
        }), 403

    try:
        verified = webauthn.verify_authentication_response(
            credential=json.dumps(credential),
            expected_challenge=expected,            # [FIX A] freshness
            expected_rp_id=RP_ID,
            expected_origin=EXPECTED_ORIGIN,        # [FIX B] anti-phishing
            credential_public_key=stored["public_key"],
            credential_current_sign_count=stored["sign_count"],  # [FIX C] clone check
        )
    except wa_exc.InvalidAuthenticationResponse as e:
        return jsonify({"status": "error", "message": f"login rejected: {e}"}), 401

    # [FIX C] belt-and-suspenders: reject a counter that did not advance.
    if verified.new_sign_count <= stored["sign_count"] and stored["sign_count"] != 0:
        return jsonify({"status": "error",
                        "message": "possible cloned authenticator (counter did not advance)"}), 401

    # [FIX D] the always-zero case: asserted 0 against stored 0 is the one
    # situation FIX C (and the library) deliberately let through. Budget it.
    if verified.new_sign_count == 0 and stored["sign_count"] == 0:
        stored["zero_count_uses"] += 1
        if stored["zero_count_uses"] >= ZERO_COUNT_MAX_USES:
            stored["retired"] = True

    stored["sign_count"] = verified.new_sign_count
    return jsonify({"status": "ok", "message": f"Welcome, {username}! (verified)"})


if __name__ == "__main__":
    print(f" * HARDENED FIDO2 server on http://localhost:{PORT}  (rp_id={RP_ID})")
    print(f" * Enforces challenge (single-use), origin ({EXPECTED_ORIGIN}), and counter.")
    app.run(port=PORT, debug=False)
