"""
vulnerable/server.py   --   runs on http://localhost:5006
=========================================================
A FIDO2/WebAuthn relying party with the classic beginner mistakes. It DOES
verify the assertion signature correctly -- which is exactly why it feels secure
to whoever wrote it. What it skips:

  [MISSING CHECK A]  challenge is never validated or consumed  -> replay
  [MISSING CHECK B]  origin in clientDataJSON is never checked  -> phishing
  [MISSING CHECK C]  signCount is never checked                 -> cloned key

"It verified the signature and logged me in" is the trap. A valid signature only
proves someone holds the private key. It says nothing about whether this login is
FRESH, for THIS site, or from the ONE genuine device.
"""

import os
import sys
import base64
from flask import Flask, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))
from cose import signature_is_valid, parse_authenticator_data  # noqa: E402

RP_ID = "demo.localhost"
PORT = 5006

app = Flask(__name__)

# In-memory "database". users[username] = {"public_key": cose_bytes, "sign_count": int}
users = {}
# Challenges we handed out. We store them... and then never actually enforce them.
issued_challenges = {}


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

    # Decode the attestationObject to pull out the public key. We trust it
    # blindly here (attestation "none"), which for consumer login is fine.
    import cbor2
    att_obj = cbor2.loads(b64url_decode(credential["response"]["attestationObject"]))
    auth_data = att_obj["authData"]

    # attestedCredentialData starts at byte 37: aaguid(16) credIdLen(2) credId(L) coseKey
    cred_id_len = int.from_bytes(auth_data[53:55], "big")
    cose_start = 55 + cred_id_len
    public_key_cose = auth_data[cose_start:]

    users[username] = {"public_key": public_key_cose, "sign_count": 0}
    return jsonify({"status": "registered", "username": username})


@app.post("/login/begin")
def login_begin():
    username = request.json["username"]
    challenge = os.urandom(32)
    issued_challenges[username] = challenge
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

    response = credential["response"]
    auth_data = b64url_decode(response["authenticatorData"])
    client_data_json = b64url_decode(response["clientDataJSON"])
    signature = b64url_decode(response["signature"])
    stored = users[username]

    # The ONE check this server performs: is the signature valid?
    if not signature_is_valid(stored["public_key"], auth_data, client_data_json, signature):
        return jsonify({"status": "error", "message": "bad signature"}), 401

    # [MISSING CHECK A] We never compare the challenge inside client_data_json to
    #                   issued_challenges[username], and never consume it.
    # [MISSING CHECK B] We never parse client_data_json["origin"] and compare it
    #                   to the expected origin.
    # [MISSING CHECK C] We never compare parse_authenticator_data(auth_data)
    #                   ["sign_count"] to stored["sign_count"].

    return jsonify({"status": "ok", "message": f"Welcome, {username}! (login accepted)"})


if __name__ == "__main__":
    print(f" * VULNERABLE FIDO2 server on http://localhost:{PORT}  (rp_id={RP_ID})")
    print(" * Verifies signatures only. No challenge / origin / counter checks.")
    app.run(port=PORT, debug=False)
