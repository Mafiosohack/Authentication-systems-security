#!/usr/bin/env python3
"""
System 5 - JWT-Based Token Authentication for Stateless APIs
PHASE 1: VULNERABLE IMPLEMENTATION  (Flask)

This is the API a developer builds when they read "use JWTs for stateless auth"
on a blog and stop there. It works. It demos. And it is broken in six distinct
ways, numbered inline as VULN-1 .. VULN-6 for presenter clarity.

Run:  python3 vulnerable_jwt_api.py     (listens on http://localhost:5008)

Stack note: per series convention, the VULNERABLE app is Flask, the HARDENED
app is FastAPI. The point is the auth logic, not the framework.
"""

import time
import base64
import json
import jwt  # PyJWT
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Server keypair. The server INTENDS to sign tokens with RS256 (asymmetric).
# The public key is published at /jwks - which is completely normal and correct
# on its own. The danger is entirely in how verification is written (VULN-1).
# Fixed seed-free generation per boot is fine because attacks fetch the live key.
# ---------------------------------------------------------------------------
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = _private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
PUBLIC_PEM = _private_key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

# In-memory "database". Passwords stored as plaintext - not the focus of this
# system (covered in System 1), kept trivial so the lab stays about tokens.
USERS = {
    "alice": {"password": "password123", "role": "user",
              "email": "alice@corp.internal", "employee_id": "E-1007"},
    "admin": {"password": "supersecret",  "role": "admin",
              "email": "root@corp.internal", "employee_id": "E-0001"},
}

# VULN-3 support: refresh tokens are just stored in a set and never rotated or
# invalidated. Once issued, a refresh token is valid until the heat death of
# the universe.
ISSUED_REFRESH_TOKENS = set()


# ===========================================================================
# TOKEN ISSUANCE
# ===========================================================================
def issue_access_token(username):
    user = USERS[username]
    payload = {
        "sub": username,
        "role": user["role"],
        # VULN-6: Sensitive data baked into the token. A JWT payload is signed,
        # NOT encrypted - it is base64url, readable by anyone holding the token.
        # PII and internal identifiers do not belong here.
        "email": user["email"],
        "employee_id": user["employee_id"],
        "iat": int(time.time()),
        # VULN-2: No "exp" claim. These access tokens never expire. Combined
        # with VULN-4 (no revocation) a single leaked token is permanent access.
        # Also no "aud" and no "iss" - nothing binds this token to THIS API.
    }
    return jwt.encode(payload, PRIVATE_PEM, algorithm="RS256")


def issue_refresh_token(username):
    payload = {"sub": username, "type": "refresh", "iat": int(time.time())}
    token = jwt.encode(payload, PRIVATE_PEM, algorithm="RS256")
    ISSUED_REFRESH_TOKENS.add(token)
    return token


# ===========================================================================
# TOKEN VERIFICATION  <-- the heart of the vulnerability surface
# ===========================================================================
def verify_access_token(token):
    """
    VULN-1 (Algorithm confusion): This function reads the algorithm out of the
    token's OWN header and trusts it. That single decision enables two attacks:

      * alg=none  -> attacker strips the signature entirely and we 'verify'
                     nothing, accepting any forged payload.
      * alg=HS256 -> attacker re-signs the token with HMAC, using the server's
                     PUBLIC RSA key (published at /jwks) as the HMAC secret.
                     We hand PyJWT the public key as the HMAC key and it
                     happily validates the attacker's forgery.
                     (RFC 8725 s2.1; CVE-2015-9235)

    The correct code pins the algorithm: algorithms=["RS256"]. This does not.
    """
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "RS256")

    if alg == "none":
        # Trusting alg=none: decode with signature verification disabled.
        return jwt.decode(token, options={"verify_signature": False})

    # VULN-1 continued: the verification key is chosen by the attacker-controlled
    # alg. For HS256 the PUBLIC key bytes are (mis)used as the HMAC secret.
    # NOTE: PyJWT deliberately refuses to use a PEM as an HMAC key, so the bug
    # only ships when a developer hand-rolls verification (or uses an outdated
    # library). That naive code is reproduced here so the attack is real:
    if alg.startswith("HS"):
        import hmac as _hmac, hashlib as _hashlib
        header_seg, payload_seg, sig_seg = token.split(".")
        signing_input = f"{header_seg}.{payload_seg}".encode()
        expected = _hmac.new(PUBLIC_PEM, signing_input, _hashlib.sha256).digest()
        got = base64.urlsafe_b64decode(sig_seg + "=" * (-len(sig_seg) % 4))
        if _hmac.compare_digest(expected, got):
            return json.loads(base64.urlsafe_b64decode(
                payload_seg + "=" * (-len(payload_seg) % 4)))
        raise ValueError("bad HS256 signature")

    # VULN-2 continued: verify_exp/aud/iss all effectively off - tokens carry
    # none of those claims, and we ask for none of them.
    return jwt.decode(token, PUBLIC_PEM, algorithms=[alg],
                      options={"verify_exp": False})


def bearer_token():
    h = request.headers.get("Authorization", "")
    return h[7:] if h.startswith("Bearer ") else None


# ===========================================================================
# ENDPOINTS
# ===========================================================================
@app.route("/jwks")
def jwks():
    # Publishing the public key is normal. It is only dangerous because of the
    # broken verifier (VULN-1). Real JWKS endpoints look just like this.
    return PUBLIC_PEM, 200, {"Content-Type": "application/x-pem-file"}


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    u, p = data.get("username"), data.get("password")
    if u in USERS and USERS[u]["password"] == p:
        return jsonify(access_token=issue_access_token(u),
                       refresh_token=issue_refresh_token(u))
    return jsonify(error="invalid credentials"), 401


@app.route("/api/profile")
def profile():
    tok = bearer_token()
    if not tok:
        return jsonify(error="missing token"), 401
    try:
        claims = verify_access_token(tok)
    except Exception as e:
        return jsonify(error=f"invalid token: {e}"), 401
    return jsonify(message=f"profile for {claims['sub']}", claims=claims)


@app.route("/api/admin")
def admin():
    tok = bearer_token()
    if not tok:
        return jsonify(error="missing token"), 401
    try:
        claims = verify_access_token(tok)
    except Exception as e:
        return jsonify(error=f"invalid token: {e}"), 401
    # Authorization decision rides entirely on a claim inside the token. If the
    # token can be forged (VULN-1), this check is meaningless.
    if claims.get("role") != "admin":
        return jsonify(error="forbidden - admin only"), 403
    return jsonify(message="TOP SECRET admin panel",
                   data="all user records, billing, kill switch")


@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.get_json(force=True)
    rt = data.get("refresh_token")
    # VULN-3: No rotation, no reuse detection. The same refresh token can be
    # presented forever, by anyone who has a copy, and we mint a fresh access
    # token every time. A stolen refresh token = indefinite access, and the
    # legitimate user never sees a sign anything is wrong.
    if rt in ISSUED_REFRESH_TOKENS:
        try:
            claims = jwt.decode(rt, PUBLIC_PEM, algorithms=["RS256"])
        except Exception as e:
            return jsonify(error=f"bad refresh: {e}"), 401
        return jsonify(access_token=issue_access_token(claims["sub"]))
    return jsonify(error="unknown refresh token"), 401


@app.route("/logout", methods=["POST"])
def logout():
    # VULN-4: The stateless logout paradox, done wrong. This endpoint returns
    # 200 and does NOTHING server-side. The access token the client was using
    # remains fully valid until it expires - and per VULN-2 it never expires.
    # "Logout" here is pure theatre.
    return jsonify(message="logged out (client should delete its token)")


if __name__ == "__main__":
    print("[VULNERABLE] System 5 JWT API on http://localhost:5008")
    print("[VULNERABLE] users: alice/password123 (user), admin/supersecret (admin)")
    app.run(port=5008, debug=False)
