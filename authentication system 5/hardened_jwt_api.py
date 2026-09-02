#!/usr/bin/env python3
"""
System 5 - JWT-Based Token Authentication for Stateless APIs
PHASE 3: HARDENED IMPLEMENTATION  (FastAPI)

A clean rebuild with security designed in, not patched on. Each defense cites
the vulnerability it closes (V1..V6 from the vulnerable app) and the standard
it follows. Where a defense reintroduces server state, the tradeoff is named.

Design summary
  V1 alg confusion   -> algorithm PINNED to RS256; alg=none and HS256 rejected
                        outright (RFC 8725 s3.1/s3.2).
  V2 no expiry       -> short-lived access tokens (15 min) with exp/iat/iss/aud
                        all validated (RFC 7519 s4.1; RFC 8725 s3.8).
  V3 no rotation     -> refresh tokens rotate on every use, with reuse detection:
                        replaying a spent refresh token revokes the whole family
                        (RFC 9700 s4.13/s4.14 - "Refresh Token Protection").
  V4 no revocation   -> per-user token_version + short TTL gives real revocation.
                        This DELIBERATELY reintroduces minimal server state - the
                        stateless-purity tradeoff, made consciously.
  V5 bearer replay   -> DPoP sender-constraining (RFC 9449): the access token is
                        bound to the client's key (cnf.jkt); every request must
                        carry a fresh proof signed by that key. A stolen token
                        alone is useless.
  V6 PII in token    -> token carries only sub/role; no email/employee_id. A JWT
                        is signed, not encrypted - assume the payload is readable.

Run:  uvicorn hardened_jwt_api:app --port 5009
"""

import base64
import hashlib
import json
import time
import uuid

import jwt  # PyJWT - audited library, used with STRICT settings
from argon2 import PasswordHasher
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicNumbers, SECP256R1)

app = FastAPI(title="System 5 - Hardened JWT API")

# --- Named constants (no magic numbers; all security-relevant) ---------------
SIGNING_ALG = "RS256"          # PINNED. The verifier never reads alg from a token.
ACCESS_TTL = 15 * 60           # 15 minutes - short by design (V2/V4)
REFRESH_TTL = 30 * 24 * 60 * 60
ISSUER = "https://auth.system5.local"
AUDIENCE = "system5-api"
DPOP_MAX_AGE = 60              # a DPoP proof older than this is rejected (replay)

# --- Server RSA signing keypair (RS256) --------------------------------------
_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_KEY = _priv
PUBLIC_KEY = _priv.public_key()

# --- "Database" --------------------------------------------------------------
_ph = PasswordHasher()
USERS = {
    "alice": {"hash": _ph.hash("password123"), "role": "user"},
    "admin": {"hash": _ph.hash("supersecret"), "role": "admin"},
}
# V4: minimal reintroduced state. Bumping a user's version invalidates every
# access token already issued to them. This is the price of real revocation in
# an otherwise-stateless design, and it is a deliberate, bounded amount of state.
TOKEN_VERSION = {"alice": 1, "admin": 1}

# V3: refresh-token family store. jti -> {family, sub, used}. A "family" is one
# login's chain of rotating refresh tokens.
REFRESH_STORE: dict[str, dict] = {}
REVOKED_FAMILIES: set[str] = set()

# V5: DPoP proof replay cache - jti -> expiry. Bounded by DPOP_MAX_AGE.
SEEN_DPOP_JTI: dict[str, float] = {}


# ===========================================================================
# Helpers
# ===========================================================================
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint: SHA-256 over the canonical required members,
    in lexicographic order, no whitespace. This is the stable identifier we
    bind an access token to (cnf.jkt)."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"), sort_keys=True).encode()
    return _b64url(hashlib.sha256(canonical).digest())


def issue_access_token(sub: str, jkt: str) -> str:
    now = int(time.time())
    claims = {
        "sub": sub,
        "role": USERS[sub]["role"],
        "typ": "access",
        "iss": ISSUER,          # V2: bind token to this issuer
        "aud": AUDIENCE,        # V2: bind token to this API
        "iat": now,
        "exp": now + ACCESS_TTL,  # V2: short, mandatory expiry
        "ver": TOKEN_VERSION[sub],  # V4: revocation hook
        "cnf": {"jkt": jkt},    # V5: bind token to the client's DPoP key
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, PRIVATE_KEY, algorithm=SIGNING_ALG)


def issue_refresh_token(sub: str, family: str) -> str:
    now = int(time.time())
    jti = uuid.uuid4().hex
    REFRESH_STORE[jti] = {"family": family, "sub": sub, "used": False}
    claims = {"sub": sub, "typ": "refresh", "family": family, "jti": jti,
              "iss": ISSUER, "iat": now, "exp": now + REFRESH_TTL}
    return jwt.encode(claims, PRIVATE_KEY, algorithm=SIGNING_ALG)


def verify_access_token(token: str) -> dict:
    """Strict verification. The algorithm is pinned; alg=none and HS256 forgeries
    are rejected because PyJWT is told the ONLY acceptable algorithm is RS256 and
    is handed the RSA public key (V1)."""
    try:
        claims = jwt.decode(
            token, PUBLIC_KEY,
            algorithms=[SIGNING_ALG],          # V1: no algorithm agility
            audience=AUDIENCE, issuer=ISSUER,  # V2
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"invalid token: {e}")
    if claims.get("typ") != "access":
        raise HTTPException(401, "wrong token type")
    # V4: revocation check. A token whose version is behind the user's current
    # version was issued before a logout/credential-change and is dead.
    if claims.get("ver") != TOKEN_VERSION.get(claims["sub"]):
        raise HTTPException(401, "token revoked")
    return claims


def verify_dpop_proof(proof: str, htm: str, htu: str,
                      access_token: str | None = None) -> str:
    """Verify a DPoP proof JWT (RFC 9449) and return the key thumbprint (jkt).

    The proof is self-signed with the client's private key; the public JWK is in
    its header. Verifying the proof proves the presenter HOLDS that private key.
    Binding the resulting jkt to the access token's cnf.jkt is what stops a
    stolen bearer token from being used by anyone else (V5)."""
    try:
        header = json.loads(_b64url_decode(proof.split(".")[0]))
    except Exception:
        raise HTTPException(401, "malformed DPoP proof")
    if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
        raise HTTPException(401, "bad DPoP header")
    jwk = header.get("jwk") or {}
    try:
        pub = EllipticCurvePublicNumbers(
            int.from_bytes(_b64url_decode(jwk["x"]), "big"),
            int.from_bytes(_b64url_decode(jwk["y"]), "big"),
            SECP256R1()).public_key()
    except Exception:
        raise HTTPException(401, "bad DPoP jwk")
    try:
        body = jwt.decode(proof, pub, algorithms=["ES256"])
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"DPoP signature invalid: {e}")

    # Bind the proof to THIS request (method + URL) - RFC 9449 s4.2.
    if body.get("htm") != htm or body.get("htu") != htu:
        raise HTTPException(401, "DPoP htm/htu mismatch")
    # Freshness + single-use (replay protection).
    iat = body.get("iat", 0)
    if abs(time.time() - iat) > DPOP_MAX_AGE:
        raise HTTPException(401, "DPoP proof expired")
    jti = body.get("jti")
    now = time.time()
    for k, exp in list(SEEN_DPOP_JTI.items()):  # opportunistic cleanup
        if exp < now:
            del SEEN_DPOP_JTI[k]
    if not jti or jti in SEEN_DPOP_JTI:
        raise HTTPException(401, "DPoP proof replay")
    SEEN_DPOP_JTI[jti] = now + DPOP_MAX_AGE
    # When presented with an access token, the proof must also commit to it via
    # the ath claim - SHA-256 of the access token (RFC 9449 s4.2).
    if access_token is not None:
        expected_ath = _b64url(hashlib.sha256(access_token.encode()).digest())
        if body.get("ath") != expected_ath:
            raise HTTPException(401, "DPoP ath mismatch")
    return jwk_thumbprint(jwk)


def authed_claims(request: Request, authorization: str, dpop: str) -> dict:
    """Resolve a DPoP-bound access token for a resource request."""
    if not authorization.startswith("DPoP "):
        raise HTTPException(401, "expected DPoP-scheme Authorization")
    token = authorization[5:]
    claims = verify_access_token(token)
    htu = str(request.url).split("?")[0]
    jkt = verify_dpop_proof(dpop, request.method, htu, access_token=token)
    # V5: the proof's key MUST match the key the token was bound to at issuance.
    if claims["cnf"]["jkt"] != jkt:
        raise HTTPException(401, "token not bound to this DPoP key")
    return claims


# ===========================================================================
# Endpoints
# ===========================================================================
class LoginBody(BaseModel):
    username: str
    password: str


@app.get("/jwks")
def jwks():
    # Safe to publish: the algorithm is pinned, so this key can only ever be
    # used to VERIFY RS256 - it can never be coerced into an HMAC secret (V1).
    pem = PUBLIC_KEY.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"public_key_pem": pem.decode()}


@app.post("/login")
def login(body: LoginBody, request: Request, dpop: str = Header(default="")):
    user = USERS.get(body.username)
    try:
        if not user:
            raise Exception()
        _ph.verify(user["hash"], body.password)  # argon2 (V-from System 1)
    except Exception:
        raise HTTPException(401, "invalid credentials")
    if not dpop:
        raise HTTPException(400, "DPoP proof required")
    # Bind this login's tokens to the client's key.
    htu = str(request.url).split("?")[0]
    jkt = verify_dpop_proof(dpop, "POST", htu)
    family = uuid.uuid4().hex
    return {
        "access_token": issue_access_token(body.username, jkt),
        "refresh_token": issue_refresh_token(body.username, family),
        "token_type": "DPoP",
    }


@app.post("/refresh")
def refresh(request: Request, refresh_token: str = Header(default=""),
            dpop: str = Header(default="")):
    if not refresh_token or not dpop:
        raise HTTPException(400, "refresh_token and DPoP headers required")
    try:
        claims = jwt.decode(refresh_token, PUBLIC_KEY, algorithms=[SIGNING_ALG],
                            issuer=ISSUER, options={"require": ["exp", "jti"]})
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"invalid refresh token: {e}")
    if claims.get("typ") != "refresh":
        raise HTTPException(401, "wrong token type")

    jti, family, sub = claims["jti"], claims["family"], claims["sub"]
    # V3: reuse detection. A refresh token already spent, or from a revoked
    # family, means theft - burn the entire family so neither party can refresh.
    if family in REVOKED_FAMILIES or REFRESH_STORE.get(jti, {}).get("used", True):
        REVOKED_FAMILIES.add(family)
        raise HTTPException(401, "refresh token reuse detected - family revoked")

    htu = str(request.url).split("?")[0]
    jkt = verify_dpop_proof(dpop, "POST", htu)
    REFRESH_STORE[jti]["used"] = True              # V3: rotation - old token dies
    return {
        "access_token": issue_access_token(sub, jkt),
        "refresh_token": issue_refresh_token(sub, family),  # V3: new one issued
        "token_type": "DPoP",
    }


@app.get("/api/profile")
def profile(request: Request, authorization: str = Header(default=""),
            dpop: str = Header(default="")):
    claims = authed_claims(request, authorization, dpop)
    # V6: only non-sensitive claims exist to return.
    return {"sub": claims["sub"], "role": claims["role"]}


@app.get("/api/admin")
def admin(request: Request, authorization: str = Header(default=""),
          dpop: str = Header(default="")):
    claims = authed_claims(request, authorization, dpop)
    if claims.get("role") != "admin":
        raise HTTPException(403, "admin only")
    return {"message": "admin panel", "data": "sensitive records"}


@app.post("/logout")
def logout(request: Request, authorization: str = Header(default=""),
           dpop: str = Header(default="")):
    claims = authed_claims(request, authorization, dpop)
    sub = claims["sub"]
    # V4: REAL revocation. Bumping the version instantly invalidates every
    # outstanding access token for this user; revoking their families kills
    # refresh too. Logout is no longer theatre.
    TOKEN_VERSION[sub] += 1
    for info in REFRESH_STORE.values():
        if info["sub"] == sub:
            REVOKED_FAMILIES.add(info["family"])
    return {"message": "logged out - all tokens for this user revoked"}
