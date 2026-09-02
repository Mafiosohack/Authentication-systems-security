#!/usr/bin/env python3
"""Verify the hardened API: legitimate DPoP flow works, all five attacks fail.
Uses FastAPI's in-process TestClient (no socket).

Every check below is a REAL assert against the live response from the running
hardened_jwt_api.py. A failed property raises AssertionError naming the control,
and the script exits non-zero. Nothing prints "verification complete" unless all
14 checks actually passed. (Earlier revisions printed a verdict without asserting;
that theatre is gone.)
"""
import base64, hashlib, json, sys, time, uuid
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from fastapi.testclient import TestClient

from hardened_jwt_api import app, PUBLIC_KEY
from cryptography.hazmat.primitives import serialization

c = TestClient(app)
BASE = "http://testserver"


def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def new_key(): return ec.generate_private_key(SECP256R1())


def jwk_of(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64url(n.x.to_bytes(32, "big")),
            "y": b64url(n.y.to_bytes(32, "big"))}


def proof(key, htm, htu, token=None):
    payload = {"htm": htm, "htu": htu, "jti": uuid.uuid4().hex,
               "iat": int(time.time())}
    if token is not None:
        payload["ath"] = b64url(hashlib.sha256(token.encode()).digest())
    return jwt.encode(payload, key, algorithm="ES256",
                      headers={"typ": "dpop+jwt", "jwk": jwk_of(key)})


_PASSED = 0


def check(label, cond):
    """Assert `cond`. On failure raise AssertionError naming the property, so the
    run stops and exits non-zero. On success record and echo a PASS line."""
    global _PASSED
    assert cond, f"CHECK FAILED: {label}"
    _PASSED += 1
    print(f"    [PASS] {label}")


print("=" * 70)
print("LEGITIMATE DPoP FLOW")
print("=" * 70)
k = new_key()
r = c.post("/login", json={"username": "alice", "password": "password123"},
           headers={"dpop": proof(k, "POST", f"{BASE}/login")})
check("login succeeds with a valid DPoP proof (expected 200, got %d)" % r.status_code,
      r.status_code == 200)
access = r.json()["access_token"]
refresh = r.json()["refresh_token"]

r = c.get("/api/profile", headers={"authorization": f"DPoP {access}",
          "dpop": proof(k, "GET", f"{BASE}/api/profile", token=access)})
check("profile reachable with bound token + matching proof (expected 200, got %d)"
      % r.status_code, r.status_code == 200)
check("V6 no PII in token: profile returns only {sub, role}, got keys %s"
      % sorted(r.json().keys()),
      set(r.json().keys()) == {"sub", "role"})

r = c.get("/api/admin", headers={"authorization": f"DPoP {access}",
          "dpop": proof(k, "GET", f"{BASE}/api/admin", token=access)})
check("role enforced: alice (role=user) denied /api/admin (expected 403, got %d)"
      % r.status_code, r.status_code == 403)

print("\n" + "=" * 70)
print("V3 DEFENSE - refresh rotation + reuse detection (RFC 9700)")
print("=" * 70)
r = c.post("/refresh", headers={"refresh-token": refresh,
           "dpop": proof(k, "POST", f"{BASE}/refresh")})
check("V3 refresh rotation: a valid refresh rotates to new tokens (expected 200, got %d)"
      % r.status_code, r.status_code == 200)
new_refresh = r.json()["refresh_token"]
check("V3 refresh rotation: the rotated refresh token differs from the original",
      new_refresh != refresh)
# Replay the ORIGINAL (now-spent) refresh token: this is the theft signal.
r = c.post("/refresh", headers={"refresh-token": refresh,
           "dpop": proof(k, "POST", f"{BASE}/refresh")})
detail = str(r.json().get("detail", ""))
check("V3 reuse detection: replaying the spent refresh is rejected as reuse "
      "(expected 401 citing reuse/revocation, got %d %r)" % (r.status_code, detail),
      r.status_code == 401 and ("reuse" in detail.lower() or "revok" in detail.lower()))
# The rotated token is now also dead because the whole family was burned.
r = c.post("/refresh", headers={"refresh-token": new_refresh,
           "dpop": proof(k, "POST", f"{BASE}/refresh")})
check("V3 reuse detection: the rotated token is also dead once the family is "
      "burned (expected 401, got %d)" % r.status_code, r.status_code == 401)

print("\n" + "=" * 70)
print("V4 DEFENSE - real revocation on logout")
print("=" * 70)
k2 = new_key()
r = c.post("/login", json={"username": "alice", "password": "password123"},
           headers={"dpop": proof(k2, "POST", f"{BASE}/login")})
access2 = r.json()["access_token"]
stolen = access2  # attacker grabs a copy
r = c.post("/logout", headers={"authorization": f"DPoP {access2}",
           "dpop": proof(k2, "POST", f"{BASE}/logout", token=access2)})
check("logout succeeds for the legitimate holder (expected 200, got %d)"
      % r.status_code, r.status_code == 200)
r = c.get("/api/profile", headers={"authorization": f"DPoP {stolen}",
          "dpop": proof(k2, "GET", f"{BASE}/api/profile", token=stolen)})
detail = str(r.json().get("detail", ""))
check("V4 revocation: a token captured before logout is rejected AFTER logout "
      "(expected 401 reporting 'revoked', got %d %r)" % (r.status_code, detail),
      r.status_code == 401 and "revok" in detail.lower())

print("\n" + "=" * 70)
print("V1 DEFENSE - algorithm confusion (alg=none / RS256->HS256)")
print("=" * 70)
forged = {"sub": "alice", "role": "admin", "typ": "access", "iss":
          "https://auth.system5.local", "aud": "system5-api",
          "iat": int(time.time()), "exp": int(time.time()) + 999,
          "ver": 1, "cnf": {"jkt": "x"}, "jti": "x"}
none_tok = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode()) + "." + \
    b64url(json.dumps(forged).encode()) + "."
r = c.get("/api/admin", headers={"authorization": f"DPoP {none_tok}",
          "dpop": proof(new_key(), "GET", f"{BASE}/api/admin", token=none_tok)})
check("V1 alg pinning: an alg=none forgery is rejected (expected 401, got %d)"
      % r.status_code, r.status_code == 401)
pem = PUBLIC_KEY.public_bytes(serialization.Encoding.PEM,
      serialization.PublicFormat.SubjectPublicKeyInfo)
hdr = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
pl = b64url(json.dumps(forged).encode())
import hmac
sig = b64url(hmac.new(pem, f"{hdr}.{pl}".encode(), hashlib.sha256).digest())
hs_tok = f"{hdr}.{pl}.{sig}"
r = c.get("/api/admin", headers={"authorization": f"DPoP {hs_tok}",
          "dpop": proof(new_key(), "GET", f"{BASE}/api/admin", token=hs_tok)})
check("V1 alg pinning: an RS256->HS256 forgery (public key as HMAC secret) is "
      "rejected (expected 401, got %d)" % r.status_code, r.status_code == 401)

print("\n" + "=" * 70)
print("V5 DEFENSE - bearer replay by a different client (DPoP)")
print("=" * 70)
kv = new_key()
r = c.post("/login", json={"username": "admin", "password": "supersecret"},
           headers={"dpop": proof(kv, "POST", f"{BASE}/login")})
victim_token = r.json()["access_token"]
# Attacker has the token but NOT the victim's private key. They use their own.
katt = new_key()
r = c.get("/api/admin", headers={"authorization": f"DPoP {victim_token}",
          "dpop": proof(katt, "GET", f"{BASE}/api/admin", token=victim_token)})
check("V5 DPoP binding: a stolen token presented with the ATTACKER'S own key is "
      "rejected (expected 401, got %d)" % r.status_code, r.status_code == 401)
# And the legitimate holder still works (proves the 401 above is the binding,
# not a broken token).
r = c.get("/api/admin", headers={"authorization": f"DPoP {victim_token}",
          "dpop": proof(kv, "GET", f"{BASE}/api/admin", token=victim_token)})
check("V5 DPoP binding: the legitimate key still authenticates the same token "
      "(expected 200, got %d)" % r.status_code, r.status_code == 200)

print("\n=== hardened verification complete: %d/14 checks asserted PASS ===" % _PASSED)
assert _PASSED == 14, f"expected 14 checks, only {_PASSED} ran"
sys.exit(0)
