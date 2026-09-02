#!/usr/bin/env python3
"""Run the five System 5 attacks against the HARDENED API and assert each one is
blocked. No socket: FastAPI's in-process TestClient.

One function per attack script, reproducing that script's exploit step against
hardened_jwt_api.py. Where the exploit needs a legitimately issued token first
(refresh replay, use-after-logout, bearer replay) the legitimate step is done
with a proper DPoP proof so the assert isolates the control under test rather
than tripping over the DPoP requirement at /login.

    attack_alg_confusion.py       -> V1 alg pinning
    attack_no_expiry.py           -> V2 mandatory exp
    attack_refresh_no_rotation.py -> V3 rotation + reuse detection
    attack_no_revocation.py       -> V4 logout revocation
    attack_bearer_replay.py       -> V5 DPoP sender-constraining

Each attack function returns True when the attacker GAINED what the attack is
after. The harness asserts every return is False and exits non-zero otherwise.
No blanket except: an unexpected exception is a failure, not a print.
"""
import base64, hashlib, hmac, json, sys, time, uuid
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from fastapi.testclient import TestClient

from hardened_jwt_api import app, PUBLIC_KEY

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


def login(key, username="alice", password="password123"):
    r = c.post("/login", json={"username": username, "password": password},
               headers={"dpop": proof(key, "POST", f"{BASE}/login")})
    assert r.status_code == 200, f"setup: legitimate login failed ({r.status_code})"
    return r.json()["access_token"], r.json()["refresh_token"]


def resource(path, token, key):
    return c.get(path, headers={"authorization": f"DPoP {token}",
                                "dpop": proof(key, "GET", f"{BASE}{path}", token=token)})


def claims_of(tok):
    seg = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


# ---------------------------------------------------------------------------
# The attacks. Each returns True iff the attacker gained what the attack is for.
# ---------------------------------------------------------------------------
def attack_alg_confusion():
    """attack_alg_confusion.py: forge an admin token via alg=none and via
    RS256->HS256 using the published public key as the HMAC secret. Gain = any
    forgery reaches /api/admin with 200."""
    forged = {"sub": "alice", "role": "admin", "typ": "access",
              "iss": "https://auth.system5.local", "aud": "system5-api",
              "iat": int(time.time()), "exp": int(time.time()) + 999,
              "ver": 1, "cnf": {"jkt": "x"}, "jti": uuid.uuid4().hex}
    none_tok = (b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode()) + "." +
                b64url(json.dumps(forged).encode()) + ".")
    pem = PUBLIC_KEY.public_bytes(serialization.Encoding.PEM,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    hdr = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pl = b64url(json.dumps(forged).encode())
    sig = b64url(hmac.new(pem, f"{hdr}.{pl}".encode(), hashlib.sha256).digest())
    hs_tok = f"{hdr}.{pl}.{sig}"
    a = resource("/api/admin", none_tok, new_key())
    b = resource("/api/admin", hs_tok, new_key())
    print(f"    alg=none forgery -> HTTP {a.status_code}; RS256->HS256 forgery -> HTTP {b.status_code}")
    return a.status_code == 200 or b.status_code == 200


def attack_no_expiry():
    """attack_no_expiry.py: the attack's premise is that access tokens carry no
    'exp'. Gain = a token without exp (or with an exp not in the future) that the
    API accepts."""
    key = new_key()
    access, _ = login(key)
    cl = claims_of(access)
    has_exp = "exp" in cl
    exp_in_future = has_exp and cl["exp"] > int(time.time())
    accepted = resource("/api/profile", access, key).status_code == 200
    print(f"    token has exp={has_exp} (future={exp_in_future}); accepted now={accepted}")
    return not (has_exp and exp_in_future)


def attack_refresh_no_rotation():
    """attack_refresh_no_rotation.py: redeem a stolen refresh token repeatedly
    while the victim keeps using the same one. Gain = the same refresh token is
    redeemed more than once, or the victim's parallel use raises no alarm."""
    key = new_key()
    _, refresh = login(key)
    stolen = refresh
    def redeem(rt):
        r = c.post("/refresh", headers={"refresh-token": rt,
                   "dpop": proof(key, "POST", f"{BASE}/refresh")})
        return r.status_code == 200 and "access_token" in r.json(), r.status_code
    a1, s1 = redeem(stolen)   # first redemption is legitimate-looking
    a2, s2 = redeem(stolen)   # second use of the SAME token = reuse
    a3, s3 = redeem(stolen)
    legit, s4 = redeem(refresh)  # victim tries the original too
    print(f"    attacker redeem #1/#2/#3 -> {s1}/{s2}/{s3}; victim -> {s4}")
    # Attack gains if ANY redemption after the first succeeds, or the victim's
    # reuse of the spent token succeeds.
    return a2 or a3 or legit


def attack_no_revocation():
    """attack_no_revocation.py: a token captured before logout is replayed after
    the victim logs out. Gain = the stolen token still reaches /api/profile."""
    key = new_key()
    access, _ = login(key)
    stolen = access
    before = resource("/api/profile", stolen, key).status_code
    lo = c.post("/logout", headers={"authorization": f"DPoP {access}",
                "dpop": proof(key, "POST", f"{BASE}/logout", token=access)})
    assert lo.status_code == 200, f"setup: logout failed ({lo.status_code})"
    after = resource("/api/profile", stolen, key).status_code
    print(f"    stolen token before logout -> {before}; after logout -> {after}")
    return before == 200 and after == 200


def attack_bearer_replay():
    """attack_bearer_replay.py: an unrelated client replays the victim's token.
    Here the attacker has the token but not the victim's DPoP key, so they sign
    a proof with their own key. Gain = the resource accepts it."""
    kv = new_key()
    access, _ = login(kv)
    katt = new_key()
    r = resource("/api/profile", access, katt)
    r_legit = resource("/api/profile", access, kv)
    print(f"    attacker's key -> HTTP {r.status_code}; victim's own key -> HTTP {r_legit.status_code}")
    assert r_legit.status_code == 200, "setup: the legitimate holder must still work"
    return r.status_code == 200


ATTACKS = [
    ("attack_alg_confusion",       "V1 alg pinning",              attack_alg_confusion),
    ("attack_no_expiry",           "V2 mandatory expiry",         attack_no_expiry),
    ("attack_refresh_no_rotation", "V3 rotation + reuse detection", attack_refresh_no_rotation),
    ("attack_no_revocation",       "V4 logout revocation",        attack_no_revocation),
    ("attack_bearer_replay",       "V5 DPoP sender-constraining", attack_bearer_replay),
]

failures = []
for name, control, fn in ATTACKS:
    print(f"\n{'#' * 22} {name} {'#' * 22}")
    gained = fn()
    if gained:
        failures.append(f"{name} SUCCEEDED against the hardened build -> {control} is NOT holding")
        print(f"    [FAIL] attacker gained -> {control} broken")
    else:
        print(f"    [PASS] attack blocked by {control}")

print("\n" + "=" * 70)
if failures:
    for f in failures:
        print("[!] " + f)
    print(f"=== verification FAILED: {len(failures)}/{len(ATTACKS)} attacks succeeded ===")
    sys.exit(1)
assert len(ATTACKS) == 5
print("=== verification complete: all 5 attacks blocked by the hardened build ===")
sys.exit(0)
