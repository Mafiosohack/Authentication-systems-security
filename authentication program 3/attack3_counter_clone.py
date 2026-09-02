"""
attacks/attack3_counter_clone.py
================================
ATTACK: an attacker who extracted the private key runs a CLONED authenticator
alongside the victim's real one.

Both devices hold the same key and credential id, so both produce valid
signatures. The only protocol-level tripwire is the signature counter: each
device counts its own logins independently, so the two counters drift apart. A
server that tracks the counter sees a login whose counter is LOWER than the last
one it recorded -- impossible for a single honest device -- and flags a clone.

WHY IT MIGHT WORK: if the server never stores or compares signCount, the clone
is indistinguishable from the original.

MAPS TO:  [MISSING CHECK C] signCount never tracked.
DEFEATED BY (hardened): counter regression rejected as a suspected clone.

CAVEAT (put this in the report): many synced passkeys report signCount = 0 on
every assertion, so counter-based clone detection is eroding industry-wide. It
remains meaningful for single-device hardware authenticators.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))
from client import Client, clone_device  # noqa: E402


def run_attack(base_url="http://localhost:5006", true_origin="https://demo.localhost"):
    print("\n--- ATTACK 3: Cloned Authenticator (signature counter) ---")
    c = Client(base_url, true_origin)
    user = "carol_clone"

    c.register(user)
    print("  [setup] carol registered; she logs in twice on her real device...")
    for _ in range(2):
        resp, _ = c.login(user)
    print(f"  [setup] real device now at higher counter; server last saw it advancing.")

    print("  [attack] attacker clones the key (counter resets to its own zero)...")
    clone = clone_device(c.devices[user])
    resp, _ = c.login(user, device=clone)
    print(f"  [attack] clone login -> {resp['status']}: {resp.get('message')}")

    if resp["status"] == "ok":
        print("  RESULT: VULNERABLE -- clone accepted; counter never checked.")
        return True
    else:
        print("  RESULT: DEFENDED -- counter regression flagged the clone.")
        return False


if __name__ == "__main__":
    run_attack()
