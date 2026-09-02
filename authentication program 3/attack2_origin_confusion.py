"""
attacks/attack2_origin_confusion.py
===================================
ATTACK: the phishing / adversary-in-the-middle scenario -- the one TOTP could
never survive.

The victim is lured to https://evil.localhost. Their browser (here, our client)
honestly stamps the origin it actually sees -- evil.localhost -- into
clientDataJSON, and the victim's real authenticator signs it against a FRESH
challenge relayed from the genuine server. The attacker forwards this perfectly
valid, perfectly fresh assertion to the real server.

WHY IT MIGHT WORK: the signature is valid and the challenge is fresh. The ONLY
thing that betrays the attack is the origin embedded in clientDataJSON. If the
server doesn't check it, the phish succeeds.

MAPS TO:  [MISSING CHECK B] origin never verified.
DEFEATED BY (hardened): expected_origin enforced -> evil.localhost != demo.localhost.

NOTE (state this when presenting): a real browser would refuse to use the
demo.localhost credential on evil.localhost at all (RP ID scoping), so layer one
stops this before it starts. We simulate the client to demonstrate the server's
backstop -- layer two -- which is the check developers actually forget.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))
from client import Client  # noqa: E402

PHISHING_ORIGIN = "https://evil.localhost"


def run_attack(base_url="http://localhost:5006", true_origin="https://demo.localhost"):
    print("\n--- ATTACK 2: Origin Confusion (Phishing) ---")
    c = Client(base_url, true_origin)
    user = "bob_phish"

    c.register(user)
    print(f"  [setup] bob registered on the real site ({true_origin}).")

    print(f"  [attack] bob is phished; his browser stamps origin={PHISHING_ORIGIN}")
    print("  [attack] his real key signs a FRESH challenge; attacker relays it...")
    resp, _ = c.login(user, origin=PHISHING_ORIGIN)
    print(f"  [attack] relayed assertion -> {resp['status']}: {resp.get('message')}")

    if resp["status"] == "ok":
        print("  RESULT: VULNERABLE -- phishing succeeded; origin was ignored.")
        return True
    else:
        print("  RESULT: DEFENDED -- origin mismatch rejected the phish.")
        return False


if __name__ == "__main__":
    run_attack()
