"""
attacks/attack1_challenge_replay.py
===================================
ATTACK: capture one legitimate assertion, then send the exact same bytes again.

WHY IT MIGHT WORK: the assertion is signed and the signature stays valid forever.
If the server doesn't bind each assertion to a fresh, single-use challenge, an
attacker who records one login (network tap, malware, logs) can replay it to log
in again at will.

MAPS TO:  [MISSING CHECK A] challenge not validated / not consumed.
DEFEATED BY (hardened): expected_challenge enforced + challenge popped on use.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))
from client import Client  # noqa: E402


def run_attack(base_url="http://localhost:5006", true_origin="https://demo.localhost"):
    print("\n--- ATTACK 1: Challenge Replay ---")
    c = Client(base_url, true_origin)
    user = "alice_replay"

    c.register(user)
    print("  [setup] alice registered, performs one honest login...")
    resp, captured = c.login(user)
    print(f"  [setup] honest login -> {resp['status']}: {resp['message']}")

    print("  [attack] attacker re-sends the SAME captured assertion...")
    replay_resp = c.replay(user, captured)
    print(f"  [attack] replay -> {replay_resp['status']}: {replay_resp.get('message')}")

    if replay_resp["status"] == "ok":
        print("  RESULT: VULNERABLE -- the stale assertion was accepted again.")
        return True
    else:
        print("  RESULT: DEFENDED -- the replayed assertion was rejected.")
        return False


if __name__ == "__main__":
    run_attack()
