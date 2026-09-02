"""
hardened/rerun_attacks.py
=========================
Runs the EXACT SAME three attack scripts from attacks/, unchanged, but pointed at
the hardened server on port 5007. All three should now fail. Same attacker, same
code -- the only difference is a server that performs the checks.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "engine"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "attacks"))

import attack1_challenge_replay as a1
import attack2_origin_confusion as a2
import attack3_counter_clone as a3

HARDENED = "http://localhost:5007"
ORIGIN = "https://demo.localhost"

print("=" * 70)
print("  Re-running all attacks against the HARDENED server (5007)")
print("=" * 70)

results = {
    "Challenge replay": a1.run_attack(HARDENED, ORIGIN),
    "Origin confusion": a2.run_attack(HARDENED, ORIGIN),
    "Counter clone": a3.run_attack(HARDENED, ORIGIN),
}

print("\n" + "=" * 70)
print("  SUMMARY (False = attack failed = defense held)")
for name, succeeded in results.items():
    verdict = "STILL VULNERABLE" if succeeded else "DEFENDED"
    print(f"   {name:<20} attack_succeeded={succeeded!s:<5}  -> {verdict}")
print("=" * 70)

if any(results.values()):
    sys.exit(1)
print("  All attacks defeated.")
