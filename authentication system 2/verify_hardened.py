"""
HARDENED VERIFICATION — run the same attacks against the hardened app (5004)
and confirm each one now fails (except phishing, which we acknowledge).
"""
import requests, pyotp, time

T = "http://127.0.0.1:5004"
U, P = "admin", "SuperSecret123"
SECRET = "JBSWY3DPEHPK3PXP"

def test_mfa_bypass():
    s = requests.Session()
    s.post(f"{T}/login", data={"username": U, "password": P})
    r = s.get(f"{T}/dashboard")  # try to skip TOTP
    blocked = "Dashboard" not in r.text
    print(f"  MFA Bypass (V6)      : {'BLOCKED' if blocked else 'STILL VULNERABLE'}")

def test_secret_leak():
    r = requests.get(f"{T}/totp-secret", params={"user": U})
    blocked = r.status_code == 404
    print(f"  Secret endpoint (V5) : {'BLOCKED (404, no endpoint)' if blocked else 'STILL EXPOSED'}")

def _sleep_to_next_step(step=30):
    """Block until just past the start of the next TOTP time-step."""
    time.sleep(step - (time.time() % step) + 0.5)

def _consume_code(code):
    """One fresh session: password login then submit `code`. Returns the
    Response so callers can distinguish success / rejection / 429."""
    s = requests.Session()
    s.post(f"{T}/login", data={"username": U, "password": P})
    return s.post(f"{T}/verify-totp", data={"code": code})

def _authenticate_fresh(max_steps=3):
    """Log in and pass TOTP with a genuinely fresh (never-consumed) step.
    On a normal run the current code works immediately; on a quick rerun that
    step is already consumed, so we advance to the next step boundary
    (last_used_step only ever tracks PAST steps, so a newer step is guaranteed
    fresh) and retry. Returns (code, ok) where ok means the dashboard was reached.
    A success also clears the per-user fail counter server-side (F1)."""
    totp = pyotp.TOTP(SECRET)
    code = None
    for _ in range(max_steps):
        code = totp.now()
        r = _consume_code(code)
        if r.status_code == 429:            # locked/limited by a prior test — wait it out
            time.sleep(2)
            continue
        if "Dashboard" in r.text:
            return code, True
        _sleep_to_next_step()               # stale step: advance and retry
    return code, False

def test_replay():
    """
    V2: a TOTP code, once accepted, must never authenticate a second time.
    Replay protection is stateful — last_used_step persists in the DB — so a
    naive test that reuses .now() gives FALSE failures on a quick rerun: its
    'first' use is really a replay of a step an earlier run already consumed.
    To stay robust we authenticate with a genuinely fresh step, then prove the
    immediate replay of that same code is rejected.
    """
    code, first_ok = _authenticate_fresh()

    # Replay the SAME code right away in a new session. Because we replay
    # immediately, the step is still inside the validation window, so a rejection
    # here is the replay guard (F2) at work, not the window (F3) expiring it.
    replay_ok = "Dashboard" in _consume_code(code).text

    blocked = first_ok and not replay_ok
    print(f"  Replay (V2)          : "
          f"{'BLOCKED (2nd use rejected)' if blocked else f'CHECK — first_use={first_ok}, replay={replay_ok}'}")
    assert blocked, f"replay protection failed (first_use={first_ok}, replay_accepted={replay_ok})"

def test_window():
    """
    V3: the vulnerable app used a +/-3-step window (7 codes valid at once).
    The hardened app uses window=1 (+/-1 step => 3 codes max). We assert the
    boundary directly: codes at offsets +2..+4 (60-120s in the future) MUST
    be rejected.

    Why FUTURE offsets specifically: a future time-step is always newer than
    the user's last consumed step, so the replay guard (F2) never rejects it
    on its own -- a rejection here is purely the *window* saying no. That makes
    the test clean and idempotent across reruns, unlike counting acceptances
    (which the replay guard confounds once last_used_step is persisted).
    """
    now = time.time()
    totp = pyotp.TOTP(SECRET)
    accepted_offsets = []
    for off in (2, 3, 4):  # +60s, +90s, +120s -- all outside a window=1 config
        s = requests.Session()
        s.post(f"{T}/login", data={"username": U, "password": P})
        code = totp.at(now + off * 30)
        r = s.post(f"{T}/verify-totp", data={"code": code})
        if "Dashboard" in r.text:
            accepted_offsets.append(off)
        time.sleep(0.1)

    # A narrowed window rejects every out-of-window code. In the vuln app,
    # offsets +2 and +3 would sail through -- this assertion catches that.
    blocked = not accepted_offsets
    print(f"  Window (V3)          : "
          f"{'NARROWED (offsets >+1 rejected)' if blocked else f'STILL WIDE — accepted {accepted_offsets}'}")
    assert blocked, f"out-of-window TOTP codes accepted at offsets {accepted_offsets}"

def test_ratelimit():
    """
    V1: repeated wrong TOTP codes must get the account locked out (bounded
    brute force), not allow unlimited guessing.

    Two independent defenses can produce the 429, and we distinguish them:
      * per-user lockout  (F1, the V1 fix): after MAX_TOTP_ATTEMPTS wrong tries
        the app replies 'Too many attempts. Try later.'
      * global rate-limit (Flask-Limiter, 10/min): defense in depth, generic 429.
    We submit wrong codes until we're refused and assert that refusal happens
    within a small bound — which holds no matter which defense fires, and no
    matter how many failed attempts earlier tests already left on the account.
    From a clean state the per-user lockout is observed on the 6th wrong code
    (the 6th sees the lock the 5th set, since MAX_TOTP_ATTEMPTS=5); earlier
    tests only make it fire sooner, never later.
    """
    MAX_PROBES = 8
    locked_after, mechanism = None, None
    for i in range(1, MAX_PROBES + 1):
        r = _consume_code("000000")
        per_user = "Too many attempts" in r.text
        if per_user or r.status_code == 429:
            locked_after = i
            mechanism = "per-user lockout (F1)" if per_user else "global rate-limit"
            break

    locked = locked_after is not None
    detail = (f"after {locked_after} wrong code(s) via {mechanism}" if locked
              else f"NOT triggered in {MAX_PROBES} wrong codes")
    print(f"  Rate limit (V1)      : {'LOCKED OUT ' + detail if locked else 'STILL OPEN — ' + detail}")
    assert locked, f"brute-force not stopped: no lockout/rate-limit in {MAX_PROBES} wrong codes"

if __name__ == "__main__":
    print("Running attacks against HARDENED app (port 5004):\n")
    test_mfa_bypass()
    test_secret_leak()
    test_replay()
    test_window()
    test_ratelimit()
    print("\n  Phishing relay (A5)  : NOT BLOCKED — see System 3 (passkeys)")
