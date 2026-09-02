"""
oauth_engine.py
================
From-scratch OAuth 2.0 / OpenID Connect primitive layer for System 4.

This module deliberately contains NO Flask, NO web framework, and NO
security policy decisions. It provides the raw cryptographic and encoding
primitives that an Authorization Server and Client need. WHERE and WHETHER
these primitives are validated is the job of the server code -- which is
exactly the surface we attack and then harden.

Implemented from scratch (no PyJWT / authlib) so the JWT mechanics are
visible and so System 5 (JWT deep-dive) has a foundation to build on.

Standards reference:
  - RFC 6749  OAuth 2.0 Authorization Framework
  - RFC 7636  PKCE
  - RFC 7519  JSON Web Token
  - RFC 9700  OAuth 2.0 Security Best Current Practice (Jan 2025)
  - OpenID Connect Core 1.0
"""

import os
import json
import time
import hmac
import hashlib
import base64
import secrets


# --------------------------------------------------------------------------
# base64url helpers (RFC 7515 / 7519 -- no padding)
# --------------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


# --------------------------------------------------------------------------
# Opaque token / code generation
# --------------------------------------------------------------------------
def generate_authorization_code() -> str:
    """High-entropy, single-use-by-policy authorization code."""
    return secrets.token_urlsafe(32)


def generate_access_token() -> str:
    """Opaque bearer access token (RFC 6750)."""
    return secrets.token_urlsafe(32)


def generate_state() -> str:
    """CSRF token for the authorization request (RFC 6749 sec 10.12)."""
    return secrets.token_urlsafe(24)


def generate_nonce() -> str:
    """OIDC nonce -- binds an id_token to a specific auth request."""
    return secrets.token_urlsafe(24)


# --------------------------------------------------------------------------
# PKCE (RFC 7636)
# --------------------------------------------------------------------------
def generate_code_verifier() -> str:
    """43-128 char high-entropy verifier."""
    return secrets.token_urlsafe(64)[:128]


def derive_code_challenge(code_verifier: str, method: str = "S256") -> str:
    """
    Derive the code_challenge from a verifier.
      S256:  BASE64URL(SHA256(ASCII(verifier)))
      plain: verifier  (NOT RECOMMENDED -- RFC 9700)
    """
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        return b64url_encode(digest)
    elif method == "plain":
        return code_verifier
    raise ValueError(f"unsupported PKCE method: {method}")


def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    """Constant-time check that a verifier matches a stored challenge."""
    if code_verifier is None or code_challenge is None:
        return False
    derived = derive_code_challenge(code_verifier, method)
    return hmac.compare_digest(derived, code_challenge)


# --------------------------------------------------------------------------
# JWT  (RFC 7519) -- built by hand on purpose
# --------------------------------------------------------------------------
def jwt_encode(payload: dict, key: str, alg: str = "HS256") -> str:
    """
    Encode a JWT. Supports HS256 and the (dangerous) 'none' alg so the
    System 4 attack scripts can forge unsigned tokens against a client
    that fails to pin the algorithm.
    """
    header = {"alg": alg, "typ": "JWT"}
    segments = [
        b64url_encode(json.dumps(header, separators=(",", ":")).encode()),
        b64url_encode(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segments).encode("ascii")

    if alg == "HS256":
        sig = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
        segments.append(b64url_encode(sig))
    elif alg == "none":
        segments.append("")  # unsecured JWS -- empty signature
    else:
        raise ValueError(f"unsupported alg: {alg}")

    return ".".join(segments)


def jwt_decode_unverified(token: str) -> tuple[dict, dict]:
    """Decode header+payload WITHOUT checking the signature. For inspection."""
    h_b64, p_b64, _ = token.split(".")
    header = json.loads(b64url_decode(h_b64))
    payload = json.loads(b64url_decode(p_b64))
    return header, payload


def jwt_verify(token: str, key: str, *,
               expected_alg: str = "HS256",
               expected_iss: str | None = None,
               expected_aud: str | None = None,
               expected_nonce: str | None = None) -> dict:
    """
    Strict JWT verification suitable for an OIDC id_token.

    Raises ValueError on ANY failure. The hardened client uses this with all
    expectations set; the vulnerable client bypasses it entirely.

    Checks, in order:
      1. algorithm is pinned (rejects 'none' and alg swapping)
      2. signature is valid
      3. iss matches (if provided)
      4. aud matches (if provided)
      5. exp not passed
      6. nonce matches (if provided)
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT")
    h_b64, p_b64, sig_b64 = parts
    header = json.loads(b64url_decode(h_b64))

    # 1. pin the algorithm -- the single most important check
    if header.get("alg") != expected_alg:
        raise ValueError(f"alg mismatch: token={header.get('alg')} expected={expected_alg}")

    # 2. verify signature
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    expected_sig = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(b64url_encode(expected_sig), sig_b64):
        raise ValueError("signature verification failed")

    payload = json.loads(b64url_decode(p_b64))

    # 3. issuer
    if expected_iss is not None and payload.get("iss") != expected_iss:
        raise ValueError(f"iss mismatch: {payload.get('iss')}")

    # 4. audience
    if expected_aud is not None:
        aud = payload.get("aud")
        aud_ok = (aud == expected_aud) or (isinstance(aud, list) and expected_aud in aud)
        if not aud_ok:
            raise ValueError(f"aud mismatch: {aud}")

    # 5. expiry
    if "exp" in payload and int(time.time()) >= int(payload["exp"]):
        raise ValueError("token expired")

    # 6. nonce (OIDC replay defence)
    if expected_nonce is not None and payload.get("nonce") != expected_nonce:
        raise ValueError(f"nonce mismatch: {payload.get('nonce')}")

    return payload


def build_id_token(*, iss: str, sub: str, aud: str, key: str,
                   nonce: str | None = None, ttl: int = 300,
                   extra: dict | None = None, alg: str = "HS256") -> str:
    """Construct a signed OIDC id_token."""
    now = int(time.time())
    payload = {"iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl}
    if nonce is not None:
        payload["nonce"] = nonce
    if extra:
        payload.update(extra)
    return jwt_encode(payload, key, alg=alg)


if __name__ == "__main__":
    # smoke test
    v = generate_code_verifier()
    c = derive_code_challenge(v, "S256")
    assert verify_pkce(v, c, "S256")
    assert not verify_pkce("wrong", c, "S256")

    tok = build_id_token(iss="https://as.local", sub="alice",
                         aud="client-123", key="secret", nonce="n1")
    claims = jwt_verify(tok, "secret", expected_iss="https://as.local",
                        expected_aud="client-123", expected_nonce="n1")
    assert claims["sub"] == "alice"

    # 'none' forgery must fail strict verification
    forged = jwt_encode({"sub": "admin"}, "", alg="none")
    try:
        jwt_verify(forged, "secret")
        raise SystemExit("FAIL: none token accepted")
    except ValueError:
        pass

    print("oauth_engine self-test OK")
