#!/usr/bin/env python3
"""
From-scratch JWT (JWS compact serialization) engine.
Series credibility cornerstone for System 5 — built from raw primitives,
then verified byte-identical against PyJWT (see verify_against_pyjwt.py).

Implements the JWS compact serialization described in RFC 7515, the
algorithm identifiers in RFC 7518, and the JWT claim structure in RFC 7519.

A JWT is just three base64url segments joined by dots:

    base64url(header) . base64url(payload) . base64url(signature)

The signature covers the ASCII string  header.payload  (the "signing input").
That is the entire trick. Everything dangerous about JWTs flows from the fact
that the *header* — controlled by whoever holds the token — declares which
algorithm the verifier should use. This engine intentionally exposes that so
the attacks in Phase 2 are real, not simulated.
"""

import json
import hmac
import hashlib
import base64
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ---------------------------------------------------------------------------
# base64url WITHOUT padding — RFC 7515 Appendix C. Standard base64 uses + / =
# which are not URL-safe; JWS strips the '=' padding entirely.
# ---------------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    # Re-add the padding base64 needs; len must be a multiple of 4.
    padding_needed = -len(segment) % 4
    return base64.urlsafe_b64decode(segment + ("=" * padding_needed))


def _json_segment(obj: dict) -> str:
    # Compact separators so our bytes match what mainstream libraries emit.
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=False).encode("utf-8")
    return b64url_encode(raw)


# ---------------------------------------------------------------------------
# Signing primitives. One function per algorithm. The verifier MUST decide
# which of these to call based on its OWN policy, never the token's header —
# but a naive implementation does exactly the wrong thing (see vulnerable app).
# ---------------------------------------------------------------------------
def _sign_hs256(signing_input: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, signing_input, hashlib.sha256).digest()


def _sign_rs256(signing_input: bytes, private_key) -> bytes:
    # RSASSA-PKCS1-v1_5 over SHA-256 — the "RS256" of RFC 7518.
    return private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def _verify_rs256(signing_input: bytes, signature: bytes, public_key) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Public encode/decode API
# ---------------------------------------------------------------------------
def encode(payload: dict, key: Any, alg: str = "HS256") -> str:
    """Produce a signed (or unsigned) JWT.

    key meaning depends on alg:
      HS256 -> bytes shared secret
      RS256 -> an RSA private key object
      none  -> ignored (no signature) — RFC 7518 'none', the unsecured JWS
    """
    header = {"alg": alg, "typ": "JWT"}
    signing_input = f"{_json_segment(header)}.{_json_segment(payload)}".encode("ascii")

    if alg == "HS256":
        sig = _sign_hs256(signing_input, key if isinstance(key, bytes) else key.encode())
    elif alg == "RS256":
        sig = _sign_rs256(signing_input, key)
    elif alg == "none":
        sig = b""  # The unsecured JWS. Signature segment is empty.
    else:
        raise ValueError(f"unsupported alg: {alg}")

    return f"{signing_input.decode('ascii')}.{b64url_encode(sig)}"


def decode_header(token: str) -> dict:
    """Read the header WITHOUT verifying. Useful and dangerous — the header is
    attacker-controlled, so anything read here must never drive trust decisions."""
    header_seg = token.split(".")[0]
    return json.loads(b64url_decode(header_seg))


def decode_payload_unverified(token: str) -> dict:
    payload_seg = token.split(".")[1]
    return json.loads(b64url_decode(payload_seg))


def verify(token: str, key: Any, allowed_algs: list[str]) -> dict:
    """Verify a JWT correctly.

    The single most important defense (RFC 8725 sec 3.1): the caller passes the
    set of algorithms IT will accept. The algorithm named in the token header is
    only honored if it is in that allow-list, and 'none' is never silently
    accepted. This function is what the HARDENED app uses.
    """
    try:
        header_seg, payload_seg, sig_seg = token.split(".")
    except ValueError:
        raise ValueError("malformed token: expected three segments")

    header = json.loads(b64url_decode(header_seg))
    alg = header.get("alg")

    if alg not in allowed_algs:
        raise ValueError(f"alg '{alg}' not in allowed set {allowed_algs}")

    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    signature = b64url_decode(sig_seg)

    if alg == "HS256":
        expected = _sign_hs256(signing_input, key if isinstance(key, bytes) else key.encode())
        if not hmac.compare_digest(expected, signature):
            raise ValueError("signature verification failed (HS256)")
    elif alg == "RS256":
        if not _verify_rs256(signing_input, signature, key):
            raise ValueError("signature verification failed (RS256)")
    elif alg == "none":
        # Only reachable if a caller explicitly allow-listed 'none'. We don't.
        raise ValueError("'none' algorithm rejected")
    else:
        raise ValueError(f"unsupported alg: {alg}")

    return json.loads(b64url_decode(payload_seg))


# Helper to generate an RSA keypair for RS256 demos.
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def public_key_to_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
