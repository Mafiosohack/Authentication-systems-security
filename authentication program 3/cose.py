"""
engine/cose.py
==============
The relying party's (server's) view of the credential: COSE decoding and manual
signature verification.

At registration the authenticator handed the server a COSE_Key -- a CBOR map
holding the public key. Here we turn that blob back into a usable ECDSA public
key and verify assertion signatures BY HAND. This is the from-scratch verifier
counterpart to authenticator.py, and `signature_is_valid` below is the only thing
the VULNERABLE server ever checks.

Everything here is real: real COSE/CBOR decoding, the real authenticatorData byte
layout, and real ECDSA-on-P-256 verification.
"""

import struct
import hashlib

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# COSE_Key labels (RFC 8152) for an EC2 / P-256 / ES256 key.
COSE_KTY = 1     # key type
COSE_ALG = 3     # algorithm
COSE_CRV = -1    # curve
COSE_X = -2      # x coordinate
COSE_Y = -3      # y coordinate

KTY_EC2 = 2      # two-coordinate elliptic curve key
ALG_ES256 = -7   # ECDSA with SHA-256
CRV_P256 = 1     # NIST P-256


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def cose_to_public_key(cose_bytes: bytes):
    """
    Decode a COSE_Key CBOR blob into a cryptography EllipticCurvePublicKey.

    We accept ONLY EC2 / P-256 / ES256 -- the single algorithm this system uses.
    Anything else raises: silently accepting an unexpected key type is exactly how
    real verifiers get burned (algorithm-confusion attacks).
    """
    cose = cbor2.loads(cose_bytes)

    if cose.get(COSE_KTY) != KTY_EC2:
        raise ValueError(f"unexpected COSE kty {cose.get(COSE_KTY)} (want EC2=2)")
    if cose.get(COSE_ALG) != ALG_ES256:
        raise ValueError(f"unexpected COSE alg {cose.get(COSE_ALG)} (want ES256=-7)")
    if cose.get(COSE_CRV) != CRV_P256:
        raise ValueError(f"unexpected COSE crv {cose.get(COSE_CRV)} (want P-256=1)")

    x = int.from_bytes(cose[COSE_X], "big")
    y = int.from_bytes(cose[COSE_Y], "big")
    numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return numbers.public_key()


def parse_authenticator_data(auth_data: bytes) -> dict:
    """
    Split authenticatorData into its fixed-size head fields.

    Layout (the first 37 bytes are present in every assertion; attested credential
    data and extensions, if any, follow and are not needed here):

        [32] rpIdHash    = SHA256(rp_id)
        [ 1] flags       = UP | UV | (AT at registration)
        [ 4] signCount   = big-endian uint32
    """
    if len(auth_data) < 37:
        raise ValueError("authenticatorData too short (need at least 37 bytes)")
    return {
        "rp_id_hash": auth_data[0:32],
        "flags": auth_data[32],
        "sign_count": struct.unpack("!I", auth_data[33:37])[0],
    }


def signature_is_valid(public_key_cose: bytes,
                       auth_data: bytes,
                       client_data_json: bytes,
                       signature: bytes) -> bool:
    """
    The ONE check the vulnerable server performs.

    Reconstruct the signed payload exactly as the authenticator built it --

        signed_payload = authenticatorData || SHA256(clientDataJSON)

    -- and verify the ECDSA signature against the stored public key.

    Returns True/False and never raises: to a verifier, a bad signature is an
    ordinary "no", not an exceptional condition. A valid result here proves only
    that *someone holding the private key signed these bytes* -- it says nothing
    about freshness (challenge), site (origin), or device identity (counter).
    Those are the checks the vulnerable server forgets.
    """
    try:
        public_key = cose_to_public_key(public_key_cose)
    except Exception:
        # Malformed or unexpected key material -> treat as invalid, don't crash.
        return False

    signed_payload = auth_data + sha256(client_data_json)
    try:
        public_key.verify(signature, signed_payload, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
