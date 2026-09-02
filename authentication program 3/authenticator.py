"""
engine/authenticator.py
=======================
A WebAuthn authenticator, built from scratch.

In the real world this code runs inside a YubiKey, a phone's secure enclave, or
a laptop's TPM. The browser talks to it over USB/NFC/internal APIs. We cannot use
a real browser in an attack lab (the browser would refuse to perform our attacks),
so we reproduce the authenticator's exact behaviour in Python.

Everything here is REAL cryptography and REAL WebAuthn binary formats:
  - ECDSA on the NIST P-256 curve (the "ES256" algorithm, COSE id -7)
  - COSE_Key CBOR encoding of the public key
  - the authenticatorData byte layout (rpIdHash || flags || signCount || [attested cred data])
  - the signed payload: authenticatorData || SHA256(clientDataJSON)

The proof that we got it right is in engine/verify_against_library.py, where the
production `py_webauthn` library accepts the output of this file as valid.
"""

import os
import json
import struct
import hashlib
import base64

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    """base64url WITHOUT padding -- the encoding WebAuthn uses everywhere."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# Flag bits inside authenticatorData (one byte).
FLAG_UP = 0x01   # bit 0: User Present  (user touched the key / passed a gesture)
FLAG_UV = 0x04   # bit 2: User Verified (PIN or biometric)
FLAG_AT = 0x40   # bit 6: Attested credential data included (registration only)


class SoftwareAuthenticator:
    """
    A single registered credential living on a simulated device.

    A real authenticator can hold many credentials; one instance here = one
    credential, which keeps the demo readable. The private key NEVER leaves this
    object -- mirroring the hardware guarantee that it never leaves the device.
    """

    # In real authenticators the AAGUID identifies the make/model. Zeros = "I'm
    # not telling you what I am", which is normal for privacy-preserving devices.
    AAGUID = b"\x00" * 16

    def __init__(self):
        # The signet ring. Generated on-device, extractable by nobody.
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        # A random handle the server uses to look this credential up later.
        self.credential_id = os.urandom(32)
        # Increments on every assertion. The server watches this to spot clones.
        self.sign_count = 0

    # -- public key, in the two encodings the protocol needs --------------------

    def _public_numbers(self):
        return self._private_key.public_key().public_numbers()

    def cose_public_key(self) -> bytes:
        """
        The public key as a COSE_Key (a CBOR map). This is the exact blob the
        server stores. For an EC2/P-256/ES256 key the map is:
            1  (kty) : 2   -> Elliptic Curve, two coordinates
            3  (alg) : -7  -> ES256 (ECDSA w/ SHA-256)
           -1  (crv) : 1   -> P-256
           -2  (x)   : 32-byte X coordinate
           -3  (y)   : 32-byte Y coordinate
        """
        nums = self._public_numbers()
        x = nums.x.to_bytes(32, "big")
        y = nums.y.to_bytes(32, "big")
        cose = {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        # canonical=True -> deterministic CBOR, which is what the spec wants.
        return cbor2.dumps(cose, canonical=True)

    # -- authenticatorData ------------------------------------------------------

    def _authenticator_data(self, rp_id: str, include_attested_cred: bool) -> bytes:
        """
        Build the authenticatorData byte string.

        Layout (registration includes the last, variable-length section;
        authentication stops after signCount):

            [32 bytes] rpIdHash   = SHA256(rp_id)
            [1  byte ] flags      = UP | UV | (AT during registration)
            [4  bytes] signCount  = big-endian uint32
            -- attested credential data (REGISTRATION ONLY) --
            [16 bytes] aaguid
            [2  bytes] credentialIdLength (big-endian)
            [N  bytes] credentialId
            [M  bytes] credentialPublicKey (COSE_Key CBOR)
        """
        rp_id_hash = sha256(rp_id.encode())

        flags = FLAG_UP | FLAG_UV
        if include_attested_cred:
            flags |= FLAG_AT

        data = rp_id_hash
        data += struct.pack("!B", flags)
        data += struct.pack("!I", self.sign_count)

        if include_attested_cred:
            cose = self.cose_public_key()
            data += self.AAGUID
            data += struct.pack("!H", len(self.credential_id))
            data += self.credential_id
            data += cose

        return data

    # -- registration ceremony --------------------------------------------------

    def create(self, rp_id: str, client_data_json: bytes) -> dict:
        """
        navigator.credentials.create() -- the device side of registration.

        The authenticator does NOT inspect clientDataJSON. It signs (for attested
        formats) or simply embeds its hash. Here we use attestation format "none"
        (no attestation statement), which is what the overwhelming majority of
        consumer sites use. The output is an attestationObject: a CBOR map of
        {fmt, attStmt, authData}.
        """
        auth_data = self._authenticator_data(rp_id, include_attested_cred=True)
        attestation_object = cbor2.dumps(
            {"fmt": "none", "attStmt": {}, "authData": auth_data},
            canonical=True,
        )
        return {
            "id": b64url_encode(self.credential_id),
            "rawId": b64url_encode(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(client_data_json),
                "attestationObject": b64url_encode(attestation_object),
            },
            "clientExtensionResults": {},
        }

    # -- authentication ceremony ------------------------------------------------

    def get(self, rp_id: str, client_data_json: bytes) -> dict:
        """
        navigator.credentials.get() -- the device side of authentication.

        THIS is the heart of the protocol. The authenticator:
          1. bumps its signature counter,
          2. builds fresh authenticatorData (no attested cred data this time),
          3. signs  authenticatorData || SHA256(clientDataJSON)  with the private key.

        The browser supplied clientDataJSON, which contains the true origin. By
        signing a hash of it, the device cryptographically commits to "this
        assertion was produced for THAT origin and THAT challenge" -- without ever
        needing to understand either.
        """
        self.sign_count += 1
        auth_data = self._authenticator_data(rp_id, include_attested_cred=False)

        signed_payload = auth_data + sha256(client_data_json)
        signature = self._private_key.sign(signed_payload, ec.ECDSA(hashes.SHA256()))

        return {
            "id": b64url_encode(self.credential_id),
            "rawId": b64url_encode(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(client_data_json),
                "authenticatorData": b64url_encode(auth_data),
                "signature": b64url_encode(signature),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }


# ---------------------------------------------------------------------------
# The CLIENT (browser) side helpers
# ---------------------------------------------------------------------------
# In a real flow the BROWSER builds clientDataJSON. It is the honest notary that
# writes the true origin. We expose it as a function so the attack scripts can
# play a DISHONEST notary -- a luxury a real browser never grants an attacker,
# which is precisely why these attacks only work against a server that forgets
# to check.

def build_client_data(ceremony_type: str, challenge: bytes, origin: str) -> bytes:
    """
    ceremony_type: "webauthn.create" (registration) or "webauthn.get" (auth)
    Returns the raw clientDataJSON bytes that get hashed and signed.
    """
    client_data = {
        "type": ceremony_type,
        "challenge": b64url_encode(challenge),
        "origin": origin,
        "crossOrigin": False,
    }
    # separators without spaces -> compact, stable bytes.
    return json.dumps(client_data, separators=(",", ":")).encode("utf-8")
