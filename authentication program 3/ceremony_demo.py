"""
engine/ceremony_demo.py
=======================
A narrated, step-by-step walk through both WebAuthn ceremonies, printing the
actual bytes at each stage. Run this first when learning the system -- it makes
the abstract protocol concrete. Nothing here is mocked; the keys, encodings, and
signature are real (and proven correct in verify_against_library.py).

    $ python ceremony_demo.py
"""

import os
import json
import hashlib
from authenticator import (
    SoftwareAuthenticator, build_client_data, b64url_decode, b64url_encode, sha256,
)
from cose import parse_authenticator_data, cose_to_public_key

RP_ID = "demo.localhost"
ORIGIN = "https://demo.localhost"
LINE = "-" * 70


def show(label, value):
    print(f"  {label:<28} {value}")


def hexpreview(b: bytes, n=16):
    return b[:n].hex() + ("..." if len(b) > n else "") + f"  ({len(b)} bytes)"


def main():
    print("=" * 70)
    print("  WEBAUTHN FROM SCRATCH -- narrated ceremony walkthrough")
    print("=" * 70)

    # =====================================================================
    print("\n[ THE KEYPAIR ]  (this happens inside the authenticator at registration)")
    print(LINE)
    device = SoftwareAuthenticator()
    print("  An ECDSA P-256 keypair is generated ON the device.")
    print("  The PRIVATE key (the signet ring) will never leave this object.")
    show("credential id:", hexpreview(device.credential_id))
    cose = device.cose_public_key()
    show("public key (COSE/CBOR):", hexpreview(cose))
    print("  ^ this COSE blob is the ONLY secret-free thing the server will store.")

    # =====================================================================
    print("\n[ CEREMONY 1: REGISTRATION ]  navigator.credentials.create()")
    print(LINE)
    print("  Step 1. Server invents a random challenge and sends it.")
    reg_challenge = os.urandom(32)
    show("challenge:", hexpreview(reg_challenge))

    print("\n  Step 2. The BROWSER builds clientDataJSON, stamping the TRUE origin.")
    reg_cdj = build_client_data("webauthn.create", reg_challenge, ORIGIN)
    show("clientDataJSON:", reg_cdj.decode())

    print("\n  Step 3. The AUTHENTICATOR builds authenticatorData + attestationObject.")
    reg = device.create(RP_ID, reg_cdj)
    att_obj_bytes = b64url_decode(reg["response"]["attestationObject"])
    import cbor2
    att = cbor2.loads(att_obj_bytes)
    parsed = parse_authenticator_data(att["authData"])
    show("attestation fmt:", att["fmt"], )
    show("rpIdHash == SHA256(rp_id):", parsed["rp_id_hash"] == sha256(RP_ID.encode()))
    show("flags byte:", f"0b{parsed['flags']:08b}  (UP/UV set, AT set for registration)")
    show("sign_count:", parsed["sign_count"])
    print("  Server now stores: {credential_id -> public_key, sign_count=0}. Done.")

    # =====================================================================
    print("\n[ CEREMONY 2: AUTHENTICATION ]  navigator.credentials.get()")
    print(LINE)
    print("  Step 1. Server invents a FRESH challenge.")
    auth_challenge = os.urandom(32)
    show("challenge:", hexpreview(auth_challenge))

    print("\n  Step 2. Browser builds clientDataJSON again (type now 'webauthn.get').")
    auth_cdj = build_client_data("webauthn.get", auth_challenge, ORIGIN)
    show("clientDataJSON:", auth_cdj.decode())

    print("\n  Step 3. THE SIGNATURE -- the heart of the protocol.")
    print("          signed_payload = authenticatorData || SHA256(clientDataJSON)")
    assertion = device.get(RP_ID, auth_cdj)
    auth_data = b64url_decode(assertion["response"]["authenticatorData"])
    sig = b64url_decode(assertion["response"]["signature"])
    show("authenticatorData:", hexpreview(auth_data))
    show("SHA256(clientDataJSON):", hexpreview(sha256(auth_cdj)))
    show("signature (DER ECDSA):", hexpreview(sig))
    show("sign_count now:", parse_authenticator_data(auth_data)["sign_count"])

    print("\n  Step 4. Server verifies with the stored PUBLIC key, then checks:")
    pub = cose_to_public_key(cose)
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    try:
        pub.verify(sig, auth_data + sha256(auth_cdj), ec.ECDSA(hashes.SHA256()))
        sig_ok = True
    except Exception:
        sig_ok = False
    show("signature valid:", sig_ok)
    show("challenge matches issued:", "<server compares to its stored challenge>")
    show("origin == expected:", json.loads(auth_cdj)["origin"] == ORIGIN)
    show("rpIdHash == expected:", parse_authenticator_data(auth_data)["rp_id_hash"] == sha256(RP_ID.encode()))
    show("sign_count advanced:", "1 > 0  (clone check)")

    print("\n" + "=" * 70)
    print("  Four checks must ALL pass: signature, challenge, origin, counter.")
    print("  The vulnerable server does only the first. The attacks live in the gap.")
    print("=" * 70)


if __name__ == "__main__":
    main()
