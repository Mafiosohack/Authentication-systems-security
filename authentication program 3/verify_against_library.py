"""
engine/verify_against_library.py
================================
The credibility proof. Our hand-built authenticator (engine/authenticator.py)
produces registration and authentication outputs. We feed them, unmodified, to
the PRODUCTION `py_webauthn` library's verification functions -- the same code a
real relying party would trust. If the library accepts them, our byte layouts,
COSE encoding, and signature are correct down to the last bit.

This mirrors System 2, where TOTP built from scratch was verified against pyotp.
"""

import os
from authenticator import SoftwareAuthenticator, build_client_data, b64url_decode

import webauthn
import json

RP_ID = "demo.localhost"
ORIGIN = "https://demo.localhost"


def main():
    print("=" * 70)
    print("  Verifying from-scratch engine output against py_webauthn")
    print("=" * 70)

    device = SoftwareAuthenticator()

    # ----- REGISTRATION -----------------------------------------------------
    reg_challenge = os.urandom(32)
    reg_cdj = build_client_data("webauthn.create", reg_challenge, ORIGIN)
    reg_response = device.create(RP_ID, reg_cdj)

    verified_reg = webauthn.verify_registration_response(
        credential=json.dumps(reg_response),
        expected_challenge=reg_challenge,
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
    )
    print("\n[REGISTRATION] py_webauthn ACCEPTED our attestationObject.")
    print(f"  credential id (b64url) : {reg_response['id'][:24]}...")
    print(f"  public key bytes stored: {len(verified_reg.credential_public_key)} bytes (COSE)")
    print(f"  initial sign_count     : {verified_reg.sign_count}")

    # The server stores these two things. Nothing secret.
    stored_public_key = verified_reg.credential_public_key
    stored_sign_count = verified_reg.sign_count

    # ----- AUTHENTICATION ---------------------------------------------------
    auth_challenge = os.urandom(32)
    auth_cdj = build_client_data("webauthn.get", auth_challenge, ORIGIN)
    auth_response = device.get(RP_ID, auth_cdj)

    verified_auth = webauthn.verify_authentication_response(
        credential=json.dumps(auth_response),
        expected_challenge=auth_challenge,
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        credential_public_key=stored_public_key,
        credential_current_sign_count=stored_sign_count,
    )
    print("\n[AUTHENTICATION] py_webauthn ACCEPTED our signature.")
    print(f"  signature verified     : True")
    print(f"  new sign_count         : {verified_auth.new_sign_count}")

    print("\n" + "=" * 70)
    print("  RESULT: the production library trusts our from-scratch crypto.")
    print("  Every byte layout, the COSE key, and the ECDSA signature are correct.")
    print("=" * 70)


if __name__ == "__main__":
    main()
