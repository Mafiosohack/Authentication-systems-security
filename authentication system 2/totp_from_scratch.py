"""
TOTP FROM SCRATCH  —  RFC 6238 (TOTP) built on RFC 4226 (HOTP)

TOTP is built in layers. Each layer is small. The whole thing is ~60 lines of
actual logic. We build every layer except SHA-1 itself (the cryptographic
primitive — we treat it as a black box via hashlib, exactly as the RFC does).

  Layer 0 : SHA-1          -> hashlib (the primitive)
  Layer 1 : HMAC-SHA1      -> built from scratch here (RFC 2104)
  Layer 2 : HOTP           -> HMAC + dynamic truncation (RFC 4226)
  Layer 3 : TOTP           -> HOTP with counter = time / 30 (RFC 6238)

Run this file to see each layer's output and a cross-check against the
reference pyotp library (proves our math is correct).
"""

import hashlib
import struct
import time
import base64


# ══════════════════════════════════════════════════════════════
# LAYER 1 — HMAC-SHA1 FROM SCRATCH  (RFC 2104)
#
# HMAC exists to answer: "how do you keep a hash secret-keyed so an attacker
# who can see the message can't forge the hash without the key?"
#
# Naive answer: H(key || message). This is BROKEN — vulnerable to length
# extension attacks. HMAC's nested construction fixes that.
#
#   HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
#
#   K'   = key normalized to the hash block size (64 bytes for SHA-1)
#   ipad = 0x36 repeated 64 times   (inner pad)
#   opad = 0x5c repeated 64 times   (outer pad)
#   ||   = concatenation
#
# The two different pads ensure the inner and outer hashes use effectively
# different keys, which is what defeats length extension.
# ══════════════════════════════════════════════════════════════

def hmac_sha1_from_scratch(key: bytes, message: bytes) -> bytes:
    BLOCK_SIZE = 64  # SHA-1 processes data in 512-bit (64-byte) blocks

    # Step 1: keys longer than the block size are hashed down first
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha1(key).digest()

    # Step 2: pad the key with zero bytes up to the block size
    key = key.ljust(BLOCK_SIZE, b"\x00")

    # Step 3: derive the inner and outer padded keys
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)

    # Step 4: inner = H(ipad || message)
    inner_digest = hashlib.sha1(ipad + message).digest()

    # Step 5: outer = H(opad || inner)  -> this is the HMAC
    return hashlib.sha1(opad + inner_digest).digest()


# ══════════════════════════════════════════════════════════════
# LAYER 2 — HOTP  (RFC 4226)
#
# An HMAC is 20 bytes — way too long for a human to type. HOTP turns it into
# a short numeric code via "dynamic truncation".
#
#   1. hs = HMAC-SHA1(secret, counter)          -> 20 bytes
#   2. offset = low 4 bits of the LAST byte       (a value 0..15)
#   3. take the 4 bytes starting at that offset
#   4. mask off the top bit (avoids sign issues)  -> a 31-bit integer
#   5. code = integer mod 10^digits               -> e.g. 6 digits
#
# Why "dynamic" truncation (offset from the hash itself) instead of just
# taking the first 4 bytes? So an attacker can't predict WHICH 4 bytes of the
# HMAC become the code — it depends on the HMAC output itself.
# ══════════════════════════════════════════════════════════════

def hotp_from_scratch(secret: bytes, counter: int, digits: int = 6) -> str:
    # counter must be an 8-byte big-endian integer (">Q" = unsigned 64-bit BE)
    counter_bytes = struct.pack(">Q", counter)

    hs = hmac_sha1_from_scratch(secret, counter_bytes)  # 20 bytes

    # --- dynamic truncation ---
    offset = hs[-1] & 0x0F                      # last nibble: 0..15
    four_bytes = hs[offset:offset + 4]          # 4 bytes at that offset
    code_int = struct.unpack(">I", four_bytes)[0]  # big-endian 32-bit uint
    code_int &= 0x7FFFFFFF                       # mask the high bit -> 31 bits

    code = code_int % (10 ** digits)             # reduce to N digits
    return str(code).zfill(digits)               # left-pad with zeros


# ══════════════════════════════════════════════════════════════
# LAYER 3 — TOTP  (RFC 6238)
#
# TOTP is just HOTP where the counter is derived from the current time:
#
#   counter = floor( (now - T0) / time_step )
#     T0        = 0  (Unix epoch)
#     time_step = 30 seconds (the standard)
#
# So every 30 seconds the counter ticks up by 1, and the code changes.
# Both sides (your phone and the server) share the secret and read the same
# clock, so they compute the same counter -> the same code. No network needed.
# ══════════════════════════════════════════════════════════════

def totp_from_scratch(secret: bytes, for_time: float = None,
                      time_step: int = 30, digits: int = 6) -> str:
    if for_time is None:
        for_time = time.time()
    counter = int(for_time // time_step)
    return hotp_from_scratch(secret, counter, digits)


# ══════════════════════════════════════════════════════════════
# VERIFICATION with a TIME WINDOW
#
# Clocks drift. Network adds latency. The user takes a second to type.
# So servers accept codes from nearby time steps too:  [-window .. +window].
#
# This is a SECURITY KNOB. window=1 means 3 codes are valid at once
# (previous, current, next) = 90 seconds of validity. A larger window is
# more forgiving but TRIPLES (or worse) the attacker's hit chance per guess.
# This knob becomes a vulnerability when set too wide. (See attacks.)
# ══════════════════════════════════════════════════════════════

def verify_totp_from_scratch(secret: bytes, submitted_code: str,
                             window: int = 1, time_step: int = 30,
                             digits: int = 6, for_time: float = None) -> bool:
    if for_time is None:
        for_time = time.time()
    for step_offset in range(-window, window + 1):
        candidate_time = for_time + (step_offset * time_step)
        if totp_from_scratch(secret, candidate_time, time_step, digits) == submitted_code:
            return True
    return False


# ══════════════════════════════════════════════════════════════
# BASE32 — how authenticator apps store the secret
#
# Google Authenticator / Authy show/scan the secret as BASE32 text
# (e.g. "JBSWY3DPEHPK3PXP"). The raw secret is bytes; base32 makes it
# typeable. We decode base32 -> raw bytes before feeding the HMAC.
# ══════════════════════════════════════════════════════════════

def base32_to_bytes(secret_b32: str) -> bytes:
    secret_b32 = secret_b32.upper().replace(" ", "")
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)  # base32 needs length % 8 == 0
    return base64.b32decode(secret_b32 + pad)


# ══════════════════════════════════════════════════════════════
# DEMO + CROSS-CHECK against pyotp (proves our implementation is correct)
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import pyotp

    print("=" * 64)
    print("TOTP FROM SCRATCH — verification against pyotp")
    print("=" * 64)

    # A known base32 secret (what an authenticator app would hold)
    secret_b32 = "JBSWY3DPEHPK3PXP"
    secret_raw = base32_to_bytes(secret_b32)

    print(f"\nSecret (base32): {secret_b32}")
    print(f"Secret (raw bytes, hex): {secret_raw.hex()}")

    # --- Layer 1 check: our HMAC vs Python's hmac module ---
    import hmac as ref_hmac
    msg = struct.pack(">Q", 0)
    ours = hmac_sha1_from_scratch(secret_raw, msg).hex()
    ref  = ref_hmac.new(secret_raw, msg, hashlib.sha1).hexdigest()
    print(f"\n[Layer 1] HMAC-SHA1(secret, counter=0)")
    print(f"  ours: {ours}")
    print(f"  ref : {ref}")
    print(f"  match: {ours == ref}")

    # --- Layer 2 check: HOTP at counter 0..3 ---
    print(f"\n[Layer 2] HOTP codes (counter 0-3):")
    for c in range(4):
        ours_h = hotp_from_scratch(secret_raw, c)
        ref_h  = pyotp.HOTP(secret_b32).at(c)
        print(f"  counter={c}: ours={ours_h}  ref={ref_h}  match={ours_h == ref_h}")

    # --- Layer 3 check: TOTP at a fixed timestamp ---
    fixed_time = 1700000000  # a fixed point so both sides compute the same code
    ours_t = totp_from_scratch(secret_raw, for_time=fixed_time)
    ref_t  = pyotp.TOTP(secret_b32).at(fixed_time)
    print(f"\n[Layer 3] TOTP at t={fixed_time}:")
    print(f"  ours: {ours_t}")
    print(f"  ref : {ref_t}")
    print(f"  match: {ours_t == ref_t}")

    # --- Live code right now ---
    live = totp_from_scratch(secret_raw)
    secs_left = 30 - int(time.time()) % 30
    print(f"\n[Live] Current TOTP: {live}  (valid for {secs_left} more seconds)")

    print("\n" + "=" * 64)
    print("If all 'match' are True, the from-scratch math is correct.")
    print("=" * 64)
