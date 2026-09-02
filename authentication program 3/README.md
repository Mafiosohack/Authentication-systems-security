# System 3 — Passkeys / FIDO2 / WebAuthn

Phishing-resistant authentication, built → attacked → hardened. This is the
direct answer to System 2's unfixable gap: TOTP codes carry no binding to *who*
is asking, so a valid code works on a phishing site. FIDO2 binds every signature
to the **origin**, so a relayed signature is useless against the real site.

## The honest framing (say this when presenting)

Real WebAuthn needs a **browser** — it builds `clientDataJSON`, enforces
origin/RP ID, and talks to the authenticator. An attack lab can't use a real
browser (it would refuse to run the attacks), so the **authenticator and client
are simulated in Python** — exactly as System 2 built TOTP from scratch before
checking it against `pyotp`. The simulation is faithful: real ECDSA P-256 keys,
real COSE encoding, real WebAuthn byte layouts, real signatures. The proof is
`engine/verify_against_library.py`, where the production `py_webauthn` library
accepts our hand-built output as valid.

Phishing resistance in production is **two layers**: (1) the browser refuses to
use a credential on a mismatched origin, and (2) the server verifies the origin
as a backstop. Our lab has no browser, so it demonstrates **layer 2 — the
server-side checks developers actually forget.**

## Layout

```
engine/
  authenticator.py          from-scratch simulated authenticator (keys, COSE, byte layouts, signing)
  cose.py                   server-side COSE decode + manual signature verify (used by vulnerable server)
  client.py                 browser+authenticator client used by the attacks
  ceremony_demo.py          narrated, byte-level walkthrough of both ceremonies  <-- start here
  verify_against_library.py proof: py_webauthn accepts our output
vulnerable/
  server.py                 RP on :5006 — verifies signature ONLY (3 checks missing)
attacks/
  attack1_challenge_replay.py   replay a captured assertion        (missing: challenge)
  attack2_origin_confusion.py   phishing / origin confusion        (missing: origin)
  attack3_counter_clone.py      cloned authenticator               (missing: counter)
hardened/
  server.py                 RP on :5007 — full checks via py_webauthn
  rerun_attacks.py          runs the SAME three attacks; all rejected
report/
  System3_FIDO2_WebAuthn_Report.docx
```

## The four server-side checks (the whole point)

A valid signature only proves *someone holds the private key*. A correct server
must ALSO verify:

| Check     | Question it answers              | Attack if missing      |
|-----------|----------------------------------|------------------------|
| Signature | Does the key holder sign this?   | (impersonation)        |
| Challenge | Is this login *fresh*?           | Challenge replay       |
| Origin    | Is this for *my site*?           | Phishing               |
| Counter   | Is this the *one* genuine device?| Cloned authenticator   |

The vulnerable server does only the first. The attacks live in that gap.

## Run it

```bash
pip install -r requirements.txt

# 1. Learn the protocol (no server needed)
python engine/ceremony_demo.py
python engine/verify_against_library.py

# 2. Attacks SUCCEED against the vulnerable server
python vulnerable/server.py                  # terminal A (:5006)
python attacks/attack1_challenge_replay.py   # terminal B
python attacks/attack2_origin_confusion.py
python attacks/attack3_counter_clone.py

# 3. The SAME attacks FAIL against the hardened server
python hardened/server.py                    # terminal A (:5007)
python hardened/rerun_attacks.py             # terminal B
```

## Two caveats to keep you honest in Q&A

- **Ignoring attestation is not a vulnerability here.** Attestation verifies the
  authenticator's make/model; most consumer sites deliberately use `none`. It
  matters for enterprise hardware allow-listing, not general login. Don't present
  it as an exploitable flaw.
- **Counter-based clone detection is eroding.** Synced passkeys often report
  `signCount = 0` forever, so Attack 3's defense is meaningful mainly for
  single-device hardware authenticators (e.g. a YubiKey).
```
