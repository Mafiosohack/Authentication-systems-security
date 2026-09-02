# System 3 — Passkeys / FIDO2 / WebAuthn
## Practical Report: Built → Proven → Attacked → Hardened

**Date:** 2026-06-10
**Subject:** A from-scratch WebAuthn relying party, three server-side attacks against the
common "verify the signature and log them in" mistake, and the three fixes that close them.
**Result in one line:** Three attacks succeeded against a server that checks only the
signature; the same three attacks — unchanged — all failed once the server also checked the
challenge, the origin, and the counter.

---

## 0. Table of contents
1. Executive summary
2. Environment and what was run (including two reconstructed modules)
3. How the system inherently works (the foundation)
4. The vulnerable server: what it checks and what it skips
5. Attack 1 — Challenge Replay
6. Attack 2 — Origin Confusion / Phishing
   - 6.5 Deep-dive: *can the attacker forge the browser location?* (the two-jaw trap)
7. Attack 3 — Cloned Authenticator / Signature Counter
   - 7.5 Deep-dive: *multiple devices, account sharing, and why the counter is a signal not a verdict*
8. Consolidated results (vulnerable vs hardened, with real error messages)
9. Honesty caveats for presentation / Q&A
10. The two reconstructed files (how the lab is wired)
11. Conclusion — why FIDO2 beats TOTP

---

## 1. Executive summary

FIDO2/WebAuthn is **phishing-resistant authentication**. It exists to fix the one gap TOTP
(System 2) could never close: a TOTP code is a bare number that has no idea *which site* asked
for it, so a phishing site can relay it to the real site and win. FIDO2 binds every login
signature to the **origin** of the site that requested it, so a relayed signature is useless
against the real site — *provided the server actually checks the origin.*

The whole assessment is a demonstration that the cryptographic signature is necessary but **not
sufficient**. A valid signature proves only that *someone holds the private key*. A correct
relying party must additionally verify:

| Check | Question it answers | Attack if the server skips it |
|-------|---------------------|-------------------------------|
| **Signature** | Did the real key sign these bytes? | (impersonation) |
| **Challenge** | Is this login *fresh*, or a recording? | Attack 1 — replay |
| **Origin** | Was this signed for *my* site? | Attack 2 — phishing |
| **Counter** | Is this the *one* genuine device? | Attack 3 — clone |

The **vulnerable server** (`server.py`, port 5006) performs only the first check. The three
attacks each walk through one of the three open doors. The **hardened server**
(`mnt/.../hardened/server.py`, port 5007) performs all four (delegating to the production
`py_webauthn` library), and the identical attacks are all rejected.

---

## 2. Environment and what was run

**Platform:** Windows 11, Python 3.14.
**Dependencies installed** (`requirements.txt`): `flask`, `cbor2`, `cryptography`, `webauthn`
(py_webauthn), `requests`.

**Two modules had to be reconstructed before anything could run.** The project as delivered was
missing `cose.py` and `client.py` — two core modules imported by the vulnerable server, the
ceremony demo, and all three attack scripts. They were not present anywhere in the project tree.
They were rebuilt from the exact function signatures and byte layouts that the surrounding code
(`authenticator.py` and both servers) already required; see section 10. The reconstruction was
validated by the fact that the production `py_webauthn` library accepts the output (section 3)
and that all attacks and defenses behave exactly as the scripts' own pass/fail logic expects.

**Scripts executed, in order:**
1. `python verify_against_library.py` — proof the crypto is real.
2. `python server.py` — start the vulnerable server (port 5006).
3. `python attack1_challenge_replay.py`, `attack2_origin_confusion.py`, `attack3_counter_clone.py`.
4. `python mnt/user-data/outputs/system3_fido2/hardened/server.py` — start the hardened server (port 5007).
5. `python rerun_attacks.py` — the same three attacks against the hardened server.

---

## 3. How the system inherently works (the foundation)

WebAuthn has two ceremonies. Both are simulated faithfully in Python because a real browser would
refuse to perform the attacks — but every byte layout, the COSE key, and the ECDSA signature are
real (proven below).

### 3.1 The actors
- **Authenticator** (`authenticator.py` → `SoftwareAuthenticator`): in the real world this is a
  YubiKey, phone secure enclave, or TPM. It holds an **ECDSA P-256 private key** that *never leaves
  the device*. One instance here = one credential.
- **Browser / client** (`client.py` → `Client`): the honest notary. It builds `clientDataJSON`,
  stamping the **true origin** of the page actually loaded. A real browser cannot be made to lie
  about this; our simulated client *can*, which is the only reason the attacks are performable.
- **Relying party / server** (`server.py` or the hardened server): stores the public key and the
  sign counter, issues challenges, and verifies assertions.

### 3.2 Registration — `navigator.credentials.create()`
1. Server invents a random 32-byte **challenge** and sends it.
2. The **browser** builds `clientDataJSON`, stamping the true origin:
   ```json
   {"type":"webauthn.create","challenge":"<b64url>","origin":"https://demo.localhost","crossOrigin":false}
   ```
3. The **authenticator** generates its keypair and builds an **attestationObject** (CBOR map of
   `{fmt:"none", attStmt:{}, authData:…}`). The server extracts and stores the public key as a
   **COSE_Key** plus an initial `sign_count = 0`.

The server now stores exactly two non-secret things: `{credential_id → public_key, sign_count}`.

### 3.3 Authentication — `navigator.credentials.get()`  (the heart of the protocol)
1. Server invents a **fresh** challenge.
2. Browser builds `clientDataJSON` again (`type` is now `"webauthn.get"`), stamping the origin.
3. The authenticator does three things:
   - **bumps its signature counter** (`self.sign_count += 1`),
   - builds fresh **authenticatorData**,
   - signs the payload:
     ```
     signed_payload = authenticatorData || SHA256(clientDataJSON)
     ```
4. The server verifies the signature with the stored public key, then (if correct) checks
   challenge, origin, and counter.

### 3.4 The two binary structures that carry everything

**`authenticatorData`** (the bytes the device signs over, alongside the client-data hash):
```
[32 bytes] rpIdHash    = SHA256(rp_id)          ← which site this key belongs to
[ 1 byte ] flags       = UP | UV | (AT at reg)  ← user present / verified / attested-data-present
[ 4 bytes] signCount   = big-endian uint32      ← the clone tripwire
-- registration only: attested credential data --
[16 bytes] aaguid
[ 2 bytes] credentialIdLength
[ N bytes] credentialId
[ M bytes] credentialPublicKey (COSE_Key)
```

**`clientDataJSON`** (built by the browser, hashed into the signed payload):
```json
{"type":"…","challenge":"<b64url>","origin":"https://…","crossOrigin":false}
```
The **origin** lives here, inside the signed payload. That single field is what makes FIDO2
phishing-resistant (section 6).

**The COSE_Key** (the public key, stored by the server) is a CBOR map:
```
1 (kty): 2   → EC2 (elliptic curve, two coords)
3 (alg): -7  → ES256 (ECDSA + SHA-256)
-1 (crv): 1  → P-256
-2 (x): 32-byte X coordinate
-3 (y): 32-byte Y coordinate
```

### 3.5 Proof the crypto is real (`verify_against_library.py`)
Our hand-built registration and authentication outputs were fed, unmodified, to the production
`py_webauthn` library — the same code a real relying party trusts. Result:

```
[REGISTRATION] py_webauthn ACCEPTED our attestationObject.
  public key bytes stored: 77 bytes (COSE)
  initial sign_count     : 0
[AUTHENTICATION] py_webauthn ACCEPTED our signature.
  signature verified     : True
  new sign_count         : 1
```

**Significance:** when the attacks succeed later, it cannot be dismissed as "the toy crypto was
broken." The byte layouts, COSE encoding, and ECDSA signature are correct down to the bit. The
vulnerability is **not** in the cryptography — it is in *what the server checks*.

---

## 4. The vulnerable server: what it checks and what it skips

`server.py` (port 5006) performs exactly one check on login:

```python
# The ONE check this server performs: is the signature valid?
if not signature_is_valid(stored["public_key"], auth_data, client_data_json, signature):
    return jsonify({"status": "error", "message": "bad signature"}), 401

# [MISSING CHECK A] never compares the challenge to the one it issued, never consumes it
# [MISSING CHECK B] never parses clientDataJSON["origin"] and compares it
# [MISSING CHECK C] never compares sign_count to the stored value
return jsonify({"status": "ok", ...})
```

It even *issues* a challenge in `/login/begin` and stores it — then never enforces it. "It
verified the signature and logged me in" is the trap. The three attacks live in the three missing
checks.

---

## 5. Attack 1 — Challenge Replay  (missing check: **Challenge**)

**File:** `attack1_challenge_replay.py` → maps to *Missing Check A*.

### 5.1 What it does
1. `alice` registers and performs **one honest login** (server says `ok`).
2. The attacker captures the exact bytes of that assertion (network tap, malware, or logs).
3. The attacker re-sends **the identical bytes** — no new key, no new signature, a photocopy.

### 5.2 Result against the vulnerable server
```
[setup] honest login -> ok: Welcome, alice_replay! (login accepted)
[attack] replay -> ok: Welcome, alice_replay! (login accepted)
RESULT: VULNERABLE -- the stale assertion was accepted again.
```

### 5.3 Why it works
A login is supposed to be a *fresh* event. The mechanism that guarantees freshness is the
**challenge**: the server invents a new random 32-byte value before each login and says "sign
*this*." Because it is random and single-use, a signature over it proves "this login happened
just now, in response to me."

But an ECDSA signature is mathematically valid **forever**. Freshness therefore *cannot* come from
the signature — it must come from the server **remembering which challenge it issued and refusing
to honour that challenge twice.** The vulnerable server issues a challenge and then never compares
or consumes it, so a recording is indistinguishable from a live login.

**Analogy:** the signature is a signed cheque. With no challenge it is a cheque with no date —
cashable repeatedly. The challenge is a one-time reference number the bank crosses off on first
use.

### 5.4 The patch (hardened server)
```python
expected = issued_challenges.pop(username, None)   # FETCH and DELETE in one move
if expected is None:
    return error("no pending challenge (already used?)"), 401
... expected_challenge=expected ...                # the replay carries a STALE challenge → reject
```
`pop` is the whole fix: the challenge is **consumed** the instant it is used. A replay finds the
matching challenge already gone.

### 5.5 Result against the hardened server
```
[attack] replay -> error: no pending challenge (already used?)
RESULT: DEFENDED -- the replayed assertion was rejected.
```
The honest login consumed the challenge; the replay reaches for it and it is gone. The freshness
check fires *before* the signature is even relevant.

---

## 6. Attack 2 — Origin Confusion / Phishing  (missing check: **Origin**)

**File:** `attack2_origin_confusion.py` → maps to *Missing Check B*. This is the most important
attack in the assessment — the entire reason FIDO2 was invented. It **defeats the Attack 1 fix**:
the challenge here is genuinely fresh, proving freshness alone is not enough.

### 6.1 What it does
1. `bob` registers normally on the real site, `https://demo.localhost`.
2. Bob is phished onto `https://evil.localhost` — a clone run by the attacker.
3. evil.localhost relays a **real, fresh challenge** from the genuine server (man-in-the-middle).
4. Bob's **real authenticator** signs it — Bob did nothing wrong, he touched his real key.
5. The attacker forwards the signed assertion to the real server.

### 6.2 Result against the vulnerable server
```
[attack] bob is phished; his browser stamps origin=https://evil.localhost
[attack] his real key signs a FRESH challenge; attacker relays it...
[attack] relayed assertion -> ok: Welcome, bob_phish! (login accepted)
RESULT: VULNERABLE -- phishing succeeded; origin was ignored.
```

### 6.3 Why it works
The browser stamps the **true origin** into `clientDataJSON`, and the authenticator signs a hash
of the whole structure. So the signature cryptographically commits to *"this was signed for THIS
origin."* When bob is on evil.localhost, his honest browser stamps
`"origin":"https://evil.localhost"` — it cannot lie about where it is. The assertion arriving at
the real server therefore carries a **self-incriminating label**. The phish is fully detectable.
The only question is whether the server **reads the label** — and the vulnerable server never
parses or compares the origin.

### 6.4 The patch (hardened server)
```python
expected_origin="https://demo.localhost"   # [FIX B]
```
py_webauthn pulls `origin` out of the signed `clientDataJSON` and compares it:
`evil.localhost ≠ demo.localhost` → rejected.

### 6.5 Deep-dive: *can the attacker forge the browser location?*  (the two-jaw trap)

> **Question asked during the practical:** if the signed origin is the integral protection, can the
> attacker — who *knows* the real origin they are impersonating — manipulate things to make the
> device sign `demo.localhost` instead of `evil.localhost`?

**Answer: no.** The attacker needs an assertion that has **both** a valid signature **and**
`origin:"https://demo.localhost"` inside the signed clientDataJSON. There are exactly two ways to
try, and each is blocked:

**Jaw 1 — edit the clientDataJSON in transit (`evil` → `demo`).**
The signature covers `authenticatorData || SHA256(clientDataJSON)` — a hash of the *entire*
clientDataJSON. The server recomputes that hash from the clientDataJSON it receives and verifies
the signature against it. Flip one byte (`evil`→`demo`) and the hash changes, so the signature no
longer matches → **the signature check rejects it.**

**Jaw 2 — forge a fresh clientDataJSON saying `demo` and sign it yourself.**
To produce a *new* valid signature over a `demo` payload you need the **private key**. It was
generated inside the victim's authenticator and **never leaves the hardware**. The attacker can
only relay what the victim's device actually signed — and that says `evil`. → **No key, no forged
signature.**

So the attacker is trapped: *valid signature ⟹ origin says `evil`* (caught by the origin check),
or *origin says `demo` ⟹ signature invalid* (caught by the signature check). Never both at once.

**"But they could make the browser stamp `demo`."** The origin is written by the **victim's
browser**, reporting the **real address bar**. The victim is on `evil.localhost` because that is
where the phishing link sent them; the attacker controls `evil.localhost`, not `demo.localhost`.
To make the browser honestly stamp `demo.localhost`, the attacker would have to actually serve the
page *from* `demo.localhost` — which requires owning the domain and a valid TLS certificate for
it. So the origin binding quietly rides on the existing **TLS/PKI** trust: you cannot get a valid
certificate for a domain you do not own, so you cannot make a victim's browser believe your fake
site *is* the real one.

**Second lock — RP ID scoping (layer 1).** At registration the credential is scoped to the RP ID
`demo.localhost`. A *real* browser will not even offer that credential to a page running on
`evil.localhost`. That is why, in this lab, the browser had to be **simulated** to perform the
attack at all. The server-side origin check is **layer 2** — the backstop we are demonstrating,
and the one developers actually forget. The two layers together are what make FIDO2
*phishing-resistant* rather than merely *phishing-discouraged*.

### 6.6 Result against the hardened server
```
[attack] relayed assertion -> error: login rejected: Unexpected client data origin
         "https://evil.localhost", expected "https://demo.localhost"
RESULT: DEFENDED -- origin mismatch rejected the phish.
```
The signature is valid and the challenge is fresh — both jaws held, so the attacker could not
forge the origin — and the assertion confesses `evil.localhost`. The server simply reads the
confession.

---

## 7. Attack 3 — Cloned Authenticator / Signature Counter  (missing check: **Counter**)

**File:** `attack3_counter_clone.py` → maps to *Missing Check C*. This attack starts from a
**stronger assumption** than the others: the attacker has *already extracted the private key*. The
key is meant to be unstealable, so this check is the **last-resort tripwire** for when that
guarantee has already failed — defense in depth.

### 7.1 What it does
1. `carol` registers (server stores `sign_count = 0`).
2. She logs in **twice** on her real device; the authenticator increments its counter before each
   signature, so it signs `count=1`, then `count=2`. The server watches it climb.
3. The attacker spins up a **clone**: same private key, same credential id, but a *fresh device*
   that counts from its own zero.
4. The clone logs in → it signs `count=1`.

### 7.2 Result against the vulnerable server
```
[setup] real device now at higher counter; server last saw it advancing.
[attack] attacker clones the key (counter resets to its own zero)...
[attack] clone login -> ok: Welcome, carol_clone! (login accepted)
RESULT: VULNERABLE -- clone accepted; counter never checked.
```

### 7.3 Why it works
Every authenticator keeps a private tally — "this is the Nth time I have ever signed" — and stamps
it into the signed `authenticatorData`. A single honest device can only ever count **upward**. Now
there are **two** devices sharing one identity, each counting independently. The real device
reached **2**; the clone, counting from its own zero, presents **1**. From the server's view the
counter went **2 → 1** — impossible for one honest device. It is an odometer rolling backward:
proof a second device exists. The clone's signature *is* valid (it holds the real key), so the
counter regression is the only possible tripwire — and the vulnerable server never stores or
compares the counter.

### 7.4 The patch (hardened server)
```python
credential_current_sign_count=stored["sign_count"]          # [FIX C] py_webauthn compares
...
# belt-and-suspenders manual guard:
if verified.new_sign_count <= stored["sign_count"] and stored["sign_count"] != 0:
    return error("possible cloned authenticator (counter did not advance)"), 401
stored["sign_count"] = verified.new_sign_count              # remember the new high-water mark
```
The server remembers the highest counter it has seen and demands every login **advance past it**.
The clone's `1 ≤ 2` → flagged. The genuine device, still climbing (3, 4, …), passes.

### 7.5 Deep-dive: *multiple devices, account sharing, and why the counter is a signal, not a verdict*

> **Point raised during the practical:** many services let one account be used on very different
> devices in very different locations, which can make the sign count appear to go backwards — so
> counter-based detection is only reliable where the account and the hardware are one-to-one;
> otherwise it is an *indicator that something may be wrong and action is needed*, not a proof.

This is correct, with one important technical sharpening:

**The counter is per-*credential*, not per-*account*.** When you register on a new device, that
device creates its **own separate credential** — its own keypair, its own `credential_id`, its own
counter. The server stores a separate `(public_key, sign_count)` line **per credential_id**, and
on each login it looks up *that specific credential* (the assertion carries its `rawId`) and
compares against *that credential's* stored counter. So **two different devices on one account =
two independent credentials = two independent counter lines.** Ordinary multi-device,
multi-location use causes **no regression**, because the server never compares one device's counter
to another's.

**So when does the counter legitimately go backwards?** Only when **one credential — the same
private key — exists on multiple devices at once.** The mainstream case where that is *by design*
is **synced passkeys** (iCloud Keychain, Google Password Manager), which deliberately copy the same
credential to all your devices. Multiple machines then increment "the same" counter independently,
so it genuinely collides or regresses. That is precisely why those platforms report
`signCount = 0` on every login — so the server's "did it advance?" check has nothing to trip on.
(The hardened code accounts for this with the `and stored["sign_count"] != 0` guard, which skips
the check for always-zero counters rather than locking out a legitimate synced passkey.)

So the precise statement is: it is not *account*-sharing across devices that breaks the counter
(each device usually has its own credential and its own counter) — it is *credential*-sharing
across devices. A copied key is **either** a synced passkey (benign) **or** a clone (malicious),
and the counter alone cannot distinguish them.

**Therefore the counter is a risk signal, not a verdict.** A regression means *"two things claim to
be the one device that holds this key."* The correct response is **risk-based, not a hard block**:

- **1:1 hardware model** (e.g. a single YubiKey, one credential bound to one un-copyable device) →
  a regression is a strong, near-certain clone signal; reasonable to **hard-reject / revoke**.
- **Everywhere else** (synced or copyable credentials) → a soft signal; the right action is to
  **step up**: re-verify the user, force re-authentication, flag/alert the session, possibly
  require re-registration. *Investigate and act* — do not lock out.

For the report: *the signature counter is a defense-in-depth tripwire whose strength depends
entirely on whether the deployment guarantees one-credential-to-one-device. Treat its output as
"raise an alarm and act," not "proof of attack."*

---

## 8. Consolidated results

Same attacker code, same three scripts, in both runs. The **only** difference is which server is
listening.

| Attack | Missing check | Attacker needs | Vulnerable (:5006) | Hardened (:5007) — actual error |
|--------|---------------|----------------|--------------------|----------------------------------|
| 1. Replay | Challenge (freshness) | a recording | **VULNERABLE** — `ok` | **DEFENDED** — `no pending challenge (already used?)` |
| 2. Phishing | Origin (which site) | a relay | **VULNERABLE** — `ok` | **DEFENDED** — `Unexpected client data origin "https://evil.localhost", expected "https://demo.localhost"` |
| 3. Clone | Counter (which device) | the stolen key | **VULNERABLE** — `ok` | **DEFENDED** — `Response sign count of 1 was not greater than current count of 2` |

Hardened summary output:
```
Challenge replay     attack_succeeded=False  -> DEFENDED
Origin confusion     attack_succeeded=False  -> DEFENDED
Counter clone        attack_succeeded=False  -> DEFENDED
All attacks defeated.
```

**Critical observation:** in the hardened run, every *honest* step still succeeded
(`Welcome, … (verified)`). The fixes reject attacks **without breaking legitimate use** — the mark
of a good security control. A check that also locks out real users is a denial-of-service, not a
defense.

---

## 9. Honesty caveats (for presentation / Q&A)

These keep the assessment intellectually honest and pre-empt the obvious challenges:

- **The browser is simulated, and that is the point.** Real WebAuthn needs a real browser to build
  `clientDataJSON` and enforce origin/RP-ID. A real browser would *refuse* to perform these attacks
  (RP-ID scoping, layer 1). We simulate the client to demonstrate **layer 2 — the server-side
  checks developers actually forget.** The simulation is faithful: real ECDSA P-256 keys, real COSE
  encoding, real WebAuthn byte layouts, real signatures (proven in `verify_against_library.py`).
- **Ignoring attestation is *not* a vulnerability here.** Attestation verifies the authenticator's
  make/model; consumer sites deliberately use `fmt:"none"`. It matters for enterprise hardware
  allow-listing, not general login. Do not present it as an exploitable flaw.
- **Counter-based clone detection is eroding.** Synced passkeys report `signCount = 0` forever
  (section 7.5), so Attack 3's defense is meaningful mainly for single-device hardware
  authenticators (a YubiKey). Present the counter as a risk signal, not a universal protection.
- **Phishing resistance is two layers.** (1) The browser refuses a credential on a mismatched
  origin; (2) the server verifies the origin as a backstop. This lab, having no browser,
  demonstrates layer 2.

---

## 10. The two reconstructed files (how the lab is wired)

Both modules were missing from the delivered project and were rebuilt to the exact contract the
rest of the code requires.

**`cose.py` — the server/verifier side.** Turns the stored COSE public key back into a usable key
and verifies signatures by hand. Exports:
- `parse_authenticator_data(auth_data)` → `{rp_id_hash, flags, sign_count}` (splits the fixed
  37-byte head of authenticatorData).
- `cose_to_public_key(cose_bytes)` → a `cryptography` EC public key; accepts **only** EC2/P-256/
  ES256 and raises on anything else (refusing unexpected key types is how real verifiers avoid
  algorithm-confusion attacks).
- `signature_is_valid(public_key_cose, auth_data, client_data_json, signature)` → `bool`. Rebuilds
  `signed_payload = auth_data || SHA256(client_data_json)` and verifies the ECDSA signature. This
  is the *single* check the vulnerable server performs.

**`client.py` — the browser + authenticator driver the attacks use.** Exposes honest defaults *and*
the knobs an attacker needs. Exports:
- `Client(base_url, true_origin)` with `.devices`, `.register(user)`,
  `.login(user, origin=…, device=…)` → `(response, captured_assertion)`, and
  `.replay(user, captured)` (re-sends captured bytes verbatim, no fresh `/login/begin`).
- `clone_device(device)` → a new authenticator sharing the **same private key and credential id**
  but with its counter reset to 0 (models a key-extraction clone).

The honest path uses `true_origin` and the user's real device; the attacks override the origin
(phishing), swap in a clone (clone attack), or replay captured bytes (replay attack) — precisely
the capabilities a real browser denies an attacker.

---

## 11. Conclusion — why FIDO2 beats TOTP

A TOTP code is a bare secret that does not know who is asking; relay it to the real site and it
works, so phishing is *unfixable*. A FIDO2 assertion welds the **origin** to a **signature the
attacker cannot forge** (section 6.5), so a relayed assertion arrives stamped with the attacker's
own domain — it confesses the attack. The server only has to read the confession.

The single sentence that carries the whole assessment:

> **A valid signature only proves that someone holds the key. The *challenge* proves the login is
> fresh, the *origin* proves it is for your site, and the *counter* proves it is the one real
> device. Forget any one of the three and the matching attack walks straight in.**

The vulnerable server checked only the signature, and all three attacks succeeded. The hardened
server checked all four, and the same three attacks — unchanged — all failed, while every
legitimate login still worked.
