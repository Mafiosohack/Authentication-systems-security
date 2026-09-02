# Authentication Systems Security

Six authentication mechanisms, each built three times: a deliberately vulnerable
implementation, a set of working attacks against it, and a hardened rebuild that the
same attacks are re-run against. Every attack runs on localhost against code in this
repository. Nothing is simulated with mocked responses; verdicts come from real HTTP
responses.

| # | System | What it covers | Folder |
|---|--------|----------------|--------|
| 1 | Password + sessions | hashing, rate limiting, enumeration, session forgery/fixation | `authentication program/` |
| 2 | TOTP multi-factor | RFC 6238 built from scratch, replay, window, secret storage, flow binding, AiTM relay | `authentication system 2/` |
| 3 | Passkeys / FIDO2 / WebAuthn | challenge, origin, signature counter, from-scratch authenticator proven against `py_webauthn` | `authentication program 3/` |
| 4 | OAuth 2.0 / OpenID Connect | redirect_uri, state, PKCE, code replay, id_token validation, RFC 9700 controls | `authentication system 4/` |
| 5 | JWT for stateless APIs | algorithm confusion, expiry, refresh rotation, revocation, DPoP sender-constraining | `authentication system 5/` |
| 6 | Account recovery + enrollment | enumeration, mass assignment, host-header poisoning, token lifecycle, IDOR, OTP lockout | `authentication system 6/system-6-account-recovery/` |

The thread running through the series: systems 1 to 5 harden the front door, and
system 6 shows that none of it matters if the recovery flow is weak.

## Quick start

One Python environment runs everything.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Folder names contain spaces, so quote them when you `cd`. Each system's servers
recreate their own SQLite or in-memory state on start, so there is no setup step
beyond installing dependencies. Ports are listed per system below; only one
stack per port at a time.

Node is needed only if you want to regenerate the System 4 Word report
(`npm install docx && node build_report.js`).

## Repository layout note

Two systems keep their hardened build under a `mnt/user-data/outputs/...` path.
That is where the files were produced originally, and the attack and verify
scripts refer to those paths, so they were kept rather than moved:

```
authentication program/mnt/user-data/outputs/system1/hardened/app.py
authentication system 2/mnt/user-data/outputs/system2/hardened/app.py
authentication program 3/mnt/user-data/outputs/system3_fido2/hardened/server.py
```

Runtime databases (`*.db`), `__pycache__`, virtual environments and local tool
settings are git-ignored.

---

## System 1: Password authentication and sessions

**Folder:** `authentication program/`

| Role | File | Port |
|------|------|------|
| Vulnerable app | `app.py` | 5000 |
| Hardened app | `mnt/user-data/outputs/system1/hardened/app.py` | 5001 |
| Attack chain | `attack_demo.py` | targets the port set in `TARGET` at the top of the file |
| DVWA variant | `dvwa_attack_demo.py` | external DVWA host, not part of the local lab |
| Report | `SYSTEM1_REPORT.md`, `DEMO_GUIDE.md` | |

Vulnerabilities (V1 to V7): unsalted MD5, no rate limit, verbose errors that
enumerate usernames, hardcoded `secret_key` enabling session forgery, cookies with no
`HttpOnly`/`SameSite`, no session regeneration (fixation), Flask debugger exposed.

Hardened fixes (F1 to F10): bcrypt with per-user salt, Flask-Limiter at 10/min/IP,
generic error message, `SECRET_KEY` from the environment, cookie flags, `session.clear()`
before login, `debug=False`, plus account lockout after 5 failures, constant-time
comparison and a dummy hash so missing users cost the same time as real ones.

```bash
cd "authentication program"
python app.py                                                # vulnerable, :5000
python mnt/user-data/outputs/system1/hardened/app.py         # hardened, :5001
python attack_demo.py                                        # enumeration -> brute force -> offline MD5 crack
```

Known documentation gap: `attack_demo.py`'s docstring says it targets :5000 but the
`TARGET` constant in the file points at :5001. Set it to whichever build you are demonstrating.

---

## System 2: Password + TOTP multi-factor

**Folder:** `authentication system 2/`

| Role | File | Port |
|------|------|------|
| Vulnerable app | `app.py` | 5002 |
| Hardened app | `mnt/user-data/outputs/system2/hardened/app.py` | 5004 |
| Attacks 1 to 4 | `attack_demo.py` | targets :5002 |
| Attack 5, AiTM relay | `relay_proxy.py` + `victim_simulator.py` | proxy on :5003 relaying to :5002 |
| Hardened verification | `verify_hardened.py` | targets :5004, asserts on replay, window and lockout |
| TOTP from scratch | `totp_from_scratch.py` | HMAC-SHA1 -> HOTP -> TOTP, cross-checked against `pyotp` |

Vulnerabilities (V1 to V6): no rate limit on TOTP verification, no replay protection,
window of ±3 steps (7 codes valid at once), secret stored in plaintext, an endpoint
that returns the secret, and the session marked authenticated after the password
step so `/dashboard` is reachable without ever entering a code.

Hardened fixes: per-user lockout after 5 wrong codes plus a 10/min limiter on the
verify route, `last_used_step` replay guard, window of ±1, secret encrypted at rest
with Fernet, no secret endpoint, and a `pending_user` state that only becomes a real
session after the code is accepted.

The relay proxy is the honest limit of this system: a real-time phishing relay
defeats TOTP no matter how well it is implemented, because the code carries no
binding to the site asking for it. That is the bridge to System 3.

```bash
cd "authentication system 2"
python app.py                                                # vulnerable, :5002
python attack_demo.py                                        # bypass, secret leak, replay, brute-force surface
python relay_proxy.py                                        # then, in another terminal:
python victim_simulator.py                                   # victim "logs in" through the proxy
python mnt/user-data/outputs/system2/hardened/app.py         # hardened, :5004
python verify_hardened.py                                    # asserts replay/window/lockout hold
```

---

## System 3: Passkeys / FIDO2 / WebAuthn

**Folder:** `authentication program 3/` (its own `README.md` and
`System3_Practical_Report.md` go deeper)

| Role | File | Port |
|------|------|------|
| Simulated authenticator | `authenticator.py` | ECDSA P-256, COSE, real authenticatorData byte layout |
| COSE decode + manual verify | `cose.py` | what the vulnerable server checks |
| Browser + authenticator client | `client.py` | the attacks drive this |
| Protocol walkthrough | `ceremony_demo.py` | prints every byte of both ceremonies |
| Credibility proof | `verify_against_library.py` | production `py_webauthn` accepts our output |
| Vulnerable RP | `server.py` | 5006 |
| Hardened RP | `mnt/user-data/outputs/system3_fido2/hardened/server.py` | 5007 |
| Attacks | `attack1_challenge_replay.py`, `attack2_origin_confusion.py`, `attack3_counter_clone.py` | |
| Re-run against hardened | `rerun_attacks.py` | exits non-zero if any attack succeeds |

A valid signature only proves someone holds the private key. The vulnerable server
verifies the signature and nothing else. The hardened server also checks the
challenge (consumed on use), the origin, and the signature counter.

FIX D, added after the independent audit: synced passkeys report `signCount=0`
forever and the spec skips the monotonic check when both sides are zero, so a
record that never advanced past zero could be authenticated by a cloned
zero-count assertion indefinitely. The hardened server now keeps a separate
`zero_count_uses` budget; after 5 zero-count logins the credential is retired
(HTTP 403, distinct message) and the user must re-register. The existing
counter check for advanced records is unchanged.

```bash
cd "authentication program 3"
python ceremony_demo.py
python verify_against_library.py
python server.py                                             # vulnerable, :5006
python attack1_challenge_replay.py                           # each attack succeeds
python attack2_origin_confusion.py
python attack3_counter_clone.py
python mnt/user-data/outputs/system3_fido2/hardened/server.py   # hardened, :5007
python rerun_attacks.py                                      # same three attacks, all rejected
```

---

## System 4: OAuth 2.0 / OpenID Connect

**Folder:** `authentication system 4/` (its own `README.md` covers the RFC mapping)

Two three-server stacks on the same ports, never run at once: authorization server
:5000, client :5001, resource server :5002. `vuln_*` files are the broken stack,
`hardened_*` the fixed one. `oauth_engine.py` holds the from-scratch primitives
(codes, tokens, PKCE, hand-built HS256 JWT) and has a self-test.

| # | Flaw | Hardened control |
|---|------|------------------|
| 1 | `redirect_uri` not validated | exact-string match against registration |
| 2 | no `state` | state bound to the user-agent session |
| 3 | no PKCE | `code_challenge` required and verified |
| 4 | code replayable | single-use codes; reuse revokes tokens minted from the code |
| 5 | id_token not verified | pinned alg, signature, iss, aud, nonce all checked |

```bash
cd "authentication system 4"
python oauth_engine.py                                       # self-test
python run_simulation.py                                     # vuln stack 5/5 succeed, hardened 0/5
```

Scope caveat found in the audit: `attack5_idtoken.py` does not talk to a running
server. It calls the engine's decode/verify functions locally and picks the
strategy from the `IDTOKEN_STRATEGY` environment variable, so "the same attack
hits both stacks" is true for attacks 1 to 4 only.

---

## System 5: JWT authentication for stateless APIs

**Folder:** `authentication system 5/`

| Role | File | Port |
|------|------|------|
| Vulnerable API (Flask) | `vulnerable_jwt_api.py` | 5008 |
| Hardened API (FastAPI) | `hardened_jwt_api.py` | `uvicorn hardened_jwt_api:app --port 5009` |
| JWT from scratch | `jwt_engine.py` | RFC 7515/7518/7519 compact serialization |
| Attacks | `attack_alg_confusion.py`, `attack_no_expiry.py`, `attack_refresh_no_rotation.py`, `attack_no_revocation.py`, `attack_bearer_replay.py` | target :5008 |
| Hardened verification | `verify_hardened.py` | 14 asserting checks, in-process, no socket |
| Attacks vs hardened | `verify_attacks.py` | drives all 5 attacks at the hardened build and asserts each is blocked |

Vulnerable (V1 to V6): the verifier trusts the token's own `alg` (so `alg=none` and
RS256->HS256 with the published public key both forge admin), no `exp`, refresh
tokens never rotate, logout does nothing server-side, bearer tokens usable by
anyone holding the string, and PII in the payload.

Hardened: algorithm pinned to RS256, 15-minute `exp` with iss/aud validated,
refresh rotation with reuse detection that burns the whole token family, a
per-user token version so logout truly revokes, DPoP sender-constraining
(RFC 9449) so a stolen token is useless without the client's private key, and
only `sub`/`role` in the token.

Both verifiers were rewritten after the audit so that every check is a real
assertion and the scripts exit non-zero on any failure. Each control was
deliberately broken on a scratch copy and confirmed to trip the matching
assertion by name.

```bash
cd "authentication system 5"
python vulnerable_jwt_api.py                                 # :5008, then run any attack_*.py
python verify_hardened.py                                    # 14/14 asserted
python verify_attacks.py                                     # 5/5 attacks blocked
```

Known documentation gap: `jwt_engine.py`'s docstring references a
`verify_against_pyjwt.py` that is not in the repository.

---

## System 6: Account recovery and enrollment

**Folder:** `authentication system 6/system-6-account-recovery/` (see `CLAUDE.md` for
the design brief and `attack_lab/README.md` for the visual console)

| Role | File | Port |
|------|------|------|
| Vulnerable (Flask) | `vulnerable/vulnerable_account_recovery.py` | 5000 |
| Hardened (FastAPI) | `hardened/hardened_account_recovery.py` | 5000, same JSON shapes so attacks run unmodified |
| Attacks | `attacks/attack_*.py`, one per vulnerability | |
| Visual attack lab | `attack_lab/attack_lab.py` | 8000, toggles the target between builds |
| Evidence | `report/.vuln_before_output.txt`, `report/.hardened_after_output.txt`, `report/.hardened_onmerits_output.txt` | |

| # | Vulnerability | Hardened fix |
|---|---------------|--------------|
| 1 | distinct "username/email taken" errors | one generic response either way |
| 2 | `User(**json)` mass assignment to admin | explicit Pydantic allowlist; `is_admin` never client-settable |
| 3 | known vs unknown email diverge in recovery | identical response and code path |
| 4 | reset link built from the `Host` header | link built from server-side `BASE_URL` |
| 5 | token is `int(time*1000)`, OTP from `random` | `secrets`; token stored as sha256 at rest |
| 6 | no expiry, no single use | 15-minute TTL, delete on use, invalidate all sibling tokens |
| 7 | no OTP lockout | 5 attempts per challenge plus per-IP sliding window |
| 8 | reset target taken from client `email` | target comes only from the token record |

The hardened build's `/outbox` redacts tokens by default. That means attacks 4, 6
and 8 fail in default mode before the real defense is reached (they get a 422 for a
null token). The honest proof that single-use, TTL and account binding work is the
run with `HARNESS_EXPOSE_TOKENS=1`, captured in `report/.hardened_onmerits_output.txt`.

```bash
cd "authentication system 6/system-6-account-recovery"
python vulnerable/vulnerable_account_recovery.py             # :5000, then run attacks/*.py
python hardened/hardened_account_recovery.py                 # :5000 (stop the vulnerable one first)
HARNESS_EXPOSE_TOKENS=1 python hardened/hardened_account_recovery.py   # on-merits mode for #6/#8
python attack_lab/attack_lab.py                              # visual console on :8000
```

---

## Verification status

An independent verification pass was run across the whole series after the reports
were written. Fixed since then: the System 1 rate-limit wiring, the System 4
hardcoded client secret key, the System 2 window/replay tests (now real asserts,
proven by mutation), System 3 FIX D above, and both System 5 verifiers.

Still open, deliberately left in place and documented rather than quietly patched:

- **System 2:** the password step at `/login` has no throttle or lockout. Only the
  TOTP step is limited. 15 wrong passwords returned 200 every time.
- **System 3:** `/login/finish` distinguishes registered from unregistered users by
  status code, body and timing. A malformed `clientDataJSON` also produces an
  unhandled 500.
- **System 4:** public-client id_tokens are signed with the literal string
  `spa-no-secret`. A forged token signed with that constant passes the strict
  verifier for the `spa` audience. No SPA relying party exists in the repository
  to submit it to, but any that verified correctly would accept it.
- **System 6:** `/register` hashes the password only on the new-account branch, so
  an existing email answers in about 7 ms and a new one in about 65 ms. The bodies
  are identical, the timing is not.
- **Systems 3, 4, 5:** no rate limiting on the primary credential endpoint of any
  of them. System 1 and System 6 are the only builds with throttling.
- **System 1 report:** the sentence claiming the hardened build "trips obvious
  alerts" has no alerting code behind it. The only signal is a `[SECURITY] Locked`
  line printed to stdout on lockout.

## Standards referenced

RFC 6238 and 4226 (TOTP/HOTP), WebAuthn Level 2 and FIDO2 CTAP, RFC 6749/6750/7636
and RFC 9700 (OAuth 2.0 Security BCP), OpenID Connect Core 1.0, RFC 7515/7518/7519
and RFC 8725 (JWT/JWS and best practices), RFC 9449 (DPoP), NIST SP 800-63B,
OWASP ASVS v4 sections 2 and 2.5, and the CWE entries cited inline in each attack.

## Safety

Everything here is a teaching lab. Every server binds to localhost, every attack is
hardcoded to 127.0.0.1, and the vulnerable builds say so in their first docstring.
Do not deploy any of the vulnerable code, and do not point the attack scripts at
systems you do not own.
