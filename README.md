# Authentication Security Research Series

> ⚠️ **Contains intentionally vulnerable code.** Every `vulnerable_*` implementation in this repo has real, working security flaws by design, for education and offensive-security research. Do not deploy any `vulnerable_*` file. Only `hardened_*` implementations reflect production-grade practice.

## What this is

Five authentication mechanisms — built vulnerable, exploited with working attack scripts, then rebuilt hardened — treated as one continuous research arc rather than five disconnected tutorials. Each system follows the same four-phase methodology (below), so the series functions as a controlled study of *how authentication fails* and *what class of fix actually closes the gap*, not just a list of CVEs reproduced in a sandbox.

27 vulnerabilities were identified and exploited end-to-end across the five systems.

## Cross-system findings

The point of running this as one series instead of five isolated builds is that the same failure modes resurface in different clothing:

- **Brute-force / rate-limiting gaps recur across Systems 1 and 2.** No rate limiting on login attempts (System 1) and no rate limiting on TOTP code verification (System 2) are the same underlying failure — missing attempt-throttling — expressed against two different credentials.
- **Algorithm confusion recurs across Systems 4 and 5.** `alg=none` / signature-algorithm downgrade shows up in OAuth's `id_token` validation (System 4) and again in the JWT access token (System 5), which is why System 5 carries the deeper cryptographic treatment — it's where the class of bug gets fixed properly (algorithm pinning), not just patched locally.
- **The series traces one continuous answer to credential theft and replay:** stealable passwords (System 1) → relayable TOTP codes, phishable via adversary-in-the-middle even when perfectly implemented (System 2) → origin-bound public-key credentials that close the phishing gap (System 3) → delegated-auth trust boundaries (System 4) → sender-constrained, DPoP-bound API tokens that can't be replayed even if stolen (System 5).

## Systems

| # | System | Core Mechanism | Vulnerabilities Found | Key Hardening |
|---|--------|-----------------|------------------------|----------------|
| 1 | [Password / Session Auth](./system-1-password-session) | Server-side sessions, cookie auth | 7 — unsalted MD5, no rate limiting, user enumeration via verbose errors, hardcoded secret key (session forgery via flask-unsign), missing cookie flags, session fixation, debug-mode RCE | bcrypt (cost 12), rate limiting + lockout, generic errors with constant-time dummy-hash comparison, 256-bit env-sourced secret, HttpOnly/Secure/SameSite, session regeneration on login |
| 2 | [TOTP MFA](./system-2-totp-mfa) | Password + time-based OTP, built from RFC primitives (HMAC-SHA1 → HOTP → TOTP) | 6 — no rate limiting on code verification, no replay protection, oversized time window (7 simultaneously valid codes), plaintext secret storage, unauthenticated secret-leak endpoint, MFA-bypass flow flaw | Rate-limited lockout, per-step replay tracking, tight ±1 window, Fernet-encrypted secrets, endpoint removed, strict `mfa_passed` flow binding. Also demonstrates that real-time AiTM phishing relay defeats even a fully hardened TOTP flow — a class limitation, not an implementation bug |
| 3 | [Passkeys / FIDO2 / WebAuthn](./system-3-passkeys-webauthn) | Public-key auth via WebAuthn | 3 — missing challenge validation (replay), missing origin validation (phishing/origin confusion), missing signCount check (cloned authenticator goes undetected) | Full challenge/origin/signCount verification per WebAuthn spec |
| 4 | [OAuth 2.0 / OIDC](./system-4-oauth-oidc) | Federated / delegated auth | 5 — unvalidated `redirect_uri`, missing `state` (CSRF / code injection), no PKCE, authorization-code replay, `id_token` validation failure (`alg=none` + wrong-key acceptance) | Strict redirect_uri allowlisting, mandatory `state`, PKCE, single-use codes, full `id_token` signature/claim validation |
| 5 | [JWT API Auth](./system-5-jwt-api-auth) | Stateless bearer tokens | 6 — algorithm confusion (`alg=none`, RS256→HS256), no expiry, no refresh rotation, no revocation, unconstrained bearer tokens, PII in payload | Algorithm pinning, 15-min access TTL, refresh rotation with reuse detection and family revocation, per-user token versioning for real revocation, DPoP sender-constraining (RFC 9449) |

## Standards this work is checked against

RFC 6238 (TOTP), RFC 4226 (HOTP), RFC 2104 (HMAC), RFC 7519 (JWT), RFC 7515 (JWS), RFC 8725 (JWT Best Current Practices), RFC 9449 (DPoP), RFC 9700 (OAuth 2.0 Security Best Current Practice).

## Methodology — four phases, every system

1. **Vulnerable implementation** — built the way a developer who skipped security training would build it. Real attack surface, not simulated.
2. **Attack scripts** — one working, self-contained exploit per vulnerability. Reproducible, no external infrastructure.
3. **Hardened implementation** — a clean rebuild with security designed in, not a patch layered on top. Every vulnerability from phase 2 addressed, with tradeoffs noted where they exist.
4. **Security research report** — vulnerability analysis, attack demonstrations, hardening rationale, references.

## Repository structure

```
auth-security-research/
├── README.md                        ← this file
├── system-1-password-session/
│   ├── README.md
│   ├── vulnerable_password_session.py
│   ├── attacks/
│   ├── hardened_password_session.py
│   └── report.pdf
├── system-2-totp-mfa/
├── system-3-passkeys-webauthn/
├── system-4-oauth-oidc/
└── system-5-jwt-api-auth/
```

## Running the code

Each system is self-contained. From inside a system's folder:

```bash
pip install -r requirements.txt
python vulnerable_<system_name>.py        # start the vulnerable target
python attacks/attack_<vulnerability>.py  # run against it on localhost
python hardened_<system_name>.py          # start the hardened rebuild
```

No external services or credentials required — every attack runs against localhost.

---

*Independent security research conducted as part of ongoing offensive-security portfolio work.*
