# System 6 — Account Recovery & Enrollment

This is the sixth system in an authentication security research series. Systems 1–5
covered password/session auth, TOTP MFA, passkeys/WebAuthn, OAuth2/OIDC, and JWT.
This system covers the account lifecycle's two soft doors: **recovery** and
**enrollment**.

## Thesis (this drives the report)

Systems 1–5 hardened the *front door*. System 6 is the observation that none of it
matters if the recovery flow is weak — recovery is the hallway everyone forgets to
lock. The interesting failures here are **flow-logic** failures, not factor strength.
OTP brute force is ONE vulnerability inside this system, not the frame. Do not
headline the report on OTP math; headline it on token lifecycle, link poisoning,
account binding, and enrollment access control.

## The 4-Phase Structure (no exceptions)

1. **Vulnerable implementation** — Flask. Real, demonstrable vulnerabilities, not
   simulated. Inline comments marking each vuln and why. Must run end-to-end.
   File: `vulnerable/vulnerable_account_recovery.py` (ALREADY BUILT — verify it runs).
2. **Attack scripts** — one per vulnerability, in `attacks/`. Self-contained, run
   against localhost, print clear proof of attacker gain, reproducible every run.
   No placeholder values — they run unmodified.
3. **Hardened implementation** — FastAPI. Clean rebuild with security designed in,
   not a patch. Every vuln below addressed. Every security decision inline-commented
   with the *why* and any tradeoff. File: `hardened/hardened_account_recovery.py`.
4. **Report** — professional Word `.docx` via python-docx. Section structure below.
   File: `report/System_6_Account_Recovery.docx`.

## The 8 vulnerabilities → remediation map

The hardened build must address ALL of these. Do not drop one or invent extras.

| # | Vulnerability | Fix in the hardened build |
|---|---|---|
| 1 | Enumeration at enrollment (distinct "username/email taken" errors) | Generic response; send verification mail regardless of existence. Note the UX tradeoff. |
| 2 | Mass assignment → admin at signup (`User(**json)`) | Explicit Pydantic model, allowlist of settable fields only. `is_admin` never client-settable. |
| 3 | Enumeration in recovery (known vs unknown email diverge) | Always return the same generic "if an account exists, an email was sent"; same code path/timing. |
| 4 | Host-header injection in reset link | Build the reset URL from a server-side configured `BASE_URL`. Never trust the `Host` header. |
| 5 | Predictable OTP (`random`) + time-based token | `secrets.token_urlsafe(32)` for the token; store it HASHED (sha256) at rest so a DB leak yields no live tokens. If a numeric OTP is kept, `secrets.randbelow`, but prefer the link-token. |
| 6 | No expiry, no single-use, replayable | Short TTL (15 min), single-use (delete on use), invalidate ALL of a user's tokens on successful reset. |
| 7 | No rate limit / lockout on OTP verify | Per-account + per-IP attempt cap with backoff/lockout. Prefer high-entropy token over 6-digit code. |
| 8 | Broken account binding / IDOR on reset (target from client `email`) | Derive the target account from the token record ONLY. Never trust a client-supplied email/user_id. |

Baseline hygiene the hardened build must also observe (not System-6 headline vulns,
but do not ship without them): passwords hashed with `argon2-cffi` or `bcrypt`
(never plaintext) since the reset path writes new passwords.

## Attack script naming (Phase 2)

One-to-one with the table above:

- `attacks/attack_enrollment_enumeration.py`   (#1)
- `attacks/attack_mass_assignment.py`          (#2)
- `attacks/attack_recovery_enumeration.py`     (#3)
- `attacks/attack_host_header_injection.py`    (#4)
- `attacks/attack_weak_secrets.py`             (#5)
- `attacks/attack_token_replay.py`             (#6)
- `attacks/attack_otp_bruteforce.py`           (#7)
- `attacks/attack_idor_reset.py`               (#8)

## Report structure (Phase 4)

1. Executive Summary — what this system is, why it matters (1 paragraph)
2. System Overview — the recovery + enrollment flow, how it works
3. Vulnerability Analysis — each of the 8: severity, what it enables
4. Attack Demonstrations — what was run, what it proved (paste real output)
5. Hardened Implementation — what changed, why, tradeoffs
6. Key Takeaways — what a dev/security engineer must remember
7. References — cite the standards (see below)

**Tone:** professional security research, written for a technical team lead, not a
professor. No padding, no minimum word count. Only #7 is a rerun of the Systems 1–2
rate-limiting failure class; #4, #6, #8, #2 are new territory — say so, it's the point.

## Standards to cite

- OWASP ASVS v4 §2 (Authentication) and §2.5 (Credential Recovery)
- OWASP "Forgot Password" and "Credential Stuffing" cheat sheets
- NIST SP 800-63B (memorized secrets, look-up secrets, rate limiting)
- CWE-640 (weak password recovery), CWE-620 (unverified password change),
  CWE-644 (host header), CWE-915 (mass assignment), CWE-307 (no attempt limit),
  CWE-639 (IDOR / authorization bypass)

## Tool / library conventions

- Python 3.x. Flask for the vulnerable app, FastAPI for the hardened one.
- `secrets` for all tokens/codes. `argon2-cffi` or `bcrypt` for passwords.
- `cryptography` where needed. `requests` for attack HTTP.
- Attacks run without modification, no placeholders. Every crypto choice commented.
- If you deviate from this plan (library, port, design), document the reason in the report.

## Scope note

This system is intentionally UNIFIED — recovery *and* enrollment in one system.
If we later decide to split, enrollment (#1, #2) becomes System 7 and this stays
recovery-only. Default: keep unified.

## Working style

Go phase by phase. Verify each phase runs and show output before moving to the next.
Do NOT one-shot all four phases silently — checkpoint after Phase 2 and Phase 3.
