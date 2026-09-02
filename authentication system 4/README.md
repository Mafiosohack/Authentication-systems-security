# System 4 — OAuth 2.0 / OpenID Connect

Authentication Security Study Series. Methodology: **vulnerable → live attacks → hardened**.

Standards basis: RFC 6749, RFC 6750, RFC 7636, **RFC 9700** (OAuth 2.0 Security BCP, Jan 2025),
OpenID Connect Core 1.0. OAuth 2.1 is still an IETF draft and is treated as forward guidance only.

## Layout

All files live flat in one folder (cross-platform: Windows / Linux / macOS).

```
oauth_engine.py            from-scratch primitives: codes, tokens, PKCE, hand-built JWT
launch.py                  test harness: starts/stops a stack of servers
run_simulation.py          ONE command: runs all 5 attacks vs vulnerable, then vs hardened
vuln_auth_server.py        vulnerable stack: AS (5000) + client (5001) + resource (5002)
vuln_client_app.py
vuln_resource_server.py
hardened_auth_server.py    hardened stack: same three servers, RFC 9700 controls, same ports
hardened_client_app.py
hardened_resource_server.py
attack1..attack5_*.py      standalone attacks, each exposes attack() -> (ok, detail)
build_report.js            generates the Word report
System4_OAuth_OIDC_Report.docx
```

The vulnerable and hardened stacks use the **same ports** and never run at once — the harness
tears one down before starting the other. That is deliberate: it lets the fixed attack scripts hit
both stacks unchanged, so each control blocks its attack by its *intended* mechanism rather than by
an incidental redirect-URI mismatch.

## Seeded data (both stacks)

- Users: `alice`/`alicepw` (victim), `mallory`/`mallorypw` (attacker)
- Clients: `webapp` (confidential, secret `webapp-secret-0xDEADBEEF`) and `spa` (public, no secret)

## Run the engine self-test

```bash
python oauth_engine.py         # -> oauth_engine self-test OK
```

## Run the whole simulation (recommended)

One command starts the vulnerable stack, runs all 5 attacks (they succeed),
tears it down, then starts the hardened stack and runs the same 5 attacks
(they are all blocked):

```bash
python run_simulation.py
```

Expected: vulnerable stack 5/5 attacks succeed, hardened stack 0/5.

## Run a single attack by hand

Start one stack, then call an attack's `attack()`:

```python
import importlib
from launch import servers
specs = [("as","vuln_auth_server.py",5000),
         ("client","vuln_client_app.py",5001),
         ("rs","vuln_resource_server.py",5002)]
with servers(specs):
    ok, detail = importlib.import_module("attack1_redirect_uri").attack()
    print(("VULNERABLE " if ok else "BLOCKED ") + detail)
```

Swap the `vuln_` prefixes for `hardened_` (ports unchanged) to confirm it's blocked.

## The five vulnerabilities

| # | Flaw | Control (RFC 9700) |
|---|------|--------------------|
| 1 | redirect_uri not validated | exact-string match against registration (§2.1/§4.1) |
| 2 | no `state` | state bound to user-agent session (RFC 6749 §10.12, §4.7) |
| 3 | no PKCE | code_challenge required + verified (RFC 7636, §2.1.1) |
| 4 | code replayable | single-use codes + reuse revocation (§4.5) |
| 5 | id_token not verified | strict verify: pin alg, check sig/iss/aud/nonce (OIDC Core §3.1.3.7) |

## Regenerate the report

```bash
npm install docx
node build_report.js
python3 /mnt/skills/public/docx/scripts/office/validate.py System4_OAuth_OIDC_Report.docx
```

## Scope boundary with System 5

The OIDC id_token is a JWT. System 4 stops at the **validation policy** (does the client verify it
at all). System 5 attacks the token cryptography itself: RS256→HS256 algorithm confusion, `none`
against non-pinning libraries, weak-secret brute force, JWKS spoofing. The strict verifier built
here is System 5's defensive baseline. Implicit grant and DPoP/refresh-token rotation are noted but
not built.
