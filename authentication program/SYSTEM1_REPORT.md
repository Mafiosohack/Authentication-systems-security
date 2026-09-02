# System 1 — Basic Password Auth + Sessions
## Full Working Report (Build, Test, Attack-Chain Analysis, Hardening)

Prepared as a personal reference for presentation — covers everything built, run,
and discovered during the testing session on 2026-06-08.

---

## 1. What System 1 Is

System 1 is a paired demo: a **deliberately vulnerable** Flask login system and a
**hardened** rewrite of the same system, plus a Python script that actively attacks
the vulnerable one. The goal is to show — live, with real traffic, not slides — how
a handful of common authentication mistakes turn into a full compromise, and how
each mistake maps to a specific, well-understood fix.

**Files involved:**
| File | Role |
|---|---|
| `app.py` | Vulnerable login system (Flask + SQLite), port 5000 |
| `attack_demo.py` | Live exploit chain: enumeration → brute force → offline crack |
| `mnt/.../hardened/app.py` | Hardened rewrite of the same system, port 5001 |
| `dvwa_attack_demo.py` | Adapted brute-force script for testing against DVWA on Metasploitable (lab use) |
| `DEMO_GUIDE.md` | Presentation script with anticipated Q&A and OWASP mapping |

**OWASP anchor:** A07:2021 — *Identification and Authentication Failures*
(formerly A02:2017). Covers weak credential hashing, brute force without lockout,
session fixation, and missing cookie security flags — all present in `app.py`.

---

## 2. The Vulnerable App — Structure & Catalogued Flaws (V1–V7)

`app.py` is a small Flask app: a login form posts to `/login`, which checks the
submitted credentials against a SQLite table (`vuln_users.db`), and on success
sets a session and redirects to `/dashboard`. Seeded accounts:

```
admin  → 0192023a7bbd73250516f069df18b500   (admin123)   role: admin
john   → 5f4dcc3b5aa765d61d8327deb882cf99   (password)   role: user
alice  → e10adc3949ba59abbe56e057f20f883e   (123456)     role: user
bob    → (qwerty)                                         role: user
```

### The seven intentional weaknesses

| ID | Flaw | Where in code | Why it matters |
|---|---|---|---|
| **V1** | Unsalted MD5 password hashing | `hashlib.md5(password.encode()).hexdigest()` | No per-user salt → identical passwords produce identical hashes; rainbow tables and GPU cracking work directly; MD5 is fast (billions/sec), making offline cracking nearly instant |
| **V2** | No rate limiting | login route has zero throttling | Attacker can submit unlimited login attempts at full network speed — brute force becomes trivial |
| **V3** | Verbose error messages | `"User not found"` vs `"Wrong password"` | Server confirms whether a username exists *before* checking the password — lets an attacker enumerate valid accounts before attacking passwords |
| **V4** | Hardcoded secret key | `app.secret_key = "secret123"` | Flask signs session cookies with this key. A known/guessable key lets an attacker **forge** a valid, signed session cookie for any user/role without ever logging in |
| **V5** | No cookie security flags | Flask defaults — no `HttpOnly`/`Secure`/`SameSite` | Session cookie can be read by JavaScript (XSS exposure), sent over plain HTTP (MITM exposure), and attached to cross-site requests (CSRF exposure) |
| **V6** | No `session.clear()` before login | session values set directly on top of the existing session | Session fixation: an attacker can pre-establish a session ID, trick the victim into authenticating under it, and inherit the now-authenticated session |
| **V7** | `debug=True` | `app.run(debug=True, ...)` | Exposes Werkzeug's interactive debugger on unhandled exceptions — in some configurations this gives an attacker a live Python shell inside the server process (full RCE) |

---

## 3. Environment Setup — What We Actually Built & Ran Today

### Steps performed
1. Installed dependencies: `pip install -r requirements.txt`
   → `flask 3.1.3`, `flask-limiter 4.1.1`, `bcrypt 5.0.0`, `requests 2.34.2`
2. Started the **vulnerable app** (`app.py`) on `http://127.0.0.1:5000`
3. Started the **hardened app** (`mnt/.../hardened/app.py`) on `http://127.0.0.1:5001`
4. Ran `attack_demo.py` against the vulnerable app — full exploit chain executed live
5. Wrote and added `dvwa_attack_demo.py` — a parameterized brute-force script
   adapted for testing the user's own NIDS event-correlation feature against
   Metasploitable/DVWA in their VMware lab (separate, authorized range)

### Two real bugs discovered while running this (worth mentioning live — shows you tested, not just read)

**Bug 1 — Unicode crash on Windows (environment issue, not a vuln)**
Both `app.py` and the hardened app print seed-hash output using the arrow
character `→` (U+2192). Windows' default console codepage (`cp1252`) can't
encode it, causing `UnicodeEncodeError` and an immediate crash on startup.
**Fix used:** set `PYTHONIOENCODING=utf-8` before running:
```powershell
$env:PYTHONIOENCODING="utf-8"
python app.py
```

**Bug 2 — Broken routes in the hardened app (real code bug, not an intentional flaw)**
The hardened app's login view function was named `login_view`, but `index()`,
`dashboard()`, and `logout()` all called `redirect(url_for("login"))` — an
endpoint name that doesn't exist (Flask names endpoints after the function).
This raised `werkzeug.routing.exceptions.BuildError: Could not build url for
endpoint 'login'. Did you mean 'login_view' instead?` and made `/`, `/dashboard`,
and `/logout` all return `500 Internal Server Error`. **Fixed** by renaming the
function back to `login` (matching the vulnerable app's convention and what the
`url_for` calls expected).

> **Presentation point:** this is a great real-world illustration that *"hardened"
> code still needs to be run and tested* — a security rewrite can introduce its
> own bugs that break core functionality, and only execution (not code review
> alone) surfaces them.

---

## 4. Live Attack Run — Actual Results Against the Vulnerable App

Command run: `PYTHONIOENCODING=utf-8 python attack_demo.py` against
`http://127.0.0.1:5000`

### Attack 1 — Username Enumeration (exploits V3)
Sent one fixed wrong password against 10 candidate usernames, read back the
error string.

```
[+] VALID → admin
[-] Invalid: administrator
[-] Invalid: root
[-] Invalid: user
[+] VALID → john
[+] VALID → alice
[+] VALID → bob
[-] Invalid: test
[-] Invalid: guest
[-] Invalid: support

→ 4 valid usernames found: ['admin', 'john', 'alice', 'bob']
```
**Result: 100% of real accounts identified, zero accounts guessed wrong as valid — from error text alone.**

### Attack 2 — Credential Brute Force (exploits V2 + weak passwords)
Took the first confirmed username (`admin`) and hammered `/login` with a
40-word built-in password list (no rate limiting in the way).

```
[+] PASSWORD FOUND: 'admin123'
[+] Attempts: 28 | Time: 0.3s | Rate: 86 req/s
```
**Result: full admin credential recovered in under a third of a second, 28 guesses.**

### Attack 3 — Offline MD5 Hash Cracking (exploits V1)
Simulated a stolen database dump (3 hashes) and cracked them locally —
no server interaction at all.

```
Cracking 'admin' → 0192023a7bbd73250516f069df18b500 → CRACKED: 'admin123'  (0.0ms)
Cracking 'john'  → 5f4dcc3b5aa765d61d8327deb882cf99 → CRACKED: 'password'  (0.0ms)
Cracking 'alice' → e10adc3949ba59abbe56e057f20f883e → CRACKED: '123456'    (0.0ms)
```
**Result: all three hashes cracked instantly (0.0 ms each) against a 40-word list.
A real attacker with `rockyou.txt` (14M entries) and a GPU running hashcat
(10+ billion MD5/sec) would crack effectively any dictionary-based password
in the same database in well under a second per hash.**

### Overall summary line from the run
```
Valid users found:  ['admin', 'john', 'alice', 'bob']
Password cracked:   admin123
All hashes cracked: yes (in milliseconds, offline)
```
**Total elapsed time from "knowing nothing" to "three plaintext passwords recovered": well under two seconds.**

---

## 5. The Manual Attack Chain — "Entry to Root", Step by Step

This answers the question a mentor is very likely to ask: *if you did this by
hand, with no script, what's the realistic path from first contact to having
every password hash?* The script runs three exploits as separate demos — a real
attacker chains them, and picks whichever path is fastest, not necessarily the
one that's most "complete."

### Stage 0 — Recon
Hit `/`, get redirected to `/login`. Notice it's Flask (cookie literally named
`session`, characteristic error pages). Submit a wrong password against a couple
of usernames just to observe *how* the app responds — this is where the two
different error strings get noticed.

### Stage 1 — Username enumeration (exploits V3)
Systematically probe a username list with one fixed bad password.
`"Wrong password"` = account exists. `"User not found"` = it doesn't.
Within minutes: confirmed list of real accounts (`admin`, `john`, `alice`, `bob`).
**This is the force-multiplier step** — it turns a 2D guessing problem
(username × password) into a 1D one (password only, against known-good usernames).

### Stage 2 — The fork: three different ways to get "in"
A skilled attacker does **not** default to brute force — they pick the quietest,
fastest door available. This is the part most worth emphasizing:

**Path A — Brute force (exploits V2 + weak seeded passwords)**
Loud and slow. Works *only* because the seeded passwords happen to be common
dictionary words. Against a genuinely strong password, this path fails outright —
worth saying explicitly, because it shows brute force is not a universal hammer,
just the most "visible" attack and the one beginners reach for first.

**Path B — Session forgery via the hardcoded secret key (exploits V4)** — *see deep dive in section 6*
The quiet, surgical option. No login attempt is ever made — nothing shows up
in a failed-login log, because there isn't one. This is the path that defeats
naive "watch for failed logins" detection entirely.

**Path C — RCE via the exposed debugger (exploits V7)**
The fastest and most devastating. `debug=True` activates Werkzeug's interactive
debugger on any unhandled exception. If an attacker can trigger one (malformed
input, unexpected field types) and reach the debugger console, they get a live
Python shell **inside the Flask process itself** — i.e., code execution as the
OS user running the app. This is no longer "logged in as admin" — this *is* the
server. This is the literal meaning of "root" in the original question.

### Stage 3 — From foothold to "all the hashes"
**Key structural distinction a mentor will probe for:** being authenticated and
dumping the *entire* password database are two different problems. Logging in
(Paths A or B) only yields *your own* session — there's no admin panel here that
exposes other users' data. To get *every* hash at once, the attacker needs
filesystem or database access, not just a session. That's exactly what Path C
hands them: from a Python shell inside the process, `vuln_users.db` is just a
SQLite file on disk —
```python
import sqlite3
conn = sqlite3.connect("vuln_users.db")
conn.execute("SELECT * FROM users").fetchall()
```
— and every username + MD5 hash falls out in one query.
(Note: this app's DB query *is* parameterized — `WHERE username = ?` — so there
is **no SQL-injection path** here specifically; the `DEMO_GUIDE.md` mentions SQLi
only as one *generic* possible dump vector across systems. For *this* app, the
debugger is the realistic route to a full dump.)

### Stage 4 — Offline cracking (exploits V1)
Now fully offline — no server interaction needed at all. Unsalted MD5 means:
rainbow tables work directly, identical passwords across users yield identical
hashes (cracking `alice`'s `123456` for free reveals every other user who reused
it), and a consumer GPU running hashcat performs 10+ billion guesses/second.

### One-paragraph version for a slide
> "Enumerate usernames (V3) → take the fastest entry point available — forged
> session (V4) or debugger RCE (V7), not brute force (V2) — → use that foothold
> to read the database file directly → crack every recovered hash offline in
> milliseconds because they're unsalted MD5 (V1)."

---

## 6. Deep Dive — Session Forgery via the Hardcoded Secret Key (V4)

This is the most "surgical" path in the chain and worth its own explanation,
because it's the one that's easiest to get wrong if asked to explain it on the spot.

**The mechanism:**
Flask doesn't store session data server-side by default — it serializes the
session dict (e.g., `{"user": "admin", "role": "admin"}`), cryptographically
**signs** it with `app.secret_key` using `itsdangerous`, and ships the signed
blob to the browser as the `session` cookie. On each request, Flask re-verifies
the signature using the same key before trusting the cookie's contents.

**The flaw:**
`app.secret_key = "secret123"` is a fixed, hardcoded string — not a per-deployment
secret. *The signature is only as trustworthy as the key is secret.* If an
attacker learns this key (leaked source repo, exposed `.git` directory, backup
file, the Werkzeug debugger reading source files, or simply because `"secret123"`
is a common throwaway default that gets reused across tutorials and toy projects),
they can:

1. Construct any session payload they like — e.g. `{"user": "admin", "role": "admin"}`
2. Sign it themselves, locally, using the *same* key and the *same* `itsdangerous`
   serialization Flask uses
3. Present that self-made cookie to `/dashboard`

The server verifies the signature, sees it matches, and **trusts the contents
completely** — because as far as it can tell, only something holding the secret
key could have produced a validly-signed cookie. The attacker never submits a
username or password. There is no failed-login event, no brute-force pattern,
nothing for a naive monitoring system to catch. They simply *arrive*, already
authenticated as whoever they chose to be.

**Why this is the "quiet" path that matters most to call out:**
Most authentication-failure detection (rate limiting, lockouts, alerting on
repeated failed logins — even a NIDS correlation engine watching for brute-force
bursts) is built around the assumption that an attacker has to *interact* with
the login mechanism to get in. Session forgery via a known signing key
**routes around the login mechanism entirely**. It's the cleanest illustration
of why "fix the obvious thing (passwords)" isn't sufficient — the trust anchor
underneath the whole session system has to be solid too.

**The fix (F4 in the hardened app):**
```python
_SECRET_KEY = os.environ.get("SECRET_KEY")
if not _SECRET_KEY:
    _SECRET_KEY = secrets.token_hex(32)
```
A secret pulled from the environment (or generated randomly per-deployment with
`secrets.token_hex`, a cryptographically secure random generator) can't be known
in advance, can't be guessed, and isn't shared across deployments — so a forged
cookie can't be produced without first compromising the server itself (at which
point the attacker has bigger wins available anyway).

---

## 7. The Hardened App — Fixes Catalogue (F1–F10) and What Each One Closes

| ID | Fix | Closes | Mechanism |
|---|---|---|---|
| **F1** | bcrypt, work factor 12, per-user salt | V1 | Replaces fast unsalted MD5 with a deliberately slow (~250ms/check), salted algorithm. Identical passwords now produce *different* stored hashes; offline cracking drops from billions/sec to a tiny fraction of that |
| **F2** | Flask-Limiter — 10 attempts/minute/IP | V2 | Throttles login attempts server-side; turns "unlimited guesses at network speed" into a slow, loud, easily-alertable trickle |
| **F3** | Single generic error message ("Invalid credentials") | V3 | Removes the signal that distinguished "user exists" from "user doesn't" — enumeration becomes impossible from response *content* |
| **F4** | `SECRET_KEY` from environment / `secrets.token_hex(32)` | V4 | Removes the fixed, guessable signing key — session forgery becomes computationally infeasible (see section 6) |
| **F5** | `HttpOnly`, `SameSite=Lax` cookie flags (`Secure` for production) | V5 | Blocks JavaScript from reading the cookie (mitigates XSS-based theft) and blocks the cookie from being sent on cross-site requests (mitigates CSRF) |
| **F6** | `session.clear()` before setting new session values | V6 | Forces a fresh session ID at login — an attacker's pre-fixed session ID never becomes authenticated |
| **F7** | `debug=False` | V7 | Removes the interactive debugger entirely — no RCE surface from unhandled exceptions |
| **F8** *(bonus)* | Account lockout — 5 failures → 5-minute lock | — | Adds a *per-username* defense layered on top of the *per-IP* rate limiter (F2). Neither alone is sufficient: rate limiting alone is bypassed by an attacker with many IPs; lockout alone is bypassed by spreading guesses across many accounts. Together they cover both axes |
| **F9** *(bonus)* | Constant-time comparison via `bcrypt.checkpw` | — | Prevents an attacker from distinguishing correct vs incorrect *characters* of a password by measuring micro-differences in comparison time |
| **F10** *(bonus)* | Pre-computed dummy hash run for non-existent users | — | The single most subtle fix: even with generic error *text* (F3), a missing user would normally return in ~2ms (no bcrypt call) while a real-but-wrong-password user takes ~250ms (bcrypt runs). That timing gap **alone** would let an attacker re-enumerate usernames by measuring response latency. Running `bcrypt.checkpw` against a dummy pre-computed hash even when the user doesn't exist makes both paths cost the same — closing the side-channel that F3's text fix didn't |

### Why the hardened app survives the *exact same* attack chain
- **Stage 1 (enumeration)** fails immediately: every response says `"Invalid credentials"`, and F10 ensures it even *takes the same amount of time* to say it. `attack_demo.py` run against port 5001 reports zero confirmed usernames and exits early — the chain never gets off the ground.
- **Stage 2 / Path A (brute force)** would be throttled by F2 (10/min/IP) and then locked out entirely by F8 (5 failures → 5 min lock) — converting "86 requests/sec, cracked in 0.3s" into something that takes the attacker hours and trips obvious alerts the entire time.
- **Stage 2 / Path B (session forgery)** is closed outright by F4 — there is no fixed key to learn, so there's nothing to forge a valid signature with.
- **Stage 2 / Path C (debugger RCE)** is closed outright by F7 — no debugger, no RCE surface, no path to the database file.
- **Stage 4 (offline cracking)**, even in the worst case where hashes *were* somehow exfiltrated, F1's bcrypt (work factor 12, ~250ms/check, per-user salt) turns "milliseconds to crack a whole database" into a problem that would take meaningfully long per password, with no shortcuts from shared-password collisions (because salts make every hash unique even for identical passwords).

**The structural point this proves:** the hardened app doesn't rely on any single
fix being perfect — it breaks the chain at *several independent links*
simultaneously. Even if one fix were misconfigured or missed, the others still
hold. That's defense-in-depth in practice, not just in name.

---

## 8. Recommendations (General, Beyond This Demo)

1. **Hash passwords with bcrypt or Argon2, never fast general-purpose hashes
   (MD5, SHA-1, raw SHA-256).** Argon2 (PHC winner, 2015) adds *memory* hardness
   on top of bcrypt's CPU hardness, making GPU-based parallel cracking
   significantly harder. In Python: `passlib` or `argon2-cffi`.
2. **Always combine per-IP rate limiting with per-account lockout.** They defend
   against different attacker shapes (distributed vs. targeted) and neither
   alone is sufficient.
3. **Never let error responses (text *or* timing) reveal whether an account
   exists.** Generic messages plus constant-cost code paths (F3 + F9 + F10
   together) are what actually closes this — a generic message alone leaves a
   timing side-channel open.
4. **Treat `SECRET_KEY` (and any signing/encryption key) as a deployment-specific
   secret**, generated with a CSPRNG (`secrets.token_hex`) and supplied via
   environment variables or a secrets manager — never hardcoded, never reused
   across projects or environments.
5. **Set all three cookie security flags** (`HttpOnly`, `Secure`, `SameSite`)
   as a baseline, not an afterthought — each blocks a *different* theft/misuse
   vector (JS access, plaintext transport, cross-site requests respectively).
6. **Always regenerate the session ID at the authentication boundary**
   (`session.clear()` before setting authenticated values) to eliminate fixation.
7. **Never run `debug=True` (or any framework's debug/dev mode) anywhere
   reachable from outside localhost.** The convenience it offers a developer is
   precisely the convenience it offers an attacker.
8. **Test the "secure" version, not just the vulnerable one.** As this session
   demonstrated firsthand (the broken `url_for("login")` endpoint reference),
   a hardened rewrite can ship its own functional bugs — code review alone
   would not have caught it; only running it did.

---

## 9. Anticipated Q&A (from `DEMO_GUIDE.md`, useful to have memorized)

**Rate limiting vs. account lockout?**
Rate limiting is per-IP; lockout is per-username. An attacker with many IPs
bypasses rate limiting (distributed brute force); an attacker targeting one
account specifically triggers lockout. Neither alone is sufficient — both
are needed (this is exactly F2 + F8 together).

**What is session fixation?**
Attacker visits the login page, obtains session ID `ABC123`. Without
`session.clear()`, if the victim authenticates while still holding that same
session ID, the *attacker's* pre-existing session becomes authenticated as the
victim. `session.clear()` forces a fresh ID at the authentication boundary,
severing that link.

**Why bcrypt over SHA-256?**
SHA-256 is *designed* to be fast (a GPU computes ~10 billion/sec — great for
checksums, terrible for password storage). bcrypt is *designed* to be slow
(~250ms/check, tunable via work factor) — turning an attacker's offline crack
rate from billions/sec down to thousands/sec, and the work factor can be raised
as hardware improves.

**What about Argon2?**
The current best practice (Password Hashing Competition winner, 2015). Adds
*memory* hardness on top of CPU hardness — GPUs are excellent at massively
parallel CPU-bound work but much worse at massively parallel *memory-bound*
work, so Argon2 resists GPU cracking better than bcrypt does. Python: `passlib`
or `argon2-cffi`.

**Where does CSRF fit in?**
Browsers send cookies automatically on every request to a domain — including
ones triggered by a malicious third-party site. `SameSite=Lax` (set in the
hardened app, F5) blocks cross-site cookie submission for most cases; explicit
CSRF tokens add another layer. Token-based auth (e.g., JWT in an `Authorization`
header rather than a cookie) sidesteps the cookie-based CSRF problem entirely,
at the cost of needing its own protections (e.g., XSS becomes the bigger concern
since the token typically lives in JS-accessible storage).

---

*End of report — System 1, generated from the live testing session on 2026-06-08.*
