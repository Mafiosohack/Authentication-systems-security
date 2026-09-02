# System 1 — Basic Password Auth + Sessions
## Live Demo Script

---

### Environment Setup (do this before mentor arrives)

```bash
pip install -r requirements.txt

# Terminal A — vulnerable app
cd vulnerable && python app.py
# Runs on http://localhost:5000

# Terminal B — attack demo
# Keep ready, don't run yet

# Terminal C — hardened app  
cd hardened && python app.py
# Runs on http://localhost:5001
```

---

### Demo Flow

**Step 1 — Show the vulnerable login page**
Navigate to http://localhost:5000 in browser.
> "This is the baseline — a login form backed by MD5-hashed passwords stored in SQLite.
>  No rate limiting, no account lockout, standard Flask sessions."

**Step 2 — Show the source code vulnerability (V1)**
Open vulnerable/app.py, point to:
```python
pwd_hash = hashlib.md5(password.encode()).hexdigest()
```
> "Passwords are stored as unsalted MD5. I've seen this exact pattern in real systems —
>  Kioptrix had the same thing. Once you get the hash, you're offline. The server is
>  irrelevant after that."

Show the DB seed output on startup:
```
admin  → 0192023a7bbd73250516f069df18b500  (admin123)
john   → 5f4dcc3b5aa765d61d8327deb882cf99  (password)
alice  → e10adc3949ba59abbe56e057f20f883e  (123456)
```
> "If alice and carol both use '123456', their hashes are identical.
>  Crack one, you've cracked both. No salt = no per-user uniqueness."

**Step 3 — Show the verbose error messages (V3)**
Login with: username=admin, password=wrongpass → "Wrong password"
Login with: username=nobody, password=wrongpass → "User not found"
> "Two different error messages. The server is confirming whether a username
>  exists before checking the password. Attacker doesn't need to brute-force
>  username + password space simultaneously — they enumerate usernames first,
>  then attack passwords only."

**Step 4 — Run the attack**
Switch to Terminal B:
```bash
python attacks/attack_demo.py
```
Walk through output:
- Attack 1: Enumerate valid usernames from the candidate list
- Attack 2: Brute force a valid user's password
- Attack 3: Crack the MD5 hash offline in milliseconds

> "Three distinct attacks chained. In a real engagement, I'd run this against
>  a staging environment, not production. The rate here would be 500–1000
>  requests/second with no server-side resistance."

**Step 5 — Show hardened app**
Navigate to http://localhost:5001. Log in, fail 5 times.
> "Same interface. Same flow. Very different behavior under attack."

Show hardened/app.py key changes:
- bcrypt with rounds=12 (F1)
- Generic error message (F3)
- DUMMY_HASH timing anchor (F10)
- session.clear() before login (F6)
- Cookie flags (F5)

> "The most subtle fix is F10 — the dummy hash.
>  bcrypt.checkpw takes ~250ms. If 'user not found' returns in 2ms
>  and 'wrong password' returns in 250ms, you can still enumerate
>  valid usernames by measuring response time. The dummy hash forces
>  both paths through bcrypt at the same cost."

---

### Questions the mentor will likely ask

**"What's the difference between account lockout and rate limiting?"**
Rate limiting is per-IP. Account lockout is per-username.
An attacker with 1000 IPs bypasses rate limiting (distributed brute force).
An attacker targeting a specific user hits the lockout.
Both are needed. Neither is sufficient alone.

**"What does session fixation mean?"**
Attacker navigates to the login page. Gets a session ID: ABC123.
Without session.clear(), if victim logs in with that same session ID,
the attacker's existing session becomes authenticated.
session.clear() rotates the session ID on login. Attacker's session stays anonymous.

**"Why bcrypt over SHA-256?"**
SHA-256 is designed to be fast — GPU can compute 10 billion/sec.
bcrypt is designed to be slow — ~250ms per check is tunable.
Attacker's offline crack rate drops from billions/sec to thousands/sec.
Work factor is adjustable as hardware improves.

**"What about Argon2?"**
Argon2 is the current winner (PHC, 2015). Adds memory hardness.
SHA-256 and bcrypt are CPU-bound — GPUs handle them easily.
Argon2 requires large RAM → GPUs can't parallelize as effectively.
In Python: use passlib or argon2-cffi. For this demo, bcrypt is fine.

**"CSRF — where does it fit?"**
Session cookies are sent automatically by the browser on every request.
A malicious site can make the victim's browser submit a POST to your login/action endpoints.
Mitigation: SameSite=Lax (already set in hardened version) + CSRF tokens.
JWT in Authorization header is not cookie-based → immune to CSRF by default.
(Preview for System 5.)

---

### OWASP Anchor
A07:2021 — Identification and Authentication Failures
Formerly A02:2017. Specifically covers:
- Weak credential hashing
- Brute force without lockout
- Session fixation
- Missing cookie security flags
