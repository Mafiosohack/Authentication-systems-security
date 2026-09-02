"""
VICTIM SIMULATOR for the AiTM relay demo.

Plays the role of a user who has been tricked into visiting the proxy
(port 5003) instead of the real app (port 5002). The victim does everything
correctly from their own perspective: enters their real password, reads their
authenticator, types a valid fresh code. They believe they logged in normally.

This exists so the relay demo is self-contained and reproducible without an
actual human. The victim uses the REAL secret only because, in this lab, we
play both roles. In reality the victim simply reads the code off their phone.
"""

import requests
import pyotp

PROXY = "http://127.0.0.1:5003"     # the victim was lured here (it's the proxy)
REAL_SECRET = "JBSWY3DPEHPK3PXP"    # in reality this lives only on the victim's phone

USERNAME = "admin"
PASSWORD = "SuperSecret123"


def run_victim():
    print("\n--- VICTIM'S VIEW (believes this is the real site) ---")
    s = requests.Session()

    # 1. Victim opens the (phishing) login page
    s.get(f"{PROXY}/")
    print("  Victim: opened the login page")

    # 2. Victim enters their real password
    s.post(f"{PROXY}/login", data={"username": USERNAME, "password": PASSWORD})
    print(f"  Victim: entered password for {USERNAME}")

    # 3. Victim reads a FRESH, VALID code off their authenticator and types it
    live_code = pyotp.TOTP(REAL_SECRET).now()
    print(f"  Victim: read code {live_code} off authenticator app, typed it")
    r = s.post(f"{PROXY}/verify-totp", data={"code": live_code})

    if "Welcome" in r.text:
        print("  Victim: sees 'Welcome — you are logged in'. Suspects nothing.")
    print("--- END VICTIM'S VIEW ---\n")


if __name__ == "__main__":
    run_victim()
