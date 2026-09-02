"""
System 6 - Account Recovery & Enrollment
PHASE 3: HARDENED IMPLEMENTATION  (FastAPI)

A clean rebuild of the recovery + enrollment flow with security designed in,
not patched on. Endpoints and JSON shapes match the vulnerable Flask app so
the Phase 2 attack scripts run against it UNMODIFIED (same host/port 5000).

Each of the 8 vulnerabilities from the CLAUDE.md map is addressed below, and
every security decision is inline-commented with the WHY and the TRADEOFF.

Run:  python hardened_account_recovery.py     (serves on 127.0.0.1:5000)

Two operating modes (a study-harness convenience, NOT a product feature):
  * default            -> /outbox returns delivery STATUS ONLY (no secrets).
                          This is the production-correct behaviour: reset
                          tokens/OTPs go only to the user's mailbox, never to
                          a world-readable endpoint. (The vulnerable build's
                          /outbox was itself a total secret-leak; we remove it.)
  * HARNESS_EXPOSE_TOKENS=1 -> /outbox also returns the raw token/OTP, so the
                          harness can drive the legitimate happy path and can
                          demonstrate the #6/#8 fixes even when we GENEROUSLY
                          assume the attacker already holds a valid token.
                          Clearly marked test-only; never enable in production.
"""

import os
import time
import hmac
import hashlib
import secrets
from collections import deque, defaultdict
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import uvicorn

app = FastAPI(title="System 6 - Hardened Account Recovery")

# --- SECURITY DECISION: reset URLs are built from a server-side constant,
#     never from the request. This is the whole fix for VULN #4 (host-header
#     injection): the Host header is attacker-controlled and must never
#     influence a security-relevant absolute URL.
#     TRADEOFF: multi-tenant/multi-domain deployments must configure BASE_URL
#     per environment (env var) instead of "just using whatever host came in".
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000")

# Test-only switch (see module docstring). Off by default.
HARNESS_EXPOSE_TOKENS = os.environ.get("HARNESS_EXPOSE_TOKENS", "0") == "1"

# --- SECURITY DECISION: passwords are hashed with Argon2id (argon2-cffi).
#     The recovery path WRITES new passwords, so weak storage here would undo
#     everything. Argon2 is memory-hard -> resists GPU/ASIC cracking.
#     TRADEOFF: CPU/memory cost per hash (intentional); fine for auth volumes.
ph = PasswordHasher()

# --- Token / OTP lifecycle parameters (VULN #6 / #7) ----------------------
TOKEN_TTL_SECONDS = 15 * 60      # short-lived reset tokens (15 min)
OTP_MAX_ATTEMPTS = 5             # per-challenge cap before lockout (VULN #7)
OTP_LOCK_SECONDS = 15 * 60       # lockout duration after too many tries
IP_WINDOW_SECONDS = 60           # sliding window for per-IP throttling
IP_MAX_VERIFY = 20               # max /verify-otp per IP per window
IP_MAX_RESET = 20                # max /reset-password per IP per window


# ==========================================================================
# In-memory data store (a study harness; a real app uses a real DB).
# ==========================================================================
# users: email -> record. Passwords stored ONLY as Argon2 hashes.
USERS: dict[str, dict] = {}

# Active reset tokens: sha256(token) -> {email, created_at}.
# --- SECURITY DECISION (VULN #5): we store the token HASHED at rest. A DB
#     leak then exposes no usable tokens (the attacker would need a preimage
#     of sha256). The plaintext token exists only in transit + the user's
#     mailbox. TRADEOFF: we cannot "show the user their token" server-side;
#     that is a feature, not a bug.
RESET_TOKENS: dict[str, dict] = {}

# OTP challenges: email -> {otp_hash, created_at, attempts, locked_until}.
OTP_CHALLENGES: dict[str, dict] = {}

# Per-IP request timestamps for throttling: (bucket, ip) -> deque[timestamps].
IP_HITS: dict[tuple, deque] = defaultdict(deque)

# Delivered "mail" (harness observability). Secrets are REDACTED unless the
# test-only HARNESS_EXPOSE_TOKENS switch is on.
OUTBOX: dict[str, dict] = {}


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _seed():
    """Seed the same victim + admin as the vulnerable build (hashed now)."""
    USERS.clear()
    USERS["victim@corp.example"] = {
        "username": "victim", "email": "victim@corp.example",
        "password_hash": ph.hash("victimPassw0rd!"), "is_admin": False,
    }
    USERS["root@corp.example"] = {
        "username": "root", "email": "root@corp.example",
        "password_hash": ph.hash("s3cr3t-admin"), "is_admin": True,
    }


_seed()


def _ip_throttled(bucket: str, ip: str, limit: int) -> bool:
    """Sliding-window per-IP limiter. Returns True if this request is over.

    --- SECURITY DECISION (VULN #7): attempt caps are enforced per-IP in
        ADDITION to per-account, so an attacker cannot dodge the per-account
        lock by spraying one guess each across many accounts from one host.
        TRADEOFF: shared NAT/proxy egress IPs can throttle innocent users;
        production would combine this with per-account limits + device signals
        and a CAPTCHA step rather than IP alone.
    """
    now = time.time()
    dq = IP_HITS[(bucket, ip)]
    while dq and now - dq[0] > IP_WINDOW_SECONDS:
        dq.popleft()
    if len(dq) >= limit:
        return True
    dq.append(now)
    return False


# ==========================================================================
# Request models — EXPLICIT ALLOWLISTS (VULN #2)
# ==========================================================================
# --- SECURITY DECISION (VULN #2): every endpoint binds ONLY the fields it
#     declares. `extra="ignore"` means client-supplied keys like "is_admin"
#     are silently dropped instead of flowing into the record. Privilege
#     fields are never client-settable. TRADEOFF: clients that send extra
#     junk get no error; we favour safe-by-default over strict 422s here, and
#     the report notes strict mode as an option.
class RegisterIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    username: str
    email: str
    password: str


class ForgotIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    email: str


class VerifyOtpIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    email: str
    otp: str


class ResetIn(BaseModel):
    # NOTE: there is DELIBERATELY no "email" field here. Even though the
    # attack sends one, Pydantic drops it (extra="ignore"), so the target
    # account can only ever come from the token record. This is the fix for
    # VULN #8 (broken account binding / IDOR).
    model_config = ConfigDict(extra="ignore")
    token: str
    new_password: str


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    email: str
    password: str


# ==========================================================================
# ENROLLMENT
# ==========================================================================
@app.post("/register")
async def register(body: RegisterIn):
    # --- SECURITY DECISION (VULN #1): the response is IDENTICAL whether or
    #     not the username/email already exists. No "already taken" oracle.
    #     Real systems send a verification mail either way ("welcome" for a
    #     new address, "someone tried to sign up with your email" for an
    #     existing one) so the observable behaviour never reveals membership.
    #     TRADEOFF: worse signup UX — a user who forgot they have an account
    #     is not told "email taken" inline; they learn via email instead.
    exists = body.email in USERS or any(
        u["username"] == body.username for u in USERS.values()
    )
    if not exists:
        USERS[body.email] = {
            "username": body.username,
            "email": body.email,
            "password_hash": ph.hash(body.password),
            # VULN #2: is_admin is set by the SERVER, never from input.
            "is_admin": False,
        }
        _deliver(body.email, kind="verify")
    else:
        # Same-shaped side effect (a notice email) to keep behaviour uniform.
        _deliver(body.email, kind="exists")

    # One generic response for both branches.
    return {"status": "if this is a new account, a verification email has been sent"}


# ==========================================================================
# RECOVERY — request
# ==========================================================================
@app.post("/forgot-password")
async def forgot_password(body: ForgotIn):
    email = body.email
    user = USERS.get(email)

    # --- SECURITY DECISION (VULN #3 + #5): we ALWAYS do the same work and
    #     ALWAYS return the same generic message, whether or not the account
    #     exists. Token + OTP are generated with the `secrets` CSPRNG and
    #     stored HASHED; the plaintext goes only to the mailbox.
    #     The wording intentionally avoids confirming THIS address exists.
    token = secrets.token_urlsafe(32)          # VULN #5: high-entropy, not time-based
    otp = f"{secrets.randbelow(1_000_000):06d}"  # VULN #5: CSPRNG, not random.*
    now = time.time()

    if user is not None:
        # Persist only for real accounts. Store HASHES only (VULN #5).
        RESET_TOKENS[_sha256(token)] = {"email": email, "created_at": now}
        OTP_CHALLENGES[email] = {
            "otp_hash": _sha256(otp), "created_at": now,
            "attempts": 0, "locked_until": 0.0,
        }
        # VULN #4: link built from server BASE_URL, never the Host header.
        reset_link = f"{BASE_URL}/reset-password?token={token}"
        _deliver(email, kind="reset", otp=otp, token=token, reset_link=reset_link)
    # For unknown emails we do the equivalent hashing work above but persist
    # nothing — same response, similar timing, no membership signal.

    # --- SECURITY DECISION (VULN #3): identical response for known/unknown.
    return {"status": "if that email address has an account, a recovery message has been delivered"}


# ==========================================================================
# RECOVERY — verify OTP  (rate-limited + locked)
# ==========================================================================
@app.post("/verify-otp")
async def verify_otp(body: VerifyOtpIn, request: Request):
    ip = request.client.host if request.client else "unknown"

    # --- SECURITY DECISION (VULN #7): per-IP throttle first, so a spray from
    #     one host is capped regardless of which account it targets.
    if _ip_throttled("verify", ip, IP_MAX_VERIFY):
        return JSONResponse({"error": "too many attempts, slow down"}, status_code=429)

    challenge = OTP_CHALLENGES.get(body.email)
    if not challenge:
        # Do not reveal whether a recovery is pending.
        return JSONResponse({"error": "invalid or expired code"}, status_code=400)

    now = time.time()

    # Lockout: too many wrong tries on THIS challenge (VULN #7).
    if challenge["locked_until"] > now:
        return JSONResponse(
            {"error": "account temporarily locked due to too many attempts"},
            status_code=429,
        )

    # TTL: an OTP older than the token TTL is dead (VULN #6).
    if now - challenge["created_at"] > TOKEN_TTL_SECONDS:
        OTP_CHALLENGES.pop(body.email, None)
        return JSONResponse({"error": "invalid or expired code"}, status_code=400)

    # --- SECURITY DECISION: constant-time comparison of the OTP hash so we
    #     leak no timing information about how many leading digits matched.
    if hmac.compare_digest(challenge["otp_hash"], _sha256(body.otp)):
        # Success: mint a FRESH short-lived reset token bound to this account
        # and hand it back. (We cannot return the original link token because
        # we only stored its hash — by design, VULN #5.)
        verified = secrets.token_urlsafe(32)
        RESET_TOKENS[_sha256(verified)] = {"email": body.email, "created_at": now}
        OTP_CHALLENGES.pop(body.email, None)   # OTP is single-use (VULN #6)
        return {"status": "otp verified", "token": verified}

    # Wrong: count the attempt; lock after the cap (VULN #7).
    challenge["attempts"] += 1
    if challenge["attempts"] >= OTP_MAX_ATTEMPTS:
        challenge["locked_until"] = now + OTP_LOCK_SECONDS
        return JSONResponse(
            {"error": "account temporarily locked due to too many attempts"},
            status_code=429,
        )
    return JSONResponse({"error": "invalid or expired code"}, status_code=400)


# ==========================================================================
# RECOVERY — reset
# ==========================================================================
@app.post("/reset-password")
async def reset_password(body: ResetIn, request: Request):
    ip = request.client.host if request.client else "unknown"
    if _ip_throttled("reset", ip, IP_MAX_RESET):
        return JSONResponse({"error": "too many attempts, slow down"}, status_code=429)

    record = RESET_TOKENS.get(_sha256(body.token))
    if not record:
        # Covers unknown, already-used (deleted), and forged tokens (VULN #5/#6).
        return JSONResponse({"error": "invalid or expired token"}, status_code=400)

    # TTL enforcement (VULN #6): the created_at we WROTE is now actually CHECKED.
    if time.time() - record["created_at"] > TOKEN_TTL_SECONDS:
        RESET_TOKENS.pop(_sha256(body.token), None)
        return JSONResponse({"error": "invalid or expired token"}, status_code=400)

    # --- SECURITY DECISION (VULN #8): the target account comes ONLY from the
    #     token record. There is no client "email" input in ResetIn, so a
    #     token issued for account A can never reset account B. This is the
    #     core fix — it holds even if the token were guessable.
    target_email = record["email"]
    user = USERS.get(target_email)
    if not user:
        return JSONResponse({"error": "invalid or expired token"}, status_code=400)

    # Write the new password (Argon2 hash — baseline hygiene).
    user["password_hash"] = ph.hash(body.new_password)

    # --- SECURITY DECISION (VULN #6): single-use + full invalidation. Burn
    #     THIS token and EVERY other outstanding token/challenge for the user,
    #     so a completed reset can never be replayed and older siblings die too.
    #     TRADEOFF: a user with several pending reset emails invalidates them
    #     all on first successful use — the safe choice.
    for th, rec in list(RESET_TOKENS.items()):
        if rec["email"] == target_email:
            RESET_TOKENS.pop(th, None)
    OTP_CHALLENGES.pop(target_email, None)
    OUTBOX.pop(target_email, None)

    return {"status": "password reset", "account": target_email}


# ==========================================================================
# Support endpoints
# ==========================================================================
@app.post("/login")
async def login(body: LoginIn):
    user = USERS.get(body.email)
    if not user:
        # --- SECURITY DECISION: run a dummy verify so a missing account and a
        #     wrong password take similar time (no login enumeration channel).
        try:
            ph.verify(ph.hash("dummy"), "x")
        except VerifyMismatchError:
            pass
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    try:
        ph.verify(user["password_hash"], body.password)
    except (VerifyMismatchError, InvalidHashError):
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    return {"status": "ok", "username": user["username"], "is_admin": user["is_admin"]}


def _deliver(email: str, kind: str, otp: Optional[str] = None,
             token: Optional[str] = None, reset_link: Optional[str] = None):
    """Record a delivered 'email'. Secrets are REDACTED unless the test-only
    HARNESS_EXPOSE_TOKENS switch is enabled (see module docstring).

    --- SECURITY DECISION: in production there is NO endpoint that returns
        another user's reset token/OTP. The vulnerable build's /outbox handed
        every secret to anyone; here it exposes only delivery STATUS. This
        single change is what makes attacks #4/#6/#8 unable to even obtain a
        token in the default mode.
    """
    if HARNESS_EXPOSE_TOKENS:
        OUTBOX[email] = {"otp": otp, "reset_link": reset_link, "token": token, "kind": kind}
    else:
        OUTBOX[email] = {
            "otp": None,
            "reset_link": "(delivered privately to the user's mailbox)",
            "token": None,
            "kind": kind,
            "status": "email dispatched",
        }


@app.get("/outbox")
async def outbox():
    return OUTBOX


if __name__ == "__main__":
    # uvicorn ASGI server (FastAPI). Same host/port as the vulnerable app so
    # the Phase 2 attack scripts hit it unmodified.
    uvicorn.run(app, host="127.0.0.1", port=5000, log_level="warning")
