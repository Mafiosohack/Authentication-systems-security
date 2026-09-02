"""run_simulation.py -- the whole System 4 story in one command.

It does this, twice:
  1. Start a stack of 3 servers (auth server :5000, client :5001, resource :5002).
  2. Run all 5 attacks against it.
  3. Shut the stack down.

First pass uses the VULNERABLE servers   -> every attack should SUCCEED.
Second pass uses the HARDENED servers     -> every attack should be BLOCKED.

Both stacks use the same ports on purpose, so the exact same attack scripts hit
both -- proving each control blocks its attack by its intended mechanism.

    python run_simulation.py
"""
import importlib, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from launch import servers

# (module name, plain-English description, root-cause it exploits)
ATTACKS = [
    ("attack1_redirect_uri", "redirect_uri is not checked  -> steal the code"),
    ("attack2_csrf_state",   "no 'state' value            -> login CSRF / fixation"),
    ("attack3_pkce",         "no PKCE                      -> redeem a leaked code"),
    ("attack4_code_replay",  "code is not single-use       -> replay it for more tokens"),
    ("attack5_idtoken",      "id_token not verified        -> forge an identity"),
]


def stack(prefix):
    """Build the (name, path, port) specs for the vuln_ or hardened_ stack."""
    return [
        ("auth",     os.path.join(HERE, f"{prefix}_auth_server.py"),     5000),
        ("client",   os.path.join(HERE, f"{prefix}_client_app.py"),      5001),
        ("resource", os.path.join(HERE, f"{prefix}_resource_server.py"), 5002),
    ]


def run_attacks(label, idtoken_strategy):
    os.environ["IDTOKEN_STRATEGY"] = idtoken_strategy
    print(f"\n{'='*70}\n  ATTACKING THE {label} STACK\n{'='*70}")
    results = []
    for mod, desc in ATTACKS:
        m = importlib.import_module(mod)
        importlib.reload(m)                 # re-read env / fresh state each pass
        ok, detail = m.attack()
        results.append(ok)
        verdict = "VULNERABLE" if ok else "BLOCKED   "
        print(f"\n[{verdict}] {mod}")
        print(f"            flaw : {desc}")
        print(f"            result: {detail}")
    return results


def main():
    print("OAuth 2.0 / OpenID Connect security simulation  (System 4)")
    print("Pattern: same attacks, run first against broken servers, then fixed ones.")

    with servers(stack("vuln")):
        vuln = run_attacks("VULNERABLE", idtoken_strategy="vulnerable")

    with servers(stack("hardened")):
        hard = run_attacks("HARDENED", idtoken_strategy="hardened")

    print(f"\n{'='*70}\n  SUMMARY\n{'='*70}")
    print(f"  Vulnerable stack: {sum(vuln)}/5 attacks succeeded "
          f"(want 5/5 -- it's supposed to be broken).")
    print(f"  Hardened stack  : {sum(hard)}/5 attacks succeeded "
          f"(want 0/5 -- every control held).")
    ok = (sum(vuln) == 5 and sum(hard) == 0)
    print(f"\n  {'PASS: simulation behaved exactly as designed.' if ok else 'CHECK: unexpected result above.'}")


if __name__ == "__main__":
    main()
