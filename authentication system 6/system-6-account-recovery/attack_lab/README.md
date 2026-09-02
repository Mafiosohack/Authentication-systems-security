# Attack Lab (supplementary visualization tool)

A visual console for the System 6 attacks. **Not part of the graded deliverable** —
it mirrors the canonical scripts in `attacks/` and exists only to *see* what each
attack does on the wire.

It serves a page on `http://127.0.0.1:8000` and, on each click, fires the **real**
HTTP requests of an attack at the target app on `127.0.0.1:5000`, returning every
request/response so the page can render exactly what went over the wire. Verdicts
(GAIN vs BLOCKED) are computed from the actual responses, so the before/after is honest.

It manages the target as a subprocess, so the **Vulnerable ↔ Hardened** toggle in the
top-right switches which app is under attack (hardened runs with
`HARNESS_EXPOSE_TOKENS=1` so the lifecycle/binding fixes are demonstrated even when the
attacker is generously handed real tokens).

## Run

From the project root, with the venv active:

```
python attack_lab/attack_lab.py
```

Then open <http://127.0.0.1:8000>. Click any attack; flip the target toggle to compare.
Each run restarts a fresh in-memory target for reproducibility.

Requires: `fastapi`, `uvicorn`, `requests` (already in `requirements.txt`). Ports 5000
and 8000 must be free; the tool frees 5000 itself when (re)starting the target.
