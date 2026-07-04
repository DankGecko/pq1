---
surface: <clear-signing | trustzone-gateway | secure-element | sca-fi | firmware-update-secure-boot | usb-companion | offchain-signing | onchain-contracts | trusted-ui | silicon-lockdown | fv>
run_date: YYYY-MM-DD
reviewer: <model / agent + backend, e.g. "opus-4.8 via run_review.py --backend claude">
scope: <the specific claims / files / SL-modes reviewed this pass>
status: open   # open → in-review → resolved  (see findings/README.md lifecycle)
---

# Adversarial-review findings — <surface> — YYYY-MM-DD

## Summary

<n findings: A confirmed-real, B false-positive, C accepted/by-design.> One-line verdict
(e.g. "no headline hole; one MED hardening gap"). Note whether this pass EXECUTED the
checkers (Kani / rainbow / forge / lake / prod-check) or read source only.

## Findings

<!-- One block per finding. `Fn` id is stable; update Status + Resolution as it is worked
     through. Delete this comment and the example below when filling a real report. -->

### F1 — <short title>
- **Status:** 🔲 OPEN   <!-- 🔲 OPEN · 🔬 REVIEWED · ✅ FIXED · ☑️ ACCEPTED · 🚫 INVALID · ⏸ DEFERRED -->
- **Mode / severity:** <catalog id e.g. CS3 / TZ4 / SL2> · <LOW | MED | HIGH>
- **Location:** `path/to/file.rs:line`
- **What:** one-sentence statement of the defect / gap.
- **PoC (falsifiable):** <the runnable artifact — a flip→decline test, a Kani counterexample, a rainbow BYPASS, a `#print axioms` diff, a merged diff that skipped a gate. No PoC ⇒ this is a "suspicion", list it under §Suspicions, not here.>
- **Disposition:** CONFIRMED_REAL | FALSE_POSITIVE | ALREADY_FIXED | OPEN_RESEARCH
- **Proposed fix:** <and flag if the fix would break an invariant / regress a proof / weaken a fence>
- **Resolution:** <FILLED WHEN HANDLED — what was done + commit SHA + date, or why accepted/invalid/deferred + the tracking item (work-todo #…)>

<!-- ### F2 — … -->

## Suspicions (unverified — no PoC)

<Things that smelled wrong but you could not produce a falsifiable PoC for. Not findings;
next round's leads.>

## Honest residual (the run is INVALID without this)

1. **What I tried to break and COULDN'T** — the claims that survived + the strongest single failed PoC-attempt per claim.
2. **What I did NOT look at** — modes/files/surfaces not walked; the next round's target list.
3. **Provenance** — did this pass EXECUTE the checkers, or read source + the ledger only? A source-only pass is weaker; say so plainly.
