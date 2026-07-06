---
surface: fv
run_date: 2026-07-04
reviewer: opus-4.8 (1M ctx), single-reviewer executing pass (planned 9-agent swarm blocked by session limit)
scope: FV soundness weighted to the FRESHEST proofs (A3.1 in-kernel Yul parser + elision bridge, §33 digit-extraction, R2/refinement) + full V1-V11 / G1-G5 re-sweep vs the claims inventory
status: open   # F1 still 🔲 OPEN (coverage gap not yet closed); F2 REVIEWED, F3 INVALID, F4 ACCEPTED
catalogue: ../REVIEW_PROVENANCE.md   # authoritative per-round verdict + handled-state
note: confirmed findings tracked in AXIOM_STATUS.json / STATUS.md / docs/work-todo.md
---

# Adversarial-review findings — FV soundness — 2026-07-04

## Summary

4 findings: **1 confirmed coverage gap (MED, F1), 1 labeling nuance (LOW, F2), 1 false-positive
withdrawn on self-review (F3), 1 disclosed-leaf accepted (F4/G5).** One-line verdict: **no headline
soundness hole** — the freshest, never-reviewed surface (the A3.1 in-kernel Yul parser) survives
every attack under executed evidence; the residual is coverage + one over-stated ledger citation.

**This pass EXECUTED the checkers:** `verify-audit` (#print axioms), `verify-ledger-consistency`
(+ its 14-control self-test), `verify-fv-lints`, `verify-gate-enforcement`, `verify-parse-transcription`
(+ the `c10Source` byte-pin), `verify-extracted`, `verify-extract-differential`, plus live source
reads of every cited proof. Method = the V1-V11 / G1-G5 catalog in
`docs/verification/fv-adversarial-review-playbook.md` Part C.

> **Depth caveat.** The planned 9-finder + adversarial-cross-vote **swarm was blocked by a session
> limit** (all subagents errored), so this is a *single-reviewer executing* pass. Stronger than a
> source-read pass on the surfaces I ran; weaker on breadth (per-scope Kani harness-by-harness, the
> model↔Solidity path enumeration). Re-run the swarm to close that residual — see §Honest residual.

## Findings

### F1 — Safe-wrapped CoW `orderUid` binding is not ∀/Kani-covered (the ledger cite overstates)
- **Status:** 🔲 OPEN
- **Mode / severity:** G3 (coverage-completeness) / V11 · **MED**
- **Location:** `secure/src/tx/eip712/safe/cow_binding.rs` (the `orderUid.owner == Safe` resolver)
- **What:** the binding resolver that ties a CoW order to the presign calldata with
  `orderUid.owner == the Safe` (not the wallet sender) contains **zero `#[kani::proof]`**, yet
  `THREAT_CLAIM_MAP.md` (`S-CLEAR-SIGN-DECODE-DRIFT` / `S-DISPLAY-VS-SIGN`) cites `kani-cowswap` as
  covering "orderUid/presign binding". The Kani harness in `tx/src/cowswap_order.rs` proves only
  204-byte **decode**-soundness; the security-critical **binding** leg rests on host render tests only.
- **PoC (falsifiable):** `grep -rl 'kani::proof' secure/src/tx/eip712/safe/cow_binding.rs` → **no
  match**. The map's own footnote [^3] independently concedes: "the claimed orderUid/presign BINDING
  lives in uncited secure/src/tx/eip712/safe/cow_binding.rs and is NOT Kani-proven here."
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** extract the `cow_binding` decision (owner-match + presign-order-digest match) into
  a host-linkable pure fn; add a Kani harness asserting `decode==Ok ⟹ rendered.owner == SafeTx signer
  ∧ order_digest == presign_calldata.order_digest`; add a mutation (flip owner-equality → harness must
  FAIL) to `kani_mutations.json`. Does not touch any invariant.
- **Resolution:** _pending — recommend promoting to `docs/work-todo.md` (clear-signing coverage)._

### F2 — `pin_lockstep.spthy` ledger cite ("abstract") under-conveys the model's disclosed idealization
- **Status:** 🔬 REVIEWED
- **Mode / severity:** V9 / V11 · **LOW**
- **Location:** `contracts/verification/tamarin/pin_lockstep.spthy:21-42`; ledger cite
  `THREAT_CLAIM_MAP.md` `S-PIN-COMPARE-SW` (PARTIAL, "proto-pin-lockstep — abstract")
- **What:** the model self-discloses (in-file) that its `tamper` predicate "catches STRICTLY LESS
  than" the deployed reconcile-to-strictest — incl. that **in the shipping config the SE050 counter
  reads `None`, so a single OPTIGA counter reset is undetected by the modeled predicate** — and calls
  itself "an IDEALIZED-SPEC result, NOT a faithful statement about the deployed reconciliation." The
  one-word ledger label "abstract" conveys less than the model's own two-paragraph caveat.
- **PoC (falsifiable):** `pin_lockstep.spthy:30-42` (the divergence is stated in-file); the map marks
  the row PARTIAL (not COVERED), so it is honestly disclosed, not hidden.
- **Disposition:** CONFIRMED_REAL (labeling; the substantive coverage gap is §Areas-not-covered item 2)
- **Proposed fix:** expand the ledger cite from "abstract" to "idealized-spec; single-OPTIGA-reset
  undetected under SE050-`None`; deployed defense = silicon lockout (silicon-E2E)". Labeling only, no
  proof regression.
- **Resolution:** _pending — trivial ledger-label edit; no code/proof change._

### F3 — "mutual authentication" vs non-injective queries in `scp03_handshake.pv` — WITHDRAWN
- **Status:** 🚫 INVALID
- **Mode / severity:** V11 · (drafted LOW)
- **Location:** `contracts/verification/proverif/scp03_handshake.pv:98` (+ `optiga_shield_handshake.pv`)
- **What (as drafted):** the "mutual authentication" comment sits over non-injective agreement queries,
  which don't rule out replay.
- **Why INVALID:** `scp03_handshake.pv:52` **explicitly documents** the queries are non-injective and
  that "injectivity / no-replay is `../tamarin/scp03_replay.spthy`'s" job. The authors correctly scoped
  the property and documented the delegation. Not an overstatement. Kept here as the honest audit trail
  — the exact false positive the (blocked) cross-vote exists to kill, killed by re-reading the source.
- **Disposition:** FALSE_POSITIVE
- **Resolution:** withdrawn 2026-07-04 on self-review (source re-read, not quote); no action.

### F4 — `Crypto/Quantitative.lean` G5 disclosure-integrity check — PASSED
- **Status:** ☑️ ACCEPTED
- **Mode / severity:** G5 (qualitative-shadow) · **INFO**
- **Location:** `contracts/verification/lean/SphincsCVerify/Crypto/Quantitative.lean`
- **What:** the file is a genuine qualitative shadow (log-domain `by decide` Nat inequalities of the
  *cited* EUF-CMA / SM-DT-TCR bounds; adversary advantage `ε(A)` stays the cited `BreaksHash`,
  unquantified). It **exhaustively self-discloses** this, and `THREAT_CLAIM_MAP.md` cites it correctly
  ("96-bit generic-attack floor at cap over CITED upstream bit-count terms"). **No overclaim found.**
- **PoC:** the docstring's own disclosure + the closure dump (`advantage_floors_within_slot_cap` has
  *no* axioms — a pure arithmetic fact, correctly presented as such).
- **Disposition:** ALREADY_FIXED (disclosed leaf)
- **Resolution:** accepted 2026-07-04 — disclosed by design; only recommend a `verify-ledger-consistency`
  scan flagging any *marketing* doc that cites it as "the quantitative bound proven" (see §Improvements).

## Areas still NOT covered by FV (coverage-completeness / G3 — the primary deliverable)

From `THREAT_CLAIM_MAP.md` (61 surfaces: 4 COVERED · 30 PARTIAL · **1 UNCLAIMED** · 26 out-of-scope),
cross-checked live:

1. **`S-SCA-PRF-LEAK` — the sole fully UNCLAIMED in-scope threat.** Horizontal DPA/EM on
   `PRF(SK.seed)` (STM32 HASH periph, zero DPA resistance). Mitigations exist (consumption-mask,
   F-16 shuffle) but **no covering claim**. A claim needs a leakage model or a measured TVLA/CPA
   result promoted to a tracked leaf. **Top FV gap.**
2. **Firmware invariants #2/#3/#4 + the clear-sign display pipeline have ZERO Lean coverage** — model
   (idealized, F2) / abstract-protocol / silicon-E2E / host-test only, no kernel-∀. A proof would need
   the firmware gating/decoders extracted (§33-style) + Kani/Lean on the decision logic.
3. **Verifier ∀-signature equivalence to *deployed bytecode* (A3.1 R1b + symbolic-∀)** — model↔spec ∀
   is kernel-proven; R1a (source↔AST) is now kernel + byte-pin; **R1b (solc→bytecode) is corpus/KAT
   only** (deliberate cited-TCB; verified compilation is multi-person-year).
4. **Wallet control-flow bytecode discharge (Halmos/Kontrol) is LOCAL/manual, not per-PR CI** — the
   per-PR tripwire is only the codehash-freeze test; the 42 Halmos / 30 KEVM re-run is manual.
5. **§33 extracted-Lean ↔ shipped-Rust is 6-vector corpus, not ∀** (Charon/Aeneas is the TCB; the
   `verify-extract-differential` gate self-discloses "not a ∀").
6. **CT/SCA (`checkct`) is never CI-gated** (`workflow_dispatch` + `continue-on-error`, WIP).
7. **57 of ~93 Kani harnesses have no anti-vacuity screen** (`verify-kani-mutation` = 6 mut / 4 files).
8. **Miri + differential/fuzz surfaces have never had a first *adversarial* pass** (only the gates run).
9. **Reachability↔cap composition is disclosed-incomplete** — the numeric floor is conditional on
   `q ≤ cap`; the full `Reachable → q ≤ cap` ∀ theorem "is not yet assembled" (P1 note).

## Improvements (non-blocking FV hardening)

- **Wire `cow_binding` into Kani** (fixes F1) — highest-value coverage add.
- **Re-label (or re-model) `pin_lockstep.spthy`** (fixes F2).
- **Promote `checkct` to a blocking per-PR gate** once the binsec/opam toolchain is CI-installable.
- **Extend `verify-kani-mutation`** toward the 57 unscreened harnesses (≥1 mutation/file).
- **Per-PR "Halmos-or-Kontrol re-run required on codehash change"** check.
- **Add a marketing-doc scan to `verify-ledger-consistency`** flagging any doc citing `Quantitative.lean`
  as "the quantitative bound proven" without the qualitative-shadow disclosure (closes the G5 drift risk).

## Honest residual (the run is INVALID without this)

1. **What I tried to break and COULDN'T** —
   - *A3.1 in-kernel parser (freshest surface):* attacked V6 (self-oracle), V9 (parser unfaithful to
     Yul), G1 (kernel proof unenforced), G2 (pin binds wrong bytes). All refuted by execution: byte-pin
     PASS (9256 B == `.sol` L37-230); `parse_c10` closure **NONE**; operand order `shl(x,y)=y<<x`
     guard-tested correct; **both** the byte-pin (`a31-transcription.yml`, per-PR) **and** the kernel
     proof (`lean-fv.yml lake build`, `C10Parse` imported + `--tstack=32768`) are CI-enforced; docs
     honestly disclose R1b untouched.
   - *`theft_free` closure:* live `#print axioms` = exactly the documented 11; ledger-consistency PASS
     w/ 14-control self-test incl. the `=verifyYulModel`→FALSE guard; BreaksHash firewall PASS (no
     `→ False`); cap witness `combinedCapInvariant_empty` closure `[propext]` (non-circular).
   - *§33:* spec theorems import the machine-generated Aeneas `Funs.lean`; differential green (corpus).
   - *Protocol anti-vacuity (07-02 asymmetry):* refuted-as-fixed — reachability witnesses now in
     `scp03_handshake.pv` + `optiga_shield_handshake.pv`.
2. **What I did NOT look at** — the model-diverse swarm did not run (no cross-vote, no per-scope
   9-way depth); Kani harness-by-harness vacuity, the model↔Solidity path enumeration
   (reentrancy/delegatecall/upgrade faithfulness), and the EUF-CMA guard-lemma non-vacuity were reasoned
   from source + closure dumps, not exhaustively attacked; `verify-proof-mutation`, `verify-lean4checker`,
   Halmos, Kontrol were **not** re-run this pass; G2 codehash reality-drift was **not** re-fetched from
   mainnet. **Next round:** re-run the swarm (fan-out per §Areas-not-covered); a live proverif/tamarin
   run to confirm F2 empirically; the first Miri + differential/fuzz adversarial pass.
3. **Provenance** — `executing` (ran the gates above), **not** the model-diverse swarm the playbook
   Layer-2 prescribes. A single-reviewer executing pass: strong on the surfaces it ran, breadth-limited.
