# The claim — exactly what is and isn't proven (2026-06-12)

This file is the single source of truth for **what you may publicly claim**
about the PQSmartWallet formal-verification stack. It is deliberately
conservative. If a marketing line is not derivable from the "✅ Claimable"
section below, do not ship it.

---

## ✅ Claimable (true, reproduced)

> **The PQSmartWallet's on-chain control flow is formally verified, and the
> verification is connected to the deployed bytecode.** A Lean 4
> kernel-checked theorem (`theft_free`, 0 `sorry`, an explicit 11-axiom
> base) proves theft-freedom over a faithful model of the wallet; the
> **wallet `validateUserOp` / `executeWithOffchainCount` /
> `executeBatchWithOffchainCount`, the factory `createAccount`, and the
> `PQMultiOwnable` owner table** are each proven, by symbolic execution of
> the **deployed runtime bytecode** (Halmos + z3, both compiler profiles,
> pinned codehashes), to be **pointwise-equal to those Lean models** over
> symbolic inputs — including a genuinely ∀-quantified owner index on every
> money-moving path; and the **executable Lean SPHINCS+C10 verifier spec
> reproduces the deployed verifier's accept/reject decision on the complete
> shared KAT corpus** (full functional verify, 10/10, hard check).

Specifically and defensibly:

1. **Kernel proof.** `theft_free` and its claim corollaries are checked by
   the Lean 4 kernel with **zero `sorry`** and an axiom closure of exactly
   11 named axioms (`make verify-audit`). Reproduced 2026-06-12.
2. **Control-flow bytecode discharge.** 38 Halmos rules pass on **both** the
   `default` (runs=200) and `deploy` (runs=999999) profiles' deployed
   bytecode, against pinned codehashes — validate (pointwise + per-property;
   the wrapper ownerIndex is covered by enumerating the installed set
   `{0,1,2}` + concrete reps for the unset partition + a symbolic sweep over
   the installed slots `{1,2}` — the unset partition cannot be swept
   symbolically, a disclosed Halmos dynamic-bytes-getter ceiling), execute
   (pointwise over a genuinely symbolic ∀ ownerIndex + atomicity), factory
   (`createAccount ⟺ precondition` iff), owner-table (add/remove/initialize
   pointwise + read-parity). Reproduced 2026-06-11 (`make verify-bytecode`).
3. **The bootstrap-cap bug is really fixed.** The few-time-cap under-count
   (`PQBootstrapCapEvasion`) is closed in the validation phase and locked by
   tests; `forge test` 108/108. Reproduced 2026-06-11.
4. **Verifier functional layer — executable Lean differential, KAT +
   mutant scale.** Two **executable** Lean↔bytecode differentials, both
   HARD CHECKS (non-zero exit on drift): (a) `lake exe verify-test-vectors`
   — the Lean spec (`Spec.Signature.verify`: digest, htIdx, FORS forest,
   WOTS+C count/digit grind, chain stepping, subtree Merkle, final root
   compare) matches the deployed verifier's accept/reject decision on all
   10 KAT vectors; (b) `lake exe verify-mutant-corpus` — the same spec
   matches the deployed bytecode on a **246-entry adversarial corpus**
   (4 positive controls + 242 near-miss mutants mirroring the bytecode
   screen's classes, plus dense sweeps of both historic defect sites),
   where the corpus' expected column is **deployed-bytecode ground truth**
   asserted by `forge test --match-contract SPHINCsC10AsmMutantCorpusTest`
   (exact two-directional parity). The historic reconstruction-layer
   divergence (two defects: the `chainHash` chain-pos field and
   `loadWord32` straddling-read semantics) was localised by
   `scripts/gap1_differential.py` and fixed 2026-06-12. The three-way
   Rust↔Solidity↔Lean differential is therefore real on **every** layer,
   at **252 distinct agreement points**, in both accept and reject
   directions. Reproduced 2026-06-12.
5. **Verifier negative direction.** The deployed verifier bytecode rejects a
   ≈250-mutant wrong-accept battery and the 6 negative KAT vectors, and
   accepts the 4 valid vectors (`forge test`). Reproduced 2026-06-11.

The honest trust base for (1)–(2): the Lean kernel; that a Halmos+z3 rule is
a sound solver session (the harness↔property and `LeanModel.sol`↔Lean-file
transcriptions are in the TCB, not Lean proof terms); SHA-256 modeled as an
uninterpreted function; and the verifier modeled as an uninterpreted function
inside the wallet rules (which is exactly what makes them tractable and what
A5/A3.1 are supposed to discharge separately). For (4): the KAT corpus is
finite (10 vectors); equality at 10 points validates but does not prove the
universally-quantified A3.1 axiom (see below).

---

## ❌ NOT claimable (the named gaps)

Do **not** say any of the following:

* ~~"The smart contracts are fully mathematically proven to the bytecode."~~
  The **verifier's ∀-signature functional equivalence is not proven** — the
  Lean↔bytecode agreement is established on the 10-vector corpus (plus the
  bytecode-side mutant screen), which is **evidence, not a proof, of the
  universally-quantified A3.1**. GAP-2 (Verity / Kontrol-KEVM) remains open,
  as do the rigor/scope gaps (GAP-7..13) in
  [`MISSING_FOR_FULL_BYTECODE_PROOF.md`](MISSING_FOR_FULL_BYTECODE_PROOF.md).
* ~~"The SPHINCS+C10 verifier is formally verified / proven correct to the
  bytecode."~~ Its functional behaviour is carried by an executable
  Lean↔bytecode differential on the corpus + the bytecode KAT + the mutant
  screen — **testing-grade evidence**. There is **no** ∀-signature proof.
* "A three-way Rust↔Solidity↔Lean differential validates the verifier." —
  now TRUE and claimable as stated (since 2026-06-12 the Lean leg covers the
  full functional layer as a hard check), provided it is presented as a
  *differential/testing* result, not as a proof.

### The formerly-blocking defect (RESOLVED 2026-06-12)

`solidityVerifier_compiles_correctly` (A3.1) asserts the deployed verifier
equals the Lean `verifyYulModel` for all inputs. Until 2026-06-12 that
equality was **contradicted by a concrete KAT vector** — the Lean spec
returned `false` on the valid vectors, so A3.1 was a **false axiom** and the
kernel "green" carried no real-world force on the verifier dimension. The
divergence was localised to exactly two one-line semantic defects (the
WOTS chain-position ADRS field and the straddling `calldataload`
zero-padding), both in the *Lean model*, not the contract; both are fixed,
and `lake exe verify-test-vectors` now enforces full-corpus agreement as a
hard check. **A3.1 is no longer refuted by any known input; it remains an
axiom whose universal claim is corpus-validated, not proven** (that
residual is GAP-2). History and root-cause: 
[`A3_1_VERIFIER_GAP.md`](A3_1_VERIFIER_GAP.md).

Also still cited-TCB by decision (not "proven to bytecode"): **A2** EntryPoint
v0.6 honesty, **A4** EVM-executes-per-spec (incl. the emitted-CALL byte
delivery on the execute path), **A5** SPHINCS+C10 EUF-CMA (Barbosa et al.;
the `+C` transition is a cited argument), **A1** SHA-256 precompile = FIPS.

---

## What it takes to reach "fully proven to bytecode"

In dependency order:

1. ~~**Make the Lean verifier executably faithful.**~~ **DONE 2026-06-12.**
   `lake exe verify-test-vectors` reports full-verify 10/10 and
   `requireFullVerify = true` (hard check). A3.1's equality is now
   corpus-consistent and the Lean refinement (`verifyRefined_eq_spec`,
   still `rfl`) carries real faithfulness on every executed layer. The
   ∀-signature equivalence remains a *citation* to the executable KAT +
   mutant screen + EUF-CMA, not a symbolic bytecode proof.
2. **Discharge the verifier's ∀-signature equivalence on bytecode.** Not
   possible under uninterpreted SHA-256 (the digit branches fork on
   unconstrained symbolic values). Needs an **interpreted-hash reachability**
   engine (Kontrol/KEVM) or **verified compilation** (Verity,
   [`PATH_TO_VERIFIED_BYTECODE.md`](PATH_TO_VERIFIED_BYTECODE.md)). Even Verity
   stops at Yul, leaving A1/A2/A4 as cited-TCB.
3. **Optionally** reduce A2/A4 from cited-TCB to bytecode (Kontrol against the
   deployed EntryPoint) — a large, separate engagement.

With step 1 landed, the maximal honest headline is the **✅ Claimable**
block above — "control flow proven to the deployed bytecode; verifier
functionally validated by an executable three-way differential on the full
KAT corpus (hard check)" — still **not** "fully proven to bytecode" (that
requires step 2 plus the GAP-7..13 closures, or explicit acceptance of the
named TCB).
