# The claim — exactly what is and isn't proven (2026-06-11)

This file is the single source of truth for **what you may publicly claim**
about the PQSmartWallet formal-verification stack. It is deliberately
conservative. If a marketing line is not derivable from the "✅ Claimable"
section below, do not ship it.

---

## ✅ Claimable (true, reproduced)

> **The PQSmartWallet's on-chain control flow is formally verified, and the
> verification is connected to the deployed bytecode.** A Lean 4
> kernel-checked theorem (`theft_free`, 0 `sorry`, an explicit 11-axiom
> base) proves theft-freedom over a faithful model of the wallet; and the
> **wallet `validateUserOp` / `executeWithOffchainCount` /
> `executeBatchWithOffchainCount`, the factory `createAccount`, and the
> `PQMultiOwnable` owner table** are each proven, by symbolic execution of
> the **deployed runtime bytecode** (Halmos + z3, both compiler profiles,
> pinned codehashes), to be **pointwise-equal to those Lean models** over
> symbolic inputs — including a genuinely ∀-quantified owner index on every
> money-moving path.**

Specifically and defensibly:

1. **Kernel proof.** `theft_free` and its claim corollaries are checked by
   the Lean 4 kernel with **zero `sorry`** and an axiom closure of exactly
   11 named axioms (`make verify-audit`). Reproduced 2026-06-11.
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
4. **Verifier digest layer.** An **executable** Lean↔FIPS↔bytecode KAT
   (`lake exe verify-test-vectors`) shows the Lean SHA-256 reference and the
   `hMsg` digest + hypertree-index extraction match the deployed verifier's
   on all 10 vectors (hard check). Reproduced 2026-06-11.
5. **Verifier negative direction.** The deployed verifier bytecode rejects a
   ≈250-mutant wrong-accept battery and the 6 negative KAT vectors, and
   accepts the 4 valid vectors (`forge test`). Reproduced 2026-06-11.

The honest trust base for (1)–(2): the Lean kernel; that a Halmos+z3 rule is
a sound solver session (the harness↔property and `LeanModel.sol`↔Lean-file
transcriptions are in the TCB, not Lean proof terms); SHA-256 modeled as an
uninterpreted function; and the verifier modeled as an uninterpreted function
inside the wallet rules (which is exactly what makes them tractable and what
A5/A3.1 are supposed to discharge separately).

---

## ❌ NOT claimable (the named gaps)

Do **not** say any of the following:

* ~~"The smart contracts are fully mathematically proven to the bytecode."~~
  The **verifier's functional correctness is not proven** — see below.
* ~~"The SPHINCS+C10 verifier is formally verified / proven correct to the
  bytecode."~~ Its FORS/WOTS+C/Merkle functional behaviour is carried by
  **testing only** (bytecode KAT + mutant screen). There is **no** ∀-signature
  proof and the Lean verifier model is **not executably faithful**.
* ~~"A three-way Rust↔Solidity↔Lean differential validates the verifier."~~
  The Lean leg is real only on the **digest/index sub-layers**; on the
  functional layer the Lean spec returns `false` on valid vectors. The
  real differential is Rust↔Solidity (bytecode) + the digest-layer Lean check.

### The one blocking defect

`solidityVerifier_compiles_correctly` (A3.1) asserts the deployed verifier
equals the Lean `verifyYulModel` for all inputs. That equality is
**contradicted by a concrete KAT vector** (`Spec.Signature.verify` returns
`false` where the bytecode returns `true`), so **A3.1 is currently false as
stated** — the WOTS+C / hypertree reconstruction layer of the Lean spec
diverges from the deployed Yul ADRS layout and was never executed until now.
`theft_free` is still kernel-valid as a formal object, but a proof resting on
a false axiom does **not** establish bytecode-level security on the verifier
dimension. Full analysis: [`A3_1_VERIFIER_GAP.md`](A3_1_VERIFIER_GAP.md).

Also still cited-TCB by decision (not "proven to bytecode"): **A2** EntryPoint
v0.6 honesty, **A4** EVM-executes-per-spec (incl. the emitted-CALL byte
delivery on the execute path), **A5** SPHINCS+C10 EUF-CMA (Barbosa et al.;
the `+C` transition is a cited argument), **A1** SHA-256 precompile = FIPS.

---

## What it takes to reach "fully proven to bytecode"

In dependency order:

1. **Make the Lean verifier executably faithful.** Reimplement the WOTS+C /
   hypertree reconstruction ADRS layer to byte-match the deployed Yul, until
   `lake exe verify-test-vectors` reports full-verify 10/10 and
   `requireFullVerify` is flipped to `true`. Then A3.1's equality becomes
   *true* and the Lean refinement (`verifyRefined_eq_spec`, still `rfl`)
   carries real faithfulness. This removes the false-axiom problem but still
   leaves the ∀-signature equivalence as a *citation* to the executable KAT +
   EUF-CMA, not a symbolic bytecode proof.
2. **Discharge the verifier's ∀-signature equivalence on bytecode.** Not
   possible under uninterpreted SHA-256 (the digit branches fork on
   unconstrained symbolic values). Needs an **interpreted-hash reachability**
   engine (Kontrol/KEVM) or **verified compilation** (Verity,
   [`PATH_TO_VERIFIED_BYTECODE.md`](PATH_TO_VERIFIED_BYTECODE.md)). Even Verity
   stops at Yul, leaving A1/A2/A4 as cited-TCB.
3. **Optionally** reduce A2/A4 from cited-TCB to bytecode (Kontrol against the
   deployed EntryPoint) — a large, separate engagement.

Until step 1 lands, the maximal honest headline is the **✅ Claimable**
block above — "control flow proven to bytecode; verifier validated by
testing" — not "fully proven to bytecode."
