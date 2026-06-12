# What is missing to claim "fully mathematically proven to the bytecode"

**Status date:** 2026-06-12 (GAP-1 closed; original list 2026-06-11). This
is the complete, itemised gap list between the *current* state and the
*unqualified* claim "the PQSmartWallet smart contracts are fully
mathematically proven to the deployed bytecode." It is the master
checklist; the per-topic detail lives in
[`THE_CLAIM.md`](THE_CLAIM.md), [`A3_1_VERIFIER_GAP.md`](A3_1_VERIFIER_GAP.md),
[`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md), and
[`PATH_TO_VERIFIED_BYTECODE.md`](PATH_TO_VERIFIED_BYTECODE.md).

Each gap has: **what** is unproven, **why** it is open, **what closes it**,
and a rough **cost/dependency**. Gaps are ordered by how badly they block the
headline claim.

---

## Definition — what "fully proven to the bytecode" would require

For every deployed contract (`PQSmartWallet`, `PQSmartWalletFactory`,
`PQMultiOwnable`, `SPHINCsC10Asm`), a machine-checked theorem whose statement
quantifies over the **deployed runtime bytecode** (not a Lean model of it) and
whose **axiom base** contains only items that are themselves either (a) Lean
kernel built-ins, or (b) discharged against that same bytecode, or (c) a small,
explicitly-listed set of universally-trusted external facts (FIPS SHA-256, the
EVM spec) that the entire Ethereum ecosystem already trusts.

Today `theft_free` is kernel-checked, but its axiom base contains items that
are **not** in (a)–(c): several "cited-TCB" axioms that are model-level
fictions, plus the fact that the bytecode-level discharges are **solver
sessions, not Lean proof terms**. (The formerly-false A3.1 axiom — GAP-1 —
was repaired 2026-06-12.) The gaps below enumerate the delta.

---

## BLOCKING gaps (must close before any "proven to bytecode" claim about the verifier)

### ~~GAP-1 — A3.1 is a FALSE axiom~~ — CLOSED 2026-06-12
- **What it was:** `solidityVerifier_compiles_correctly` asserts
  `∀ inputs, DeployedBytecode.SPHINCsC10Asm_verify = verifyYulModel`, and a
  concrete KAT vector refuted it: `Spec.Signature.verify` returned `false`
  on the valid vectors the deployed bytecode accepts — a **false axiom**.
- **Actual root cause (narrower than the original diagnosis):** exactly two
  one-line semantic defects in the Lean model, localised by the
  per-intermediate differential oracle `scripts/gap1_differential.py`:
  (1) `Spec.Hash.chainHash` stepped the WOTS chain position through the
  ADRS chain-*index* field (bytes [20..24)), erasing the index, instead of
  the chain-*pos* field (bytes [24..28)) the Rust signer and deployed Yul
  use; (2) `ByteVec.loadWord32` returned an all-zero word for the one read
  that straddles the signature end (the final layer-1 Merkle sibling at
  offset 3992/4008), where `calldataload` returns the real suffix +
  zero-padding. Everything else — digest, FORS forest, forsPk, digit
  extraction, ADRS packings, offsets — was already byte-faithful.
- **Closure evidence:** `lake exe verify-test-vectors` full-verify **10/10**
  with `requireFullVerify = true` (**hard check**, regression-guarded);
  `verifyRefined_eq_spec` still `rfl`; 0 `sorry`; axiom closure unchanged.
  Postmortem: [`A3_1_VERIFIER_GAP.md`](A3_1_VERIFIER_GAP.md).
- **What it does NOT close:** the universal quantifier. A3.1 is now
  corpus-validated (no known refuting input) but still an *axiom*; the
  ∀-signature equivalence is GAP-2.

### GAP-2 — No ∀-signature equivalence of the verifier on the bytecode
- **What:** even with GAP-1 closed, there is no symbolic proof that the
  *deployed verifier bytecode* equals the (now-faithful) spec over **all**
  4008-byte signatures — only a 10-vector KAT + a ~250-mutant wrong-accept
  screen (finite testing) + the Lean refinement (a model-to-model `rfl`).
- **Why open:** the verifier branches on base-`w` digits of
  `sha256(seed‖adrs‖node‖count)`. With SHA-256 modelled as an **uninterpreted
  function** (= axiom A1), every digit is an unconstrained symbolic value, so
  the path set explodes — no UF-based symbolic engine (Halmos) can close it.
- **What closes it:** an **interpreted-hash reachability** engine (Kontrol /
  KEVM, which can reason about concrete SHA-256 along reachable paths) **or**
  **verified compilation** (Verity — write the verifier in the Lean EDSL and
  carry a machine-checked Lean→Yul lowering proof; see
  `PATH_TO_VERIFIED_BYTECODE.md`).
- **Cost/dependency:** large, separate engagement; depends on GAP-1 for the
  faithful spec to compare against. Even Verity stops at Yul (leaves GAP-5).

---

## CITED-TCB gaps (trusted external facts; "proven" only if you accept them as axioms)

These are the items that, even after GAP-1/GAP-2, keep "fully proven to the
bytecode" from being literally true — each is a fact assumed, not discharged
against the bytecode. They are the *same* assumptions most audited contracts
rely on, but they must be disclosed, not hidden.

### GAP-3 — A1: SHA-256 precompile (0x02) = FIPS 180-4
- **What/why:** every Halmos rule treats `0x02` as an uninterpreted function;
  the equality `precompile = FIPS-SHA256` is assumed. Discharge today is a NIST
  CAVS parity test + universal consensus-client trust.
- **What closes it (if ever):** KEVM's modelled precompile semantics. Normally
  left as universal-Ethereum TCB.

### GAP-4 — A2: EntryPoint v0.6 honesty
- **What/why:** `entrypoint_honest` is a property of a **10-line Lean model**
  of EntryPoint v0.6 (`Bridge/EntryPoint.lean`), not the deployed mainnet
  EntryPoint bytecode. It asserts "balance only moves after `validateUserOp`
  returned success, and EntryPoint never debits the wallet directly."
- **What closes it:** Kontrol against the deployed EntryPoint v0.6 bytecode at
  `0x5FF1…2789` (the docs estimate an 8–12 month engagement). Otherwise cited
  OZ/ChainSecurity/Spearbit audits + 18 mo mainnet.

### GAP-5 — A4: EVM-executes-per-spec (incl. emitted-CALL byte delivery)
- **What/why:** `evm_bytecode_executes_correctly` is a `True` marker. It also
  carries the execute path's external-CALL byte delivery (the Halmos execute
  rules prove the wallet *reaches* `target.call{value}(data)` with the guards
  passed; that the EVM then delivers those exact bytes is A4, not A3.2-exec).
- **What closes it:** KEVM as the formal EVM-semantics referent. Universal
  Ethereum trust; essentially never discharged per-contract.

### GAP-6 — A5: SPHINCS+C10 EUF-CMA, and the "+C" transition
- **What/why:** `EUF_CMA_SPHINCSplusC` + 3 hardness-shape axioms are cited to
  Barbosa et al. (ASIACRYPT 2024, EasyCrypt-mechanised) — **for SPHINCS+**. The
  **SPHINCS+C (count/target-sum) transition** is a *paper argument*, not
  mechanised, and is the bridge to the actual deployed parameter set.
- **What closes it:** mechanise the +C transition (research effort) or accept
  the citation. Note this is *cryptographic* soundness, orthogonal to bytecode
  faithfulness — but it is part of "the wallet is theft-free" end-to-end.

---

## RIGOR gaps (the bytecode discharges are solver sessions, not kernel proofs)

### GAP-7 — A Halmos rule is a cited solver session, not a Lean proof term
- **What:** the 38 bytecode rules are **not** in the Lean kernel. Trusting them
  adds to the TCB: (a) Halmos + z3 soundness; (b) the **harness↔property**
  correspondence (that each `check_*` asserts what its name/docstring claims);
  (c) the **transcription** correspondence — `LeanValidateUserOpModel.sol` ↔
  `Wallet/ValidateUserOp.lean` and `LeanExecuteModel.sol` ↔ `Wallet/Execute.lean`
  are hand-written side-by-side restatements, auditable by eye but not
  machine-checked equal to the Lean source.
- **What closes it:** verified compilation (Verity) makes the model *be* the
  source, eliminating (c); a KEVM/Kontrol proof discharged into Lean would
  eliminate (a)/(b). Otherwise these stay in the TCB.

### GAP-8 — The PQ1 Halmos patch is itself trusted
- **What:** stock Halmos 0.3.x has a SHA-256 precompile sort bug; we run a
  patched build (`halmos/0001-sha256-precompile-sort.patch`). The patch keeps
  SHA-256 uninterpreted (sound), but the patched tool is part of the TCB and is
  not independently audited.
- **What closes it:** upstream the patch + pin a released, audited Halmos.

---

## SCOPE / COMPLETENESS gaps (the discharges hold over *envelopes*, not unconditionally)

### GAP-9 — Validate `ownerIndex`: unset partition is concrete-reps only
- **What:** the validate pointwise-equivalence sweeps a *symbolic* index over
  the **installed** slots `{1,2}` and **enumerates** `{0,1,2}`, but the **unset
  partition (≥3)** is covered only by concrete reps `{3, 2^200, max}`. A
  symbolic sweep of it **errors** (`NotConcreteError` — Halmos cannot allocate
  the `ownerAtIndex` dynamic-bytes return for a symbolic non-installed key).
- **Mitigation today:** the wallet's behaviour on every unset index is uniform
  (owner length 0 ≠ 64 ⇒ reject), so the reps are representative — but it is
  not a ∀-proof. The *execute* path IS genuinely ∀-index.
- **What closes it:** a symbolic engine that models the mapping getter for a
  symbolic key, or a manual Lean lemma that the unset branch is index-uniform.

### GAP-10 — Owner-set SHAPE is concrete in the validate equivalence
- **What:** the validate/owner-table equivalence fixes the *installed set*
  shape (bootstrap at 0, slots at 1 and 2; ≥3 unset). Owner *contents* and
  counters are symbolic, but the rules do not range over arbitrary owner-set
  shapes (e.g. more installed slots, gaps).
- **What closes it:** parametrise the harness over owner-set shapes (bounded),
  or a Lean inductive argument that behaviour depends only on
  `(ownerAtIndex(i), counters(i))` per index (already true by inspection).

### GAP-11 — Execute equivalence: single-credit envelope, success-direction only
- **What:** `HalmosExecuteEquiv` stamps the execution credit via **one** real
  `validateUserOp`; the Lean `Execute` model has a single
  `validatedOwnerPlusOne` field. Multi-op bundles (several slots' credits in
  one EntryPoint `handleOps`) are not modelled. The axiom is also the
  **success direction** only (`bytecode returns some σ' ⇒ model agrees`); the
  Lean model is the all-dispatch-succeeds model.
- **What closes it:** extend the Lean model + harness to a per-slot credit map
  and bundle semantics; add the failure-direction equivalence.

### GAP-12 — A3.2 carries a reachable-state hypothesis
- **What:** the validate equivalence is conditioned on
  `∀ i, slotUses[i] + offchainSigCount[i] ≤ MaxSlotUses` (the kernel-proven
  `combinedCap_inductive`). Outside it the bytecode reverts (checked-add
  overflow) where the ℕ model returns failure. This is sound (unreachable
  states) but is a hypothesis on the theorem, not an unconditional ∀.
- **What closes it:** nothing required — it is correct by design; listed for
  completeness because the bytecode↔model equality is **not** unconditional.

### GAP-13 — solc is trusted between Solidity source and bytecode
- **What:** the wallet/factory are written in Solidity and compiled by
  `solc 0.8.28`; the Halmos rules run on the *output* bytecode, so they verify
  *around* solc rather than trusting it — but the **pinning** (codehash ==
  pin) and the assumption that the pinned bytecode is what deploys are TCB.
- **What closes it:** verified compilation (Verity) for the whole wallet, not
  just the verifier; reproducible-build attestation of the deploy artifact.

---

## Definition-of-done checklist

To drop every qualifier and claim "fully proven to the bytecode":

- [x] **GAP-1** — `lake exe verify-test-vectors` full-verify 10/10; `requireFullVerify = true`; A3.1 no longer refuted. **CLOSED 2026-06-12.**
- [ ] **GAP-2** — verifier ∀-signature equivalence via Kontrol/KEVM or Verity.
- [ ] **GAP-7 / GAP-8** — bytecode discharges carried as Lean proof terms (Verity) or audited solver + upstreamed patch.
- [ ] **GAP-9 / GAP-10 / GAP-11** — index/shape/credit envelopes generalised to ∀ (or Lean lemmas covering them).
- [ ] **GAP-3 / GAP-4 / GAP-5 / GAP-6 / GAP-13** — either discharged (Kontrol/KEVM/Verity) or **explicitly accepted** as the named universal-Ethereum + crypto TCB, and the public claim worded to say so.

With GAP-1 closed, the **maximal honest claim** is the one in
[`THE_CLAIM.md`](THE_CLAIM.md): *control flow proven to the deployed
bytecode; verifier functionally validated by an executable three-way
(Rust↔Solidity↔Lean) differential on the full KAT corpus, as a hard
check.* "Fully proven to the bytecode" additionally requires GAP-2 and the
GAP-7..13 closures (or their explicit TCB acceptance).
