# A3.1 — the verifier functional-equivalence gap (honest status)

**Date:** 2026-06-11. **Severity:** verification-stack honesty (no on-chain
exploit; the deployed verifier itself is unchanged and is exercised by the
on-bytecode KAT + mutant screen below). **Status of the headline
`theft_free` proof:** unaffected at the kernel level — but the gap below
bounds exactly how far A3.1 connects that proof to the verifier bytecode.

## TL;DR

The Lean SPHINCS+C10 verifier spec (`Spec.Signature.verify`) had **never
been executed on a concrete signature** until 2026-06-11. When run against
the 10 shared KAT vectors (`lake exe verify-test-vectors`), it returns
`false` on the **valid** vectors. So the Lean verifier model is **not
functionally faithful** to the deployed bytecode, and the previously
advertised "three-way Rust ↔ Solidity ↔ Lean KAT differential" for A3.1
was, on the Lean leg, a stub (a print statement). This document records
the precise gap, what *is* validated, and what closing it requires.

## What the runner shows

`lake exe verify-test-vectors` replays all 10 vectors through the
executable spec and reports three sub-layers:

| Sub-layer | Lean function | Result vs bytecode ground truth |
|---|---|---|
| hMsg **digest** | `Spec.Hash.hMsg` (over `Spec.Sha256Impl`) | **10/10 byte-exact** (HARD CHECK) |
| **htIdx** extraction | `Util.extractHtIndex` | **10/10 exact** (HARD CHECK) |
| **full functional verify** | `Spec.Signature.verify` | **valid vectors return `false`** — GAP |

So the SHA-256 reference, the `hMsg` preimage layout, and the hypertree-leaf
index extraction are genuinely faithful (a real Lean-SHA256 ↔ FIPS ↔
deployed-digest cross-check). The divergence is strictly **downstream of the
digest**, in the reconstruction layer.

## Where it diverges (localised)

`Spec.Hypertree.verifyWithDigest` reaches `Spec.Wots.pkFromSig`, which
recomputes the WOTS+C digest and checks `digitSum digits = TargetSum`
(= 205). On the valid vectors this check **fails** (`pkFromSig` → `none` →
`verifyHypertree` → `none` → `verify` → `false`). The first-order cause is
the **ADRS bit-layout**: the Lean `Spec.Adrs.make` builds a clean
structured 32-byte address (`layer ‖ tree ‖ atype ‖ kp ‖ ci ‖ cp ‖ ha`)
intended to "mirror `address.rs`", whereas the deployed Yul packs ad-hoc
words such as

```
wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))
chainBase := and(or(wotsAdrs, shl(64, i)), 0xFF..FF00000000FFFFFFFF)
pkAdrs   := or(shl(224,layer), or(shl(160,idxTree), or(shl(128,1), shl(96,idxLeaf))))
treeAdrs := or(shl(224,layer), or(shl(160,idxTree), shl(128,2)))
```

with the per-chain index threaded at `shl(64, i)` and the chain position at
`shl(32, digit+step)`. For the recomputed WOTS digest (hence the digit sum,
hence every chain endpoint and the Merkle path) to match, the Lean ADRS
bytes must equal these packed words **byte-for-byte** at every call site.
They evidently do not. Because the digit-sum gate fails first, any further
divergences in the FORS / WOTS chain / subtree-Merkle reconstruction are
currently **masked** and not yet individually characterised.

## The sharp consequence: the A3.1 axiom is currently FALSE as stated

`solidityVerifier_compiles_correctly` (A3.1) asserts

```
∀ pkSeed pkRoot message sig,
  DeployedBytecode.SPHINCsC10Asm_verify pkSeed pkRoot message sig
    = verifyYulModel pkSeed pkRoot message sig
```

We have **exhibited a concrete counterexample**: on KAT `valid-1` the
deployed bytecode returns `true` while `verifyYulModel` (= `verifyRefined`
= `Spec.Signature.verify`) returns `false`. So the universally-quantified
equality is **false**, and A3.1 is not "partially discharged" — as written
it is a **false axiom**.

Two precise implications, kept separate so neither is over- or under-stated:

* **Formally:** `theft_free` is still kernel-checked; Lean does not know or
  care that A3.1 is false. But a proof resting on a false axiom carries no
  real-world force — and worse, a false axiom is *inconsistent with reality*,
  so the axiom base could in principle derive contradictory conclusions.
  The kernel "green" is therefore **not** evidence of bytecode-level
  security on the verifier dimension.

* **Operationally (why no on-chain bug):** the **deployed** verifier is the
  Rust-signer's matched pair and is exercised directly by the bytecode KAT +
  mutant screen (all PASS). The falsity is in the *Lean model*, not the
  contract. Nothing on-chain is broken; what is broken is the *claim that the
  Lean proof reaches the verifier bytecode*.

**Required correction (either path):**
1. Make `Spec.Signature.verify` executably faithful (so the equality holds
   and A3.1 becomes true + discharged), **or**
2. Restate A3.1 honestly: drop the verifier-functional equality from the
   formal bridge and record the verifier's correctness as an **empirical /
   cited** assumption (bytecode KAT + mutant screen + the Rust↔Solidity
   matched-pair), i.e. treat the verifier like A2/A4/A5 (cited-TCB) rather
   than as a discharged bytecode bridge.

Until one of these lands, the project must NOT claim the verifier is
"mathematically proven to the bytecode."

## What this does and does NOT mean

* It does **not** mean the deployed verifier is wrong. The deployed
  `SPHINCsC10Asm.verify` bytecode **accepts** all four valid vectors
  (`forge test --match-test test_verifyAllKatVectors`, PASS) and **rejects**
  every member of the ~250-mutant wrong-accept screen
  (`SPHINCsC10AsmAdversarial.t.sol`, PASS) and the 6 negative KAT vectors.
  The Rust signer and the Solidity verifier are a validated matched pair.

* It **does** mean A3.1's *formal* leg is weaker than the prior docs
  implied. The chain
  `Spec.Signature.verify → verifyRefined (rfl) → verifyYulModel (rfl) →
  [A3.1 axiom] → deployed bytecode` is internally consistent, but its
  left end (`Spec.Signature.verify`) does not compute the function the
  deployed bytecode computes. So the Lean refinement establishes
  *internal* structure, not *external* faithfulness, on the reconstruction
  layer. The FORS-`htIdx` ADRS binding added in `fcee705a` is **structural
  only** — it was never executably confirmed against a vector.

## Corrected A3.1 evidence ledger

A3.1 (`solidityVerifier_compiles_correctly`) is **`discharged-bytecode-partial`**,
and the honest decomposition is:

1. **Digest + index layer** — executable Lean ↔ FIPS ↔ bytecode KAT, 10/10
   (`lake exe verify-test-vectors`, HARD CHECK). *New, real.*
2. **Input gates** — Halmos over the deployed bytecode (length revert,
   N-mask reject), 3 rules (`HalmosVerifier.t.sol`).
3. **Functional behaviour (FORS/WOTS+C/Merkle/hypertree)** — **empirical
   only**: the 10-vector positive KAT + the ~250-mutant wrong-accept screen,
   both on the deployed bytecode. **No formal ∀-signature equivalence**, and
   **no executable Lean cross-check** (this gap). This is the named residual.

The earlier phrasing "Lean refinement (incl. FORS htIdx) + 10 KAT vectors"
must be read as: *structural* Lean refinement (not executably faithful on
reconstruction) + *bytecode-side* KAT (the Rust↔Solidity leg is real; the
Lean leg validates only the digest/index sub-layer).

## Why it is not closed in-session

Making `Spec.Signature.verify` executably faithful is a **bit-exact
reimplementation-and-validation** of the WOTS+C and hypertree ADRS layer
(≥4 distinct packings + index threading + the count/target-sum grind +
subtree Merkle ordering), each cross-checked against Rust/Yul intermediates.
That is a multi-day effort with compounding-bug risk, not a localized fix —
exactly the work the verified-compilation path
(`PATH_TO_VERIFIED_BYTECODE.md`, Verity) or an interpreted-hash symbolic
discharge (Kontrol/KEVM) is meant to absorb.

## Closure criteria (when this doc can be deleted)

* `lake exe verify-test-vectors` reports **full verify 10/10** and
  `requireFullVerify` in `Main.lean` is flipped to `true` (hard check); **and**
* the Lean `Spec.Signature.verify` digest/index/reconstruction all match on
  the corpus, with `verifyRefined_eq_spec` still `rfl`; **then**
* A3.1 can be promoted from `discharged-bytecode-partial` to
  `discharged-bytecode` for the functional layer (the ∀-signature symbolic
  equivalence over a 4008-byte sig remains intractable under uninterpreted
  SHA-256 regardless — see below).

## The deeper ∀-signature ceiling (separate from this gap)

Even a perfectly faithful executable Lean spec would not give a *symbolic*
∀-signature equivalence on the bytecode under Halmos: the verifier branches
on base-`w` digits of `sha256(seed‖adrs‖node‖count)`, and with SHA-256 an
**uninterpreted** function (= axiom A1) every digit is an unconstrained
symbolic value, so the path set explodes and no UF-based symbolic engine can
close it. Closing *that* needs an interpreted-hash reachability tool
(Kontrol/KEVM) or verified compilation (Verity). This is why A3.1 stays
`-partial` independently of the reconstruction gap above.
