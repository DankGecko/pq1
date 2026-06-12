# A3.1 — the verifier functional-equivalence gap (RESOLVED 2026-06-12)

**Original date:** 2026-06-11. **Resolved:** 2026-06-12. This document is
kept as the postmortem of record: what the gap was, what the *actual* root
cause turned out to be (the original diagnosis below was partially wrong),
how it was closed, and what residual remains (GAP-2 — the ∀-signature
equivalence — which is tracked in `MISSING_FOR_FULL_BYTECODE_PROOF.md`,
not here).

## TL;DR (post-resolution)

The Lean SPHINCS+C10 verifier spec (`Spec.Signature.verify`) had never been
executed on a concrete signature until 2026-06-11; it returned `false` on
the valid KAT vectors the deployed bytecode accepts, so the A3.1 axiom
(`∀ inputs, bytecode = verifyYulModel`) was **false as stated**.

On 2026-06-12 the divergence was localised by a byte-level differential
oracle (`scripts/gap1_differential.py` — an exact Python transliteration of
the deployed Yul, traced per-intermediate, against an exact replica of the
Lean spec) to **two one-line semantic defects, both in the Lean model**:

1. **`Spec.Hash.chainHash` stepped the WOTS chain position through the
   wrong ADRS field.** It called `Adrs.setChainIndex` (bytes [20..24)) per
   step — overwriting the chain index `i` the caller had set — where the
   Rust signer (`hash.rs::chain_hash`, `a[24..28) = pos`) and the deployed
   Yul (`or(chainBase, shl(32, add(digit, step)))`) thread the position
   through the `chain_pos` field (bytes [24..28)) and preserve the index.
   Fix: new `Adrs.setChainPos` + one-line change in `chainHash`.

2. **`ByteVec.loadWord32` returned an all-zero word for any read crossing
   the end of the signature.** `calldataload` semantics zero-pad only the
   bytes *past* the end; the deployed verifier's final layer-1
   Merkle-sibling read sits at offset 3992 of the 4008-byte signature, so
   the real bytes [3992..4008) ‖ 16 zero bytes must be returned. The
   pre-fix definition zeroed the entire word, destroying the last sibling
   of the layer-1 auth path. Fix: partial-read + zero-pad in the
   out-of-bounds branch.

With both fixed, `lake exe verify-test-vectors` reports **full-verify
10/10** and `requireFullVerify = true` makes it a **hard check** (non-zero
exit on any future drift). `verifyRefined_eq_spec` remains `rfl`; the full
proof stack builds with 0 `sorry` and an unchanged axiom closure.

## Correction to the original diagnosis

The 2026-06-11 version of this document attributed the failure to the
**ADRS bit-layout of `Spec.Adrs.make`** ("clean structured address" vs the
Yul's "ad-hoc packed words") and claimed the failure point was the
**layer-0 digit-sum gate** (`pkFromSig → none`). Both were wrong:

* `Spec.Adrs.make`'s field placement (layer ‖ tree(8) ‖ atype ‖ kp ‖ ci ‖
  cp ‖ ha) is **byte-identical** to every packed word the Yul constructs.
  The digest, FORS forest (all 13 roots), forsPk, layer-0 WOTS digest and
  layer-0 digit sum were **already byte-faithful** before the fix — the
  differential proved this per-intermediate.
* The first divergence was the layer-0 **chain endpoints** (defect 1).
  The digit-sum failure observed at *layer 1* was a downstream symptom:
  wrong endpoints → wrong layer-0 WOTS pk → wrong subtree root → wrong
  layer-1 `currentNode` → garbage layer-1 WOTS digest → digit-sum ≠ 205.

Lesson recorded for the next gap of this shape: diagnose with an
executable per-intermediate differential **before** writing the
root-cause narrative. The masking structure ("gate fails first") invited
a plausible-but-wrong story that survived a day in the ledger.

## What the runner shows (since 2026-06-12)

| Sub-layer | Lean function | Result vs bytecode ground truth |
|---|---|---|
| hMsg **digest** | `Spec.Hash.hMsg` (over `Spec.Sha256Impl`) | **10/10 byte-exact** (HARD CHECK) |
| **htIdx** extraction | `Util.extractHtIndex` | **10/10 exact** (HARD CHECK) |
| **full functional verify** | `Spec.Signature.verify` | **10/10 accept/reject agreement** (HARD CHECK) |
| **mutant-corpus verify** | `Spec.Signature.verify` (`lake exe verify-mutant-corpus`) | **246/246 agreement** on the adversarial corpus, expected values asserted against the deployed bytecode by forge (HARD CHECK) |

The 246-entry corpus (`test/c10_mutant_corpus.json`, deterministic, from
`scripts/gen_mutant_corpus.py`) mirrors the bytecode screen's mutation
classes and adds dense sweeps of both historic defect sites (the
straddling-read tail [3992,4008) and the per-layer count fields), so the
two specific bugs of this postmortem are regression-locked at corpus
scale on BOTH legs.

Reproduce: `cd contracts/verification && make verify` (or
`python3 scripts/gap1_differential.py [--lean-fixed]` for the standalone
byte-level oracle with per-intermediate tracing).

## What this does and does NOT establish

* It **does** make A3.1 no longer refuted: no known input distinguishes
  `Spec.Signature.verify` from the deployed bytecode. The three-way
  Rust ↔ Solidity ↔ Lean differential is now real on every layer.
* It does **not** prove the universally-quantified A3.1. Equality at 10
  corpus points (+ the ~250-mutant wrong-accept screen on the bytecode
  side) is testing-grade evidence. The ∀-signature equivalence over
  4008-byte signatures remains open — and remains **intractable under
  uninterpreted SHA-256** (the verifier branches on base-`w` digits of
  `sha256(seed‖adrs‖node‖count)`; with SHA-256 uninterpreted every digit
  is an unconstrained symbolic value and the path set explodes). Closing
  it needs interpreted-hash reachability (Kontrol/KEVM) or verified
  compilation (Verity). That is **GAP-2** in
  `MISSING_FOR_FULL_BYTECODE_PROOF.md` and is why A3.1's ledger entry
  stays `discharged-bytecode-partial` (functional layer now
  corpus-discharged by executable differential; ∀-layer open).

## Closure criteria (met)

* ✅ `lake exe verify-test-vectors` reports **full verify 10/10** and
  `requireFullVerify` in `Main.lean` is `true` (hard check);
* ✅ digest/index/reconstruction all match on the corpus, with
  `verifyRefined_eq_spec` still `rfl`;
* ✅ A3.1 promoted: functional layer `discharged-bytecode` on the corpus
  (executable Lean differential), ∀-signature residual explicitly named
  (GAP-2). See `AXIOM_STATUS.json`.
