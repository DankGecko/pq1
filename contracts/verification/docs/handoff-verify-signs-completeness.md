# Handoff — `verify_signs` completeness (Group V round-trip leg)

Scoping + attack plan for discharging `Spec/Theorems.lean::verify_signs`'s
`consistent sk` hypothesis. This is the open *completeness* (round-trip) leg of
the verifier; it is **not** in the `theft_free` dependency closure (theft-freedom
uses only acceptance ⇒ verifier-returned-true + EUF-CMA), so it is a usability
guarantee (the wallet must accept firmware-produced signatures), not a safety
gap. Effort: **person-months** — the bulk is completing the reference signer,
which is currently a partial stub. This document makes that concrete.

## STATUS UPDATE (2026-06-27)

**Sub-lemma 1 of 4 — `merkle_roundtrip` — DONE** (`SphincsCVerify/Verifier/MerkleRoundtrip.lean`,
commit on master). Defines the honest signer-side Merkle tree `mtNode` + auth
path `mtAuthPath` (matching `htStep`'s `thPair`+`Adrs.treeNode` shape exactly)
and proves `verifyAuthPath` of an honest path reconstructs the tree root, by a
clean loop-invariant induction (`htAcc_climbs`) over the climb height via
`htAcc_succ`. Signer-independent (abstract over the leaf function `lf`), so the
FORS and hypertree legs reuse it. Axiom closure `[propext, Classical.choice,
Quot.sound]` — purely kernel (holds for any `thPair`).

**Sub-lemma 2 of 4 — `wots_chain_roundtrip` — DONE** (`SphincsCVerify/Verifier/WotsRoundtrip.lean`): the WOTS+ chain-composition `chainHash_compose` + `wots_chain_roundtrip`, closure `[propext, Quot.sound]`.

**Sub-lemma 3 of 4 — `fors_roundtrip` — DONE** (`SphincsCVerify/Verifier/ForsRoundtrip.lean`): FORS tree round-trip (`forsMtNode`/`forsMtAuthPath` + `forsAcc_climbs`), mirrors merkle_roundtrip; closure `[propext, Classical.choice, Quot.sound]`. Sub-lemma 4 (hypertree D=2) next needs a full `wots_pk_roundtrip` (the aggregate WOTS pk from an honest signature over all L chains + thMulti + the digit-sum/TargetSum), then composes wots_pk_roundtrip + merkle_roundtrip across the 2 layers.

The remaining work below
is unchanged: complete the signer, then sub-lemmas 2–4 + assembly.

## Where it stands (2026-06-26)

- `verify_signs` is **proven from** `consistent sk` (a one-line appeal); the
  predicate `consistent sk := ∀ m sig, Signer.sign sk m = some sig →
  Hypertree.verify sk.pkSeed sk.pkRoot m sig = true` packages the round-trip.
- `consistent sk` is **provably FALSE** for the current `Spec/Signer.lean::sign`
  — see the blocker below — so the round-trip cannot be closed without first
  completing the signer.
- **Foundation already done** (do NOT redo): kernel-computable SHA-256
  (`Spec/Sha256Impl.lean`), `verifyRefined_eq_spec` (the Yul↔spec verifier
  refinement), `grindR` / `forsSecret` / `findCount` (the real grinding +
  FORS-secret derivations in `Signer.lean`), and the `serialise/deserialise`
  round-trip (`Bytes.lean`). The VERIFY side is complete:
  `Hypertree.verifyAuthPath` / `verifyHypertree` / `verify` all reconstruct
  roots from auth paths.

## Blocker — complete the reference signer (`Spec/Signer.lean::sign`)

`sign` computes `grindR` and the FORS *secrets* honestly, but emits **placeholder
zero arrays** for everything the verifier reconstructs a root from. Concretely,
the three placeholders to replace:

1. `forsAuthPaths : Array (Array (ByteVec 16))` — currently
   `Array.ofFn (n := K-1) fun _ => Array.replicate A (zero 16)`. Must become the
   real **FORS Merkle auth paths**: the `A` sibling nodes on the path from each
   FORS leaf to its tree root, under `sk_seed`. **Requires a `treehash`
   function** (the signing-side Merkle tree build) — which does not yet exist in
   the spec (only the verify-side `verifyAuthPath` does). Add
   `Spec` `treehash`/`forsTreehash` producing `(root, authPath)`.
2. `layerSig.wots.chains : Array (ByteVec 16)` — currently
   `Array.replicate L (zero 16)`. Must become the real **WOTS+ chains**: for each
   of the `L` WOTS+ digits of the layer message, the chain value at the digit
   height. Plus the WOTS+C `count` (currently `0`) from `findCount` (already
   present).
3. `layerSig.authPath : Array (ByteVec 16)` — currently
   `Array.replicate SubtreeH (zero 16)`, replicated across `D` layers. Must
   become the real **hypertree subtree auth paths** (same `treehash`, over the
   WOTS+ public keys of each subtree).

Plus the **D=2 hypertree assembly**: layer 0 signs the FORS root; layer 1 signs
layer 0's subtree root; the final layer-1 root must equal `sk.pkRoot`. The
per-layer messages are currently not wired (the same `layerSig` is replicated).

## The four round-trip sub-lemmas (named in `OPEN_PROOF_OBLIGATIONS.md`, not yet
stated)

Once the signer is real, state + prove (suggested attack order):

1. **`merkle_roundtrip`** (foundational; signer-independent ONCE `treehash` is a
   pure function): `verifyAuthPath seed adrs leaf idx (treehash …).authPath =
   (treehash …).root`. Pure induction over tree height on the opaque `th_pair`.
   Everything else reuses this.
2. **`wots_chain_roundtrip`**: a WOTS+ chain advanced from a signature digit to
   the top equals the WOTS+ public-key element — chain-composition algebra over
   the opaque `th` (`chain^(w-1-d) ∘ chain^d = chain^(w-1)`).
3. **`fors_roundtrip`**: each of the `K` FORS trees round-trips its leaf to its
   root (per-tree `merkle_roundtrip`), then the `K` roots compress to the FORS
   public key — `fors_roundtrip` = `K ×` `merkle_roundtrip` + the root
   compression.
4. **`chainHash_compose`**: the D=2 hypertree composition — layer 0's
   reconstructed root feeds layer 1's leaf, and layer 1's reconstructed root is
   `pkRoot`. Uses `wots_chain_roundtrip` (each layer's WOTS+ pk) +
   `merkle_roundtrip` (each subtree).

**Assembly**: `consistent sk` then follows — `sign sk m = some sig` exposes the
honestly-constructed `(r, fors, layers)`; `verify` recomputes the same digest
(the `r`/`digest` agreement is the `grindR` postcondition) and each component
round-trips by (1)–(4), so `verify … = true`.

## Why no partial Lean lands now

- The main `SphincsCVerify` project gates on **no `sorry`/`sorryAx`**
  (`verify-audit`), so scaffold placeholders are not committable.
- `merkle_roundtrip` — the one signer-independent sub-lemma — needs a `treehash`
  to state (there is no honestly-built auth path to round-trip against; the
  verify-side `verifyAuthPath` alone has nothing to round-trip *with*). So even
  the foundational lemma is gated on the first chunk of signer completion.

Therefore the next actionable Lean step is **(a)** add a pure `treehash`
(returning `(root, authPath)`) to the spec, **(b)** prove `merkle_roundtrip`
against it, **(c)** wire `treehash` into `sign`'s FORS/HT auth paths, then
proceed through (2)–(4). Step (a)+(b) is the smallest self-contained increment
and the right place to start.
