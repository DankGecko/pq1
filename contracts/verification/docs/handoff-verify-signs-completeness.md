# Handoff — `verify_signs` completeness — **CLOSED 2026-06-29**

**RESOLVED.** `honest_consistent : WellFormed sk → consistent sk` is proven kernel-clean in `SphincsCVerify/Verifier/HonestConsistent.lean` (closure `[propext, Classical.choice, Quot.sound]`, wired into the root, no sorry). All three increments done: (1) grind postconditions (`Spec/SignerPost.lean`), (2) reference signer completion (`Spec/Signer.lean` + `Spec/Treehash.lean`), (3) the `WellFormed`/`honest_consistent` assembly. `consistent`/`verify_signs` were NOT weakened; `honest_consistent` is the new top-level theorem supplying the honestly-keygen content `verify_signs` consumes. The historical plan below is retained for reference.


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

**Sub-lemma 3 of 4 — `fors_roundtrip` — DONE** (`SphincsCVerify/Verifier/ForsRoundtrip.lean`): FORS tree round-trip (`forsMtNode`/`forsMtAuthPath` + `forsAcc_climbs`), mirrors merkle_roundtrip; closure `[propext, Classical.choice, Quot.sound]`. **Sub-lemma 4 part 1/2 — `wots_pk_roundtrip` — DONE** (appended to `WotsRoundtrip.lean`): honest WOTS sig (each chain `chainHash secret 0 dᵢ`) ⇒ `Wots.pkFromSig = some (Wots.keygenPk)`, via per-chain `wots_chain_roundtrip` + `List.map_congr_left`; closure `[propext, Quot.sound]`. **Sub-lemma 4 part 2/2 — `hypertree_roundtrip` — DONE** (`Verifier/HypertreeRoundtrip.lean`): `vhLayer_roundtrip` (one honest layer = subtree root, via `vhStep_some` + `merkle_roundtrip`) + `hypertree_roundtrip` (full D=2 via `verifyHypertree_unroll` + two `vhLayer_roundtrip`). Closure `[propext, Classical.choice, Quot.sound]`.

## ALL FOUR ROUND-TRIP SUB-LEMMAS DONE (2026-06-29)

merkle_roundtrip, wots_chain_roundtrip + wots_pk_roundtrip, fors_roundtrip (per-tree), hypertree_roundtrip — all kernel-clean, on master, wired into the SphincsCVerify root, no sorry. Remaining to close `consistent sk`:
1. **FORS-pk aggregate — `fors_pk_roundtrip` — DONE** (`Verifier/ForsRoundtrip.lean`): honest FORS+C sig ⇒ `reconstructForsPk seed digest sig = some (computeForsPk … (honest roots))`, via per-tree `fors_roundtrip` + `Array.ofFn` congruence; closure `[propext, Classical.choice, Quot.sound]`. **The full verifier-side round-trip layer is now proven** — every verifier reconstruction (merkle/wots-pk/fors-pk/hypertree) has its honest round-trip lemma.
2. **Signer completion** — replace `Spec/Signer.lean::sign`'s zero-array placeholders with the real `mtNode`/`mtAuthPath` (FORS + hypertree subtree auth paths) + WOTS chains + the D=2 layer messages, so the honest-layer/honest-fors hypotheses of the sub-lemmas are *what `sign` actually emits*.
3. **`verify` decomposition + assembly** — `verifyWithDigest` → forced-zero gate (grindR ensures last FORS index 0) → `reconstructForsPk` (piece 1) → `verifyHypertree` (`hypertree_roundtrip`) → compare to pkRoot; the digest agreement is `grindR`'s postcondition. Compose into `consistent sk`, discharging `verify_signs`.

## TRACTABILITY AUDIT (2026-06-29) — the phase IS provable; here is the exact plan

Audited `Spec/Signer.lean` + `Spec/Theorems.lean` before the signer rebuild (the
one constraint that decides whether `consistent` is even *statable*):

- **`grindR` and `findCount` are TOTAL, not `partial`.** Both are `def … termination_by limit - …` + `decreasing_by` (the loop is bounded by the `limit` parameter; returns `none` past it). So `sign sk m = some sig` carries full kernel-usable information — the worst-case "opaque partial grind ⇒ unprovable" blocker does NOT apply. `sign` is `noncomputable` (fine for proofs, ≠ partial).
- **`consistent sk` is FALSE for an arbitrary `sk`** (its docstring concedes this — it needs `pkRoot = the hypertree top root`). So do **NOT** try to prove `consistent sk` unconditionally, and do **NOT** weaken `consistent`'s definition or `verify_signs`. Instead prove a **new** theorem `honest_consistent : WellFormed sk → consistent sk`, where `WellFormed sk` packages: `sk.pkRoot = the honest hypertree top root built from (sk.skSeed, sk.pkSeed)` (the keygen-consistency the Rust `SigningKey::keygen` enforces). `verify_signs` stays as-is (it already takes `consistent sk` as a hypothesis).

### Remaining increments (each committable, in usual style)

1. **Grind postcondition lemmas — DONE** (`Spec/SignerPost.lean`): `grindR_post` (forced-zero + digest agreement), `findCount_post` (target-sum + wotsDigest shape), `extractForsIndices_getD` (index = A-bit window). Each a one-line `fun_induction` over the bounded `let rec loop`; closure `[propext, Quot.sound]` (the grinds). Originally scoped as (clean loop inductions over the bounded `let rec loop`; foundation for the assembly):
   - `grindR … = some (r, digest) → readBitsLe digest ((K-1)*A) A = 0` — the forced-zero `hzero` (gated by Signer.lean:112).
   - `grindR … = some (r, digest) → digest = hMsg (pad16 pkSeed) (pad16 pkRoot) (pad16 r) message` — the **digest agreement** (so `verify`'s recomputed digest = `sign`'s); `verify` recomputes `hMsg … (pad16 sig.r) message` and `sig.r = r`.
   - `findCount … = some (count, d) → digitSum (extractDigits d) = TargetSum ∧ d = wotsDigest seed (Adrs.wots …) msgHash count` — the `hsum` + the `hdig` for `wots_pk_roundtrip` (gated by Signer.lean:74).
   - (`let rec loop` ⇒ access via the generated `grindR.loop`/`findCount.loop` aux + its `.eq`/induction; or restate with an explicit fuel `Nat.rec`.)
2. **Signer completion** (the bulk; invasive — edits `sign`). Replace the three zero-array placeholders so the round-trip hypotheses hold **by construction** (advisor: define `sign` to emit `forsMtAuthPath`/`keygenPk`-chains/`mtAuthPath` *directly*, so `hsec`/`hpath`/`hchains`/`hwots` are `rfl`):
   - **Entry-point refactor (do FIRST, 2026-06-29 finding).** The honest tree defs `sibIdx`/`mtNode`/`mtAuthPath` (`Verifier/MerkleRoundtrip.lean`) + `forsMtNode`/`forsMtAuthPath` (`Verifier/ForsRoundtrip.lean`) are *pure Spec* (need only `th`/`thPair`/`Adrs`) but currently live in `Verifier/` files that `import Interpreter.HypertreePhase` (the whole interpreter). `sign` (in `Spec/Signer.lean`) cannot reference them there. **Nothing imports `Spec.Signer`, so there is no cycle** — move the five defs (+ `sibIdx`) into a new `Spec/Treehash.lean` (namespace `SphincsCVerify.Spec`); the Verifier round-trip lemmas keep building via `open Spec` (defs are identical, only the full name changes), and `sign` then `import`s `Spec.Treehash`. (`keygenPk`/`chainHash` are already in `Spec.Wots`, which `Signer` imports — the WOTS leaves need no move.) This unblocks emitting the honest structures from `sign`.
   - Then, with the defs accessible:
   - `forsAuthPaths[t] := forsMtAuthPath (pad16 pkSeed) htIdx (ofNat t) (fun j => forsSecret skSeed (ofNat t) (ofNat j)) (forsIndices.getD t 0)`.
   - the D=2 `layers` must be **per-layer** (not `Array.replicate D layerSig`): layer 0 WOTS-signs `forsPk`, layer 1 WOTS-signs layer 0's subtree root — the cross-layer message threading is the real signing logic (needs the honest subtree treehash to compute layer 0's root before layer 1's WOTS digits). Each layer's `wots.chains[i] := chainHash … (wotsSecret …) 0 digit_i` and `authPath := mtAuthPath …` over the `keygenPk` leaves.
3. **`WellFormed` + `honest_consistent` assembly** — the capstone (increment 2 DONE 2026-06-29: `sign` now emits the honest structures; this is what remains).

   **Key structural fact (verified 2026-06-29).** The top layer's tree index is ALWAYS 0, so the top root is message-independent (= `pkRoot`): `extractHtIndex digest = readBitsLe digest (K*A) H < 2^H` and `H = D*SubtreeH = 18 = 2*SubtreeH`, so `idxTree1 = (htIdx >>> SubtreeH) >>> SubtreeH = htIdx >>> 18 = 0`. Prove this as a lemma (`readBitsLe_lt` + `Nat.shiftRight` arithmetic).

   **`WellFormed sk`** := `sk.pkRoot = mtNode (pad16 sk.pkSeed) (UInt32.ofNat 1) (UInt64.ofNat 0) (fun kp => Wots.keygenPk (pad16 sk.pkSeed) sk.skSeed (UInt32.ofNat 1) (UInt64.ofNat 0) (UInt32.ofNat kp)) SubtreeH 0` — the fixed top-tree (layer 1, tree 0) root.

   **`honest_consistent : WellFormed sk → consistent sk`** proof:
   - `intro hwf m sig hsign`. Destructure `sign`'s three nested matches in `hsign` (`grindR`/`findCount` layer 0/`findCount` layer 1) — any `none` ⇒ `none = some sig` absurd; all `some` ⇒ `sig = {honest r, fors, layers}` (the explicit struct; `split`/`simp only` + `Option.some.injEq`).
   - Unfold `verify`/`verifyWithDigest` on the honest `sig`. **Digest agreement** `digest = hMsg (pad16 pkSeed) (pad16 pkRoot) (pad16 r) m` ⇒ `verify`'s recomputed digest = `sign`'s `digest` (`grindR_post`, with `sig.r = r`).
   - **Forced-zero gate**: `(extractForsIndices digest).getD (K-1) 0 = readBitsLe digest ((K-1)*A) A = 0` (`extractForsIndices_getD` + `grindR_post`) ⇒ `if_neg`, proceed.
   - **`reconstructForsPk = some forsPk`** (`fors_pk_roundtrip`): `hzero` (above), `hbound` (`extractForsIndices_getD` + `readBitsLe_lt`), `hsec`/`hpath` hold **by construction** (`sign`'s `forsSecrets`/`forsAuthPaths` are the matching `Array.ofFn`/`forsMtAuthPath`). The resulting `forsPk` is exactly `sign`'s `forsPk` (both `computeForsPk` over the same honest roots).
   - **`verifyHypertree seed forsPk htIdx layers = some root1`** (`hypertree_roundtrip`): `hwots0`/`hwots1` via `wots_pk_roundtrip` (`hsum`/`hdig` from `findCount_post`; `hchains` by construction — `sign`'s `chains` are the matching `chainHash` `Array.ofFn`; `hbound` from `readBitsLe_lt`); `hpath0`/`hpath1` by construction (`mtAuthPath`); `hidx0`/`hidx1` from `readBitsLe_lt` (idxLeaf < 2^SubtreeH). NB layer 1's message is `root0` = `sign`'s `root0` = `mtNode …` (cross-layer threading lines up by construction).
   - `root1 = mtNode … (ofNat idxTree1) … = mtNode … (ofNat 0) …` (idxTree1=0 fact) `= pkRoot` (`WellFormed`). Final `decide (root1 = pkRoot) = decide (pkRoot = pkRoot) = true`.

   Do NOT weaken `consistent`/`verify_signs`. `honest_consistent` is the new top-level theorem; `verify_signs` already consumes `consistent sk` as a hypothesis, so a downstream `verify_signs_of_wellformed` can chain them if desired.

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
