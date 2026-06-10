# SPHINCS+C10 — Spec-Conformance Checklist & ADRS Position-Binding Review

> **Status:** Part A is a standing code-review gate. Part B is the
> 2026-06-08 application of it that closes work-todo §18b ③
> ("FIPS-205 / RFC-9814 ADRS spec-conformance review"), spawned by the
> "would the FI sweep have caught the FORS forgery?" analysis (wf_9bc70be8).

This document exists because the `fcee705a` shared-FORS-forest forgery
(CWE-347, [`docs/work-todo.md` §18b], the few-time FORS key reused as a
many-time key) was a **structural** flaw that a *desk read* of the address
construction would have caught in minutes, yet it shipped and survived an FI
sweep (which is blind to multi-signature cryptographic-design bugs). The fix
itself shipped with **zero** regression tests. Part A turns "read the ADRS
construction" into a repeatable gate; Part B records the read.

The companion machine-checks live in:

- `sphincs-c10/tests/fors_position_binding.rs` — fast property test: every
  FORS secret / root / `fors_pk` is unique per hypertree position (②).
- `sphincs-c10/tests/fors_forgery_resistance.rs` — the end-to-end
  forest-reassembly forgery simulator the fix never shipped (①).

Run both with `--features sim-internals` (see each file's header).

---

## Part A — New-crypto-primitive spec-conformance checklist (code-review gate)

Apply this checklist to **any** change that touches a hash-based-signature
primitive — `sphincs-c10/src/**`, `contracts/smart-wallet/src/verifiers/
SPHINCsC10Asm.sol`, or a new `*-c*` parameter set — **before** merge. It is
deliberately structural (read the code, no toolchain needed); the formal
discharge (Lean / Halmos / Certora, work-todo §18b ④) is the second line of
defence, not the first.

### A.1 ADRS field binding (the class that bit us)

For **every** tweakable-hash call site, confirm the ADRS carries the full
position of the node it addresses. The FIPS-205 ADRS principle: a key/leaf
is addressed by **where it sits in the whole structure**, not just its local
index. A few-time or one-time key that is addressed by a *local* index only
is reused at every *global* position → forgeable.

- [ ] **FORS leaves & internal nodes** carry the **hypertree leaf index
      `ht_idx`** in the ADRS *tree* field (bits 160..223 / `make_adrs` arg
      2). A FORS ADRS with the tree field `= 0` (or any per-key constant) is
      the exact `fcee705a` bug.
- [ ] **FORS roots compression** (`ADRS_FORS_ROOTS`) carries `ht_idx` too —
      otherwise `fors_pk` is position-independent and one observed hypertree
      signature over it is replayable everywhere.
- [ ] **The FORS secret PRF** folds `ht_idx` (`fors_secret(sk, ht_idx, tree,
      leaf)`), so the *secret* — not just the address — is per-position.
      Both layers are required: ADRS-only binding still lets a signer that
      forgot the PRF bind leak a reusable secret; PRF-only binding still lets
      the verifier accept a cross-position splice.
- [ ] **WOTS+ / Merkle (hypertree) ADRS** carry `(layer, subtree_index)` —
      i.e. the **hypertree** `tree` index `idx_tree`, NOT the FORS `ht_idx`
      leaf. (These were never the shared-forest bug; WOTS keys are inherently
      per-position. Flag any FORS↔HT field confusion either direction.)
- [ ] **The ADRS *type* word** is correct at each site (`ADRS_WOTS=0`,
      `ADRS_WOTS_PK=1`, `ADRS_TREE=2`, `ADRS_FORS_TREE=3`,
      `ADRS_FORS_ROOTS=4`).
- [ ] **The chain-position / height field** (`make_adrs` arg 6, ADRS bytes
      [24..28)) advances correctly along WOTS chains and up Merkle levels.

### A.2 Signer ↔ verifier ↔ on-chain byte-for-byte agreement

- [ ] Every ADRS-construction change in `sphincs-c10/src/{fors,hypertree,
      wots,merkle}.rs` is mirrored **identically** in
      `SPHINCsC10Asm.sol` (the Yul `or(shl(160, htIdx), …)` words) **and**
      the host reference signer. A binding added on one side and missed on
      the other is a silent divergence: signatures verify in tests (same
      impl both ways) but fail on-chain, or worse, a verifier laxer than the
      signer accepts forgeries.
- [ ] `c10_test_vectors.json` is regenerated and the on-chain verifier
      **codehash is re-pinned** (`SPHINCsC10Asm.t.sol`,
      `PinnedCodehashes.t.sol`) — a changed verifier with a stale pinned hash
      means the deployed bytecode and the audited bytecode differ.
- [ ] `cargo test -p sphincs-c10` (incl. `--features sim-internals` for the
      forgery + position-binding guards) **and** `forge test` (all KAT
      vectors + pinned-codehash tests) pass.

### A.3 Few-time-key discipline (FORS / WOTS reuse bounds)

- [ ] The change does not increase how many signatures share a FORS forest
      or a WOTS key beyond the parameter set's design (C10: independent
      forest **per hypertree position**, on-chain caps
      `MAX_BOOTSTRAP_USES = MAX_SLOT_USES = 65,536` keeping forgery work
      ≥ 2^128 — see `fcee705a` and `docs/threat-model.md`).
- [ ] R-grinding / forced-zero-index logic is unchanged in a way that would
      bias index selection (a biased digest concentrates reuse).

### A.4 Wire-format & address stability

- [ ] Signature length stays 4008 B and the byte layout (R ‖ K secrets ‖
      K-1 auth paths ‖ D HT layers) is unchanged, or `params.rs` const
      assertions + `tests/wire_format_stability.rs` are updated deliberately.
- [ ] `pk_root` (hence the CREATE2 wallet address, invariant #6) is
      unaffected — it derives from `(sk_seed, pk_seed)` via WOTS only, never
      from FORS. **Any** change that makes `pk_root` FORS-dependent is a
      launch-blocking regression.

### A.5 Regression coverage (the gap `fcee705a` left)

- [ ] A **position-dependence** assertion exists for any newly-introduced
      ADRS field binding (mirror `tests/fors_position_binding.rs`). "Each
      position signs once and verifies" is **not** sufficient — it passes on
      the vulnerable code. Assert that material from one position does **not**
      verify at another.
- [ ] For a new few-time primitive, an **end-to-end multi-signature forgery
      simulator** exists (mirror `tests/fors_forgery_resistance.rs`): harvest
      → reassemble → forge → expect `verify == false`. The FI sweep does not
      cover this class; nothing else will.
- [ ] The Lean spec (`contracts/verification/lean/SphincsCVerify/Spec/`) and
      the Halmos/Certora discharge (`AXIOM_STATUS.json`) are re-synced or the
      gap is tracked (work-todo §18b ④).

---

## Part B — 2026-06-08 ADRS position-binding review (the `fcee705a` fix)

**Scope.** Audit that every FORS ADRS in the C10 signer and the on-chain Yul
verifier carries the hypertree leaf index `ht_idx`, per checklist A.1/A.2.
This is the line-by-line read that would have caught the original bug.

**Verdict: CONFORMANT.** All 9 FORS ADRS construction sites in Rust and all
4 FORS ADRS words in the Yul verifier carry `ht_idx` in the tree field; the
FORS secret PRF folds `ht_idx`; the WOTS/Merkle sites correctly use the
hypertree subtree index and were never the shared-forest surface; `pk_root`
and the 4008-B wire format are unchanged. The fix is signer↔verifier
byte-consistent.

### B.1 ADRS layout (reference)

`address.rs::make_adrs(layer, tree, atype, kp, ci, cp, ha)` packs a 32-byte
word (big-endian):

| Field | Bits | Bytes | `make_adrs` arg | Yul shift |
|-------|------|-------|-----------------|-----------|
| layer | 255..224 | [0..4) | `layer` | `shl(224, …)` |
| **tree** | 223..160 | [4..12) | `tree` ← **`ht_idx`** for FORS | `shl(160, …)` |
| address_type | 159..128 | [12..16) | `atype` | `shl(128, …)` |
| keypair | 127..96 | [16..20) | `kp` | `shl(96, …)` |
| chain_index | 95..64 | [20..24) | `ci` | `shl(64, …)` |
| chain_pos / height | 63..32 | [24..28) | `cp` | `shl(32, …)` |
| hash_address | 31..0 | [28..32) | `ha` | (low bits) |

The position-binding fix lives entirely in the **tree** field for FORS sites.

### B.2 Rust signer — FORS ADRS sites (`sphincs-c10/src/`)

All carry `u64::from(ht_idx)` as the `tree` argument:

| # | Site | `make_adrs(...)` | Purpose |
|---|------|------------------|---------|
| 1 | `fors.rs:128` | `(0, ht_idx, FORS_TREE, tree_idx, 0, 0, j)` | `compute_fors_root` leaf |
| 2 | `fors.rs:137` | `(0, ht_idx, FORS_TREE, tree_idx, 0, node_h+1, parent_idx)` | `compute_fors_root` node |
| 3 | `fors.rs:187` | `(0, ht_idx, FORS_TREE, tree_idx, 0, 0, j)` | `sign_fors_tree` leaf |
| 4 | `fors.rs:195` | `(0, ht_idx, FORS_TREE, tree_idx, 0, node_h+1, parent_idx)` | `sign_fors_tree` node |
| 5 | `fors.rs:243` | `(0, ht_idx, FORS_ROOTS, 0, 0, 0, 0)` | `compute_fors_pk` roots compression |
| 6 | `hypertree.rs:151` | `(0, ht_idx, FORS_TREE, K-1, 0, 0, 0)` | sign last (forced-zero) tree leaf |
| 7 | `hypertree.rs:317` | `(0, ht_idx, FORS_TREE, K-1, 0, 0, 0)` | verify last (forced-zero) tree leaf |
| 8 | `hypertree.rs:391` | `(0, ht_idx, FORS_TREE, tree_idx, 0, 0, leaf_idx)` | `reconstruct_fors_root` leaf |
| 9 | `hypertree.rs:397` | `(0, ht_idx, FORS_TREE, tree_idx, 0, h+1, parent_idx)` | `reconstruct_fors_root` node |

PRF (`hash.rs:380`): `fors_secret(sk_seed, ht_idx, tree_idx, leaf_idx)` folds
`ht_idx` into the SHA-256 preimage (`sk_seed ‖ "fors" ‖ ht_idx ‖ tree_idx ‖
leaf_idx`). ✔ A.1 secret-layer binding.

### B.3 Yul verifier — FORS ADRS words (`SPHINCsC10Asm.sol`)

`htIdx := and(shr(143, digest), 0x3FFFF)` (line 81), then:

| Site | Yul | Maps to Rust |
|------|-----|--------------|
| `:97` `leafAdrs` | `or(shl(160, htIdx), or(shl(128, 3), or(shl(96, i), treeIdx)))` | #1/#3/#8 (FORS leaf, type 3, kp=tree number `i`, ha=leaf idx) |
| `:103` `treeAdrsBase` (+`:112`) | `or(shl(160, htIdx), or(shl(128, 3), shl(96, i)))` then `or(…, or(shl(32, h+1), parentIdx))` | #2/#4/#9 (FORS internal node) |
| `:127` last tree | `or(shl(160, htIdx), or(shl(128, 3), shl(96, 12)))` | #6/#7 (forced-zero tree) |
| `:137` `rootsAdrs` | `or(shl(160, htIdx), shl(128, 4))` | #5 (roots compression, type 4) |

✔ A.2 byte-for-byte: the four Yul words mirror the nine Rust sites
one-to-one. (`i` in the Yul is the FORS tree number 0..12, mapped to
`make_adrs` `kp`; `treeIdx` is the digest-derived 11-bit leaf index, mapped
to `ha` — the naming differs from Rust but the field placement is identical.)

### B.4 Non-FORS (WOTS / hypertree-Merkle) ADRS — correctly NOT `ht_idx`-bound

`wots.rs` / `merkle.rs` build ADRS with `(layer, tree=idx_tree, …)` where
`idx_tree` is the **hypertree subtree index** for that layer (`hypertree.rs`
derives `idx_leaf = idx_tree & 0x1FF; idx_tree >>= 9` per D=2 layer; Yul
lines 153/194/204 mirror this with `shl(160, idxTree)`). These were never the
shared-forest surface — each WOTS key is inherently bound to its hypertree
position via `(layer, idx_tree, idx_leaf)`. Flagging here only to record that
the audit checked them and they are **correctly** distinct from the FORS
`ht_idx` binding (checklist A.1 last box). ✔

### B.5 Stability invariants

- `pk_root` derives from `(sk_seed, pk_seed)` via WOTS+Merkle only
  (`hypertree.rs::compute_pk_root` → `merkle::compute_subtree_root`), never
  from FORS → CREATE2 wallet addresses unchanged (invariant #6). ✔ A.4
- Signature stays 4008 B; `params.rs` const-asserts `SIG_FORS_TOTAL == 2336`,
  `SIGNATURE_LEN == 4008`. ✔ A.4
- `fcee705a` re-pinned the verifier codehash `0x919c… → 0xf1ef…` in
  `SPHINCsC10Asm.t.sol` + `PinnedCodehashes.t.sol`. ✔ A.2 (re-verify under
  `forge test` when the toolchain is available — see §18b ④; `forge` was
  absent in the 2026-06-08 dev env).

### B.6 Residual gaps (tracked, not closed by this review)

- **Formal layer (A.5 / §18b ④):** the Lean `Spec/Fors.lean` does not yet
  require `ht_idx` binding in `reconstructRoot`/`computeForsPk`, and the
  Halmos/Certora discharge against codehash `0xf1ef…` is `pending-rerun`
  (`AXIOM_STATUS.json` A3.1–A3.4). Toolchains (Lean/Halmos/Certora) and
  `forge` were unavailable in the dev environment when this review was
  written. The structural read above is the first line of defence; the
  mechanical discharge is the second and remains open.
