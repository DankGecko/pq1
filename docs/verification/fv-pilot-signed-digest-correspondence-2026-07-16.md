# FV pilot — actual-signed-digest correspondence (P1.7) — 2026-07-16

> **Scope, first (F9).** This closes the *layout-correspondence + non-vacuity*
> half of review finding **F2** for the digest the firmware actually signs. It is
> **∀-over-layout / on-chain-digest evidence**, **not** ∀-over-hash and **not** the
> Aeneas extraction of `compute_sphincs_digest_v06` (blocked — see "Why not
> extraction"). The `sha2` streaming≡concat and Solidity `abi.encodePacked`
> packing rules stay **named assumptions**, the same tier as the `sha256_pure`
> axiom used elsewhere.

## The gap (F2)

The firmware signs `aa::userop::compute_sphincs_digest_v06` — a **single SHA-256**
over a **360-byte** preimage of 12 fields. The on-chain
`PQSmartWallet.sol::sphincsDigest` recomputes the same digest with SHA-256 over
`abi.encodePacked(...)` of the same 12 fields. F2's defect: the *extracted headline*
machine-checked `compute_user_op_hash` — the EntryPoint double-**keccak** tooling
helper, which has **no production signing caller** — while the digest actually
signed was matched only by hand-inspection between Rust and Solidity.

The 12 fields (Rust `chain_update` order == Solidity `abi.encodePacked` order):

```
sender ‖ nonce ‖ sha256(initCode) ‖ sha256(callData) ‖ callGasLimit ‖
verificationGasLimit ‖ preVerificationGas ‖ maxFeePerGas ‖ maxPriorityFeePerGas ‖
sha256(paymasterAndData) ‖ entryPoint ‖ chainId
```

## What this pilot adds

Three legs, each with a negative control, so the correspondence is machine-checked
rather than eyeballed:

1. **Rust↔Solidity byte-level positive vector** (pre-existing, now load-bearing):
   `PQSmartWalletRealSig.t.sol::test_digestMatches` asserts
   `wallet.sphincsDigest(op) == expectedDigest`, where `expectedDigest` is the
   **Rust-generated** `compute_sphincs_digest_v06` value from `c10_test_vectors.json`.
   This binds the two implementations byte-for-byte on a concrete UserOp.

2. **Per-field non-vacuity** (new — `test/SphincsDigestFieldBinding.t.sol`): the
   single positive vector cannot show the digest *commits to* every field — a
   `sphincsDigest` that ignored `nonce` or `paymasterAndData` would still pass it,
   letting an attacker substitute that field under one signature. This asserts the
   on-chain digest **changes** when any single field is mutated — all 10 op-derived
   fields plus the two context inputs (`_entryPoint` immutable, `block.chainid`).
   Each assertion is itself the negative control: it fails if the digest drops that
   field. (3 tests, all pass.)

3. **Source-level field-order pin** (new —
   `scripts/check_sphincs_digest_field_order.py`, wired into
   `make verify-transcription`, CI-gated via `a31-transcription.yml`): parses the
   Rust `chain_update` sequence and the Solidity `abi.encodePacked` sequence and
   asserts they list the **same 12 fields in the same order**. A vector KAT cannot
   see a *source* reorder that a regenerated vector would also carry (swap two gas
   fields in Rust **and** regen the vectors → every committed vector still matches
   while the structure diverged). The pin catches that pre-vector. `--self-test`
   asserts a max_fee/max_priority swap and a dropped field both fire.

Together these close F2's "connect exact Rust/Solidity layouts + per-field
mutations + freshness" clause.

## Why not the Aeneas extraction (the stronger follow-up)

`compute_user_op_hash` was deliberately written buffer-form (`write_word_right_aligned`
into a `buf`, then one opaque `keccak256(&buf)`) *specifically for the Aeneas
extraction* — that transparency is what lets Lean state a ∀-over-layout theorem.
`compute_sphincs_digest_v06` instead uses the `sha2` **streaming** API
(`Sha256::new().chain_update(a).chain_update(b)…finalize()`). With `sha2` opaque,
Aeneas can only produce opaque `chain_update` calls — the concatenation semantics
stay hidden, so the extracted Lean would **not** be a byte-layout theorem.

The **stronger follow-up** (`actual-signed-digest-correspondence`, extraction
variant) is to refactor `compute_sphincs_digest_v06` to the same buffer-form
(`sha256_bytes(&buf)` over the exact 360-byte concatenation — behaviour-preserving,
since `chain_update(a).chain_update(b) ≡ sha256(a‖b)` is algebraic), then extract
and prove the layout in Lean like `UserOpEquivByteLayout` does for the tooling
helper. That edits a frozen, on-chain-coupled signing function, so it warrants its
own focused change with a golden-digest guard (old streaming form and new buffer
form must both reproduce a pinned digest hex, and the Forge differential must still
match it). Deliberately **not** done in this pass.

## Files

- `contracts/smart-wallet/test/SphincsDigestFieldBinding.t.sol` — per-field non-vacuity (Forge).
- `contracts/smart-wallet/test/PQSmartWalletRealSig.t.sol::test_digestMatches` — Rust↔Solidity byte vector (pre-existing).
- `contracts/verification/scripts/check_sphincs_digest_field_order.py` — source-level Rust↔Solidity field-order pin + self-test.
- Wired into `make -C contracts/verification verify-transcription` (CI-gated).
