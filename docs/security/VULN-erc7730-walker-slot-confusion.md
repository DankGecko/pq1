# VULN — ERC-7730 Phase-4 walker slot-confusion (clear-signing bypass)

**Status:** RESOLVED 2026-06-10 — fixed at the source (dbgen now emits ABI
head-word slots, not logical ordinals) and structurally fenced so the class
cannot silently recur (schema-version gate + dbgen refusal-to-emit + on-device
head-bound guard). See **Resolution** below.
**Class:** Trusted-display divergence — device shows one value, signs another
**Severity:** High → Critical (ship-blocker for any descriptor with a
multi-word static field). No fault injection, no warning banner.
**Found:** 2026-06-10

## Resolution (2026-06-10)

Four independent closures land together; the on-chain verifier, `pk_root`, and
CREATE2 addresses are unaffected (this is firmware + host-pipeline only). The
`ERC7730_DESCRIPTORS_ROOT` (prod + e2e) was regenerated — its preimage changed.

1. **Source fix — head-word slots (closes the bug).**
   `dbgen::erc7730::compile_structured_contract_path` (new) compiles a
   contract-calldata `#.<field>[.<member>]` path into `FieldIdx` ops whose
   **summed** args equal the field's true ABI **head-word** offset, using a new
   recursive `static_head_words` ABI-width helper (`T[N]` = N words, static
   tuple = Σ members, dynamic = one offset word). The on-device walker is
   unchanged — its existing sum is now correct by construction. `ParsedFormatKey`
   gained `top_types` / `inner_types` to carry the widths.
   *Context-aware:* EIP-712 (`encodeData` — every member one word) and `@`/`$`
   roots keep the prior ordinal / keccak-discriminator encoding; only the `#`
   contract-calldata root uses ABI widths. The Uniswap nested tuple and every
   existing single-word descriptor compile to byte-identical slots (verified).

2. **dbgen refuses to emit a hazardous descriptor (build-time).**
   `compile_structured_contract_path` hard-errors — so a hazardous descriptor
   can never be pinned — on: array index/slice (dynamic-tail op), descent into a
   dynamic tuple, a terminal field that is dynamic or multi-word static (the
   renderer reads one 32-byte word), or a name absent from the signature. The
   keccak-prefix fallback is retained ONLY for `@`/`$` envelope discriminators,
   where it is the intended encoding.

3. **Schema-version gate (structural).** IR `SCHEMA_VER` bumped `0x01 → 0x02`
   because calldata `FieldIdx` args changed meaning. `Erc7730Ir::parse`
   strict-rejects any other version, so a descriptor compiled under the old,
   slot-confusable encoding can never be walked by this firmware.

4. **On-device head-bound guard (defence-in-depth).** Each format header now
   carries `static_head_words`; the renderer (`head_bounded_body` in
   `secure/src/tx/display/erc7730/mod.rs`) truncates the body to the static head
   before walking, so any slot reaching past it (a malformed descriptor reading
   into the dynamic tail) fails the walker's bounds check and is rejected rather
   than silently rendered.

**Tests.** `secure/.../formatters.rs` proof module flipped to
`walker_slot_confusion_fixed` (walker reads the EVM-decoded word; head-bound
guard rejects out-of-head / short-head). dbgen unit tests pin golden head-slot
values for the multi-word-array, non-leading-tuple, nested-tuple,
dynamic-predecessor, EIP-712-ordinal and `@`-discriminator cases, and assert the
array-index / unknown-name / dynamic-target / multi-word-target refusals. Seed
corpus recompiles + round-trips; `gen-erc7730-descriptors --check` is in sync.

The remainder of this document is the original report, preserved for the record.

---

## Summary

The on-device ERC-7730 calldata path walker
(`secure/src/tx/display/erc7730/formatters.rs::resolve_path`, the
`RootStructured` arm) computes the head-word slot of a referenced field
by **summing the logical `FieldIdx` values** in the path program and
multiplying by 32:

```rust
// formatters.rs (RootStructured arm)
PathOp::FieldIdx => {
    let idx = u16::from_be_bytes([prog[p], prog[p + 1]]) as usize;
    p += 2;
    slot = slot.checked_add(idx)...;          // <-- SUM of logical indices
}
...
let start = slot.checked_mul(32)?;            // <-- assumes 1 word per field
let word = body.get(start..start + 32)?;
```

This is correct **only if every preceding field occupies exactly one
32-byte word.** The EVM ABI lays out a *fixed-size array* `T[N]` as `N`
consecutive head words and a *static tuple* as the sum of its members'
widths. The walker counts each top-level field as a single word, so as
soon as a referenced field is preceded by any multi-word static field,
the walker reads a **different head word than the EVM decodes** — and the
trusted UI renders that word as the field's value while the contract
executes on the real one.

The host compiler confirms the encoding is a *logical* ordinal, not a
head-slot:

```rust
// dbgen/src/erc7730.rs::resolve_field_index  (line ~1820)
if let Some(pos) = names.iter().position(|n| n == name) {
    return u16::try_from(pos) ...;   // ordinal position, NO width adjustment
}
// compile_path (~line 1779): pushes that ordinal verbatim as FieldIdx arg
out.push(PATHOP_FIELD_IDX);
out.extend_from_slice(&idx.to_be_bytes());
```

There is **no on-device check** that the calldata length matches the
descriptor's ABI head, and **no dbgen guard** rejecting descriptors with
multi-word static fields. The descriptor itself is Merkle-verified and
contract-bound, so it carries no warning banner — the user sees a fully
"trusted" clear-sign screen.

## Exploit (worked example)

Target a descriptor for a function shaped like:

```solidity
function f(uint256[3] arr, address to)
```

ABI head (post-selector), one word each: `word0=arr[0]`, `word1=arr[1]`,
`word2=arr[2]`, `word3=to`.

The descriptor labels field `to` (logical top-level index **1**). dbgen
emits `RootStructured, FieldIdx(1)`. The walker computes `slot = 1` and
reads **word 1 = arr[1]**.

Attacker crafts calldata:
- `arr[1]` (word 1) = a benign-looking address `0xBEEF…` (or the user's
  own address) — **this is what the OLED displays as "Recipient".**
- `to` (word 3) = the attacker address `0xAD…` — **this is where the
  contract actually sends/approves.**

The user confirms a screen showing the benign recipient; the signed
UserOp (`executeWithOffchainCount(…, data = this calldata)`) commits to
calldata whose word 3 routes value to the attacker. Display ≠ signed,
with no warning. The same trick works for any `amount`/`tokenAmount`
field preceded by a multi-word field, satisfying the canonical
"shows 0.2 USDC, signs the whole balance" goal.

The identical defect applies to a *static tuple* at a non-leading
position, e.g. `g((uint256 x, uint256 y) s, address to)`: `to` is logical
index 1 but EVM head word 2; the walker reads `s.y`.

## Proof

Runnable test in
`secure/src/tx/display/erc7730/formatters.rs` (mod
`walker_slot_confusion_proof`):

- `walker_reads_arr1_when_evm_uses_to` — asserts the walker resolves `to`
  to word 1 (attacker-chosen benign value) while the EVM-correct `to`
  lives in word 3.
- `single_word_predecessor_is_correct_by_luck` — control: with only
  single-word predecessors the summing walker is accidentally correct,
  which is exactly why the bug is currently masked.

```
cargo test -p sphincs-tz-secure --tests walker_slot_confusion_proof
# 2 passed
```

## Reachability

**Not exploitable against today's pinned firmware.** All eight
calldata-context descriptors in `secure/data/erc7730/` use only
single-word top-level fields; the one static tuple (Uniswap
`exactInputSingle`) is parameter 0 with single-word members, so the sum
is fortuitously correct. EIP-712 descriptors (OpenSea wyvern, Circle
`*WithAuthorization`) are safe because every EIP-712 member is exactly
one word in `encodeData`.

Because the descriptor set is Merkle-pinned, an attacker cannot *add* a
problematic descriptor. **But** dbgen accepts one without complaint, and
nothing on-device rejects it — so the first time a normal descriptor with
a fixed-size array or non-leading static tuple is curated into the root
(e.g. Uniswap `exactInput` multihop, any `*BatchTransfer`, Seaport
calldata structs), the firmware silently ships a no-warning clear-signing
forgery. This is a latent structural defect, not a safe design.

## Fix options

1. **Emit head-word slots, not logical ordinals.** Make
   `dbgen::resolve_field_index` (and tuple descent) accumulate the
   cumulative 32-byte head offset using each field's ABI width, so the
   on-wire `FieldIdx` arg *is* the head slot. The device walker then
   reads the right word with no change. Requires dbgen to know each
   field's static width (it parses the format key already).
2. **Carry ABI widths on-wire** and have the walker advance by width
   rather than by 1, and **reject any path that descends through a
   dynamic type** (already partially done — array ops are rejected).
3. **Belt-and-braces:** add an on-device check that the calldata body
   length equals the descriptor function's expected static head length,
   and reject descriptors whose fields are not all single-word until (1)
   lands. At minimum, `compile_error!`/curation-time rejection of
   multi-word static fields so dbgen cannot silently ship the hazard.

Pick (1) — it keeps the device walker trivial and closes the class at the
source.
