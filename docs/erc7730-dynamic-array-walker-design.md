# ERC-7730 dynamic-array walker — design (firewalled from the Enum/pack work)

**Status:** design-only, NOT implemented. This is the security-sensitive
half of the "new formatter / walker" work. It is deliberately kept out of
the Enum-formatter + pack-expansion change set because it **relaxes a
documented security control** (`head_bounded_body`) and therefore needs its
own review, its own Kani harnesses, and explicit re-validation against
`docs/security/VULN-erc7730-walker-slot-confusion.md`.

## Problem

The on-device ERC-7730 path resolver
(`secure/src/tx/display/erc7730/formatters.rs::resolve_path`) is
**static-head only**. It computes a field's value as a fixed 32-byte word
at `body[slot*32 .. slot*32+32]`, where `slot` is the sum of the path's
`FieldIdx` ops, and the body is first truncated to the format's
`static_head_words * 32` bytes by `head_bounded_body`
(`secure/src/tx/display/erc7730/mod.rs`). dbgen mirrors this: it **refuses
to compile** any path that uses array indexing
(`compile_structured_contract_path` → "contract calldata path uses array
index/slice — unsupported") or that descends into a dynamic type
(`compile_path` → "is dynamic … not readable by the walker").

Consequently, any descriptor whose security-relevant field lives in a
**dynamic ABI tail** declines-to-blind regardless of formatter support:

- Lido `WithdrawalQueue.requestWithdrawals(uint256[] amounts, address owner)`
- Essentially every DEX-aggregator swap struct (1inch/0x/Odos `desc`
  tuples with dynamic members, multi-hop `bytes` paths)
- Any `T[]` argument the user needs to see

The crate-side reference walker (`pqsigner-erc7730/src/walker.rs`) *already*
implements `ArrayIdx`/`ArrayLast` over an `AbiNode::Array`, and the crate
reserves the `ArrayIdx/ArraySlice/ArrayLast/ArrayAll` `PathOp`s (0x21–0x24)
— but the **device** renderer uses the simpler slot-based resolver, not the
`AbiNode` walker, and never materialises an array. So the gap is in the
*device ABI-tree construction + resolver*, not the bytecode interpreter.

## Why this is security-sensitive (do not rush)

`head_bounded_body` is a **defense**, not a limitation. It was added with
the `SCHEMA_VER 0x01 → 0x02` bump and the width-aware head-word path slots
to close the *slot-confusion* class
(`docs/security/VULN-erc7730-walker-slot-confusion.md`): a malformed or
hostile descriptor whose path slot lands in the dynamic tail must be
**rejected**, never silently rendered, because an offset word in the head
is not the value — rendering it would confirm-X-sign-Y. Loosening the
truncation to *follow* tails reopens exactly this surface. Bundling that
with feature work would dilute the review attention it specifically needs.

## Recommended approach: reuse the hardened `typed_call::abi::walk`

Do **not** hand-roll offset/length tail-following inside the
truncation-bypassing path. Build on the already-hardened ABI decoder
`pqsigner_tx::typed_call::abi::walk` (re-exported at
`secure/src/tx/typed_call/abi.rs`), which already enforces:

- canonical packing (non-canonical → reject),
- `MAX_DYNAMIC_LEN = 1 << 20`, `MAX_STATIC_ARRAY = 256`,
- top-28-bytes-of-offset/length-words MUST be zero,
- rejects tuples / nested arrays / nested dynamic types.

It returns, per argument, a `count` (#elements) and a `body_off` (offset of
the **length word** for dynamic args — step past it to reach elements).

### Bounded v1 scope (ship the smallest safe slice)

- Support **only** a single top-level dynamic array of *static* elements
  (`uint256[]`, `address[]`, `bytesN[]`) — the Lido-withdrawal shape.
- Support **only** `ArrayIdx` and `ArrayLast` descent (single value). Keep
  `ArraySlice`/`ArrayAll` refused (they need multi-value rendering, i.e.
  one walker call per leaf — a separate, larger change).
- Keep nested arrays, dynamic tuples, and `bytes`/`string` *values*
  refused (already are).

### Plumbing

1. **dbgen** (`compile_structured_contract_path`, `compile_path`,
   `static_head_words`): allow array-indexed paths to compile to
   `ArrayIdx(u32)` / `ArrayLast` bytecode for the supported shapes; keep
   refusing everything outside v1 scope. Decide whether the per-format
   `static_head_words` semantics change enough to warrant a **`SCHEMA_VER`
   0x02 → 0x03 bump** (it almost certainly does — a v2-only firmware must
   never mis-walk a v3 array descriptor; the version gate is the backstop).
2. **device** (`mod.rs` + `formatters.rs::resolve_path`): when a format
   declares dynamic args, decode the body with `typed_call::abi::walk`
   instead of the flat `head_bounded_body` slice, and resolve array path
   ops against the decoded args' `(count, body_off)` with strict bounds
   checks (index < count; element window inside body). The static-head
   fast path stays byte-identical for descriptors with no array ops.

## Verification plan (gates before this lands)

1. **New Kani harnesses**: the array resolver stays in-bounds when
   following a *symbolic* offset/length tail — never reads past `body`,
   never panics, rejects index ≥ count and non-canonical packing.
2. **Differential**: the new device array decode vs `typed_call::abi::walk`
   on the same calldata (they must agree element-for-element).
3. **VULN re-validation**: re-run / re-assert the
   `VULN-erc7730-walker-slot-confusion.md` attack — a path slot reaching a
   *non-array* dynamic tail must STILL reject. Add a negative test that a
   v2-shaped slot-confusion descriptor is refused under the new code.
4. **Fuzz**: extend `fuzz/fuzz_targets/erc7730_walker` to the array paths.
5. **Render tests**: positive (Lido `requestWithdrawals([1.0, 2.5], owner)`
   renders both amounts / the indexed amount) + negative (index past the
   array length declines-to-blind).

## Pairs with

Pack expansion: once landed, add the Lido `WithdrawalQueue` descriptor and
re-evaluate DEX-aggregator descriptors (most still need static-tuple +
dynamic-`bytes`-never handling, which is broader than v1).
