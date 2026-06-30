# ERC-7730 dynamic-array walker — design + implementation

**Status: IMPLEMENTED (v1, 2026-06-30).** Sole-dynamic-array `<arg>.[]`
render-all is live: dbgen gate (`compile_array_all_path`), device
`resolve_array` + `render_array` (scalar path byte-identical), reusing `walk`'s
hardened readers + two exact-placement equalities. Verified by: an independent
5-lens **adversarial-review workflow** (verdict SHIP, 0 confirmed breaks), the
`walk` **differential**, an **11-case adversarial test suite**, and a **Kani
proof** of `resolve_array` (panic/OOB/overflow-freedom + in-bounds element span
over a symbolic body — `pqsigner-erc7730/src/render/array.rs`). Two depth-1
single-points-of-failure the review flagged were closed: the EIP-712 ArrayAll
dbgen-gate gap + the last-byte routing footgun. Residual follow-ups (review
ranked non-blocking): a page-budget-mid-loop test and an element-type/FormatOp
coupling gate (already depth-2 via EVM-revert + the overflow banner).

The remainder of this doc is the original design (firewalled from the Enum/pack
work), preserved for the record.

---

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

## Deep-dive findings (2026-06-30) — design sharpened

A pre-implementation orientation pass corrected the v1 scope and locked the
safe shape:

1. **Single-index (`arr[i]` / `arr[-1]`) is UNSAFE — it is the array-tail-hiding
   HIGH.** Rendering `amounts[0]` while `amounts` has N elements hides
   `amounts[1..]` — the contract executes on all N, the user sees one. This is
   the exact class fixed for the typed-call renderer (Completion Log 2026-06-18:
   `render_arg`'s Array arm DECLINES on `count>1`). So **v1 must be `ArrayAll`
   (`arr[]`)** — render EVERY element (one row/page each), bounded by the page
   budget, declining-to-blind if `count` exceeds the budget. `ArrayIdx`/
   `ArrayLast` single-value stay refused (they cannot be made WYSIWYS-safe).
   This makes v1 a *multi-value* render — the thing the original doc deferred —
   so v1 IS the multi-value path, just bounded to one top-level `T[]`.

2. **Reuse `walk`'s proven word-readers, do not hand-roll.** `walk`
   (`tx/src/typed_call/abi.rs`, Kani-proven no-read-past-end) already has
   `read_offset_word` / `read_length_word` (top-28-bytes-zero + `MAX_DYNAMIC_LEN`)
   and `word`. Make `read_offset_word`/`read_length_word` `pub` and use them for
   the offset→length→element follow, so the ERC-7730 array path inherits the same
   hardened ABI-faithful checks `walk` uses (reading the SAME element the EVM
   decodes is what keeps it slot-confusion-free).

3. **Preserve the head-bound for scalars.** Replace `head_bounded_body`'s
   pre-truncation (contract-calldata path only) with passing the FULL body +
   `static_head_words` into `resolve_path`; scalar `FieldIdx`-only paths still
   require `slot < static_head_words` (the VULN slot-confusion defense, now
   explicit). Only an `ArrayAll` path may follow the dynamic tail, and only after
   its array arg's offset word (which lives IN the head) passes the same bound.
   Keep an up-front `body.len() >= static_head_words*32` check (preserves the
   short-head reject `head_bounded_body` gave). The EIP-712 path keeps its exact
   `head_bounded_body`.

4. **No `SCHEMA_VER` bump.** `ArrayAll` (PathOp `0x24`) is a reserved opcode that
   dbgen has never emitted and the device currently REJECTS; emitting it changes
   no existing field's meaning, and a firmware without walker support
   declines-to-blind on it (safe). Unlike the `0x01→0x02` bump, no `FieldIdx`
   semantics change.

5. **Verification gates (all required):** new Kani harness — `ArrayAll` resolve
   stays in-bounds + per-element span ⊆ body over a symbolic body/offset/length;
   **VULN re-validation** — the existing `walker_slot_confusion_fixed` scalar
   test (a scalar slot reaching the tail must still reject) passes unchanged;
   **array-tail-hiding re-validation** — a multi-element array renders ALL
   elements or declines (never a partial); **differential** — the element words
   read equal `walk`'s decode for the same calldata; render test — Lido
   `requestWithdrawals(uint256[] amounts, address owner)`; **adversarial-review
   workflow** before commit.

**Net:** v1 is one top-level dynamic `T[]` of static primitives, rendered in
full via `ArrayAll`, page-budget-bounded, declining-to-blind on overflow or any
out-of-scope shape — reusing `walk`'s hardened readers and preserving the scalar
head-bound defense byte-for-byte.

## Pairs with

Pack expansion: once landed, add the Lido `WithdrawalQueue` descriptor and
re-evaluate DEX-aggregator descriptors (most still need static-tuple +
dynamic-`bytes`-never handling, which is broader than v1).
