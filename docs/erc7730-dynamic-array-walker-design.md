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

---

## v2 design — rendered-value index/slice (review 3.0#2), 2026-07-02

**Status: DESIGN-ONLY. Not implemented. Supersedes the review's "+53 formats"
estimate with an honest safety classification.** This section scopes the
"value-path slice/index resolver" the 2026-07 implementation review ranked as
the #2 coverage unlock (`docs/erc7730-implementation-review-2026-07.md` §3.0).
The headline finding: **most of the "+53" is NOT a missing feature — it is
blocked by the array-tail-hiding invariant this doc already established
(v1 Deep-dive finding #1). It cannot be "unlocked" by a resolver change; only
by render-all or a reviewed per-descriptor curation.**

### What is actually blocked (from the drift-gated skip report)

`secure/data/erc7730.review.txt`'s `## skips` section (auto-generated per
finding 1.4) is now the authoritative, always-current inventory. The blocked
value index/slice shapes, by kind:

| Shape | Example (fn / field) | Count* | Kind |
|---|---|---|---|
| `arr.[-1]` rendered as an addressName **value** | 1inch `unoswap*`/`uniswapV3Swap*` `pools.[-1]` | 12+ | **array-tail-hiding (UNSAFE as single-value)** |
| `bytes.[a:b]` byte-range on a rendered value | paraswap-v6.2 `#.data.[292:324]` | 2+ | word-slice value extraction |
| `arr.[].member` (array-of-struct member) | flyingtulip `limits.[].limit` | 2 | nested array (→ EIP-712 v3 / §11 territory) |
| `bytes[].[]` dynamic-element array | kiln `validators_.[]` | 1 | dynamic-element array (out of v1 scope) |

*Counts are from the current 35-descriptor prod skip set; the full upstream
(372 descriptors) 1inch V3/V4/V5 families push the `pools.[-1]` count toward
the review's ~49. Re-derive from the skip report at review time — do not trust
a frozen number.

### Safety classification (the load-bearing part)

1. **`arr.[-1]` / `arr.[i]` rendered as a field VALUE is the array-tail-hiding
   HIGH** (v1 Deep-dive #1, and the typed-call `render_arg` Array-arm
   `count>1` decline). Showing `pools[-1]` while `pools` has N elements hides
   `pools[0..-1]` — the contract executes the whole route, the user sees one
   hop. A resolver that simply emits `ArrayIdx`/`ArrayLast` for a value path
   would REOPEN this HIGH. **This is why the 1inch slice fns stay declined, and
   it is correct.** The dbgen gate's `is_token_path` guard
   (`compile_structured_contract_path`) is the load-bearing line: extraction
   ops are allowed ONLY inside a `tokenPath` (identification), never a rendered
   value.

2. **`tokenPath: arr.[-1]` (token IDENTIFICATION) is already supported** — the
   Tier-B resolver (`compile_token_path_extraction` + `resolve.rs` `Extract`)
   landed for Uniswap/QuickSwap. So any 1inch leg whose LAST pool is consumed
   as a `tokenAmount`'s `tokenPath` (not a standalone addressName field) already
   works once its `$ref` resolves (finding 1.1). Before counting a 1inch fn as
   "blocked by slices", check the skip report: if the failing field is
   `format:addressName path:pools.[-1]` it is the unsafe value shape; if it is a
   `tokenAmount` with `params.tokenPath:pools.[-1]` it already compiles.

3. **`bytes.[a:b]` word-range** (paraswap `data.[292:324]`) is a value
   extraction from an opaque packed blob. Faithful ONLY if the 32-byte-word
   boundary and the packing are pinned; the current extractor deliberately
   rejects non-20-byte / non-canonical slices. Low value (the surrounding
   fields already carry the intent) and high risk — keep declined.

### The only safe unlocks (each its own review + Kani landing)

- **A) Render-ALL route pools** (`pools.[]` instead of `pools.[-1]`): safe
  (shows every element), reuses the shipped v1 `ArrayAll` path, but low value —
  route pools are opaque addresses the user cannot verify, and an N-hop route
  blows the 28-page budget fast. Net: mostly declines-to-blind on real routes.
  Not worth building for 1inch.
- **B) Reviewed per-descriptor curation — "identified token + hidden-route
  marker".** For a swap where the economic outcome is bounded by a SHOWN
  `minReturn`/`minReceiveAmount`, the intermediate route is not effect-bearing
  in the WYSIWYS sense (the user is protected by the min-return). Surface the
  output token (via `tokenPath: pools.[-1]`, the identification path that is
  already safe) AND a loud `route via N pools (not shown)` page, gated on:
  (i) a shown min-return field in the SAME format, (ii) a `policy.toml`
  curation entry with a written rationale (like `hidden_address_allow`),
  (iii) Kani + a render test proving the min-return is present and the marker
  renders. This is the genuine unlock for the 1inch volume — and it is a
  curation + policy mechanism, **not** a value-slice resolver.
- **C) Nested array-of-struct member** (`limits.[].limit`) is EIP-712 v3 /
  calldata §11 territory (per-element group render), tracked separately
  (review 3.0#4 / #6), not here.

### Recommendation

Do **not** build a rendered-value single-index/`[-1]` resolver — it reopens the
array-tail-hiding HIGH. Instead: (1) rely on finding 1.1 ($ref) + the existing
tokenPath extractor to unlock the 1inch legs whose token identity is a
`tokenPath` (free, already landed); (2) if the remaining 1inch addressName-value
`pools.[-1]` volume is judged worth it, pursue **unlock B** (min-return-gated
curation + hidden-route marker) as a design-doc-first, policy-driven,
adversarial-review-gated change — reusing the safe identification path, never a
value-single-index resolver. Update `docs/erc7730-implementation-review-2026-07.md`
§3.0 item 2 to reflect that "+53 via a slice resolver" is not the shape of the
safe unlock.

---

## v3 design — calldata array-of-tuple (review 3.0#4), 2026-07-02

**Status: DESIGN-ONLY. Not implemented.** The review's #1 *large* engineering
item and the one that unlocks the aggregator/bundler tail. It is the **calldata
analog of the shipped EIP-712 v2 §11 array-of-struct** render
(`docs/erc7730-nested-eip712-render-design.md`) — reuse that design's shape and
gates, translated from EIP-712 `hashStruct` encoding to calldata ABI encoding.

### What is blocked (from the skip report)

`parse_format_key` cannot parse a top-level `(...)[] name` array-of-tuple arg;
it errors "top-level tuple arg has no name" (misleading — the tuple IS named).
The blocked, batch-shaped functions:

| Descriptor | Array-of-tuple arg | Fns | Note |
|---|---|---|---|
| safe `BatchExecutor` | `(address to, uint256 value, bytes data)[] calls` | 1 | simplest shape (one dynamic member: `data`) |
| morpho `MorphoBundlerV3` | `(address to, bytes data, uint256 value, bool skipRevert, bytes32 callbackHash)[] bundle` | 2 (`multicall`/`reenter`) | the only morpho gap |
| flare `RewardManager` | `(bytes32[] merkleProof, (…) body)[] _proofs` | 4 | NESTED (array + inner tuple) — hardest |
| paraswap `Augustus-v6.2` | `((…8 fields…) order, bytes sig, …)[] orders` | ~2 | deep + dynamic bytes members |
| okx | (various batch args) | ~12 | the bulk of okx's 0/26 |

### Shape & safety

Each element is a tuple; the render must show EVERY element (array-tail-hiding
invariant — never a single index) OR decline. This is the SAME multi-value
render the v1 `ArrayAll` and the EIP-712 array-of-struct already do, so it
inherits their WYSIWYS argument: per-element group pages, bounded by the page
budget, declining-to-blind on overflow. The security-critical addition over v1
is that elements are **tuples with their own (possibly dynamic) members**, so
each element needs the per-member offset/length follow that `walk` already does
for a top-level tuple — applied per array element.

### Plumbing (mirror EIP-712 §11, translate to calldata)

1. **dbgen `parse_format_key`**: accept a trailing `(...)[] name` top-level arg;
   parse the inner tuple's member names/types (reuse the existing tuple parser).
   Emit a v0x03-style **array-of-tuple anchor** (like the nested-EIP-712 anchor):
   element tuple type, member count, per-member `FieldIdx`/format, and the
   address-word bitmap for the WYSIWYS/completeness checks — run the SAME
   completeness + visibility gates per member as a static tuple.
2. **device**: extend `resolve_array` to, per element, decode the element tuple
   with `walk`'s hardened readers (offset → element head → per-member
   offset/length for dynamic members), reading the SAME bytes the EVM decodes
   (slot-confusion-free). Render each element as a member group with divider
   pages, exactly like the EIP-712 array-of-struct render
   (`secure/src/tx/display/erc7730/nested.rs`).
3. **Scope v3.0 to the FLAT element tuple** (safe, dynamic-`bytes`-member OK):
   Safe `BatchExecutor` + Morpho `bundle` + okx batches. **Defer** the nested
   element (flare `_proofs` = `bytes32[]` + inner tuple) and the deep Augustus
   `orders` (8-field order + multiple dynamic bytes) to v3.1 — they need
   array-in-tuple + multi-dynamic-member handling that is a separate risk step.
   The `bytes data` member of a bundle element is itself embedded calldata; v3.0
   renders it via the calldata-fallback (review 3.1: hash + `callee`), NOT a
   recursive inner-CALL decode (that is the deliberately-deferred nested-calldata
   engine; the native Safe path already covers the high-value multiSend case).

### Gates (all required, mirror v1 + the nested-EIP-712 landing)

- New Kani harness: the per-element tuple decode stays in-bounds over a symbolic
  body/offset/length; element span ⊆ body; rejects `count` past budget.
- `walk` differential: per-element member words equal `walk`'s decode.
- Array-tail re-validation: a multi-element `calls[]` renders ALL elements or
  declines — never a partial.
- Completeness/visibility per element member (a hidden `to`/`value` in a bundle
  element is the same WYSIWYS hazard as a hidden top-level arg).
- Render test: Safe `BatchExecutor([(a,1,0x…),(b,2,0x…)])` renders both records.
- 5-lens adversarial-review workflow before commit.
- **SCHEMA_VER**: a new array-of-tuple anchor op the device currently rejects →
  a v2-firmware declines-to-blind on it (safe); decide per the nested-EIP-712
  precedent whether it warrants a bump (it added a new anchor without a bump
  because old firmware rejected the unknown op — same reasoning applies).

### Net

v3.0 (flat element tuple, dynamic-bytes-via-fallback) unlocks Safe
BatchExecutor + Morpho bundler + most okx batches (~15 fns) as a design-doc-
first, adversarial-review-gated, Kani-backed landing that REUSES the shipped
array + nested-struct machinery. Nested/deep element tuples (flare, Augustus)
are v3.1.
