# ERC-7730 nested-EIP-712 struct rendering — design (Phase 5 "deep types"), 2026-07-01

**Status:** DESIGN (pre-implementation). This is the firewalled, design-doc-first capability that
lifts the on-device `PARAM_NESTED_STRUCT` belt for a *bounded, cryptographically-bound* subset —
the EIP-712 analog of the calldata FollowOffset resolver. It unlocks the clear-signing of
intent-based orders (Permit2, then UniswapX / CoW-style), a real product differentiator.

Owner discipline: this relaxes a deliberate security control (the nested-struct-address-hide belt,
`docs/VULN-erc7730-eip712-nested-struct-address-hide.md`). It ships only through the array-walker
discipline: bounded subset → this doc → adversarial-review-gated (schema first, then impl) → Kani +
real-vector flip→decline tests → belt stays as the default-decline fail-safe.

## 1. Where we are (the control being relaxed)

The `VULN-…-nested-struct-address-hide` fix landed two halves:

- **Build gate (SOUND):** `dbgen::check_field_visibility` now parses the EIP-712 `encodeType` tail into
  `struct_defs` and *descends* into nested members — every nested `address` must be shown (via a field
  `path` or a shown-amount `tokenPath`) or reviewed-allowlisted, else the format is refused
  (`check_eip712_member_addresses`, `MAX_STRUCT_DEPTH = 8`, visited-set, array-of-struct-reaching-address
  refused). This is the primary correctness gate and it is NOT what we change.
- **On-device belt (the thing we lift, carefully):** `render_fields` declines the WHOLE format to
  blind-sign when any field carries `PARAM_NESTED_STRUCT = 0x41`. It exists because the current
  device nested renderer is *broken* (the EIP-712 path compiler sums global logical ordinals, so
  `details.amount` mis-resolves to the wrong top-level word) — so the safe behaviour today is to
  decline. Phase 5 replaces "decline all nested" with "faithfully render the *supported* nested
  shapes, decline the rest."

The signed value is `keccak(0x1901 ‖ domainSep ‖ structHash)`, `structHash = keccak(primary_type_hash
‖ encoded_data)`. `encoded_data` is the companion-supplied top-level `encodeData` (`static_head_words ×
32` bytes, EXACT length). A nested-struct member is one opaque `hashStruct` word inside it — signed,
but un-expandable and un-showable today.

## 2. The binding (the security spine — the ONLY sound design)

For a nested-struct member whose `hashStruct` word sits at word `k` of the parent's `encoded_data`:

```
committed = parent_ed[k*32 .. k*32+32]                      // signed, opaque
nested_ed = <companion supplies>                            // member_count × 32 bytes
REQUIRE  keccak( type_hash ‖ nested_ed )  ==  committed     // constant-time; else DECLINE whole format
then render the visible sub-fields against nested_ed
```

`type_hash = keccak(encodeType(nested))` is **dbgen-pinned in the IR** (Merkle-rooted, trusted), never
companion-supplied. By collision-resistance, a companion that shows any nested content other than what
it signed cannot make the equality hold → the device declines. Shown ⟺ signed. This is the EIP-712
analog of "follow the ABI offset word and read the same position the contract decodes", with a
cryptographic re-hash standing in for the ABI offset.

**Array-of-struct** (`T[] members`, e.g. `PermitDetails[]`): the parent word is
`keccak( elem0_hashStruct ‖ elem1_hashStruct ‖ … )`. The device verifies each element
`elem_i_hashStruct = keccak(type_hash ‖ elem_i_ed)` and then `keccak(concat of elem_hashStructs) ==
committed`, and renders each element. (v2 — see scope.)

## 3. Non-negotiable safety rules (baked from the design review — these are the review lenses)

1. **Hash the COMPLETE nested blob, display a subset; `==` length at EVERY level.** The device consumes
   *exactly* `member_count × 32` bytes for a nested struct (`member_count` from PINNED metadata, never a
   companion-declared length) and hashes all of it; it renders only the visible sub-fields. Hashing only
   the visible subset → binding never matches legit data → dead feature (caught by the render test).
   Accepting any blob length → trailing signed-but-unshown words = the 2026-06-11 attack, recursively.
2. **Default-DECLINE; the belt is inverted, not removed.** `if nested_struct { if fully_supported &&
   metadata_present { verify+render } else { decline whole format } }`. Page-budget exhaustion, depth >
   `MAX_STRUCT_DEPTH`, array count > `MAX_NESTED_ARRAY`, an unknown/unsupported member type, or a *shown*
   dynamic (`bytes`/`string`) nested member we don't yet follow → decline the WHOLE format. A rendered
   prefix that hides a tail is the array-tail-hiding WYSIWYS break.
3. **`type_hash` is dbgen-pinned per struct.** `encodeType(nested)` = that struct's own definition ‖ its
   OWN transitively-referenced struct defs, sorted (EIP-712 canonical) — NOT the line lifted from the
   parent's `encodeType`. dbgen already computes the primary's; the nested recursion must be verified.
4. **New generic `hashStruct` primitive.** CoW/Safe `struct_hash` is flat + hardcoded (13 GPv2 fields);
   neither does nested hashStruct. Phase 5 needs `hashStruct(type_hash: &[u8;32], ed: &[u8]) -> [u8;32]`
   = `keccak(type_hash ‖ ed)` with its own test. Trivial, but new code — not a reuse.
5. **Replace, don't extend, the broken nested path compiler.** The EIP-712 field compiler sums global
   logical ordinals (mis-resolves nested). Phase 5 introduces a RECURSIVE sub-format IR: a nested member
   → `{word_pos, type_hash, member_count, is_array, [visible sub-fields with LOCAL ordinals]}`, and the
   device renders sub-fields against `nested_ed` with LOCAL resolution. This is the load-bearing dbgen
   work and needs a `SCHEMA_VER` bump.
6. **The decisive test is flip→decline, not render-success.** Mirror CoW `negative_struct_hash_binds_*`:
   a REAL Permit2 payload (hashStructs computed with foundry), assert (a) the nested address/amount/date
   render correctly AND (b) flipping ANY single bit of ANY nested word — shown OR hidden — flips to
   decline. (b) proves the binding is non-vacuous; (a) alone passes even if the hash is never checked.

## 4. The recursive sub-format IR (schema — get this reviewed first)

Today an EIP-712 format's fields are flat `(label, path_off, param_off)` with a broken global-ordinal
path. Phase 5 restructures a nested-struct member into a self-describing recursive block. `SCHEMA_VER
0x02 → 0x03`.

`PARAM_NESTED_STRUCT` (0x41) changes from a bare marker to a TLV payload:

```
PARAM_NESTED_STRUCT payload (v0x03):
  word_pos      : u16 BE     -- member's hashStruct word index in the PARENT encoded_data
  type_hash     : [u8; 32]   -- keccak(encodeType(nested)), PINNED (rule 3)
  member_count  : u16 BE     -- # of 32-byte words in the nested encoded_data (rule 1, `==` check)
  flags         : u8         -- bit0 = is_array (v2); bits1..7 reserved 0
  sub_field_cnt : u8         -- number of VISIBLE sub-fields that follow
  sub_fields    : [SubField; sub_field_cnt]

SubField (same shape as a top-level field, recursive):
  label_len     : u8, label bytes
  local_path    : path program (RootStructured + FieldIdx(local ordinal)…) resolving against nested_ed
  param_off     : u16 BE     -- into the pool; a SubField MAY itself carry PARAM_NESTED_STRUCT (depth)
```

Key properties:
- The nested member's own `path` in the descriptor (`details`) is NOT a render field; it becomes the
  `word_pos` anchor. Its visible children (`details.amount`, `details.expiration`) become `sub_fields`
  with LOCAL ordinals (`amount`→word 1, `expiration`→word 2 within `PermitDetails`), and a nested
  `tokenPath` (`details.token`) compiles to a LOCAL `FieldIdx(0)` resolving against `nested_ed`.
- Hidden nested members (`nonce`) are NOT emitted as sub_fields — they are just words the hash covers
  (rule 1). `member_count` (4) is what pins the blob length, independent of how many are shown.
- Deeper nesting: a `SubField` may itself carry a `PARAM_NESTED_STRUCT` → the device recurses, consuming
  a deeper `nested_ed`, up to `MAX_STRUCT_DEPTH`.

dbgen builds this by walking `struct_defs`: for each top-level (and recursively nested) member whose
type is a struct, compute `word_pos` (its index in the parent `encodeType` member order — NOT the
descriptor field order), `type_hash`, `member_count` (= parent-struct member count), and emit the
descriptor's fields that fall under that member as LOCAL sub_fields.

## 5. Wire format (companion protocol)

`OFFCHAIN_KIND_EIP712_TYPED` today:
`[u16 ds_present][32 domainSep][32 primary_type_hash][u16 ed_len][ed][u16 trailer_len][trailer]`.

Add an OPTIONAL nested-encodeData section between `ed` and the trailer, present iff the descriptor
declares nested structs:

```
… [u16 ed_len][ed]
   [u16 nested_blob_len][ nested_blob ]        -- 0 when the format has no nested struct
   [u16 trailer_len][trailer]
```

`nested_blob` is a DFS-ordered concatenation of `[u16 len][nested_ed]` records, consumed in the SAME
order the device's recursive render descends (deterministic: parent-member order, depth-first). The
device parses lazily as it recurses; a record whose `len != member_count*32` for the struct it binds →
decline (rule 1). Total `nested_blob_len` bounded by `MAX_OFFCHAIN_EIP712_NESTED_LEN`. Backward-compatible:
a companion signing a non-nested typed message emits `nested_blob_len = 0` (or the field is absent for
old descriptors — gate on `SCHEMA_VER`).

The companion guide (`docs/companion/companion-erc7730-implementation-guide.md`) gains a nested-order
section: for each nested-struct member, ship its raw `encodeData` (the 32-byte-per-member ABI words,
addresses left-padded, etc.), DFS order.

## 6. Device changes

- New `hashStruct(type_hash, ed) -> [u8;32]` (rule 4) + a nested-binding verifier that (single) checks
  `hashStruct(type_hash, nested_ed) == committed` constant-time, or (array) verifies each element +
  the concat.
- `render_fields`: on a `PARAM_NESTED_STRUCT` field, parse the payload, pull the next `nested_ed` record
  from `nested_blob`, verify the binding (decline on mismatch/length/overflow), then recurse into the
  sub_fields with `nested_ed` as the body (LOCAL resolution; nested `tokenAmount` tokenPath resolves via
  the Tier B `resolve_token_address` against `nested_ed`). Unsupported shape → decline (rule 2).
- Belt inverted: the bare-marker decline becomes "decline iff not fully-supported/metadata-absent".
- `cmd_sign_offchain`: parse the `nested_blob` section, pass it to the renderer; the SIGN path is
  unchanged (it still signs `keccak(primary_type_hash ‖ ed)` — the nested_blob only feeds the DISPLAY
  binding, and the display binding proves ed's opaque words equal the shown content).

## 7. Scope — incremental, real-vector-driven (v1 → v2 → v3)

- **v1 (this design's build):** single-level, NON-array nested struct, elementary members.
  Targets: Permit2 **`PermitSingle`** (`PermitDetails`, 4 members, exercises nested `tokenAmount` +
  nested `tokenPath` + nested `date`) and **`PermitTransferFrom`** (`TokenPermissions`, 2 members, the
  minimal binding). Real vectors: `typeHash(PermitDetails)=0x65626cad…`, `typeHash(TokenPermissions)=
  0x618358ac…` (foundry `cast keccak`). Proves the binding + recursive-IR machinery end-to-end.
- **v2:** array-of-struct (`is_array`) → Permit2 `PermitBatch`, UniswapX `DutchOutput[] outputs`. Adds
  the per-element + concat verification and the per-element render loop (page-budget bounded).
- **v3:** deeper nesting (UniswapX `witness` → `OrderInfo` etc.) + a *shown* dynamic nested member
  (`bytes`), if any real target needs it. Each is its own increment; anything unsupported stays
  belt-declined.

## 8. Verification plan

- **Kani:** the binding verifier + the recursive descent are panic/OOB/overflow-free over adversarial
  `nested_blob` (member_count, lengths, array counts all symbolic) — bounded depth/breadth. Mirrors the
  `resolve_token_address` harness shape (trusted metadata × adversarial companion bytes).
- **Host render tests (decisive — rule 6):** a REAL Permit2 PermitSingle typed message; compute the true
  `hashStruct(PermitDetails)` + top-level `ed`; assert (a) `details.amount` renders the token symbol +
  scaled amount and `details.expiration` renders the date, spender shown, `sigDeadline`/`nonce` hidden;
  (b) flip→decline for every nested word (shown and hidden) and the top-level `details` word.
- **dbgen tests:** recursive-IR emission (word_pos = member order not field order; member_count; pinned
  type_hash matches foundry; sub_field local ordinals; nested tokenPath local), + the gate still refuses
  a hidden-nested-address descriptor (unchanged).
- **Belt regression:** an un-metadata'd / too-deep / array-when-v1 nested field still declines.
- **Adversarial review:** 5-lens workflow on (1) the recursive-IR SCHEMA first (before impl), then (2)
  the concrete implementation — binding completeness, `==` length at every level, belt-default, wire
  framing ambiguity, nested-tokenPath local resolution, page-budget fail-closed.

## 9. Decisions to confirm at schema review

- `word_pos` = member index in the parent `encodeType` order (authoritative), reconciled against the
  descriptor's field order — confirm dbgen derives it from `struct_defs`, not field declaration order.
- `nested_blob` DFS framing vs an explicit `(word_pos → record)` map — DFS is smaller + deterministic
  but couples wire order to descent order; a map is more robust to renderer reordering. Lean DFS for v1.
- SCHEMA_VER bump vs a v0x02-compatible marker-plus-sidecar — a bump is cleaner given the field-structure
  change; confirm no other consumer pins 0x02.
- Whether v1 emits the nested block only for the two Permit2 formats (corpus delta small, low blast
  radius) and leaves UniswapX belt-declined until v2/v3.
