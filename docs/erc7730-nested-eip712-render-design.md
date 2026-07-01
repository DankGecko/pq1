# ERC-7730 nested-EIP-712 struct rendering — design (Phase 5 "deep types"), 2026-07-01

**Status: IMPLEMENTED (v1, 2026-07-01).** Commits A `8bc675e8` (SCHEMA_VER 0x03 + dbgen v0x03
recursive-IR emission) → B `cf3cff72` (pure `pqsigner-erc7730/src/render/nested.rs` parser/cursor/
coverage + Kani) → C `7ea2c5f5` (`OFFCHAIN_KIND_EIP712_TYPED_V3` wire kind + `hash_struct` binding
primitive) → D `a7ca96dc` (belt INVERTED — `render_nested_struct` binds + renders; E1 pinned
reconciliation; E2 visibility-aware coverage). v1 ships **Permit2 `PermitSingle`** (the flagship
approve): the nested `PermitDetails` amount + expiration + token clear-sign, bound by
`keccak(pinned type_hash ‖ nested_ed) == the committed hashStruct word`. Decisive non-vacuity proof:
`v3_permit_single_binding_is_non_vacuous` (flip ANY of 160 nested/committed bytes → decline). A 5-lens
adversarial-review workflow found **1 confirmed HIGH** (E2 credited a `visible:"never"` sub-field's
coverage) — fixed in D (coverage credits only sub-fields that actually render). **`PermitTransferFrom`
(`TokenPermissions`, the minimal 2-member binding) now also ships** (`9b61783b`) — upstream omits its
`nonce`, so a hand-curated `nonce` `visible:"never"` completeness field unlocks it (Tier A curation
discipline, guarded by `vendored_permit2_transfer_from_curation_compiles`). **Not yet shipped:**
array-of-struct (`PermitBatch` / UniswapX `DutchOutput[]`) = v2. The design
below is retained as the authoritative spec; §10 (E1–E5) is what the implementation follows.

This is the firewalled, design-doc-first capability that
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

## 10. Schema-review outcome + MANDATED edits (2026-07-01) — the authoritative impl spec

A 5-lens adversarial review of this schema (before any code) confirmed the **binding spine is SOUND**
(`keccak(pinned type_hash ‖ companion nested_ed) == committed word`, checked constant-time before
render, gives shown==signed by collision-resistance under full companion control of `ed` and
`nested_ed`) and the **exact-length `member_count×32`** discipline. Verdict: *implement-with-edits*.
The following are BINDING and supersede the affected parts above. Implementation follows §2 (binding) +
§3 (rules) as amended here.

### E1 — Unconditional descent + binding at every depth (Gap C, HIGH — the #1 invariant)

The `PARAM_NESTED_STRUCT` descent — pull the next `nested_ed` record, verify
`keccak(type_hash ‖ nested_ed) == committed_word` — MUST run on the **structural marker alone**,
evaluated **BEFORE and INDEPENDENT of** `should_render_with_mode` / `COMPACT_MODE` / any
value-conditional visibility, at **every** depth. Only the *rendering* of an already-bound sub-field
may be visibility-gated; a hidden/skipped sub-field is just a word the hash already covers. The natural
"recurse sub-fields through the visibility loop" implementation (and any future COMPACT_MODE re-enable
of the dormant `Action::Skip` path) would silently reintroduce the fixed nested-address-hide VULN — this
is exactly what the schema-first review exists to prevent. dbgen **forces the anchor member's visibility
to `Always`** and asserts it. **Fail-loud reconciliation (mandatory):** after the whole format renders,
`records_consumed == (number of nested-descent points in the format)` AND `cursor == nested_blob_len`,
else decline. (This is the top-level analog of the belt: the device proves it bound every nested word.)

### E2 — Standalone address-coverage backstop: address-word bitmap in the TLV (Gap A, HIGH)

Rule 1 forbids only *trailing* unshown words; it permits a hidden *interior* member. So a bound-but-
unshown interior **address** word (e.g. `PermitDetails.token` omitted) renders benign while the keccak
check still passes — the hidden-tail attack pushed one level down, reachable under any `check_eip712_
member_addresses` build-gate defect. §3-rule-2 promises the belt "survives a gate regression"; the TLV
as first drafted cannot deliver that. **Edit:** `PARAM_NESTED_STRUCT` payload gains a dbgen-derived
`addr_word_bitmap` (one bit per local word, set iff that member's type is address-bearing — computed
from `struct_defs`). The device **declines the whole format** if any address-typed local word is not
covered by a visible sub-field's `path` or shown-amount `tokenPath` (or an explicit reviewed-allowlist
entry) — **independent of** whether the build gate ran correctly. The belt is thus a standalone control,
not a mirror of the gate.

### E3 — Wire version at the WIRE level, not the descriptor (Gap B, MEDIUM — framing blocker)

The `nested_blob` presence cannot be gated on the descriptor `SCHEMA_VER`: that lives inside the trailer
that `cmd_sign_offchain` parses AFTER the post-`ed` `u16` slot, so the device can't tell whether that
`u16` is `nested_blob_len` or `trailer_len` before parsing the not-yet-reached trailer (and "always
present" misreads a v0x02 companion's `trailer_len`). **Edit:** allocate a new wire kind
`OFFCHAIN_KIND_EIP712_TYPED_V3` whose parser UNCONDITIONALLY expects
`… [ed_len][ed] [u16 nested_blob_len][nested_blob] [u16 trailer_len][trailer]` (`nested_blob_len == 0`
when the format has no nested struct). v0x02 companions stay on `OFFCHAIN_KIND_EIP712_TYPED` unchanged —
true backward-compat. Drop the "or the field is absent" option. **Also reserve** a `[u16 elem_count]`
prefix on `is_array` records now (bounded by `MAX_NESTED_ARRAY`) so v2 arrays are self-delimiting
without a second wire bump.

### E4 — Three fail-closed invariants (Gap D, MEDIUM)

1. **Atomicity.** Every decline trigger is a single hard error that unwinds and DISCARDS all
   already-pushed pages — the confirm dialog never receives a partially-rendered page set. No
   per-sub-field skip-and-continue.
2. **Local bounds.** Every SubField requires `local_ordinal < member_count`; each `nested_ed` is exactly
   `member_count × 32` and a sub-field read is bounded to it (the per-record analog of `head_bounded_body`).
   An ordinal `≥ member_count` would read into the ADJACENT DFS record (cross-struct slot-confusion) —
   decline instead.
3. **Total consumption.** The DFS parse must end EXACTLY at `nested_blob_len` (folds into E1): a shortfall
   (fewer records than descent points) or trailing bytes → decline.

### E5 — Precise sub-field local-ordinal + member_count (Gap E, LOW)

A SubField's **LOCAL ordinal = the member's index in the NESTED struct's own `struct_defs` member list**
(declaration order == its `encodeData` word index) — derived identically to `word_pos`, NOT the
visible-sub-field index (which would read `amount`→word 0 = the token address, a mis-scale) and NOT
`resolve_field_index`/`inner_names` (empty for EIP-712 → ABI-hash garbage). Correct **`member_count` =
the NESTED struct's own member count** (# of 32-byte words in ITS `encodeData`), not the parent's.
**One authoritative DFS order** is used by BOTH sides — the device's descriptor-field descent order; the
companion guide MUST specify records in that exact order (with the E1 reconciliation catching any drift).

### Net updated `PARAM_NESTED_STRUCT` payload (v0x03)

```
word_pos       : u16 BE      -- member hashStruct word index in PARENT encoded_data (member order)
type_hash      : [u8; 32]    -- keccak(encodeType(nested)), pinned (rule 3)
member_count   : u16 BE      -- NESTED struct's own member count (== nested_ed / 32) (E5, rule 1)
flags          : u8          -- bit0 = is_array (v2); rest reserved 0
addr_word_bmp  : ceil(member_count/8) bytes -- bit i set iff local word i is address-bearing (E2)
sub_field_cnt  : u8
sub_fields     : [SubField]  -- visible only; LOCAL ordinals per E5; may recurse (PARAM_NESTED_STRUCT)
```

Everything else in §1–§9 stands. v1 build order: dbgen recursive-IR emission (word_pos from member
order, type_hash pinned + foundry-checked, member_count, addr_word_bmp, sub_fields local ordinals) →
`hashStruct` primitive + binding verifier (E1 unconditional, E2 backstop, E4 bounds) → `TYPED_V3` wire
kind → device recurse+render (atomic, E1 reconciliation) → Kani (adversarial nested_blob) → flip→decline
real-vector render tests (Permit2 PermitSingle/PermitTransferFrom) → impl adversarial review.

## 11. v2 — array-of-struct (`T[]`), 2026-07-02 (IMPLEMENTED)

**Status: IMPLEMENTED.** dbgen emission + gate relaxation landed `93fbec79`; the device array render
landed after a clean 5-lens adversarial review (0 findings). Permit2 **`PermitBatch`** clear-signs each
element (`Item i of N` divider), bound by `keccak(concat of per-element hashStructs) == committed`
(foundry-pinned 2-element vector `0xfd1160ad…`). `elem_count == 0` and `> MAX_NESTED_ARRAY = 6` decline;
the flip→decline test flips every element word + the committed word + a lied `elem_count` → all decline.
Bonus: Rarible ERC-721/1155 lazy-mint orders (`Part[] creators/royalties`, shown addresses) also render
via the same machinery (their `string tokenURI` shows as a raw hashStruct word — a pre-existing v1
limitation for `string` members, not a security issue). The design below stands.

v1 shipped single-level NON-array nested structs. v2 adds a
`T[] members` member — the last piece the clean Permit2 target needs (`PermitBatch`) and a prerequisite
for UniswapX `DutchOutput[]` (which additionally needs v3 deep-nesting + the `fields` group syntax + a
dynamic `bytes` member — OUT of v2 scope). v2 target = **Permit2 `PermitBatch`** ONLY:
`PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)` — identical to `PermitSingle`
except `details` is an ARRAY of the same `PermitDetails`; the sub-fields are `details.[].amount` /
`details.[].expiration` / tokenPath `details.[].token` (the `.[]` stripped for LOCAL resolution — local
ordinals are identical to v1).

### 11.1 The array binding (EIP-712 `T[]` encoding — the spine)

EIP-712 encodes a struct array `T[]` as `keccak256( hashStruct(el0) ‖ hashStruct(el1) ‖ … ‖ hashStruct(elN) )`,
where each `hashStruct(el_i) = keccak256(typeHash_T ‖ encodeData(el_i))`. So the committed parent word
for `details` is that outer keccak. The device:
1. reads `elem_count` (wire, bounded by `MAX_NESTED_ARRAY`);
2. for each element `i`: reads the next `nested_ed` record (EXACTLY `member_count × 32`, rule 1),
   computes `elem_hs_i = hash_struct(typeHash, elem_ed_i)`, and folds `elem_hs_i` into a running keccak
   of the concatenation (and retains the `elem_ed_i` slice, bounded);
3. requires `keccak(concat of elem_hs) == committed` (constant-time) — **before rendering anything**;
4. runs the E2 coverage check ONCE (every element has the same pinned struct shape → same `addr_word_bmp`
   + same sub-field local ordinals);
5. renders each element's visible sub-fields against its `elem_ed_i` (with an element-index divider).

Collect-verify-then-render (not render-during-verify) preserves WYSIWYS + atomicity: nothing is shown
until the WHOLE array binds. The retained `elem_ed_i` slices sit in a bounded `[&[u8]; MAX_NESTED_ARRAY]`
on the stack (no_std, no heap).

### 11.2 Wire — `[u16 elem_count]` prefix on `is_array` records (reserved by §10 E3)

For an `is_array` anchor the `nested_blob` section is
`[u16 elem_count]  [u16 len][elem0_ed]  [u16 len][elem1_ed]  …  [u16 len][elemN_ed]`. Non-array (v1)
records stay `[u16 len][nested_ed]` with NO prefix — the payload `flags` bit0 tells the device which wire
shape to expect. The E1 reconciliation is UNCHANGED: an array anchor is still ONE descent point
(`records_consumed += 1`), and `cursor == nested_blob.len()` proves the `elem_count` prefix + all element
records were consumed exactly (a padded/short blob → decline).

**`elem_count == 0` → EXPLICIT decline (review fix).** Do NOT rely on the top-level "no visible members"
belt — a `PermitBatch` also has a `visible:always` `spender`, which renders a page, so that belt PASSES
even with an empty array. A companion could bind an empty batch with `committed = keccak256("")` (a fixed
constant that hashes cleanly) and clear-sign "spender + zero allowances" — confusing, not the intended
decline. `render_nested_struct` refuses `elem_count == 0` outright (an empty batch signs nothing worth
showing); tested.

### 11.3 The gate relaxation (the security-sensitive part)

`check_eip712_member_addresses` (dbgen) currently REFUSES an array-of-struct that reaches an address:
*"the device cannot address elements, so any address inside cannot be shown."* v2 makes that premise
false — the device renders per element. **Edit:** for a single-level array-of-struct, DESCEND into the
element struct and apply the SAME address-coverage logic as the non-array case, matching the `M.[].<addr>`
per-element path shape (an address is "shown" iff a per-element render field or a shown per-element
`tokenPath` reaches it). A HIDDEN address inside an array element still REFUSES (unchanged for the
uncovered case). Bounded: only single-level `T[]` where `T` is a struct with elementary members; a
`T[]` whose element reaches a nested struct or a deeper array stays refused (v3). The relaxation is
gated so it can only widen coverage for shapes the emission + device actually support; anything else
falls to the bare-marker belt (decline).

**The E2 device backstop is unchanged and still independent:** the per-element `addr_word_bmp` coverage
check runs on-device regardless of the gate, so an array element with an uncovered address word declines
even if the (relaxed) gate had a defect — exactly the standalone-control promise, now for arrays.

**Impl-review target (review fix):** the gate's per-element coverage matcher MUST correctly resolve `.[]`
paths — `details.[].token` (the shown-amount tokenPath) has to map to the element's token word. If the
existing matcher doesn't understand `.[]`, the failure is either a silent false-refuse (PermitBatch drops
→ dead feature) or, worse, a mis-match that passes an uncovered address. Needs a targeted dbgen test
(the E2 device backstop is the safety net, but the gate logic is tested directly). Foundry-pin the
2-element array binding (`keccak(hashStruct(el0)‖hashStruct(el1))`) before building — same discipline as
the v1 typeHashes.

### 11.4 Caps + fail-closed

`MAX_NESTED_ARRAY = 6` (review fix — 8 was against the budget: banner + spender + 8×(amount + expiration
+ divider ≈ 3) + chain + confirm ≈ 27 vs `MAX_PAGES = 28`; 6 leaves headroom). Page-budget overflow
(`pages.push_blank()` → `Err`) MUST decline, NEVER truncate — a truncated array tail is the array-hiding
WYSIWYS break one level down. `elem_count == 0`, `elem_count > MAX_NESTED_ARRAY`, any `elem_ed_i.len() !=
member_count*32`, concat-hash mismatch, page-budget overflow, or an uncovered address → single hard `Err`
that discards all pushed pages (E4-1 atomicity, unchanged).

### 11.5 Build order (mirrors v1)

dbgen: relax the gate for covered single-level `T[]` + teach `try_compile_eip712_nested` to accept an
array member (recognize `M.[].child`, strip `.[]`, set `flags` bit0=1, keep v1 local ordinals) →
device: the array branch in `render_nested_struct` (read `elem_count`, collect-verify-concat, per-element
render) + `MAX_NESTED_ARRAY` → wire: the `is_array` `elem_count` prefix in `cmd_sign_offchain` (unchanged
kind — the shape is self-describing via the payload flags) → Kani (adversarial `elem_count` + records) →
flip→decline real-vector tests (a REAL 2-element `PermitBatch`: both elements render; flip ANY element's
ANY word — or the committed array word, or `elem_count` — → decline; a per-element non-vacuity that also
proves element `i`'s content can't masquerade as element `j`) → impl 5-lens adversarial review. UniswapX
`DutchOutput[]` stays belt-declined until v3 (deep + groups + bytes).

