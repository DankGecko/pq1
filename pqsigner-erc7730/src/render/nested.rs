//! Nested-EIP-712 struct descent — the PURE (no-keccak, host-testable,
//! Kani-tractable) half of the Phase 5 nested renderer.
//!
//! # What lives here vs. in the secure crate
//!
//! This module owns everything that does NOT need keccak or the display layer:
//!
//! * [`parse_nested_struct_param`] — parse a `PARAM_NESTED_STRUCT` v0x03 payload
//!   (`word_pos | type_hash | member_count | flags | addr_word_bmp | sub_fields`)
//!   into a bounds-checked [`NestedStructParam`], rejecting any malformed /
//!   out-of-range field. Every read is a checked `.get()`; `member_count` is
//!   capped at [`MAX_NESTED_MEMBERS`]; the sub-field records must consume the
//!   block EXACTLY (no trailing bytes — the per-block half of E4-3).
//! * [`read_next_nested_ed`] — pull the next `[u16 len][nested_ed]` record from
//!   the companion-supplied `nested_blob` DFS stream, fully bounds-checked
//!   against the REAL blob (a crafted length can only shrink coverage or
//!   `Reject`, never read out of bounds).
//! * [`validate_nested_structure`] — the E2 address-coverage backstop + the
//!   E4-2 local-ordinal bounds, computed from the PINNED metadata + the pool,
//!   INDEPENDENT of the build gate: every address-typed local word must be
//!   bound by a visible sub-field's render path OR its `tokenPath`, and every
//!   sub-field's local word must be `< member_count`.
//!
//! The keccak binding (`keccak(type_hash ‖ nested_ed) == committed`), the
//! recursion glue, and the E1 reconciliation live in the secure crate
//! (`secure/src/tx/display/erc7730`), which owns the keccak primitive and the
//! `Pages` output. This split keeps the adversarial-`nested_blob` logic behind
//! a Kani proof (keccak would make it intractable) — mirroring
//! [`super::resolve::resolve_token_address`] (trusted metadata × adversarial
//! companion bytes).
//!
//! Threat model: the payload (type_hash, member_count, addr_word_bmp,
//! sub-fields, word positions) is TRUSTED — dbgen-built, Merkle-pinned. The
//! `nested_blob` (record lengths, the `nested_ed` bytes) is fully ADVERSARIAL —
//! the companion's. These functions never panic / read OOB / overflow on ANY
//! `nested_blob`; a hostile one can only force a `Reject`.

use core::convert::TryFrom;

use crate::ir::{
    Erc7730Ir, FieldEntry, FieldIter, FormatOp, IrError, PathOp, Visibility, MAX_FIELDS_PER_FORMAT,
    MAX_NESTED_MEMBERS, MAX_NESTING,
};

use super::{
    policy::{label_has_visible_glyph, token_path_displays_identity, validate_field, TerminalKind},
    RenderErr,
};

/// Leading version byte of a structured v0x03 `PARAM_NESTED_STRUCT` payload.
/// (`0x01` is the bare belt marker for an unsupported nested member — declined
/// before this parser is ever reached.)
pub const NESTED_V3: u8 = 0x03;

/// Fixed prefix length of a v0x03 payload BEFORE the variable `addr_word_bmp`:
/// version(1) + word_pos(2) + type_hash(32) + member_count(2) + flags(1).
const NESTED_PREFIX_LEN: usize = 1 + 2 + 32 + 2 + 1;

/// Parsed (zero-copy) view of a `PARAM_NESTED_STRUCT` v0x03 block. Borrows from
/// the IR pool. All fields are TRUSTED (dbgen-built, Merkle-pinned).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NestedStructParam<'a> {
    /// The nested member's `hashStruct` word index in the PARENT `encoded_data`.
    pub word_pos: u16,
    /// `keccak(encodeType(nested))` — dbgen-pinned; the binding uses it as
    /// `keccak(type_hash ‖ nested_ed) == committed_word`.
    pub type_hash: &'a [u8; 32],
    /// The NESTED struct's OWN member count (== `nested_ed.len() / 32`). Pins the
    /// blob length independent of how many members are shown (rule 1 + E5).
    pub member_count: u16,
    /// `flags` bit0 — an array-of-struct member (v2). v1 declines these.
    pub is_array: bool,
    /// One bit per local word, set iff that member's type is address-bearing
    /// (E2). Length is exactly `ceil(member_count/8)`.
    pub addr_word_bmp: &'a [u8],
    /// Number of visible sub-field records that follow.
    pub sub_field_cnt: u8,
    /// Raw sub-field records (`FieldEntry` wire format). Iterate via
    /// [`Self::sub_fields`].
    sub_fields_blob: &'a [u8],
}

impl<'a> NestedStructParam<'a> {
    /// Iterate the visible sub-field records (reuses the [`FieldEntry`] parser).
    pub fn sub_fields(&self) -> FieldIter<'a> {
        FieldIter::from_buf(self.sub_fields_blob, self.sub_field_cnt)
    }

    /// `true` iff local word `i` is address-typed per the pinned bitmap.
    fn local_word_is_address(&self, i: usize) -> bool {
        (self.addr_word_bmp.get(i / 8).copied().unwrap_or(0) >> (i % 8)) & 1 == 1
    }
}

/// Allocation-free nested-v3 preflight introduced in schema v4 and retained
/// unchanged by schema v6.
/// Returns the number of descent records consumed by this block plus all child
/// anchors, which the enclosing format reconciles against its independently
/// authenticated `nested_descent_count`.
pub(crate) fn validate_nested_ir(
    ir: &Erc7730Ir<'_>,
    payload: &[u8],
    parent_member_count: usize,
    depth: usize,
) -> Result<u8, IrError> {
    if depth == 0 || depth > MAX_NESTING {
        return Err(IrError::OverCap);
    }
    let np = parse_nested_struct_param(payload).map_err(|_| IrError::BadPoolEntry)?;
    if np.word_pos as usize >= parent_member_count
        || np.sub_field_cnt as usize > MAX_FIELDS_PER_FORMAT
    {
        return Err(IrError::BadField);
    }

    // Unused high bitmap bits are a second wire spelling for the same member
    // types and could hide future meaning.  Require canonical zero padding.
    let remainder = np.member_count as usize % 8;
    if remainder != 0 {
        let allowed = (1u8 << remainder) - 1;
        if np
            .addr_word_bmp
            .last()
            .is_some_and(|byte| byte & !allowed != 0)
        {
            return Err(IrError::BadPoolEntry);
        }
    }

    // Reuse the independently maintained address-coverage validator.  It
    // checks every local ordinal and credits tokenPath only when the selected
    // formatter actually displays token identity.
    validate_nested_structure(ir, &np, false).map_err(|_| IrError::BadField)?;

    let mut descents = 1u8;
    for entry in np.sub_fields() {
        let field = entry?;
        let op = FormatOp::try_from(field.format_op)?;
        let params =
            super::params::parse(ir, field.param_off).map_err(|_| IrError::BadPoolEntry)?;
        let kind = params.terminal_kind.ok_or(IrError::BadField)?;

        // Schema-v6 string-preimage evidence is deliberately top-level only.
        // A nested member has its own hashStruct binding grammar and cannot
        // borrow the parent format's string-evidence ordinal stream.
        if params.eip712_string_preimage_ordinal.is_some()
            || kind == TerminalKind::Eip712StringHashWord
        {
            return Err(IrError::BadField);
        }

        // `PARAM_EXACT_EMPTY_BYTES` has one topology: an always-visible,
        // top-level contract-calldata C1 tail. A nested EIP-712 member is a
        // static encoded-data word, so accepting the marker here would let a
        // future compiler/catalogue drift reuse its meaning where no exact
        // empty ABI tail exists.
        if params.exact_empty_bytes {
            return Err(IrError::BadField);
        }

        if params.visibility != Visibility::Never && !label_has_visible_glyph(field.label) {
            return Err(IrError::BadAscii);
        }

        if let Some(child_payload) = params.nested_struct {
            if child_payload.first() != Some(&NESTED_V3)
                || kind != TerminalKind::NestedStruct
                || op != FormatOp::Raw
                || field.path_off != 0
            {
                return Err(IrError::BadField);
            }
            validate_field(op, kind, params.policy_mask()).map_err(|_| IrError::BadField)?;
            let child = validate_nested_ir(ir, child_payload, np.member_count as usize, depth + 1)?;
            descents = descents.checked_add(child).ok_or(IrError::OverCap)?;
            continue;
        }

        if kind == TerminalKind::NestedStruct || field.path_off == 0 {
            return Err(IrError::BadField);
        }
        let path = ir.path_bytes(field.path_off)?;
        let word = static_word_index(path).ok_or(IrError::BadField)?;
        if word >= np.member_count as usize {
            return Err(IrError::BadField);
        }
        if let Some(token_path) = params.token_path {
            let token_word = static_word_index(token_path).ok_or(IrError::BadField)?;
            if token_word >= np.member_count as usize || !token_path_displays_identity(op, kind) {
                return Err(IrError::BadField);
            }
        }
        validate_field(op, kind, params.policy_mask()).map_err(|_| IrError::BadField)?;
    }
    Ok(descents)
}

/// Parse a `PARAM_NESTED_STRUCT` v0x03 payload into a bounds-checked
/// [`NestedStructParam`]. Returns `Reject` on any malformed / out-of-range
/// layout (fail-closed). The caller must have already routed the bare `0x01`
/// belt marker to a decline — this parser requires the `0x03` version byte.
pub fn parse_nested_struct_param(payload: &[u8]) -> Result<NestedStructParam<'_>, RenderErr> {
    if payload.first() != Some(&NESTED_V3) {
        return Err(RenderErr::Reject("7730 nested version"));
    }
    // Fixed prefix.
    if payload.len() < NESTED_PREFIX_LEN {
        return Err(RenderErr::Reject("7730 nested short"));
    }
    let word_pos = u16::from_be_bytes([payload[1], payload[2]]);
    let type_hash: &[u8; 32] = payload[3..35]
        .try_into()
        .map_err(|_| RenderErr::Reject("7730 nested th"))?;
    let member_count = u16::from_be_bytes([payload[35], payload[36]]);
    if member_count == 0 || member_count as usize > MAX_NESTED_MEMBERS {
        return Err(RenderErr::Reject("7730 nested mc"));
    }
    let flags = payload[37];
    // Only bit0 (is_array) is defined; any reserved bit set is a
    // future-schema payload this firmware must not guess at — fail closed.
    if flags & !0x01 != 0 {
        return Err(RenderErr::Reject("7730 nested flags"));
    }
    let is_array = flags & 0x01 != 0;

    // addr_word_bmp: exactly ceil(member_count/8) bytes.
    let bmp_len = (member_count as usize).div_ceil(8);
    let mut p = NESTED_PREFIX_LEN;
    let addr_word_bmp = payload
        .get(p..p + bmp_len)
        .ok_or(RenderErr::Reject("7730 nested bmp"))?;
    p += bmp_len;

    // sub_field_cnt + the sub-field records (rest of the payload).
    let sub_field_cnt = *payload.get(p).ok_or(RenderErr::Reject("7730 nested sfc"))?;
    p += 1;
    let sub_fields_blob = &payload[p..];

    let np = NestedStructParam {
        word_pos,
        type_hash,
        member_count,
        is_array,
        addr_word_bmp,
        sub_field_cnt,
        sub_fields_blob,
    };

    // The sub-field records must parse AND consume the block EXACTLY (no
    // trailing bytes) — the per-block half of E4-3. Reusing the FieldEntry
    // parser also bounds every label + offset.
    let mut it = np.sub_fields();
    let mut seen: u8 = 0;
    for entry in it.by_ref() {
        entry.map_err(|_| RenderErr::Reject("7730 nested subfield"))?;
        seen += 1;
    }
    if seen != sub_field_cnt {
        return Err(RenderErr::Reject("7730 nested subfield count"));
    }
    if it.cursor() != sub_fields_blob.len() {
        return Err(RenderErr::Reject("7730 nested subfield trailing"));
    }

    Ok(np)
}

/// Pull the next `[u16 BE len][nested_ed]` record from the DFS `nested_blob`
/// starting at `cursor`. Returns `(nested_ed, new_cursor)`. Every read is
/// bounds-checked against the REAL `blob`, so a crafted length only `Reject`s.
pub fn read_next_nested_ed(blob: &[u8], cursor: usize) -> Result<(&[u8], usize), RenderErr> {
    let lo = blob
        .get(
            cursor
                ..cursor
                    .checked_add(2)
                    .ok_or(RenderErr::Reject("7730 blob ovf"))?,
        )
        .ok_or(RenderErr::Reject("7730 blob no len"))?;
    let len = u16::from_be_bytes([lo[0], lo[1]]) as usize;
    let data_start = cursor + 2;
    let data_end = data_start
        .checked_add(len)
        .ok_or(RenderErr::Reject("7730 blob ovf"))?;
    let ed = blob
        .get(data_start..data_end)
        .ok_or(RenderErr::Reject("7730 blob rec oob"))?;
    Ok((ed, data_end))
}

/// The local word index a STATIC path program targets, or `None` if the program
/// is not a pure `RootStructured + FieldIdx*` chain (a `FollowOffset` / array /
/// unknown op → dynamic, which cannot address a static `nested_ed` word).
/// Body-free: sums the `FieldIdx` slot args (each local member is one word).
pub fn static_word_index(prog: &[u8]) -> Option<usize> {
    if prog.first().copied()? != PathOp::RootStructured as u8 {
        return None;
    }
    let mut slot = 0usize;
    let mut p = 1usize;
    while p < prog.len() {
        match PathOp::try_from(prog[p]).ok()? {
            PathOp::FieldIdx => {
                let a = prog.get(p + 1..p + 3)?;
                slot = slot.checked_add(u16::from_be_bytes([a[0], a[1]]) as usize)?;
                p += 3;
            }
            _ => return None,
        }
    }
    Some(slot)
}

/// Validate a nested-struct block's sub-fields against the PINNED metadata,
/// INDEPENDENT of the build gate (E2 + E4-2). For every sub-field:
///   * its render path is a static local word `< member_count` (E4-2 — a word
///     `≥ member_count` would read the adjacent DFS record; a dynamic render
///     path can't address a static `nested_ed` word → both `Reject`);
///   * a local word is credited as COVERED (shown) ONLY if the sub-field
///     actually renders — i.e. `should_render_with_mode(.., compact) == Render`.
///     A `visible:"never"` (or COMPACT-skipped) sub-field is HIDDEN, so its
///     render/tokenPath words do NOT satisfy the address-coverage backstop:
///     crediting a hidden field would let an address word be "covered" yet never
///     displayed — the exact WYSIWYS break E2 exists to prevent, and it must
///     hold independent of build-gate correctness (this is why the visibility
///     filter lives HERE, not only in dbgen). `compact` MUST equal the value the
///     renderer uses (`COMPACT_MODE`) so coverage tracks the render exactly.
/// Then EVERY address-typed local word (per `addr_word_bmp`) must be covered by
/// some SHOWN sub-field's render word OR tokenPath word — else decline.
pub fn validate_nested_structure(
    ir: &Erc7730Ir<'_>,
    np: &NestedStructParam<'_>,
    compact: bool,
) -> Result<(), RenderErr> {
    use super::visibility::{should_render_with_mode, Action};

    let mc = np.member_count as usize;
    let mut covered = [false; MAX_NESTED_MEMBERS];

    for entry in np.sub_fields() {
        let sf: FieldEntry<'_> = entry.map_err(|_| RenderErr::Reject("7730 nested subfield"))?;
        let params = super::params::parse(ir, sf.param_off)?;
        let op = FormatOp::try_from(sf.format_op)
            .map_err(|_| RenderErr::Reject("7730 nested format"))?;
        let kind = params
            .terminal_kind
            .ok_or(RenderErr::Reject("7730 nested terminal kind"))?;
        // Signed-word predicates are defined only for direct top-level EIP-712
        // members. Nested members are already bound through hashStruct; never
        // accept a guard TLV here that the nested renderer would not evaluate.
        if params.word_guard.is_some() {
            return Err(RenderErr::Reject("7730 nested word guard"));
        }
        if params.eip712_string_preimage_ordinal.is_some()
            || kind == TerminalKind::Eip712StringHashWord
        {
            return Err(RenderErr::Reject("7730 nested string preimage"));
        }
        validate_field(op, kind, params.policy_mask())
            .map_err(|_| RenderErr::Reject("7730 nested field policy"))?;

        // v3 depth-2+: a nested-anchor sub-field (itself a `PARAM_NESTED_STRUCT`,
        // e.g. `witness.info` / `witness.outputs`). Its render `path_off` is a
        // placeholder (word 0), NOT a static-word program — so it must be handled
        // HERE, before any `static_word_index` on the placeholder (which could
        // otherwise mis-credit coverage). Its word is a struct/array `hashStruct`
        // word — never an `address` bit in THIS struct's `addr_word_bmp` — so it
        // needs no address coverage; only bound-check its `word_pos` against THIS
        // (the CONTAINING) struct's `member_count` (E4-2 — a `word_pos >= mc`
        // would bind the adjacent DFS record). The interior addresses of the
        // nested struct are covered by ITS OWN `validate_nested_structure` when the
        // renderer recurses into it. (A bare `0x01` belt marker fails the version
        // check in `parse_nested_struct_param` → decline, matching the renderer.)
        if let Some(payload) = params.nested_struct {
            let child = parse_nested_struct_param(payload)?;
            if kind != TerminalKind::NestedStruct
                || op != FormatOp::Raw
                || sf.path_off != 0
                || child.word_pos as usize >= mc
            {
                return Err(RenderErr::Reject("7730 nested anchor ord oob"));
            }
            continue;
        }

        // A word counts as shown ONLY if this sub-field actually renders. A
        // hidden field (never / compact-skipped / must-match-reject) covers
        // NOTHING for the address backstop.
        let shown = matches!(
            should_render_with_mode(&params, None, compact),
            Action::Render
        );

        // Render path → a static local word strictly inside the nested struct.
        // Bounds-checked for EVERY sub-field (E4-2), credited only if shown.
        let prog = ir
            .path_bytes(sf.path_off)
            .map_err(|_| RenderErr::Reject("7730 nested path"))?;
        let w = static_word_index(prog).ok_or(RenderErr::Reject("7730 nested dyn subfield"))?;
        if w >= mc {
            return Err(RenderErr::Reject("7730 nested ord oob"));
        }
        if shown {
            covered[w] = true;
        }

        // tokenPath (if any) → the local word it IDs is covered too, but only
        // when the amount field is SHOWN (E2 credits a *shown-amount* tokenPath;
        // a hidden amount's tokenPath does not surface the address).
        if let Some(tp) = params.token_path {
            let tw = static_word_index(tp).ok_or(RenderErr::Reject("7730 nested tok path"))?;
            if tw >= mc || !token_path_displays_identity(op, kind) {
                return Err(RenderErr::Reject("7730 nested tok oob"));
            }
            if shown {
                covered[tw] = true;
            }
        }
    }

    for i in 0..mc {
        if np.local_word_is_address(i) && !covered[i] {
            return Err(RenderErr::Reject("7730 nested addr uncovered"));
        }
    }
    Ok(())
}

/// Validate every elementary integer word in one already hash-bound EIP-712
/// struct body. Nested anchors are validated when their own authenticated body
/// is consumed; all other sub-fields, including hidden ones, are checked here
/// before an item divider or member page is buffered.
pub fn validate_nested_integer_words(
    ir: &Erc7730Ir<'_>,
    np: &NestedStructParam<'_>,
    nested_ed: &[u8],
) -> Result<(), RenderErr> {
    use super::policy::{integer_word_is_canonical, TerminalKind};

    let expected = (np.member_count as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 nested integer len ovf"))?;
    if nested_ed.len() != expected {
        return Err(RenderErr::Reject("7730 nested integer len"));
    }

    for entry in np.sub_fields() {
        let sf = entry.map_err(|_| RenderErr::Reject("7730 nested subfield"))?;
        let params = super::params::parse(ir, sf.param_off)?;
        if params.eip712_string_preimage_ordinal.is_some()
            || params.terminal_kind == Some(TerminalKind::Eip712StringHashWord)
        {
            return Err(RenderErr::Reject("7730 nested string preimage"));
        }
        if params.nested_struct.is_some() {
            continue;
        }
        let Some(kind @ (TerminalKind::Unsigned | TerminalKind::Signed)) = params.terminal_kind
        else {
            continue;
        };
        let width = params
            .integer_width_bytes
            .ok_or(RenderErr::Reject("7730 nested integer width"))?;
        let prog = ir
            .path_bytes(sf.path_off)
            .map_err(|_| RenderErr::Reject("7730 nested integer path"))?;
        let word_index =
            static_word_index(prog).ok_or(RenderErr::Reject("7730 nested integer dynamic"))?;
        if word_index >= np.member_count as usize {
            return Err(RenderErr::Reject("7730 nested integer ord oob"));
        }
        let start = word_index
            .checked_mul(32)
            .ok_or(RenderErr::Reject("7730 nested integer off ovf"))?;
        let word: &[u8; 32] = nested_ed
            .get(start..start + 32)
            .ok_or(RenderErr::Reject("7730 nested integer oob"))?
            .try_into()
            .map_err(|_| RenderErr::Reject("7730 nested integer word"))?;
        if !integer_word_is_canonical(kind, width, word) {
            return Err(RenderErr::Reject("7730 noncanonical nested integer"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Erc7730Ir, HEADER_LEN, SCHEMA_VER};

    /// Build a minimal contract-context IR whose pool == `pool` and formats
    /// section is empty. Lets us exercise `validate_nested_structure`'s pool
    /// reads (path programs + param blobs) without a full descriptor.
    fn ir_with_pool(pool: &[u8]) -> std::vec::Vec<u8> {
        let hl = HEADER_LEN;
        let pool_len = pool.len() as u16;
        let mut buf = std::vec![0u8; hl];
        buf[0] = SCHEMA_VER;
        buf[1] = 0x01; // CTX_CONTRACT
        buf[2..10].copy_from_slice(&1u64.to_be_bytes());
        buf[126..128].copy_from_slice(&(hl as u16).to_be_bytes());
        buf[128..130].copy_from_slice(&((hl as u16) + pool_len).to_be_bytes());
        buf[130..132].copy_from_slice(&pool_len.to_be_bytes());
        buf[132..134].copy_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(pool);
        buf.push(0u8); // format count = 0
        buf
    }

    /// A PermitSingle-shaped v0x03 payload: member_count 4, addr_bmp 0x01, two
    /// sub-fields (amount → render FieldIdx(1) + tokenPath at param_off; expiration
    /// → render FieldIdx(2)). Both carry the mandatory schema-v5 terminal kind
    /// and integer width.
    /// Path/param offsets index `pool` below.
    fn permit_single_payload() -> std::vec::Vec<u8> {
        let mut p = std::vec![NESTED_V3];
        p.extend_from_slice(&0u16.to_be_bytes()); // word_pos 0
        p.extend_from_slice(&[0xABu8; 32]); // type_hash (opaque here)
        p.extend_from_slice(&4u16.to_be_bytes()); // member_count 4
        p.push(0x00); // flags: non-array
        p.push(0x01); // addr_word_bmp: word 0 (token) is address
        p.push(2); // sub_field_cnt
                   // sub-field 0: amount — tokenAmount(0x03), label "amt"(3), path_off, param_off.
        p.push(0x03);
        p.push(3);
        p.extend_from_slice(b"amt");
        p.extend_from_slice(&1u16.to_be_bytes()); // path_off (render FieldIdx(1))
        p.extend_from_slice(&6u16.to_be_bytes()); // param_off (tokenPath FieldIdx(0))
                                                  // sub-field 1: expiration — date(0x05), label "exp"(3), path + kind params.
        p.push(0x05);
        p.push(3);
        p.extend_from_slice(b"exp");
        p.extend_from_slice(&19u16.to_be_bytes()); // path_off (render FieldIdx(2))
        p.extend_from_slice(&24u16.to_be_bytes()); // param_off (unsigned + width)
        p
    }

    /// Pool laying out the programs the payload above references:
    ///   off 1  : render FieldIdx(1)  = [len 4][10 20 00 01]
    ///   off 6  : params with tokenPath FieldIdx(0) + unsigned terminal kind
    ///   off 19 : render FieldIdx(2) = [len 4][10 20 00 02]
    ///   off 24 : params with unsigned terminal kind + width
    fn permit_single_pool() -> std::vec::Vec<u8> {
        let mut pool = std::vec![0xFFu8]; // offset-0 filler
                                          // off 1: render path FieldIdx(1)
        pool.push(4);
        pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x01]);
        // off 6: tokenPath plus mandatory uint160 terminal semantics.
        pool.push(12); // blob_len
        pool.push(0x30);
        pool.push(4);
        pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x00]);
        pool.extend_from_slice(&[0x47, 1, TerminalKind::Unsigned as u8]);
        pool.extend_from_slice(&[0x48, 1, 20]);
        // off 19: render path FieldIdx(2)
        pool.push(4);
        pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x02]);
        // off 24: mandatory uint48 terminal semantics.
        pool.extend_from_slice(&[6, 0x47, 1, TerminalKind::Unsigned as u8, 0x48, 1, 6]);
        pool
    }

    #[test]
    fn parses_permit_single_payload() {
        let payload = permit_single_payload();
        let np = parse_nested_struct_param(&payload).expect("parses");
        assert_eq!(np.word_pos, 0);
        assert_eq!(np.member_count, 4);
        assert!(!np.is_array);
        assert_eq!(np.addr_word_bmp, &[0x01]);
        assert_eq!(np.sub_field_cnt, 2);
        assert_eq!(np.sub_fields().count(), 2);
    }

    #[test]
    fn nested_subfields_reject_eip712_string_preimage_authority() {
        use crate::render::params::{
            PARAM_EIP712_STRING_PREIMAGE, PARAM_TERMINAL_KIND,
        };

        let mut pool = std::vec![0xFF, 4];
        pool.extend_from_slice(&[
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
        ]);
        pool.extend_from_slice(&[
            6,
            PARAM_TERMINAL_KIND,
            1,
            TerminalKind::Eip712StringHashWord as u8,
            PARAM_EIP712_STRING_PREIMAGE,
            1,
            0,
        ]);

        let mut payload = std::vec![NESTED_V3];
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&[0xAB; 32]);
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.push(0); // flags
        payload.push(0); // address bitmap
        payload.push(1); // sub-field count
        payload.extend_from_slice(&[FormatOp::Raw as u8, 1, b'S']);
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&6u16.to_be_bytes());

        let np = parse_nested_struct_param(&payload).unwrap();
        let ir_bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        assert_eq!(
            validate_nested_structure(&ir, &np, false),
            Err(RenderErr::Reject("7730 nested string preimage"))
        );
        assert_eq!(
            validate_nested_ir(&ir, &payload, 1, 1),
            Err(IrError::BadField)
        );
        assert_eq!(
            validate_nested_integer_words(&ir, &np, &[0u8; 32]),
            Err(RenderErr::Reject("7730 nested string preimage"))
        );
    }

    #[test]
    fn nested_subfields_reject_top_level_word_guard_authority() {
        use crate::render::params::{
            PARAM_INTEGER_WIDTH, PARAM_TERMINAL_KIND, PARAM_WORD_GUARD, WORD_GUARD_EQ,
        };

        let mut pool = std::vec![0xFF, 4];
        pool.extend_from_slice(&[
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
        ]);
        let mut params = std::vec![
            PARAM_TERMINAL_KIND,
            1,
            TerminalKind::Unsigned as u8,
            PARAM_INTEGER_WIDTH,
            1,
            32,
            PARAM_WORD_GUARD,
            33,
            WORD_GUARD_EQ,
        ];
        params.extend_from_slice(&[0u8; 32]);
        pool.push(params.len() as u8);
        pool.extend_from_slice(&params);

        let mut payload = std::vec![NESTED_V3];
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&[0xAB; 32]);
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.push(0); // flags
        payload.push(0); // address bitmap
        payload.push(1); // sub-field count
        payload.extend_from_slice(&[FormatOp::Raw as u8, 1, b'V']);
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&6u16.to_be_bytes());

        let np = parse_nested_struct_param(&payload).expect("nested block parses");
        let ir_bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&ir_bytes).expect("minimal IR");
        assert_eq!(
            validate_nested_structure(&ir, &np, false),
            Err(RenderErr::Reject("7730 nested word guard"))
        );
        assert_eq!(
            validate_nested_ir(&ir, &payload, 1, 1),
            Err(IrError::BadField)
        );
    }

    #[test]
    fn rejects_wrong_version_byte() {
        let mut payload = permit_single_payload();
        payload[0] = 0x01; // bare belt marker is NOT a v0x03 block
        assert!(parse_nested_struct_param(&payload).is_err());
    }

    #[test]
    fn rejects_reserved_flag_bits() {
        let mut payload = permit_single_payload();
        payload[37] = 0x02; // a reserved bit set → fail closed
        assert!(parse_nested_struct_param(&payload).is_err());
    }

    #[test]
    fn rejects_member_count_zero_and_over_cap() {
        let mut z = permit_single_payload();
        z[35] = 0;
        z[36] = 0;
        assert!(parse_nested_struct_param(&z).is_err());
        let mut big = permit_single_payload();
        let over = (MAX_NESTED_MEMBERS as u16) + 1;
        big[35..37].copy_from_slice(&over.to_be_bytes());
        assert!(parse_nested_struct_param(&big).is_err());
    }

    #[test]
    fn rejects_trailing_subfield_bytes() {
        let mut payload = permit_single_payload();
        payload.push(0xEE); // one trailing byte after the last sub-field
        assert!(parse_nested_struct_param(&payload).is_err());
    }

    #[test]
    fn rejects_declared_subfield_count_mismatch() {
        let mut payload = permit_single_payload();
        payload[39] = 3; // claims 3 sub-fields but only 2 records follow
        assert!(parse_nested_struct_param(&payload).is_err());
    }

    #[test]
    fn read_next_nested_ed_bounds() {
        // [len=2][aa bb] then [len=1][cc]
        let blob = std::vec![0x00, 0x02, 0xAA, 0xBB, 0x00, 0x01, 0xCC];
        let (ed0, c0) = read_next_nested_ed(&blob, 0).unwrap();
        assert_eq!(ed0, &[0xAA, 0xBB]);
        assert_eq!(c0, 4);
        let (ed1, c1) = read_next_nested_ed(&blob, c0).unwrap();
        assert_eq!(ed1, &[0xCC]);
        assert_eq!(c1, 7);
        // A length that runs past the real blob → Reject, never OOB.
        let bad = std::vec![0x00, 0x09, 0x01];
        assert!(read_next_nested_ed(&bad, 0).is_err());
    }

    #[test]
    fn static_word_index_sums_fieldidx() {
        assert_eq!(static_word_index(&[0x10, 0x20, 0x00, 0x01]), Some(1));
        assert_eq!(static_word_index(&[0x10, 0x20, 0x00, 0x00]), Some(0));
        // FollowOffset → dynamic → None.
        assert_eq!(static_word_index(&[0x10, 0x25]), None);
        // Missing RootStructured → None.
        assert_eq!(static_word_index(&[0x20, 0x00, 0x01]), None);
    }

    #[test]
    fn validate_nested_ir_rejects_exact_empty_bytes_marker() {
        use crate::render::params::{
            DYNAMIC_KIND_BYTES, PARAM_DYNAMIC_KIND, PARAM_EXACT_EMPTY_BYTES, PARAM_TERMINAL_KIND,
        };

        let mut pool = std::vec![0xFFu8];
        // off 1: nested-local static word 0. This is deliberately not a C1
        // FollowOffset path: nested EIP-712 encodeData has no ABI tail.
        pool.extend_from_slice(&[4, 0x10, 0x20, 0x00, 0x00]);
        // off 6: the otherwise policy-valid Raw/DynamicBytes marker pair.
        pool.extend_from_slice(&[
            8,
            PARAM_DYNAMIC_KIND,
            1,
            DYNAMIC_KIND_BYTES,
            PARAM_TERMINAL_KIND,
            1,
            TerminalKind::DynamicBytes as u8,
            PARAM_EXACT_EMPTY_BYTES,
            0,
        ]);

        let mut payload = std::vec![NESTED_V3];
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&[0xAB; 32]);
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.push(0); // flags
        payload.push(0); // no address-bearing words
        payload.push(1); // one sub-field
        payload.push(crate::ir::FormatOp::Raw as u8);
        payload.push(8);
        payload.extend_from_slice(b"Callback");
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&6u16.to_be_bytes());

        let ir_bytes = ir_with_pool(&pool);
        let ir = Erc7730Ir::parse(&ir_bytes).expect("minimal IR");
        assert_eq!(
            validate_nested_ir(&ir, &payload, 1, 1),
            Err(IrError::BadField)
        );
    }

    #[test]
    fn validate_covers_token_address_via_tokenpath() {
        // PermitSingle: token (word 0) is address-typed and covered ONLY by the
        // amount sub-field's tokenPath (FieldIdx(0)) — NOT a render path. The
        // validator must credit it, else this false-declines (dead feature).
        let payload = permit_single_payload();
        let np = parse_nested_struct_param(&payload).unwrap();
        let ir_bytes = ir_with_pool(&permit_single_pool());
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        validate_nested_structure(&ir, &np, false)
            .expect("token address is covered by the shown-amount tokenPath");
    }

    #[test]
    fn validate_declines_when_address_word_uncovered() {
        // Flip the addr_word_bmp so local word 1 (amount, NOT covered by any
        // token/render-of-an-address path) is claimed address-typed: no sub-field
        // covers it as an address → decline (E2 backstop fires).
        let mut payload = permit_single_payload();
        payload[38] = 0x08; // bit 3 (word 3 = nonce, never shown) marked address
        let np = parse_nested_struct_param(&payload).unwrap();
        let ir_bytes = ir_with_pool(&permit_single_pool());
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        assert!(
            validate_nested_structure(&ir, &np, false).is_err(),
            "an address-typed word with no covering sub-field must decline"
        );
    }

    /// v3 depth-2: `validate_nested_structure` must handle a sub-field that is
    /// ITSELF a nested anchor (`witness.info` / `witness.outputs`). Its render
    /// `path_off` is a placeholder — validate must read the sub-anchor's OWN
    /// `word_pos` and bound-check it against the CONTAINING struct's
    /// `member_count` (E4-2), NOT run `static_word_index` on the placeholder. A
    /// `word_pos < member_count` passes (the interior addresses are covered by the
    /// sub-anchor's own validate during the recursion); `word_pos >= member_count`
    /// declines (it would otherwise bind the adjacent DFS record).
    #[test]
    fn validate_handles_nested_anchor_subfield_word_pos_bound() {
        // Parent struct: member_count 3, NO address words (addr_bmp 0x00), ONE
        // sub-field that is a nested anchor at `child_word_pos`.
        let build = |child_word_pos: u16| -> std::vec::Vec<u8> {
            // Child v0x03 payload (member_count 2, no sub-fields).
            let mut child = std::vec![NESTED_V3];
            child.extend_from_slice(&child_word_pos.to_be_bytes());
            child.extend_from_slice(&[0xCDu8; 32]); // type_hash (opaque)
            child.extend_from_slice(&2u16.to_be_bytes()); // member_count 2
            child.push(0x00); // flags: non-array
            child.push(0x00); // addr_word_bmp (mc 2 → 1 byte)
            child.push(0); // sub_field_cnt 0
                           // Pool: off 0 filler; off 1 = param blob [blob_len][0x41 tag][tlv_len][child].
            let mut pool = std::vec![0xFFu8];
            let blob_len = 2 + child.len() + 3;
            pool.push(blob_len as u8);
            pool.push(0x41); // PARAM_NESTED_STRUCT
            pool.push(child.len() as u8);
            pool.extend_from_slice(&child);
            pool.extend_from_slice(&[0x47, 1, TerminalKind::NestedStruct as u8]);
            // Parent payload: member_count 3, addr_bmp 0x00, one nested-anchor
            // sub-field (FMT_RAW 0x01, label "sub", path_off 0 placeholder,
            // param_off 1 → the child TLV blob above).
            let mut parent = std::vec![NESTED_V3];
            parent.extend_from_slice(&0u16.to_be_bytes()); // word_pos 0
            parent.extend_from_slice(&[0xABu8; 32]); // type_hash
            parent.extend_from_slice(&3u16.to_be_bytes()); // member_count 3
            parent.push(0x00); // flags
            parent.push(0x00); // addr_word_bmp (mc 3 → 1 byte, no address words)
            parent.push(1); // sub_field_cnt 1
            parent.push(0x01); // FMT_RAW
            parent.push(3);
            parent.extend_from_slice(b"sub");
            parent.extend_from_slice(&0u16.to_be_bytes()); // path_off placeholder
            parent.extend_from_slice(&1u16.to_be_bytes()); // param_off → child TLV
                                                           // pack (parent, pool) into a length-tagged vec: [parent_len:2][parent][pool]
            let mut out = std::vec::Vec::new();
            out.extend_from_slice(&(parent.len() as u16).to_be_bytes());
            out.extend_from_slice(&parent);
            out.extend_from_slice(&pool);
            out
        };
        let run = |child_word_pos: u16| -> Result<(), RenderErr> {
            let packed = build(child_word_pos);
            let parent_len = u16::from_be_bytes([packed[0], packed[1]]) as usize;
            let parent = &packed[2..2 + parent_len];
            let pool = &packed[2 + parent_len..];
            let np = parse_nested_struct_param(parent).unwrap();
            let ir_bytes = ir_with_pool(pool);
            let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
            validate_nested_structure(&ir, &np, false)
        };
        // child word_pos 2 < parent member_count 3 → OK (bound-check passes; a
        // struct word is not an address bit, so no coverage is required).
        assert!(
            run(2).is_ok(),
            "nested-anchor sub-field at an in-bounds word_pos passes"
        );
        // child word_pos 3 == member_count → out of bounds → decline (E4-2).
        assert!(
            run(3).is_err(),
            "nested-anchor sub-field word_pos >= member_count must decline (cross-struct confusion)"
        );
    }

    #[test]
    fn validate_declines_address_covered_only_by_hidden_field() {
        // The confirmed adversarial-review finding (E2 visibility gap): make the
        // amount sub-field `visible:"never"` — its tokenPath still POINTS at the
        // token address (word 0), but because the field is HIDDEN at render time
        // it must NOT satisfy the address-coverage backstop. Else the token
        // address is signed but never displayed (WYSIWYS break). Compare to
        // `validate_covers_token_address_via_tokenpath`, which passes because the
        // amount is shown.
        let payload = permit_single_payload_amount_never();
        let np = parse_nested_struct_param(&payload).unwrap();
        let ir_bytes = ir_with_pool(&permit_single_pool_amount_never());
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        assert!(
            validate_nested_structure(&ir, &np, false).is_err(),
            "a `visible:never` sub-field must NOT cover the token address (E2 visibility)"
        );
    }

    /// Like `permit_single_payload` but the amount sub-field's `param_off` points
    /// at a pool blob carrying its tokenPath, terminal kind, AND a
    /// `visible:never` TLV (pool offset 31, see
    /// `permit_single_pool_amount_never`). The amount sub-field's
    /// `param_off` occupies payload bytes `[47..49]` (header 40 + fmt(1) +
    /// label_len(1) + "amt"(3) + path_off(2) = 47).
    fn permit_single_payload_amount_never() -> std::vec::Vec<u8> {
        let mut p = permit_single_payload();
        p[47..49].copy_from_slice(&31u16.to_be_bytes());
        p
    }

    /// The base pool (amount render @1, tokenPath blob @6, expiration render @19,
    /// expiration semantics @24, ending at offset 31) plus a
    /// `tokenPath + visible:never + uint160 semantics` blob at offset 31.
    fn permit_single_pool_amount_never() -> std::vec::Vec<u8> {
        let mut pool = permit_single_pool(); // len == 31
        assert_eq!(pool.len(), 31);
        // off 31: tokenPath + visibility:never + uint160 terminal semantics.
        pool.push(15);
        pool.push(0x30);
        pool.push(4);
        pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x00]);
        pool.push(0x3F);
        pool.push(1);
        pool.push(0x01);
        pool.extend_from_slice(&[0x47, 1, TerminalKind::Unsigned as u8]);
        pool.extend_from_slice(&[0x48, 1, 20]);
        pool
    }
}

#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    // The Kani proofs target the ADVERSARIAL surface — the companion-controlled
    // `nested_blob` (the DFS cursor reader) and any path program (the static
    // word-index extractor). `parse_nested_struct_param` operates on TRUSTED,
    // dbgen-built, Merkle-pinned payload bytes, so its panic-freedom is covered
    // by the concrete reject unit tests above (wrong version, reserved flags,
    // member_count zero/over-cap, trailing bytes, count mismatch) rather than a
    // symbolic CBMC proof: making its `member_count`-driven `bmp_len` slice + the
    // variable-length sub-field parse loop fully symbolic is intractable for
    // CBMC and adds no adversarial coverage (every read is already a checked
    // `.get()`). The two harnesses below are exactly the untrusted-input paths.

    /// The `nested_blob` is FULLY adversarial. Prove the DFS cursor reader never
    /// panics / reads OOB for ANY blob, and that a returned record lies inside
    /// the blob with the cursor strictly advanced past it.
    #[kani::proof]
    #[kani::unwind(4)]
    fn read_next_nested_ed_panic_free_and_in_bounds() {
        const N: usize = 20;
        let blob: [u8; N] = kani::any();
        let cursor: usize = kani::any();
        kani::assume(cursor <= N);
        if let Ok((ed, next)) = read_next_nested_ed(&blob, cursor) {
            // The record and its 2-byte length header lie inside the blob, and
            // the cursor advanced past both (progress ⇒ the DFS loop terminates).
            assert!(next <= blob.len());
            assert!(next >= cursor + 2);
            assert_eq!(next, cursor + 2 + ed.len());
        }
    }

    /// `static_word_index` never panics / overflows for ANY program bytes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn static_word_index_panic_free() {
        const N: usize = 10;
        let prog: [u8; N] = kani::any();
        let _ = static_word_index(&prog);
    }
}
