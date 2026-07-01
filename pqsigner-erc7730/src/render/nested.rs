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
//! `nested_blob`; a hostile one can only force a `Reject` (decline-to-blind).

use core::convert::TryFrom;

use crate::ir::{Erc7730Ir, FieldEntry, FieldIter, PathOp, MAX_NESTED_MEMBERS};
use crate::walker::path_bytes;

use super::RenderErr;

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
        .get(cursor..cursor.checked_add(2).ok_or(RenderErr::Reject("7730 blob ovf"))?)
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
/// INDEPENDENT of the build gate (E2 + E4-2). For every visible sub-field:
///   * its render path is a static local word `< member_count` (E4-2 — a word
///     `≥ member_count` would read the adjacent DFS record; a dynamic render
///     path can't address a static `nested_ed` word → both `Reject`);
///   * a `tokenAmount`'s `tokenPath` local word is credited as covered.
/// Then EVERY address-typed local word (per `addr_word_bmp`) must be covered by
/// some sub-field's render word OR tokenPath word — else decline. This delivers
/// the belt's "survives a gate regression" promise as a standalone control.
pub fn validate_nested_structure(
    ir: &Erc7730Ir<'_>,
    np: &NestedStructParam<'_>,
) -> Result<(), RenderErr> {
    let mc = np.member_count as usize;
    let mut covered = [false; MAX_NESTED_MEMBERS];

    for entry in np.sub_fields() {
        let sf: FieldEntry<'_> = entry.map_err(|_| RenderErr::Reject("7730 nested subfield"))?;

        // Render path → a static local word strictly inside the nested struct.
        let prog = path_bytes(ir, sf.path_off).map_err(|_| RenderErr::Reject("7730 nested path"))?;
        let w = static_word_index(prog).ok_or(RenderErr::Reject("7730 nested dyn subfield"))?;
        if w >= mc {
            return Err(RenderErr::Reject("7730 nested ord oob"));
        }
        covered[w] = true;

        // tokenPath (if any) → the local word it IDs is covered too (E2 credits
        // the token address a tokenAmount reaches, which is never a render word).
        let params = super::params::parse(ir, sf.param_off)?;
        if let Some(tp) = params.token_path {
            if let Some(tw) = static_word_index(tp) {
                if tw >= mc {
                    return Err(RenderErr::Reject("7730 nested tok oob"));
                }
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
    /// → render FieldIdx(2), no params). Path/param offsets index `pool` below.
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
        // sub-field 1: expiration — date(0x05), label "exp"(3), path_off, param_off 0.
        p.push(0x05);
        p.push(3);
        p.extend_from_slice(b"exp");
        p.extend_from_slice(&13u16.to_be_bytes()); // path_off (render FieldIdx(2), pool off 13)
        p.extend_from_slice(&0u16.to_be_bytes()); // no params
        p
    }

    /// Pool laying out the programs the payload above references:
    ///   off 1  : render FieldIdx(1)  = [len 4][10 20 00 01]
    ///   off 6  : param blob with tokenPath FieldIdx(0)
    ///   off 12 : render FieldIdx(2)  = [len 4][10 20 00 02]
    fn permit_single_pool() -> std::vec::Vec<u8> {
        let mut pool = std::vec![0xFFu8]; // offset-0 filler
        // off 1: render path FieldIdx(1)
        pool.push(4);
        pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x01]);
        // off 6: param blob = [blob_len][PARAM_TOKEN_PATH(0x30) len=4 | 10 20 00 00]
        pool.push(6); // blob_len
        pool.push(0x30);
        pool.push(4);
        pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x00]);
        // off 12: render path FieldIdx(2)
        pool.push(4);
        pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x02]);
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
    fn validate_covers_token_address_via_tokenpath() {
        // PermitSingle: token (word 0) is address-typed and covered ONLY by the
        // amount sub-field's tokenPath (FieldIdx(0)) — NOT a render path. The
        // validator must credit it, else this false-declines (dead feature).
        let payload = permit_single_payload();
        let np = parse_nested_struct_param(&payload).unwrap();
        let ir_bytes = ir_with_pool(&permit_single_pool());
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        validate_nested_structure(&ir, &np).expect("token address is covered by the tokenPath");
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
            validate_nested_structure(&ir, &np).is_err(),
            "an address-typed word with no covering sub-field must decline"
        );
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
