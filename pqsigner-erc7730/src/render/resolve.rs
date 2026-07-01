//! General ABI path resolver — the shared engine for the C1/C2/C3 coverage
//! increments (dynamic `bytes`/`string`, tuple-member navigation, and fields
//! that sit after other dynamic arguments).
//!
//! # What it does
//!
//! It executes a compiled path program of two navigation ops against the raw
//! calldata body and returns the leaf's byte position:
//!
//! * [`PathOp::FieldIdx`] `(slot)` — advance the current word index by `slot`
//!   (the ABI head-word offset dbgen computed for this field among its
//!   siblings). This is exactly the existing scalar resolver's behaviour.
//! * [`PathOp::FollowOffset`] — the word at the current position is an ABI
//!   *offset* (a dynamic arg / dynamic tuple / dynamic leaf). Read it through
//!   `walk`'s hardened [`read_offset_word`], move the current REGION start
//!   forward by that offset (offsets are relative to the enclosing region's
//!   start — args-body for the top level, the tuple's data start once we have
//!   descended into a dynamic tuple), and reset the word index.
//!
//! # Why it is WYSIWYS-safe
//!
//! arg N's head position is fixed by the *types* of args `0..N` (its signature),
//! which dbgen resolves at compile time (the width-aware slot fix behind
//! `VULN-erc7730-walker-slot-confusion`). So reading the offset word at that
//! signature-fixed slot and following it lands on the SAME calldata position the
//! contract's own ABI decoder reads from — the device shows exactly what
//! executes. Unlike [`super::array::resolve_array`] this needs no "sole dynamic
//! arg / whole-tail" pinning: correct per-arg head slots make the follow correct
//! for multi-dynamic layouts too. Every attacker-controlled read is a
//! bounds-checked `.get()` (`None → Reject`) and every offset is
//! `read_offset_word`-gated (top-28-bytes-zero) then `checked_*`, so no crafted
//! body panics, slices out of bounds, or overflows.
//!
//! The guarantee is *value-equality with an independent ABI decoder*, not merely
//! panic-freedom — see the differential tests in the secure crate.

use pqsigner_tx::typed_call::abi::{read_length_word, read_offset_word, MAX_DYNAMIC_LEN};

use crate::ir::PathOp;

use super::RenderErr;

/// Upper bound on navigation ops in one path program (defence-in-depth against a
/// pathological pinned descriptor; real programs are ≤ ~5 ops). Also bounds the
/// Kani proof.
pub const MAX_PATH_STEPS: usize = 16;

/// The resolved leaf — a byte position inside the calldata body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leaf {
    /// A single static 32-byte word at `body[off .. off + 32]`.
    Word(usize),
    /// A dynamic `bytes`/`string`: length word at `body[off .. off + 32]`, data
    /// at `body[off + 32 .. off + 32 + len]`. Use [`read_dynamic`] to bounds-
    /// check + extract it.
    Dynamic(usize),
}

/// Execute a RootStructured path program's navigation ops (the caller has
/// already consumed the `RootStructured` byte — `prog` is the ops that follow).
/// Returns the leaf position, or `Err` (decline-to-blind) on any malformed /
/// hostile body.
///
/// Leaf kind is structural: a program ending in `FollowOffset` resolves a
/// dynamic leaf (`bytes`/`string`); one ending in `FieldIdx` (or empty) resolves
/// a static word. `FollowOffset` mid-program is a region descent (dynamic tuple).
pub fn resolve_structured(prog: &[u8], body: &[u8]) -> Result<Leaf, RenderErr> {
    let mut region: usize = 0; // start of the current ABI region
    let mut slot: usize = 0; // word index within the current region
    let mut ended_on_follow = false;
    let mut p = 0usize;
    let mut steps = 0usize;

    while p < prog.len() {
        steps += 1;
        if steps > MAX_PATH_STEPS {
            return Err(RenderErr::Reject("7730 res path too long"));
        }
        let op = PathOp::try_from(prog[p]).map_err(|_| RenderErr::Reject("7730 res bad op"))?;
        match op {
            PathOp::FieldIdx => {
                let a = prog
                    .get(p + 1..p + 3)
                    .ok_or(RenderErr::Reject("7730 res trunc fieldidx"))?;
                slot = slot
                    .checked_add(u16::from_be_bytes([a[0], a[1]]) as usize)
                    .ok_or(RenderErr::Reject("7730 res slot ovf"))?;
                p += 3;
                ended_on_follow = false;
            }
            PathOp::FollowOffset => {
                // The word at (region + slot*32) is an offset relative to
                // `region`; read it through the hardened reader and descend.
                let word_off = region
                    .checked_add(
                        slot.checked_mul(32)
                            .ok_or(RenderErr::Reject("7730 res slot ovf"))?,
                    )
                    .ok_or(RenderErr::Reject("7730 res pos ovf"))?;
                let word = body
                    .get(word_off..word_off.checked_add(32).ok_or(RenderErr::Reject("7730 res ovf"))?)
                    .ok_or(RenderErr::Reject("7730 res off oob"))?;
                let offset =
                    read_offset_word(word).ok_or(RenderErr::Reject("7730 res bad offset"))?;
                region = region
                    .checked_add(offset)
                    .ok_or(RenderErr::Reject("7730 res region ovf"))?;
                // The region start must land inside the body (its first word is
                // read below / by the leaf reader).
                if region > body.len() {
                    return Err(RenderErr::Reject("7730 res region oob"));
                }
                slot = 0;
                p += 1;
                ended_on_follow = true;
            }
            _ => return Err(RenderErr::Reject("7730 res op unsup")),
        }
    }

    let pos = region
        .checked_add(
            slot.checked_mul(32)
                .ok_or(RenderErr::Reject("7730 res slot ovf"))?,
        )
        .ok_or(RenderErr::Reject("7730 res pos ovf"))?;
    // Every leaf begins with at least one word (a static word, or a dynamic
    // length word) that must be present.
    if pos
        .checked_add(32)
        .ok_or(RenderErr::Reject("7730 res ovf"))?
        > body.len()
    {
        return Err(RenderErr::Reject("7730 res leaf oob"));
    }
    if ended_on_follow {
        Ok(Leaf::Dynamic(pos))
    } else {
        Ok(Leaf::Word(pos))
    }
}

/// Extract a [`Leaf::Dynamic`] blob (`[u32-ish length][data]`) with full bounds
/// checks. Returns the data slice (`&body[off+32 .. off+32+len]`). The length is
/// read via `walk`'s hardened [`read_length_word`] (top-28-bytes-zero +
/// `MAX_DYNAMIC_LEN`).
pub fn read_dynamic(body: &[u8], off: usize) -> Result<&[u8], RenderErr> {
    let len_word = body
        .get(off..off.checked_add(32).ok_or(RenderErr::Reject("7730 res ovf"))?)
        .ok_or(RenderErr::Reject("7730 res no len"))?;
    let len = read_length_word(len_word).ok_or(RenderErr::Reject("7730 res bad len"))?;
    if len > MAX_DYNAMIC_LEN {
        return Err(RenderErr::Reject("7730 res len cap"));
    }
    let data_start = off
        .checked_add(32)
        .ok_or(RenderErr::Reject("7730 res ovf"))?;
    let data_end = data_start
        .checked_add(len as usize)
        .ok_or(RenderErr::Reject("7730 res ovf"))?;
    body.get(data_start..data_end)
        .ok_or(RenderErr::Reject("7730 res data oob"))
}

// ─────────────────────────────────────────────────────────────────────────
// tokenPath slice/index resolver (Tier B) — token IDENTIFICATION only.
//
// A `tokenAmount` field may point its `tokenPath` at a token address that lives
// inside a dynamic leg: a packed swap `bytes path` (`params.path.[0:20]` = the
// input token, `[-20:]` = the output token) or a dynamic `address[]`
// (`path.[0]` / `path.[-1]`). This resolver navigates to that dynamic region
// with the SAME hardened `resolve_structured` the value paths use, then applies
// ONE terminal extraction op to pull out the 20-byte address.
//
// Why this is WYSIWYS-safe where a rendered-value slice would not be. The 20
// bytes feed the `tokenAmount` token binding: on a metadata match they select
// the verified decimals/symbol; on a DB miss the renderer forces the amount to a
// RAW integer + `! raw, dec=?` (audit M-4) AND shows the extracted address on a
// loud `Token (UNVERIFIED)` page (audit 2026-06-25 MEDIUM-1, `formatters.rs`).
// So the extracted address CAN be displayed — but only as an *advisory,
// explicitly-unverified identity*, never as a value the user is asked to trust,
// and always with the amount degraded to raw. Crucially the display is
// WYSIWYS-faithful: the extraction reads the SAME ABI position the contract
// executes, so a shown token is the token that actually moves.
//
// The property that makes the extraction ops `tokenPath`-only is the blast
// radius of a WRONG/OOB extraction: it returns `Err`, so it can only mis-*name*
// an amount (which then falls to loud raw) — it can never mis-*scale* a routed
// value and never change the recipient (a separate, statically-resolved field).
// Contrast a rendered-VALUE slice (paraswap `pools.[-1]`, a shown pool address
// the user is meant to trust): a wrong extraction there is a confidently-wrong
// displayed recipient = direct theft. That asymmetry is exactly why the
// extraction ops are accepted ONLY here and are `Reject`ed by the value-path
// `resolve_structured` (its `_ => Reject` arm), and why the dbgen compiler emits
// them ONLY for a `tokenPath`, never for a rendered `path`.
//
// Every read is bounds-checked against the ACTUAL `body` buffer (not a
// companion-claimed length), so a crafted length/count word can only shrink
// coverage or force the raw fallback — never read out of bounds or panic.

/// Address byte-width — a tokenPath extraction always yields exactly this.
const ADDR_LEN: usize = 20;

/// The terminal extraction op peeled off a tokenPath program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extract {
    /// `ArraySlice`: `len` bytes of a dynamic `bytes` leaf, from `start`
    /// (`from_end` = false) or from the tail (`from_end` = true, i.e. `[-len:]`).
    Slice {
        start: usize,
        len: usize,
        from_end: bool,
    },
    /// `ArrayIdx(i)`: element `i` of a dynamic 32-byte-stride array.
    Index(usize),
    /// `ArrayLast`: the last element of a dynamic 32-byte-stride array.
    Last,
}

/// Split a tokenPath program into its navigation prefix (`FieldIdx`/
/// `FollowOffset`, handed to [`resolve_structured`]) and an OPTIONAL trailing
/// extraction op. The extraction op, if present, MUST be the final op — any
/// trailing bytes after it are a malformed program (`Reject`).
fn split_extraction(prog: &[u8]) -> Result<(&[u8], Option<Extract>), RenderErr> {
    let mut p = 0usize;
    let mut steps = 0usize;
    while p < prog.len() {
        steps += 1;
        if steps > MAX_PATH_STEPS {
            return Err(RenderErr::Reject("7730 tok path too long"));
        }
        let op = PathOp::try_from(prog[p]).map_err(|_| RenderErr::Reject("7730 tok bad op"))?;
        match op {
            PathOp::FieldIdx => {
                // 1 opcode + 2-byte slot; validated fully by resolve_structured.
                if p.checked_add(3).ok_or(RenderErr::Reject("7730 tok ovf"))? > prog.len() {
                    return Err(RenderErr::Reject("7730 tok trunc fieldidx"));
                }
                p += 3;
            }
            PathOp::FollowOffset => {
                p += 1;
            }
            PathOp::ArrayIdx => {
                let a = prog
                    .get(p + 1..p + 3)
                    .ok_or(RenderErr::Reject("7730 tok trunc idx"))?;
                let i = u16::from_be_bytes([a[0], a[1]]) as usize;
                if p + 3 != prog.len() {
                    return Err(RenderErr::Reject("7730 tok idx not last"));
                }
                return Ok((&prog[..p], Some(Extract::Index(i))));
            }
            PathOp::ArrayLast => {
                if p + 1 != prog.len() {
                    return Err(RenderErr::Reject("7730 tok last not last"));
                }
                return Ok((&prog[..p], Some(Extract::Last)));
            }
            PathOp::ArraySlice => {
                let a = prog
                    .get(p + 1..p + 6)
                    .ok_or(RenderErr::Reject("7730 tok trunc slice"))?;
                let start = u16::from_be_bytes([a[0], a[1]]) as usize;
                let len = u16::from_be_bytes([a[2], a[3]]) as usize;
                let from_end = a[4] != 0;
                if p + 6 != prog.len() {
                    return Err(RenderErr::Reject("7730 tok slice not last"));
                }
                return Ok((
                    &prog[..p],
                    Some(Extract::Slice {
                        start,
                        len,
                        from_end,
                    }),
                ));
            }
            _ => return Err(RenderErr::Reject("7730 tok op unsup")),
        }
    }
    Ok((prog, None))
}

/// Low 20 bytes of a right-aligned ABI address word at `body[off..off+32]`.
fn low20_of_word(body: &[u8], off: usize) -> Result<[u8; ADDR_LEN], RenderErr> {
    let lo = off.checked_add(12).ok_or(RenderErr::Reject("7730 tok ovf"))?;
    let hi = off.checked_add(32).ok_or(RenderErr::Reject("7730 tok ovf"))?;
    let w = body
        .get(lo..hi)
        .ok_or(RenderErr::Reject("7730 tok word oob"))?;
    let mut a = [0u8; ADDR_LEN];
    a.copy_from_slice(w);
    Ok(a)
}

/// Extract a 20-byte address from a dynamic `bytes` leaf (packed swap path).
/// `len` MUST be 20 (an address); `from_end` selects `[-20:]` vs `[start:start+20]`.
fn slice_address(
    body: &[u8],
    off: usize,
    start: usize,
    len: usize,
    from_end: bool,
) -> Result<[u8; ADDR_LEN], RenderErr> {
    if len != ADDR_LEN {
        return Err(RenderErr::Reject("7730 tok slice not 20"));
    }
    let data = read_dynamic(body, off)?; // hardened len read + full bounds
    let dl = data.len();
    let s = if from_end {
        dl.checked_sub(ADDR_LEN)
            .ok_or(RenderErr::Reject("7730 tok slice short"))?
    } else {
        start
    };
    let e = s.checked_add(ADDR_LEN).ok_or(RenderErr::Reject("7730 tok ovf"))?;
    let bytes = data
        .get(s..e)
        .ok_or(RenderErr::Reject("7730 tok slice oob"))?;
    let mut a = [0u8; ADDR_LEN];
    a.copy_from_slice(bytes);
    Ok(a)
}

/// Which element of a dynamic 32-byte-stride array to read.
enum ArrayIndex {
    At(usize),
    Last,
}

/// Extract the low-20 address of one element of a dynamic array (`T[]`) whose
/// region starts at `off` = `[count(32)][elem0(32)][elem1(32)]…`. The count word
/// is companion-controlled, so `idx < count` AND the element's 32 bytes must lie
/// inside the real body — both checked; either failure `Reject`s to raw fallback.
fn array_elem_address(
    body: &[u8],
    off: usize,
    which: ArrayIndex,
) -> Result<[u8; ADDR_LEN], RenderErr> {
    let hi = off.checked_add(32).ok_or(RenderErr::Reject("7730 tok ovf"))?;
    let count_word = body
        .get(off..hi)
        .ok_or(RenderErr::Reject("7730 tok no count"))?;
    let count = read_length_word(count_word).ok_or(RenderErr::Reject("7730 tok bad count"))? as usize;
    let idx = match which {
        ArrayIndex::At(i) => i,
        ArrayIndex::Last => count
            .checked_sub(1)
            .ok_or(RenderErr::Reject("7730 tok empty arr"))?,
    };
    if idx >= count {
        return Err(RenderErr::Reject("7730 tok idx oob"));
    }
    // elem_off = off + 32 + idx*32
    let elem_off = off
        .checked_add(32)
        .and_then(|b| idx.checked_mul(32).and_then(|o| b.checked_add(o)))
        .ok_or(RenderErr::Reject("7730 tok ovf"))?;
    low20_of_word(body, elem_off)
}

/// Resolve a tokenPath program (the bytes AFTER the `RootStructured` byte the
/// caller already consumed) to a 20-byte token address. See the module comment
/// above for the WYSIWYS/safety contract. This is the ONLY resolver that accepts
/// the `ArraySlice`/`ArrayIdx`/`ArrayLast` extraction ops.
pub fn resolve_token_address(prog: &[u8], body: &[u8]) -> Result<[u8; ADDR_LEN], RenderErr> {
    let (nav, extraction) = split_extraction(prog)?;
    let leaf = resolve_structured(nav, body)?;
    match (extraction, leaf) {
        // Static address word (`params.tokenIn`) — no extraction op.
        (None, Leaf::Word(off)) => low20_of_word(body, off),
        (None, Leaf::Dynamic(_)) => Err(RenderErr::Reject("7730 tok dyn no slice")),
        // Packed `bytes` slice (`params.path.[0:20]` / `[-20:]`).
        (Some(Extract::Slice { start, len, from_end }), Leaf::Dynamic(off)) => {
            slice_address(body, off, start, len, from_end)
        }
        // Dynamic `address[]` element (`path.[0]` / `path.[-1]`).
        (Some(Extract::Index(i)), Leaf::Dynamic(off)) => {
            array_elem_address(body, off, ArrayIndex::At(i))
        }
        (Some(Extract::Last), Leaf::Dynamic(off)) => {
            array_elem_address(body, off, ArrayIndex::Last)
        }
        // An extraction op requires a dynamic leaf; a static word is a
        // descriptor/compile bug — decline (raw fallback), never guess.
        (Some(_), Leaf::Word(_)) => Err(RenderErr::Reject("7730 tok extract on word")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    // Wire helpers.
    const FIELD_IDX: u8 = PathOp::FieldIdx as u8; // 0x20
    const FOLLOW: u8 = PathOp::FollowOffset as u8; // 0x25

    fn field(slot: u16) -> [u8; 3] {
        let b = slot.to_be_bytes();
        [FIELD_IDX, b[0], b[1]]
    }
    fn w(n: u64) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[24..].copy_from_slice(&n.to_be_bytes());
        x
    }

    #[test]
    fn fieldidx_only_matches_static_slot_sum() {
        // `f(uint256 a, uint256 b)` body, read `b` (slot 1). No FollowOffset →
        // Word at 32, identical to the legacy scalar resolver.
        let mut body = Vec::new();
        body.extend_from_slice(&w(0xAA));
        body.extend_from_slice(&w(0xBB));
        let prog = field(1);
        assert_eq!(resolve_structured(&prog, &body).unwrap(), Leaf::Word(32));
    }

    #[test]
    fn c1_top_level_dynamic_bytes() {
        // `send(uint256 x, bytes data)`: head = [x][offset], tail = [len][data].
        // Read `data` (arg slot 1) → FollowOffset → Dynamic at 64.
        let mut body = Vec::new();
        body.extend_from_slice(&w(0x11)); // x
        body.extend_from_slice(&w(64)); // offset to data (relative to args start)
        body.extend_from_slice(&w(3)); // len = 3
        body.extend_from_slice(&{
            let mut d = [0u8; 32];
            d[..3].copy_from_slice(b"abc");
            d
        });
        let mut prog = field(1).to_vec();
        prog.push(FOLLOW);
        let leaf = resolve_structured(&prog, &body).unwrap();
        assert_eq!(leaf, Leaf::Dynamic(64));
        assert_eq!(read_dynamic(&body, 64).unwrap(), b"abc");
    }

    #[test]
    fn c2_dynamic_tuple_member() {
        // `swap((uint256 amount, uint256 min) desc)` where desc is a DYNAMIC
        // tuple (pretend it has a dynamic member so it's offset-placed): head =
        // [offset], tail(tuple data) = [amount][min]. Read desc.min:
        // FieldIdx(0) FollowOffset FieldIdx(1) → Word at 32(tuple)+32 = 96.
        let mut body = Vec::new();
        body.extend_from_slice(&w(32)); // offset to tuple data
        body.extend_from_slice(&w(0xA)); // amount (tuple slot 0)
        body.extend_from_slice(&w(0xB)); // min (tuple slot 1)
        let mut prog = field(0).to_vec();
        prog.push(FOLLOW);
        prog.extend_from_slice(&field(1));
        let leaf = resolve_structured(&prog, &body).unwrap();
        // tuple data region starts at byte 32; min is slot 1 → byte 32 + 32 = 64.
        assert_eq!(leaf, Leaf::Word(64));
        assert_eq!(&body[64..96], &w(0xB));
    }

    #[test]
    fn hostile_offset_out_of_bounds_declines() {
        let mut body = Vec::new();
        body.extend_from_slice(&w(1_000_000)); // offset way past the body
        let mut prog = field(0).to_vec();
        prog.push(FOLLOW);
        assert!(resolve_structured(&prog, &body).is_err());
    }

    #[test]
    fn hostile_offset_top_bytes_nonzero_declines() {
        let mut body = Vec::new();
        let mut bad = w(64);
        bad[0] = 0x01; // top-28-bytes nonzero → read_offset_word rejects
        body.extend_from_slice(&bad);
        body.extend_from_slice(&w(0));
        let mut prog = field(0).to_vec();
        prog.push(FOLLOW);
        assert!(resolve_structured(&prog, &body).is_err());
    }

    #[test]
    fn truncated_body_declines_no_panic() {
        // Program wants slot 5 in a 1-word body.
        let body = w(0).to_vec();
        let prog = field(5);
        assert!(resolve_structured(&prog, &body).is_err());
    }

    // ── tokenPath slice/index resolver (Tier B) ─────────────────────────────
    const ARR_IDX: u8 = PathOp::ArrayIdx as u8; // 0x21
    const ARR_SLICE: u8 = PathOp::ArraySlice as u8; // 0x22
    const ARR_LAST: u8 = PathOp::ArrayLast as u8; // 0x23

    fn slice_op(start: u16, len: u16, from_end: bool) -> [u8; 6] {
        let s = start.to_be_bytes();
        let l = len.to_be_bytes();
        [ARR_SLICE, s[0], s[1], l[0], l[1], u8::from(from_end)]
    }
    fn idx_op(i: u16) -> [u8; 3] {
        let b = i.to_be_bytes();
        [ARR_IDX, b[0], b[1]]
    }
    /// A packed swap path `bytes`: token0(20) ‖ fee(3) ‖ token1(20), padded.
    fn packed_path(t0: u8, t1: u8) -> ([u8; 20], [u8; 20], Vec<u8>) {
        let a0 = [t0; 20];
        let a1 = [t1; 20];
        let mut data = Vec::new();
        data.extend_from_slice(&a0);
        data.extend_from_slice(&[0x00, 0x0b, 0xb8]); // fee 3000
        data.extend_from_slice(&a1);
        (a0, a1, data)
    }
    /// `f(bytes path)` body with `path` at arg 0.
    fn body_sole_bytes(data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&w(32)); // offset to path
        body.extend_from_slice(&w(data.len() as u64)); // length word
        let mut padded = data.to_vec();
        while padded.len() % 32 != 0 {
            padded.push(0);
        }
        body.extend_from_slice(&padded);
        body
    }

    #[test]
    fn tokenpath_slice_first20_is_input_token() {
        let (a0, _a1, data) = packed_path(0x11, 0x22);
        let body = body_sole_bytes(&data);
        let mut prog = field(0).to_vec();
        prog.push(FOLLOW);
        prog.extend_from_slice(&slice_op(0, 20, false)); // [0:20]
        assert_eq!(resolve_token_address(&prog, &body).unwrap(), a0);
    }

    #[test]
    fn tokenpath_slice_last20_is_output_token() {
        let (_a0, a1, data) = packed_path(0x11, 0x22);
        let body = body_sole_bytes(&data);
        let mut prog = field(0).to_vec();
        prog.push(FOLLOW);
        prog.extend_from_slice(&slice_op(0, 20, true)); // [-20:]
        assert_eq!(resolve_token_address(&prog, &body).unwrap(), a1);
    }

    /// `f(address[] toks)` body with two element addresses.
    fn body_address_array(elems: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&w(32)); // offset to array
        body.extend_from_slice(&w(elems.len() as u64)); // count word
        for &e in elems {
            let mut word = [0u8; 32];
            word[12..].copy_from_slice(&[e; 20]); // right-aligned address
            body.extend_from_slice(&word);
        }
        body
    }

    #[test]
    fn tokenpath_array_index0_and_last() {
        let body = body_address_array(&[0xAB, 0xCD]);
        // [0] → first element
        let mut p0 = field(0).to_vec();
        p0.push(FOLLOW);
        p0.extend_from_slice(&idx_op(0));
        assert_eq!(resolve_token_address(&p0, &body).unwrap(), [0xAB; 20]);
        // [-1] → last element
        let mut pl = field(0).to_vec();
        pl.push(FOLLOW);
        pl.push(ARR_LAST);
        assert_eq!(resolve_token_address(&pl, &body).unwrap(), [0xCD; 20]);
    }

    #[test]
    fn tokenpath_static_word_no_extraction() {
        // `f(address token)` → the low 20 bytes of the static word.
        let mut body = Vec::new();
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&[0x7E; 20]);
        body.extend_from_slice(&word);
        let prog = field(0);
        assert_eq!(resolve_token_address(&prog, &body).unwrap(), [0x7E; 20]);
    }

    #[test]
    fn tokenpath_failsafe_negatives_decline_never_panic() {
        let (_a0, _a1, data) = packed_path(0x11, 0x22);
        let body = body_sole_bytes(&data);
        // slice len != 20 (would not be an address) → decline.
        let mut bad_len = field(0).to_vec();
        bad_len.push(FOLLOW);
        bad_len.extend_from_slice(&slice_op(0, 16, false));
        assert!(resolve_token_address(&bad_len, &body).is_err());
        // start+20 past the packed data → decline (raw fallback), no panic.
        let mut oob = field(0).to_vec();
        oob.push(FOLLOW);
        oob.extend_from_slice(&slice_op(40, 20, false));
        assert!(resolve_token_address(&oob, &body).is_err());
        // array index past a claimed-large count on a short body → decline.
        let arr = body_address_array(&[0x01]); // count 1
        let mut idx5 = field(0).to_vec();
        idx5.push(FOLLOW);
        idx5.extend_from_slice(&idx_op(5));
        assert!(resolve_token_address(&idx5, &arr).is_err());
        // extraction op on a STATIC word leaf → decline (never guess).
        let mut static_body = Vec::new();
        static_body.extend_from_slice(&w(0x1234));
        let mut slice_on_word = field(0).to_vec();
        slice_on_word.extend_from_slice(&slice_op(0, 20, false));
        assert!(resolve_token_address(&slice_on_word, &static_body).is_err());
        // trailing junk after the extraction op → malformed → decline.
        let mut junk = field(0).to_vec();
        junk.push(FOLLOW);
        junk.extend_from_slice(&idx_op(0));
        junk.push(0x20); // extra op after a terminal → reject
        assert!(resolve_token_address(&junk, &body).is_err());
    }
}

#[cfg(kani)]
mod kani_harness {
    use super::*;

    /// Panic/OOB/overflow freedom over a symbolic program + body: the resolver
    /// declines-to-blind on ANY hostile input rather than crashing, and any
    /// returned leaf position is in-bounds.
    #[kani::proof]
    // Covers BOTH loops the harness reaches: the ≤7-step program loop AND the
    // 28-byte top-zero scan inside `read_offset_word`/`read_length_word` (the
    // same reader the sibling `resolve_array_multi` harness unwinds at 34). A
    // lower bound (was 6) fails the unwinding assertion on the reader loop.
    #[kani::unwind(34)]
    fn resolve_structured_panic_free_and_in_bounds() {
        const PROG_LEN: usize = 7; // up to 2 FieldIdx + FollowOffset shapes
        const BODY_LEN: usize = 160; // 5 words
        let prog: [u8; PROG_LEN] = kani::any();
        let body: [u8; BODY_LEN] = kani::any();
        if let Ok(leaf) = resolve_structured(&prog, &body) {
            match leaf {
                Leaf::Word(off) => {
                    assert!(off.checked_add(32).map(|e| e <= body.len()).unwrap_or(false));
                }
                Leaf::Dynamic(off) => {
                    assert!(off.checked_add(32).map(|e| e <= body.len()).unwrap_or(false));
                    // read_dynamic must also never panic on the resolved leaf.
                    let _ = read_dynamic(&body, off);
                }
            }
        }
    }

    // Tier B tokenPath extraction — threat model: the path PROGRAM is trusted
    // (Merkle-pinned IR built by dbgen), the calldata BODY is fully adversarial
    // (offset word, length/count word, data — every byte the companion's).
    // These harnesses fix each real program shape dbgen emits and prove the
    // resolver never panics / reads out of bounds / overflows for ANY body, so a
    // crafted length/count word only forces the raw-amount fallback.
    const FI: u8 = PathOp::FieldIdx as u8;
    const FO: u8 = PathOp::FollowOffset as u8;
    const SL: u8 = PathOp::ArraySlice as u8;
    const IX: u8 = PathOp::ArrayIdx as u8;
    const LA: u8 = PathOp::ArrayLast as u8;
    const KBODY: usize = 128; // 4 words — enough for offset→len→data with a tail

    /// `params.path.[0:20]` / `[-20:]`: nested dynamic-tuple → dynamic `bytes`
    /// (two FollowOffsets), then a 20-byte slice from start (symbolic) or tail.
    #[kani::proof]
    #[kani::unwind(34)]
    fn tok_bytes_slice_panic_free() {
        let from_end: u8 = kani::any();
        let s: u16 = kani::any();
        let prog = [
            FI, 0, 0, FO, // descend the dynamic tuple `params`
            FI, 0, 0, FO, // descend the dynamic `bytes path`
            SL, (s >> 8) as u8, s as u8, 0x00, 0x14, from_end, // ArraySlice(start=s, len=20)
        ];
        let body: [u8; KBODY] = kani::any();
        let _ = resolve_token_address(&prog, &body);
    }

    /// `path.[i]`: top-level dynamic `address[]`, element index symbolic.
    #[kani::proof]
    #[kani::unwind(34)]
    fn tok_array_index_panic_free() {
        let i: u16 = kani::any();
        let prog = [FI, 0, 2, FO, IX, (i >> 8) as u8, i as u8];
        let body: [u8; KBODY] = kani::any();
        let _ = resolve_token_address(&prog, &body);
    }

    /// `path.[-1]`: last element of a top-level dynamic `address[]` — the count
    /// word is adversarial (idx = count-1).
    #[kani::proof]
    #[kani::unwind(34)]
    fn tok_array_last_panic_free() {
        let prog = [FI, 0, 2, FO, LA];
        let body: [u8; KBODY] = kani::any();
        let _ = resolve_token_address(&prog, &body);
    }
}
