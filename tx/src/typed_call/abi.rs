//! Strict Solidity-ABI walker for the Phase 2 typed-args render.
//!
//! Two passes per the handoff doc § Sub-component 2:
//!
//!   1. **Shape pass** — verify the calldata body's geometry matches
//!      the parsed type list. Refuses any out-of-range offset/length,
//!      any non-canonical packing, any overall length mismatch.
//!   2. **Render pass** — runs only after shape pass succeeded; iterates
//!      the captured per-arg records and hands each one to the renderer.
//!
//! Strictness — Phase 2 first cut admits ONLY:
//!
//!   * Static primitives: `uintN`, `intN`, `address`, `bool`, `bytesN`.
//!   * `T[N]` and `T[]` where `T` is a static primitive (above).
//!   * Dynamic `bytes` / `string`.
//!
//! Tuples, nested arrays, and arrays whose element is itself dynamic
//! cause the walker to return `None` ⇒ the renderer falls back to the
//! Phase 1 BLIND SIGN flow. The handoff doc explicitly names tuples /
//! nested arrays as Phase 2 out-of-scope (see `out-of-scope risks`).
//!
//! Canonical packing — the walker REQUIRES dynamic tails to appear in
//! arg order, immediately after the static head, with each tail padded
//! to a 32-byte boundary. Standard Solidity ABI encoders produce this
//! shape. Any deviation (gaps, reordering, overlap) ⇒ fall back. This
//! is stricter than the spec but safer for a trusted display: a
//! non-canonical encoding that the wallet types differently from the
//! contract is exactly the spoofing avenue we want to refuse.
//!
//! Extracted verbatim (behaviour-identical) from
//! `secure/src/tx/typed_call/abi.rs` so the WYSIWYS shape/render passes
//! can be host-compiled and bounded-verified with Kani — see the
//! `#[cfg(kani)] mod verification` block at the bottom. The only change
//! from the original is widening the in-crate `pub(crate)` surface to
//! `pub` (the secure re-export shim + the firmware renderer live in a
//! separate crate) and importing `U256` from `pqsigner_tx_core`
//! directly (in `secure`, `crate::tx::eip1559` is a re-export of that
//! same type, so the renderer's `read_u256` signature is unchanged).

#![allow(dead_code)]

use crate::erc20::calldata::{decode_address_word, decode_u256_word};
use pqsigner_tx_core::eip1559::U256;

use super::parser::{ParsedSig, TypeId, TypeRef, MAX_ARGS};

/// One walked top-level arg, ready for the renderer to consume.
#[derive(Clone, Copy)]
pub struct Walked {
    pub type_id: TypeId,
    /// Byte offset into the body slice (`inner_data[4..]`).
    ///
    ///   * Static primitive          → start of the 32-byte head word
    ///   * Static array `T[N]`        → start of the first inline element
    ///   * Dynamic `bytes`/`string`   → start of the length word in tail
    ///   * Dynamic `T[]`              → start of the length word in tail
    pub body_off: usize,
    /// Element count.
    ///
    ///   * Static primitive  → 1 (unused)
    ///   * Static array T[N] → N
    ///   * Dynamic bytes/string → length in BYTES
    ///   * Dynamic T[]        → length in ELEMENTS
    pub count: u32,
}

pub struct WalkedSig {
    pub args: [Walked; MAX_ARGS],
    pub arg_count: usize,
}

/// Hard cap on dynamic length to bound the rendering work and avoid
/// overflow when computing payload sizes. 1 MiB is dramatically more
/// than any sane signing UX and 4× larger than `MAX_TX_LEN`, so any
/// real calldata will pass — we're only filtering attacker-crafted
/// length words like `2^200`.
pub const MAX_DYNAMIC_LEN: u32 = 1 << 20;

/// Top-level walk. `body` is `inner_data[4..]` — the calldata after
/// the 4-byte selector. Returns `None` on any shape violation OR any
/// type the first cut declines.
pub fn walk<'a>(parsed: &ParsedSig<'a>, body: &[u8]) -> Option<WalkedSig> {
    if body.len() % 32 != 0 {
        // The ABI head + every dynamic-payload section is 32-byte
        // aligned; any other body length is malformed.
        return None;
    }

    // Pass 1a: classify every top-level arg + sum the static head size.
    // We compute head_size up front so the dynamic-tail-offset checks
    // can refer to it.
    let mut classes: [ArgClass; MAX_ARGS] = [ArgClass::Decline; MAX_ARGS];
    let mut head_size: usize = 0;
    for i in 0..parsed.arg_count {
        let class = classify(parsed, parsed.args[i])?;
        head_size = head_size.checked_add(class.head_size())?;
        classes[i] = class;
    }
    if head_size > body.len() {
        return None;
    }

    // Pass 1b: walk head + tail, validating geometry. Tails MUST appear
    // in arg order, immediately after the static head, each padded to
    // a 32-byte boundary.
    let mut head_pos: usize = 0;
    let mut tail_cursor: usize = head_size;
    let mut walked: [Walked; MAX_ARGS] = [Walked { type_id: 0, body_off: 0, count: 0 }; MAX_ARGS];

    for i in 0..parsed.arg_count {
        let class = classes[i];
        match class {
            ArgClass::StaticPrimitive => {
                walked[i] = Walked {
                    type_id: parsed.args[i],
                    body_off: head_pos,
                    count: 1,
                };
                head_pos += 32;
            }
            ArgClass::StaticArray { count } => {
                walked[i] = Walked {
                    type_id: parsed.args[i],
                    body_off: head_pos,
                    count,
                };
                head_pos += 32 * count as usize;
            }
            ArgClass::DynBytes | ArgClass::DynString | ArgClass::DynArrayPrim => {
                if head_pos + 32 > body.len() {
                    return None;
                }
                let offset = read_offset_word(&body[head_pos..head_pos + 32])?;
                head_pos += 32;
                if offset != tail_cursor {
                    // Non-canonical packing.
                    return None;
                }
                if offset + 32 > body.len() {
                    return None;
                }
                let length = read_length_word(&body[offset..offset + 32])?;
                if length > MAX_DYNAMIC_LEN {
                    return None;
                }
                let payload_unpadded: u64 = match class {
                    ArgClass::DynBytes | ArgClass::DynString => length as u64,
                    ArgClass::DynArrayPrim => (length as u64) * 32,
                    _ => unreachable!(),
                };
                let payload_padded = round_up_to_32(payload_unpadded)?;
                let end = (offset as u64)
                    .checked_add(32)?
                    .checked_add(payload_padded)?;
                if end > body.len() as u64 {
                    return None;
                }
                tail_cursor = end as usize;
                walked[i] = Walked {
                    type_id: parsed.args[i],
                    body_off: offset,
                    count: length,
                };
            }
            ArgClass::Decline => return None,
        }
    }

    if head_pos != head_size {
        return None;
    }
    // Total body length MUST equal head + every tail section. The
    // handoff doc calls this out as the "static-shape match" check.
    if tail_cursor != body.len() {
        return None;
    }

    Some(WalkedSig { args: walked, arg_count: parsed.arg_count })
}

#[derive(Clone, Copy)]
enum ArgClass {
    /// 32-byte head, no tail. Renders directly from the head word.
    StaticPrimitive,
    /// `count * 32` bytes inline in the head, no tail. Element type
    /// is a static primitive.
    StaticArray { count: u32 },
    /// 32-byte offset in head, length+padded-bytes in tail.
    DynBytes,
    DynString,
    /// 32-byte offset in head, length + length*32 in tail. Element
    /// type is a static primitive.
    DynArrayPrim,
    Decline,
}

impl ArgClass {
    fn head_size(self) -> usize {
        match self {
            ArgClass::StaticPrimitive => 32,
            ArgClass::StaticArray { count } => 32 * count as usize,
            ArgClass::DynBytes | ArgClass::DynString | ArgClass::DynArrayPrim => 32,
            ArgClass::Decline => 0,
        }
    }
}

fn classify(parsed: &ParsedSig<'_>, id: TypeId) -> Option<ArgClass> {
    match parsed.arena.get(id) {
        TypeRef::Uint(_)
        | TypeRef::Int(_)
        | TypeRef::Address
        | TypeRef::Bool
        | TypeRef::BytesN(_) => Some(ArgClass::StaticPrimitive),
        TypeRef::Bytes => Some(ArgClass::DynBytes),
        TypeRef::String => Some(ArgClass::DynString),
        TypeRef::Array { elem, fixed_len } => {
            if !is_static_primitive(parsed, *elem) {
                return Some(ArgClass::Decline);
            }
            match fixed_len {
                None => Some(ArgClass::DynArrayPrim),
                Some(n) => {
                    let n = *n;
                    if n == 0 || n > 256 {
                        // Solidity rejects T[0]; cap N to keep the head
                        // size sane (256 * 32 = 8 KiB head is already
                        // larger than any realistic calldata).
                        return Some(ArgClass::Decline);
                    }
                    Some(ArgClass::StaticArray { count: n })
                }
            }
        }
        TypeRef::Tuple { .. } => Some(ArgClass::Decline),
    }
}

fn is_static_primitive(parsed: &ParsedSig<'_>, id: TypeId) -> bool {
    matches!(
        parsed.arena.get(id),
        TypeRef::Uint(_)
            | TypeRef::Int(_)
            | TypeRef::Address
            | TypeRef::Bool
            | TypeRef::BytesN(_)
    )
}

/// Read a 32-byte word as a u32 offset. Top 28 bytes MUST be zero;
/// otherwise the calldata is malformed (or attacker-crafted).
///
/// `pub` so the ERC-7730 dynamic-array renderer
/// (`secure/src/tx/display/erc7730/formatters.rs::render_array`) follows a
/// dynamic-array tail through the EXACT same hardened reader `walk` uses,
/// rather than re-implementing the top-28-bytes-zero gate.
pub fn read_offset_word(word: &[u8]) -> Option<usize> {
    if word.len() != 32 {
        return None;
    }
    if word[0..28].iter().any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&word[28..32]);
    Some(u32::from_be_bytes(buf) as usize)
}

/// Read a 32-byte length word, capping at u32::MAX. Same top-zero gate
/// as offsets — anything past 4 GiB is malformed for our purposes.
///
/// `pub` for the ERC-7730 dynamic-array renderer (see `read_offset_word`).
pub fn read_length_word(word: &[u8]) -> Option<u32> {
    if word.len() != 32 {
        return None;
    }
    if word[0..28].iter().any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&word[28..32]);
    Some(u32::from_be_bytes(buf))
}

fn round_up_to_32(n: u64) -> Option<u64> {
    let r = n % 32;
    if r == 0 {
        Some(n)
    } else {
        n.checked_add(32 - r)
    }
}

// ---------------------------------------------------------------------------
// Word readers used by the renderer (pass 2). These are thin wrappers
// over the existing erc20 decoders so the same address-padding /
// big-endian semantics apply.
// ---------------------------------------------------------------------------

pub fn word(body: &[u8], off: usize) -> Option<&[u8]> {
    let end = off.checked_add(32)?;
    body.get(off..end)
}

pub fn read_address(body: &[u8], off: usize) -> Option<[u8; 20]> {
    decode_address_word(word(body, off)?)
}

pub fn read_u256(body: &[u8], off: usize) -> Option<U256> {
    Some(decode_u256_word(word(body, off)?))
}

pub fn read_bool(body: &[u8], off: usize) -> Option<bool> {
    let w = word(body, off)?;
    if w[0..31].iter().any(|&b| b != 0) {
        return None;
    }
    match w[31] {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Bounded verification (Kani)
// ---------------------------------------------------------------------------
//
// Target = `walk`, the clear-sign WYSIWYS shape decoder. `body` is the
// attacker-controlled calldata (after the 4-byte selector); `parsed` is
// curator-supplied (Merkle-verified) type metadata. We therefore quantify
// over a fully symbolic `body` and pin the dangerous dimension, proving:
//
//   (a) PANIC / ARITHMETIC-OVERFLOW / SLICE-OOB FREEDOM over all symbolic
//       `body ≤ N` (Kani's default checks on every harness), and
//   (b) SOUNDNESS — "no read past end": every offset/count `walk` RETURNS
//       describes a byte span that the renderer can read entirely inside
//       `body`. The span is reconstructed from the ORIGINAL parsed type
//       (`parsed.arena`) + `body.len()` + the returned `(body_off, count)`,
//       using the renderer's *unpadded* read extent — never `walk`'s
//       internal `round_up_to_32`/`end`/`tail_cursor` — so a green run is
//       not a self-recheck. For dynamic `bytes`/`string` the unpadded
//       extent `body_off + 32 + count` is strictly smaller than the
//       padded extent `walk` bounds-checks, which is what makes this an
//       independent property rather than an echo.
//
// Bound (stated honestly): `body` is a symbolic slice of length ≤ N (N = 96
// or 128, enough for a one-word head + one dynamic tail of up to ~2 words),
// `unwind` covers the only loops in `walk` — the two 28-byte top-zero scans
// in `read_{offset,length}_word` (no body-length-proportional loop exists),
// so 33 ≫ 29 is ample. Kani runs on a 64-bit host (`usize` = u64) while the
// firmware target is 32-bit `thumbv8m`; the overflow/OOB result transfers
// because every followed offset/length is u32-bounded and the only adds on
// the accept path (`head_pos + 32`, `offset + 32`) are gated by
// `offset == tail_cursor ≤ body.len()` *before* the add, with the dynamic
// payload arithmetic done in checked u64 — none of it is width-specific.

#[cfg(kani)]
mod verification {
    use super::*;
    use super::super::parser::TypeArena;

    /// Renderer-visible read extent for one accepted arg, computed WITHOUT
    /// `walk`'s padding helper — the renderer reads `count` *unpadded*
    /// payload bytes (bytes/string), `32*count` element bytes (dyn array),
    /// `32*N` inline bytes (static array), or one 32-byte word (primitive).
    /// Returns the exclusive end offset the renderer touches.
    fn renderer_read_end(parsed: &ParsedSig<'_>, a: &Walked) -> usize {
        match *parsed.arena.get(a.type_id) {
            TypeRef::Uint(_)
            | TypeRef::Int(_)
            | TypeRef::Address
            | TypeRef::Bool
            | TypeRef::BytesN(_) => a.body_off + 32,
            TypeRef::Bytes | TypeRef::String => a.body_off + 32 + a.count as usize,
            TypeRef::Array { fixed_len: Some(n), .. } => a.body_off + 32 * n as usize,
            TypeRef::Array { fixed_len: None, .. } => a.body_off + 32 + 32 * a.count as usize,
            // walk never accepts a tuple arg; unreachable on the accept path.
            TypeRef::Tuple { .. } => a.body_off,
        }
    }

    /// PRIMARY SOUNDNESS — single dynamic `bytes` arg over symbolic body.
    /// `walk(parsed, body) == Some` ⟹ body is 32-aligned AND the renderer's
    /// unpadded read extent for the arg lies fully inside `body`. The
    /// unpadded extent (`body_off + 32 + count`) is strictly below the
    /// padded extent `walk` checks, so this is an independent OOB-freedom
    /// property, not a recheck of `walk`'s own `end ≤ body.len()`.
    #[kani::proof]
    #[kani::unwind(33)]
    fn walk_dyn_bytes_read_in_bounds() {
        const N: usize = 96;
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let body = &data[..len];

        let mut arena = TypeArena::new();
        let id = arena.alloc(TypeRef::Bytes).unwrap();
        let parsed = ParsedSig { name: &b"f"[..], args: [id; MAX_ARGS], arg_count: 1, arena };

        // In-Kani reachability witness: a concrete canonical f(bytes) frame
        // (offset 0x20, empty payload) the SAME `parsed` accepts — so the
        // accept-branch below is provably reachable WITHOUT leaning on any
        // external unit test. A reject-everything regression fails HERE.
        let mut canon = [0u8; 64];
        canon[31] = 32; // offset word == 0x20; length word == 0 (empty payload)
        assert!(walk(&parsed, &canon).is_some());

        if let Some(w) = walk(&parsed, body) {
            assert_eq!(body.len() % 32, 0);
            assert_eq!(w.arg_count, 1);
            let a = w.args[0];
            // header (length) word readable …
            assert!(a.body_off + 32 <= body.len());
            // … and the unpadded payload the renderer reads.
            assert!(renderer_read_end(&parsed, &a) <= body.len());
        }
    }

    /// SOUNDNESS — single dynamic `uint256[]` arg over symbolic body.
    /// Exercises the `length * 32` multiply path and its checked-u64
    /// overflow guard; same renderer-extent-in-bounds postcondition.
    #[kani::proof]
    #[kani::unwind(33)]
    fn walk_dyn_array_read_in_bounds() {
        const N: usize = 128;
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let body = &data[..len];

        let mut arena = TypeArena::new();
        let elem = arena.alloc(TypeRef::Uint(256)).unwrap();
        let id = arena.alloc(TypeRef::Array { elem, fixed_len: None }).unwrap();
        let parsed = ParsedSig { name: &b"f"[..], args: [id; MAX_ARGS], arg_count: 1, arena };

        // In-Kani reachability witness: canonical f(uint256[]) with an empty
        // array (offset 0x20, length 0) the SAME `parsed` accepts.
        let mut canon = [0u8; 64];
        canon[31] = 32; // offset == 0x20; length word == 0 (empty array)
        assert!(walk(&parsed, &canon).is_some());

        if let Some(w) = walk(&parsed, body) {
            assert_eq!(body.len() % 32, 0);
            let a = w.args[0];
            assert!(a.body_off + 32 <= body.len());
            assert!(renderer_read_end(&parsed, &a) <= body.len());
        }
    }

    /// SOUNDNESS — mixed static + dynamic `f(address,bytes)` over symbolic
    /// body. Exercises the head/tail accounting (a static head word followed
    /// by one dynamic tail): the static arg must sit at body_off 0 inside the
    /// head, and BOTH args' renderer read extents must be in bounds.
    #[kani::proof]
    #[kani::unwind(33)]
    fn walk_mixed_static_dyn_in_bounds() {
        const N: usize = 128;
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let body = &data[..len];

        let mut arena = TypeArena::new();
        let a0 = arena.alloc(TypeRef::Address).unwrap();
        let a1 = arena.alloc(TypeRef::Bytes).unwrap();
        let mut args = [0u16; MAX_ARGS];
        args[0] = a0;
        args[1] = a1;
        let parsed = ParsedSig { name: &b"f"[..], args, arg_count: 2, arena };

        // In-Kani reachability witness: canonical f(address,bytes) — a 64-byte
        // head (zero address word + offset 0x40) then an empty bytes tail,
        // which the SAME `parsed` accepts.
        let mut canon = [0u8; 96];
        canon[63] = 64; // arg1 offset == 0x40 (start of the tail after the head)
        assert!(walk(&parsed, &canon).is_some());

        if let Some(w) = walk(&parsed, body) {
            assert_eq!(body.len() % 32, 0);
            assert_eq!(w.arg_count, 2);
            // static head arg sits at the start of the head …
            assert_eq!(w.args[0].body_off, 0);
            assert!(renderer_read_end(&parsed, &w.args[0]) <= body.len());
            // … the dynamic tail starts at/after the 64-byte head.
            assert!(w.args[1].body_off >= 64);
            assert!(w.args[1].body_off + 32 <= body.len());
            assert!(renderer_read_end(&parsed, &w.args[1]) <= body.len());
        }
    }

    /// SOUNDNESS (bonus, generality) — a single arg whose TYPE is chosen
    /// symbolically across the structural classes {static primitive,
    /// address, dynamic bytes, dynamic array, static array}, over symbolic
    /// body. The arena alloc order mirrors `parse_type` (elem first, then
    /// the `Array` node) so the hand-built shapes are realizable-equivalent.
    #[kani::proof]
    #[kani::unwind(33)]
    fn walk_any_single_arg_read_in_bounds() {
        const N: usize = 128;
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let body = &data[..len];

        let mut arena = TypeArena::new();
        let sel: u8 = kani::any();
        let t = match sel % 5 {
            0 => TypeRef::Uint(256),
            1 => TypeRef::Address,
            2 => TypeRef::Bytes,
            3 => {
                let e = arena.alloc(TypeRef::Uint(256)).unwrap();
                TypeRef::Array { elem: e, fixed_len: None } // uint256[]
            }
            _ => {
                let e = arena.alloc(TypeRef::Address).unwrap();
                TypeRef::Array { elem: e, fixed_len: Some(3) } // address[3]
            }
        };
        let id = arena.alloc(t).unwrap();
        let parsed = ParsedSig { name: &b"f"[..], args: [id; MAX_ARGS], arg_count: 1, arena };

        // In-Kani reachability witness: a concrete canonical body matching the
        // symbolically-chosen arg type, which the SAME `parsed` accepts — so
        // the accept-branch is anchored in-Kani for EVERY type class (a
        // reject-everything regression in any class fails here, not silently).
        let mut canon = [0u8; 96];
        let clen: usize = match sel % 5 {
            0 | 1 => 32,                    // static primitive: one head word
            2 | 3 => {
                canon[31] = 32; // dyn bytes / dyn array: offset 0x20, length 0
                64
            }
            _ => 96, // address[3]: three inline words, no tail
        };
        assert!(walk(&parsed, &canon[..clen]).is_some());

        if let Some(w) = walk(&parsed, body) {
            assert_eq!(body.len() % 32, 0);
            let a = w.args[0];
            assert!(a.body_off + 32 <= body.len());
            assert!(renderer_read_end(&parsed, &a) <= body.len());
        }
    }

    /// NON-VACUITY — positive control. A concrete canonical `f(bytes)`
    /// frame is ACCEPTED and decodes to the expected (offset, count),
    /// built through the REAL `super::super::parser::parse_text_sig` so it
    /// anchors the hand-built shapes above to genuine parser output. Without
    /// this, every soundness harness could pass vacuously (a walker that
    /// rejected everything satisfies all `Some ⟹ …` postconditions).
    #[kani::proof]
    #[kani::unwind(33)]
    fn walk_accepts_canonical_bytes() {
        let parsed = super::super::parser::parse_text_sig(b"f(bytes)").unwrap();
        // head: offset word == 32; tail: length word == 4; "DATA" + 28 pad.
        let mut body = [0u8; 96];
        body[31] = 32; // offset = 0x20
        body[63] = 4; // length = 4
        body[64] = b'D';
        body[65] = b'A';
        body[66] = b'T';
        body[67] = b'A';
        match walk(&parsed, &body) {
            Some(w) => {
                assert_eq!(w.arg_count, 1);
                assert_eq!(w.args[0].body_off, 32);
                assert_eq!(w.args[0].count, 4);
            }
            None => panic!("a canonical f(bytes) frame must be accepted"),
        }
    }

    /// NON-VACUITY — on-point negative control: "read past end". A dynamic
    /// length word that claims MORE payload than the body holds must be
    /// REFUSED. The length (1000) is deliberately BELOW `MAX_DYNAMIC_LEN`
    /// (2^20) and the offset is the canonical 32, the body is 32-aligned —
    /// so the `end > body.len()` bounds check is the SOLE discriminator
    /// (not the cap, not packing, not alignment). This is exactly the
    /// hidden-OOB-read threat the soundness property forecloses.
    #[kani::proof]
    #[kani::unwind(33)]
    fn walk_rejects_oob_length() {
        let parsed = super::super::parser::parse_text_sig(b"f(bytes)").unwrap();
        let mut body = [0u8; 96];
        body[31] = 32; // canonical offset
        // length = 1000 (0x03E8) — under the cap, but far past the 96-byte body.
        body[62] = 0x03;
        body[63] = 0xE8;
        assert!(walk(&parsed, &body).is_none());
    }

    /// NON-VACUITY — negative control: non-canonical offset. A `bytes` arg
    /// whose head offset is 64 (a 32-byte gap after the one-word head)
    /// instead of the canonical 32 must be REFUSED by the packing gate.
    #[kani::proof]
    #[kani::unwind(33)]
    fn walk_rejects_noncanonical_offset() {
        let parsed = super::super::parser::parse_text_sig(b"f(bytes)").unwrap();
        let mut body = [0u8; 96];
        body[31] = 64; // offset = 64 (canonical would be 32) → gap, refuse
        // a zero length word sits at offset 64; the packing gate trips first.
        assert!(walk(&parsed, &body).is_none());
    }
}
