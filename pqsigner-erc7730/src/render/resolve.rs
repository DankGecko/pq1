//! Bounds-checked ABI path primitives for static fields and canonical C1
//! dynamic tails.
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
//!   *offset*. Read it through
//!   `walk`'s hardened [`read_offset_word`], move the current REGION start
//!   forward by that offset (offsets are relative to the enclosing region's
//!   start), and reset the word index.
//!
//! # Why it is WYSIWYS-safe
//!
//! The low-level [`resolve_structured`] primitive remains capable of walking a
//! chained offset program so its arithmetic can be tested and bounded-verified.
//! That is NOT sufficient evidence of canonical ABI framing: current IR does
//! not encode a dynamic tuple's complete head width or a multi-object tail's
//! topology. The production format preflight therefore accepts only a single
//! top-level C1 follow and requires exact whole-tail placement via
//! [`read_dynamic_whole_tail`]. C2 chained descent and multi-dynamic layouts
//! hard-refuse; dbgen does not emit them.
//!
//! Every attacker-controlled read here is bounds-checked, every offset/length
//! uses the hardened word readers, dynamic right-padding must be zero, and all
//! arithmetic is checked. Crafted bodies therefore decline rather than panic or
//! read out of bounds.

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
/// Returns the leaf position, or `Err` (reject rendering) on any malformed /
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

/// Bounds of a canonical ABI dynamic blob. Shared with the authenticated
/// multi-tail partition so sole-tail and multi-tail blobs cannot acquire
/// drifting length or zero-padding rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CanonicalBlobBounds {
    pub(crate) len: u32,
    pub(crate) data_start: usize,
    pub(crate) data_end: usize,
    pub(crate) padded_end: usize,
}

/// Exact geometry of one canonical dynamic blob that owns the complete ABI
/// tail.
///
/// Every offset is relative to byte zero of the `body` passed to
/// [`canonical_dynamic_whole_tail`]. Keeping these positions next to the
/// borrowed data prevents later nested-calldata binding code from recovering
/// security-critical intervals through pointer arithmetic or a second,
/// potentially drifting ABI walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalDynamicTail<'a> {
    /// Start of the 32-byte ABI length word.
    pub length_word_start: usize,
    /// First declared data byte, immediately after the length word.
    pub data_start: usize,
    /// Exclusive end of the declared data bytes (padding excluded).
    pub data_end: usize,
    /// Exclusive end of the zero-padded ABI object. For a whole tail this is
    /// exactly `body.len()`.
    pub padded_end: usize,
    /// The declared dynamic bytes, excluding the length word and right padding.
    pub data: &'a [u8],
}

/// Validate the length/data/right-padding framing of one ABI dynamic blob.
///
/// Solidity's canonical ABI encoding right-pads `bytes`/`string` data to a
/// 32-byte boundary with zeroes. Those padding bytes are part of the signed
/// calldata even though they are not part of the decoded value. Accepting
/// arbitrary padding would therefore let two byte-distinct authorizations
/// paint identical trusted-display pages. Keep the check in this shared reader
/// so rendered strings and tokenPath byte slices cannot diverge.
pub(crate) fn canonical_blob_bounds(
    body: &[u8],
    off: usize,
) -> Result<CanonicalBlobBounds, RenderErr> {
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
    let padded_len = (len as usize)
        .checked_add(31)
        .ok_or(RenderErr::Reject("7730 res ovf"))?
        / 32
        * 32;
    let padded_end = data_start
        .checked_add(padded_len)
        .ok_or(RenderErr::Reject("7730 res ovf"))?;
    body.get(data_start..data_end)
        .ok_or(RenderErr::Reject("7730 res data oob"))?;
    let padding = body
        .get(data_end..padded_end)
        .ok_or(RenderErr::Reject("7730 res pad oob"))?;
    if padding.iter().any(|&b| b != 0) {
        return Err(RenderErr::Reject("7730 res dirty pad"));
    }
    Ok(CanonicalBlobBounds {
        len,
        data_start,
        data_end,
        padded_end,
    })
}

/// Extract a [`Leaf::Dynamic`] blob (`[u32-ish length][data][zero padding]`)
/// with full bounds and canonical-padding checks. Returns the declared data
/// slice (`&body[off+32 .. off+32+len]`). Other canonical dynamic objects may
/// follow this one; callers that own the sole tail must use
/// [`read_dynamic_whole_tail`].
pub fn read_dynamic(body: &[u8], off: usize) -> Result<&[u8], RenderErr> {
    let bounds = canonical_blob_bounds(body, off)?;
    body.get(bounds.data_start..bounds.data_end)
        .ok_or(RenderErr::Reject("7730 res data oob"))
}

/// Extract a dynamic blob only when it is the sole, exact ABI tail.
///
/// `expected_off` is independently derived from the format's authenticated
/// `static_head_words`. Requiring both `off == expected_off` and the padded
/// object end to equal `body.len()` excludes head aliasing, gaps, overlapping
/// objects, and signed trailing calldata. This is sound only for dbgen's
/// sole-dynamic C1 shapes; C2 dynamic-tuple descent is rejected separately.
pub fn read_dynamic_whole_tail(
    body: &[u8],
    off: usize,
    expected_off: usize,
) -> Result<&[u8], RenderErr> {
    Ok(canonical_dynamic_whole_tail(body, off, expected_off)?.data)
}

/// Validate and expose the exact geometry of a sole canonical ABI dynamic
/// tail.
///
/// This is the geometry-bearing sibling of [`read_dynamic_whole_tail`]. It
/// enforces the same offset-at-head-end, checked length arithmetic, zero right
/// padding, and exact end-of-body rules, but also returns the authenticated
/// half-open data interval for callers that must bind the precise signed byte
/// range. The legacy slice reader delegates here so the two interpretations
/// cannot drift.
pub fn canonical_dynamic_whole_tail(
    body: &[u8],
    off: usize,
    expected_off: usize,
) -> Result<CanonicalDynamicTail<'_>, RenderErr> {
    if off != expected_off {
        return Err(RenderErr::Reject("7730 res offset != head end"));
    }
    let bounds = canonical_blob_bounds(body, off)?;
    if bounds.padded_end != body.len() {
        return Err(RenderErr::Reject("7730 res not whole tail"));
    }
    let data = body
        .get(bounds.data_start..bounds.data_end)
        .ok_or(RenderErr::Reject("7730 res data oob"))?;
    Ok(CanonicalDynamicTail {
        length_word_start: off,
        data_start: bounds.data_start,
        data_end: bounds.data_end,
        padded_end: bounds.padded_end,
        data,
    })
}

/// Extract a dynamic blob only when it is the sole canonical ABI tail and its
/// declared data is exactly empty.
///
/// This is the runtime predicate authenticated by
/// `PARAM_EXACT_EMPTY_BYTES`. It deliberately composes the existing whole-tail
/// reader so offset-at-head-end, canonical length-word decoding, padding, and
/// exact EOF remain one shared framing contract. The additional empty check is
/// what prevents the marker from becoming an arbitrary opaque-bytes renderer.
pub fn read_exact_empty_dynamic_whole_tail(
    body: &[u8],
    off: usize,
    expected_off: usize,
) -> Result<&[u8], RenderErr> {
    let data = read_dynamic_whole_tail(body, off, expected_off)?;
    if !data.is_empty() {
        return Err(RenderErr::Reject("7730 res dynamic not empty"));
    }
    Ok(data)
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

/// Parse the only dynamic-leaf navigation shape whose canonical placement can
/// be proven from today's IR: one top-level head slot followed directly to a
/// C1 tail object.
///
/// `prog` excludes `RootStructured`. Any further `FieldIdx` after the follow is
/// C2 dynamic-tuple descent. The IR does not encode that tuple's complete head
/// width or tail topology, so accepting it would make exact placement
/// unprovable; reject rather than infer.
pub fn c1_dynamic_slot(prog: &[u8]) -> Result<usize, RenderErr> {
    if prog.len() != 4
        || prog[0] != PathOp::FieldIdx as u8
        || prog[3] != PathOp::FollowOffset as u8
    {
        return Err(RenderErr::Reject("7730 noncanonical C2 path"));
    }
    Ok(u16::from_be_bytes([prog[1], prog[2]]) as usize)
}

/// Validate a sole top-level dynamic `address[]` as an exact whole tail.
fn validate_address_array_whole_tail(
    body: &[u8],
    off: usize,
    expected_off: usize,
) -> Result<(), RenderErr> {
    if off != expected_off {
        return Err(RenderErr::Reject("7730 tok offset != head end"));
    }
    let count_end = off
        .checked_add(32)
        .ok_or(RenderErr::Reject("7730 tok ovf"))?;
    let count_word = body
        .get(off..count_end)
        .ok_or(RenderErr::Reject("7730 tok no count"))?;
    let count = read_length_word(count_word)
        .ok_or(RenderErr::Reject("7730 tok bad count"))? as usize;
    if count > MAX_DYNAMIC_LEN as usize {
        return Err(RenderErr::Reject("7730 tok count cap"));
    }
    let elems_len = count
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 tok ovf"))?;
    let end = count_end
        .checked_add(elems_len)
        .ok_or(RenderErr::Reject("7730 tok ovf"))?;
    if end != body.len() {
        return Err(RenderErr::Reject("7730 tok array not whole tail"));
    }
    let elems = body
        .get(count_end..end)
        .ok_or(RenderErr::Reject("7730 tok elems oob"))?;
    for word in elems.chunks_exact(32) {
        if word[..12].iter().any(|&b| b != 0) {
            return Err(RenderErr::Reject("7730 tok dirty address"));
        }
    }
    Ok(())
}

/// Validate the exact canonical tail framing of a dynamic tokenPath.
///
/// The accepted program is C1 only: `FieldIdx(slot) FollowOffset` followed by
/// one terminal token extraction. Dbgen separately guarantees this is the
/// signature's sole dynamic top-level argument. Runtime independently proves
/// the offset equals the authenticated head end, the padded blob/array consumes
/// the entire body, and the selected address itself resolves canonically.
/// Returns the dynamic offset-word slot so the format preflight can require all
/// dynamic references to identify the same sole argument.
pub fn validate_canonical_token_tail(
    prog: &[u8],
    body: &[u8],
    static_head_words: u16,
) -> Result<usize, RenderErr> {
    let (nav, extraction) = split_extraction(prog)?;
    let slot = c1_dynamic_slot(nav)?;
    let shw = static_head_words as usize;
    if slot >= shw {
        return Err(RenderErr::Reject("7730 tok slot out of head"));
    }
    let head_end = shw
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 tok head ovf"))?;
    if body.len() < head_end {
        return Err(RenderErr::Reject("7730 tok short head"));
    }
    let word_start = slot
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 tok slot ovf"))?;
    let word_end = word_start
        .checked_add(32)
        .ok_or(RenderErr::Reject("7730 tok slot ovf"))?;
    let word = body
        .get(word_start..word_end)
        .ok_or(RenderErr::Reject("7730 tok off word"))?;
    let offset = read_offset_word(word).ok_or(RenderErr::Reject("7730 tok bad offset"))?;
    match extraction {
        Some(Extract::Slice { .. }) => {
            let _ = read_dynamic_whole_tail(body, offset, head_end)?;
        }
        Some(Extract::Index(_)) | Some(Extract::Last) => {
            validate_address_array_whole_tail(body, offset, head_end)?;
        }
        None => return Err(RenderErr::Reject("7730 tok dynamic no extraction")),
    }
    // Bind the extraction itself (slice bounds / selected array index / empty
    // last-element) now. The paint path resolves again, but must never turn a
    // malformed dynamic tokenPath into the old raw-amount fallback.
    let _ = resolve_token_address(prog, body)?;
    Ok(slot)
}

/// Canonical right-aligned ABI address word at `body[off..off+32]`.
fn low20_of_word(body: &[u8], off: usize) -> Result<[u8; ADDR_LEN], RenderErr> {
    let hi = off.checked_add(32).ok_or(RenderErr::Reject("7730 tok ovf"))?;
    let word = body
        .get(off..hi)
        .ok_or(RenderErr::Reject("7730 tok word oob"))?;
    if word[..12].iter().any(|&b| b != 0) {
        return Err(RenderErr::Reject("7730 tok dirty address"));
    }
    let mut a = [0u8; ADDR_LEN];
    a.copy_from_slice(&word[12..]);
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
    fn dynamic_reader_rejects_dirty_or_missing_right_padding() {
        let mut body = Vec::new();
        body.extend_from_slice(&w(3));
        let mut padded = [0u8; 32];
        padded[..3].copy_from_slice(b"abc");
        body.extend_from_slice(&padded);
        assert_eq!(read_dynamic(&body, 0).unwrap(), b"abc");

        let mut dirty = body.clone();
        dirty[35] = 1;
        assert_eq!(
            read_dynamic(&dirty, 0),
            Err(RenderErr::Reject("7730 res dirty pad"))
        );
        assert_eq!(
            read_dynamic(&body[..35], 0),
            Err(RenderErr::Reject("7730 res pad oob"))
        );
    }

    #[test]
    fn whole_tail_geometry_is_exact_and_reader_delegates_to_it() {
        let mut body = Vec::new();
        body.extend_from_slice(&w(32));
        body.extend_from_slice(&w(3));
        let mut padded = [0u8; 32];
        padded[..3].copy_from_slice(b"abc");
        body.extend_from_slice(&padded);
        let geometry = canonical_dynamic_whole_tail(&body, 32, 32).unwrap();
        assert_eq!(geometry.length_word_start, 32);
        assert_eq!(geometry.data_start, 64);
        assert_eq!(geometry.data_end, 67);
        assert_eq!(geometry.padded_end, 96);
        assert_eq!(geometry.data, b"abc");
        assert_eq!(read_dynamic_whole_tail(&body, 32, 32).unwrap(), b"abc");
    }

    #[test]
    fn whole_tail_geometry_rejects_alias_gap_padding_trailing_and_overflow() {
        let mut body = Vec::new();
        body.extend_from_slice(&w(32));
        body.extend_from_slice(&w(3));
        let mut padded = [0u8; 32];
        padded[..3].copy_from_slice(b"abc");
        body.extend_from_slice(&padded);

        // A resolved object before the authenticated head end aliases the head.
        assert_eq!(
            canonical_dynamic_whole_tail(&body, 32, 64),
            Err(RenderErr::Reject("7730 res offset != head end"))
        );

        // A resolved object after the authenticated head end leaves a signed
        // gap, even if bytes at that later position could form another object.
        assert_eq!(
            canonical_dynamic_whole_tail(&body, 64, 32),
            Err(RenderErr::Reject("7730 res offset != head end"))
        );

        let mut dirty = body.clone();
        dirty[67] = 1;
        assert_eq!(
            canonical_dynamic_whole_tail(&dirty, 32, 32),
            Err(RenderErr::Reject("7730 res dirty pad"))
        );

        body.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            canonical_dynamic_whole_tail(&body, 32, 32),
            Err(RenderErr::Reject("7730 res not whole tail"))
        );
        // The generic reader stays composable for independently validated
        // multi-object encodings; only the sole-tail reader owns EOF.
        assert_eq!(read_dynamic(&body, 32).unwrap(), b"abc");

        assert_eq!(
            canonical_dynamic_whole_tail(&[], usize::MAX, usize::MAX),
            Err(RenderErr::Reject("7730 res ovf"))
        );
    }

    #[test]
    fn exact_empty_whole_tail_accepts_only_zero_length_at_exact_eof() {
        let mut empty = Vec::new();
        empty.extend_from_slice(&w(32));
        empty.extend_from_slice(&w(0));
        assert_eq!(
            read_exact_empty_dynamic_whole_tail(&empty, 32, 32).unwrap(),
            b""
        );

        let mut nonempty = Vec::new();
        nonempty.extend_from_slice(&w(32));
        nonempty.extend_from_slice(&w(1));
        nonempty.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            read_exact_empty_dynamic_whole_tail(&nonempty, 32, 32),
            Err(RenderErr::Reject("7730 res dynamic not empty"))
        );
        assert_eq!(
            read_exact_empty_dynamic_whole_tail(&empty, 32, 64),
            Err(RenderErr::Reject("7730 res offset != head end"))
        );
        empty.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            read_exact_empty_dynamic_whole_tail(&empty, 32, 32),
            Err(RenderErr::Reject("7730 res not whole tail"))
        );
    }

    #[test]
    fn exact_c1_shape_rejects_dynamic_tuple_descent() {
        let mut c1 = field(0).to_vec();
        c1.push(FOLLOW);
        assert_eq!(c1_dynamic_slot(&c1), Ok(0));

        let mut c2 = c1;
        c2.extend_from_slice(&field(1));
        c2.push(FOLLOW);
        assert_eq!(
            c1_dynamic_slot(&c2),
            Err(RenderErr::Reject("7730 noncanonical C2 path"))
        );
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

    #[test]
    fn canonical_token_bytes_tail_is_exact_and_c2_refuses() {
        let (_a0, _a1, data) = packed_path(0x11, 0x22);
        let canonical = body_sole_bytes(&data);
        let mut prog = field(0).to_vec();
        prog.push(FOLLOW);
        prog.extend_from_slice(&slice_op(0, 20, false));
        assert_eq!(validate_canonical_token_tail(&prog, &canonical, 1), Ok(0));

        let mut dirty_pad = canonical.clone();
        *dirty_pad.last_mut().unwrap() = 1;
        assert_eq!(
            validate_canonical_token_tail(&prog, &dirty_pad, 1),
            Err(RenderErr::Reject("7730 res dirty pad"))
        );
        let mut trailing = canonical.clone();
        trailing.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            validate_canonical_token_tail(&prog, &trailing, 1),
            Err(RenderErr::Reject("7730 res not whole tail"))
        );
        let mut alias = canonical.clone();
        alias[31] = 0;
        assert_eq!(
            validate_canonical_token_tail(&prog, &alias, 1),
            Err(RenderErr::Reject("7730 res offset != head end"))
        );

        let mut c2 = field(0).to_vec();
        c2.push(FOLLOW);
        c2.extend_from_slice(&field(0));
        c2.push(FOLLOW);
        c2.extend_from_slice(&slice_op(0, 20, false));
        assert_eq!(
            validate_canonical_token_tail(&c2, &canonical, 1),
            Err(RenderErr::Reject("7730 noncanonical C2 path"))
        );
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
    fn canonical_token_address_array_rejects_dirty_unselected_word_and_suffix() {
        let body = body_address_array(&[0x11, 0x22]);
        let mut prog = field(0).to_vec();
        prog.push(FOLLOW);
        prog.extend_from_slice(&idx_op(0));
        assert_eq!(validate_canonical_token_tail(&prog, &body, 1), Ok(0));

        let mut dirty = body.clone();
        // Dirty high padding in element 1, even though tokenPath selects 0.
        dirty[96] = 1;
        assert_eq!(
            validate_canonical_token_tail(&prog, &dirty, 1),
            Err(RenderErr::Reject("7730 tok dirty address"))
        );
        let mut trailing = body;
        trailing.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            validate_canonical_token_tail(&prog, &trailing, 1),
            Err(RenderErr::Reject("7730 tok array not whole tail"))
        );
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
    // same hardened reader used by the exact sole-array resolver). A lower
    // bound (was 6) fails the unwinding assertion on the reader loop.
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

    /// Acceptance by the geometry-bearing whole-tail reader binds every
    /// returned position to the exact authenticated ABI interval. This is the
    /// pure interval kernel used by nested-calldata child binding.
    #[kani::proof]
    #[kani::unwind(34)]
    fn canonical_dynamic_whole_tail_binds_exact_interval() {
        const BODY_LEN: usize = 96;
        let body: [u8; BODY_LEN] = kani::any();
        let off: usize = kani::any();
        let expected_off: usize = kani::any();

        if let Ok(geometry) = canonical_dynamic_whole_tail(&body, off, expected_off) {
            assert!(off == expected_off);
            assert!(geometry.length_word_start == off);
            assert!(geometry.data_start == off + 32);
            assert!(geometry.data_end >= geometry.data_start);
            assert!(geometry.padded_end == body.len());
            assert!(geometry.data_end <= geometry.padded_end);
            assert!(geometry.data.len() == geometry.data_end - geometry.data_start);
            let k: usize = kani::any();
            if k < geometry.data.len() {
                let source = geometry
                    .data_start
                    .checked_add(k)
                    .expect("accepted data index cannot overflow");
                assert!(source < geometry.data_end);
                assert!(geometry.data[k] == body[source]);
            }
        }
    }

    /// For every 96-byte body and arbitrary offsets, acceptance proves the
    /// exact canonical empty-tail shape: both offsets are the 64-byte head
    /// end, the final word decodes to zero, and no bytes follow it.
    #[kani::proof]
    #[kani::unwind(34)]
    fn exact_empty_whole_tail_binds_offset_length_and_eof() {
        const BODY_LEN: usize = 96;
        let body: [u8; BODY_LEN] = kani::any();
        let off: usize = kani::any();
        let expected_off: usize = kani::any();
        if let Ok(data) = read_exact_empty_dynamic_whole_tail(&body, off, expected_off) {
            assert!(data.is_empty());
            assert!(off == expected_off);
            assert!(off == 64);
            assert!(read_length_word(&body[64..96]) == Some(0));
            assert!(off + 32 == body.len());
        }
    }

    /// Non-vacuity witness for the exact-empty predicate.
    #[kani::proof]
    #[kani::unwind(34)]
    fn exact_empty_whole_tail_accepts_concrete() {
        let body = [0u8; 96];
        let data = read_exact_empty_dynamic_whole_tail(&body, 64, 64)
            .expect("canonical zero-length tail must be accepted");
        assert!(data.is_empty());
    }

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

    // ----------------------------------------------------------------------
    // NO-MISDECODE / BYTE-BINDING (2026-07-02). The existing
    // `resolve_structured_panic_free_and_in_bounds` proves the resolver never
    // crashes and any leaf is in-bounds — but NOT that the resolved leaf lands
    // on the *right* word. That gap matters: `resolve_structured` decides WHICH
    // 32-byte word becomes the value the user sees on the trusted display
    // (the documented E2 walker-slot-confusion HIGH path). These harnesses
    // upgrade the coverage from in-bounds to a ∀ byte-binding: for a single
    // `FollowOffset` descent, the resolved DYNAMIC leaf position equals EXACTLY
    // the ABI offset word an independent decoder reads — no additive drift from
    // the region base or the FieldIdx slot. `read_offset_word` (the same
    // hardened reader `walk` uses) is the independent oracle.

    /// ∀ body: if `resolve_structured([FieldIdx(1), FollowOffset], body)`
    /// accepts a dynamic leaf at `pos`, then `pos` is EXACTLY the region-relative
    /// offset word at `body[32..64]` — the resolver's region/slot arithmetic
    /// (region += offset; slot := 0; pos := region + slot*32) collapses to the
    /// offset word with no drift. A bug that added the FieldIdx slot into `pos`,
    /// failed to reset `slot`, or shifted the region base would violate this.
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_structured_followoffset_byte_binds_to_offset_word() {
        const BODY_LEN: usize = 160; // 5 words
        let prog = [FI, 0, 1, FO]; // FieldIdx(1) ; FollowOffset -> dynamic leaf
        let body: [u8; BODY_LEN] = kani::any();
        if let Ok(Leaf::Dynamic(pos)) = resolve_structured(&prog, &body) {
            // Independent oracle: the offset word at slot 1 (region base 0).
            let expected = read_offset_word(&body[32..64])
                .expect("accepted the FollowOffset ⇒ its offset word was valid");
            assert!(pos == expected); // byte-binding: resolved leaf == offset word
            assert!(pos + 32 <= body.len()); // the leaf's length word is present
        }
        // (A program ending in FollowOffset can only yield `Dynamic` — the
        //  `ended_on_follow` flag rules out `Word` — so no `Word` arm here.)
    }

    /// Non-vacuity witness: a concrete well-formed body IS accepted and binds to
    /// the expected position — so the ∀ harness above is not vacuously true.
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_structured_binding_accepts_concrete() {
        let prog = [FI, 0, 1, FO];
        let mut body = [0u8; 160];
        // offset word at body[32..64]: big-endian value 64 in the low 4 bytes.
        body[63] = 64; // region := 64, leaf at 64..96 (in bounds)
        let leaf = resolve_structured(&prog, &body).expect("well-formed ⇒ accepted");
        assert!(leaf == Leaf::Dynamic(64));
        assert!(read_offset_word(&body[32..64]) == Some(64));
    }

    /// Negative control: a dirty top byte in the offset word makes the hardened
    /// `read_offset_word` reject, so the resolver declines-to-blind (never
    /// silently reads a truncated/aliased position). Gives the binding teeth.
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_structured_binding_rejects_dirty_offset() {
        let prog = [FI, 0, 1, FO];
        let mut body = [0u8; 160];
        body[63] = 64;
        body[32] = 0x01; // top-28-bytes nonzero -> read_offset_word rejects
        assert!(resolve_structured(&prog, &body).is_err());
    }

    // TOKEN-IDENTITY BYTE-BINDING (2026-07-02). `resolve_token_address` decides
    // WHICH token the displayed amount is denominated in — a WYSIWYS-critical
    // fact (showing "USDC" for a call that moves a different token is a spoof).
    // The tok_* harnesses above are panic-free-only. This proves the common
    // static-address-word path (`params.tokenIn`, no extraction op) byte-binds:
    // the resolved 20-byte address is EXACTLY the low 20 bytes of the calldata
    // word at the named slot — no drift from the word the contract's ABI decoder
    // reads.

    /// ∀ body: if `resolve_token_address([FieldIdx(1)], body)` (a static address
    /// word at slot 1, no extraction) accepts, the returned address equals EXACTLY
    /// `body[44..64]` — the low 20 bytes (`[off+12 .. off+32]`) of the word at
    /// `off = 32`. A slot-arithmetic or truncation drift would violate this.
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_token_address_static_word_byte_binds() {
        const BODY_LEN: usize = 128;
        let prog = [FI, 0, 1]; // FieldIdx(1); no FollowOffset -> static Word leaf
        let body: [u8; BODY_LEN] = kani::any();
        if let Ok(addr) = resolve_token_address(&prog, &body) {
            // off = region(0) + slot(1)*32 = 32; low 20 = body[32+12 .. 32+32].
            assert!(addr[..] == body[44..64]);
        }
    }

    /// Non-vacuity witness: a concrete body IS accepted and binds to the placed
    /// address — so the ∀ harness above is not vacuously true.
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_token_address_static_word_accepts_concrete() {
        let prog = [FI, 0, 1];
        let mut body = [0u8; 128];
        // place a distinctive 20-byte address in the low 20 of the slot-1 word.
        let mut i = 44usize;
        while i < 64 {
            body[i] = 0xAB;
            i += 1;
        }
        let addr = resolve_token_address(&prog, &body).expect("well-formed ⇒ accepted");
        assert!(addr == [0xABu8; 20]);
    }

    // ----------------------------------------------------------------------
    // DYNAMIC-EXTRACTION VALUE-SOUNDNESS (2026-07-04). The tok_* panic-free
    // harnesses above prove the slice/index extraction paths never crash on a
    // hostile body — but not that an ACCEPTED extraction returns the RIGHT
    // bytes. These upgrade the remaining tokenPath shapes (packed-`bytes`
    // slice `[s:s+20]` / `[-20:]`, `address[]` element `.[i]` / `.[-1]`) plus
    // the two resolve_structured arithmetic laws (slot accumulation; region-
    // chained double descent) from panic-free to ∀ byte-binding, using the
    // same independent oracles (`read_offset_word`/`read_length_word` — the
    // hardened readers `walk` uses) re-deriving every position from scratch.

    /// ∀ body, ∀ start: if `params.path.[s:s+20]` (slot-1 dynamic `bytes`,
    /// slice-from-start) accepts, the address is EXACTLY
    /// `body[off+32+s .. off+32+s+20]` where `off` is the oracle-read offset
    /// word at slot 1, AND the slice lies inside the oracle-read declared
    /// length. A start/base drift or a length-gate bypass violates this.
    #[kani::proof]
    #[kani::unwind(34)]
    fn tok_slice_start_byte_binds() {
        let s: u16 = kani::any();
        let prog = [FI, 0, 1, FO, SL, (s >> 8) as u8, s as u8, 0x00, 0x14, 0];
        let body: [u8; KBODY] = kani::any();
        if let Ok(addr) = resolve_token_address(&prog, &body) {
            let off = read_offset_word(&body[32..64])
                .expect("accepted ⇒ the slot-1 offset word was valid");
            // The dynamic leaf: length word at body[off..off+32], data at off+32.
            let len = read_length_word(&body[off..off + 32])
                .expect("accepted ⇒ the leaf length word was valid") as usize;
            let st = s as usize;
            assert!(st + ADDR_LEN <= len); // inside the declared data
            assert!(addr[..] == body[off + 32 + st..off + 32 + st + ADDR_LEN]);
        }
    }

    /// ∀ body: if `params.path.[-20:]` (slice-from-end) accepts, the declared
    /// length is ≥ 20 and the address is EXACTLY the LAST 20 data bytes
    /// `body[off+32+len-20 .. off+32+len]`. A tail-anchor drift violates this.
    #[kani::proof]
    #[kani::unwind(34)]
    fn tok_slice_from_end_byte_binds() {
        let prog = [FI, 0, 1, FO, SL, 0, 0, 0x00, 0x14, 1];
        let body: [u8; KBODY] = kani::any();
        if let Ok(addr) = resolve_token_address(&prog, &body) {
            let off = read_offset_word(&body[32..64])
                .expect("accepted ⇒ the slot-1 offset word was valid");
            // The dynamic leaf: length word at body[off..off+32], data at off+32.
            let len = read_length_word(&body[off..off + 32])
                .expect("accepted ⇒ the leaf length word was valid") as usize;
            assert!(len >= ADDR_LEN);
            assert!(addr[..] == body[off + 32 + len - ADDR_LEN..off + 32 + len]);
        }
    }

    /// Non-vacuity witness for BOTH slice directions: one concrete body where
    /// `[4:24]` and `[-20:]` select the same distinctively-placed 20 bytes.
    #[kani::proof]
    #[kani::unwind(34)]
    fn tok_slice_accepts_concrete() {
        let mut body = [0u8; KBODY];
        body[63] = 64; // slot-1 offset word -> dynamic leaf at 64
        body[95] = 24; // length word = 24; data = body[96..120]
        let mut i = 100usize; // data[4..24] = body[100..120]
        while i < 120 {
            body[i] = 0xCD;
            i += 1;
        }
        let start = [FI, 0, 1, FO, SL, 0, 4, 0x00, 0x14, 0];
        let addr = resolve_token_address(&start, &body).expect("well-formed ⇒ accepted");
        assert!(addr == [0xCDu8; 20]);
        let tail = [FI, 0, 1, FO, SL, 0, 0, 0x00, 0x14, 1]; // len-20 = 4 -> same bytes
        let addr2 = resolve_token_address(&tail, &body).expect("well-formed ⇒ accepted");
        assert!(addr2 == [0xCDu8; 20]);
    }

    /// ∀ body, ∀ i: if `path.[i]` (slot-1 dynamic `address[]` element) accepts,
    /// then `i` is strictly inside the oracle-read count AND the address is
    /// EXACTLY the low 20 bytes of element word `i`:
    /// `body[off+32+32i+12 .. off+32+32(i+1)]`. An index off-by-one or a
    /// stride/base drift violates this.
    #[kani::proof]
    #[kani::unwind(34)]
    fn tok_array_index_byte_binds() {
        let i: u16 = kani::any();
        let prog = [FI, 0, 1, FO, IX, (i >> 8) as u8, i as u8];
        let body: [u8; KBODY] = kani::any();
        if let Ok(addr) = resolve_token_address(&prog, &body) {
            let off = read_offset_word(&body[32..64])
                .expect("accepted ⇒ the slot-1 offset word was valid");
            let count = read_length_word(&body[off..off + 32])
                .expect("accepted ⇒ the count word was valid") as usize;
            let idx = i as usize;
            assert!(idx < count); // companion-claimed count actually gates
            let lo = off + 32 + 32 * idx + 12;
            assert!(addr[..] == body[lo..lo + ADDR_LEN]);
        }
    }

    /// ∀ body: if `path.[-1]` accepts, the array is non-empty and the address
    /// is EXACTLY the low 20 bytes of element `count-1`.
    #[kani::proof]
    #[kani::unwind(34)]
    fn tok_array_last_byte_binds() {
        let prog = [FI, 0, 1, FO, LA];
        let body: [u8; KBODY] = kani::any();
        if let Ok(addr) = resolve_token_address(&prog, &body) {
            let off = read_offset_word(&body[32..64])
                .expect("accepted ⇒ the slot-1 offset word was valid");
            let count = read_length_word(&body[off..off + 32])
                .expect("accepted ⇒ the count word was valid") as usize;
            assert!(count >= 1);
            let lo = off + 32 + 32 * (count - 1) + 12;
            assert!(addr[..] == body[lo..lo + ADDR_LEN]);
        }
    }

    /// Non-vacuity witness for BOTH element selectors: a concrete 1-element
    /// array where `.[0]` and `.[-1]` both bind to the placed address.
    #[kani::proof]
    #[kani::unwind(34)]
    fn tok_array_elem_accepts_concrete() {
        let mut body = [0u8; KBODY];
        body[63] = 64; // slot-1 offset word -> array region at 64
        body[95] = 1; // count word = 1; element 0 at body[96..128]
        let mut i = 108usize; // low-20 of element 0 = body[108..128]
        while i < 128 {
            body[i] = 0xEF;
            i += 1;
        }
        let at0 = [FI, 0, 1, FO, IX, 0, 0];
        let addr = resolve_token_address(&at0, &body).expect("well-formed ⇒ accepted");
        assert!(addr == [0xEFu8; 20]);
        let last = [FI, 0, 1, FO, LA];
        let addr2 = resolve_token_address(&last, &body).expect("well-formed ⇒ accepted");
        assert!(addr2 == [0xEFu8; 20]);
    }

    // RESOLVER ARITHMETIC LAWS ∀ — low-level slot accumulation and chained
    // region descent. Production contract rendering accepts only exact C1;
    // the chained case stays proved here so the generic primitive cannot drift
    // if a future IR version explicitly binds the missing tuple topology.

    /// ∀ body, ∀ s1 s2: an accepted `[FieldIdx(s1), FieldIdx(s2)]` static leaf
    /// is EXACTLY `Word(32*(s1+s2))` — slot accumulation is exact addition,
    /// with no drift, no reset, no double-count, for EVERY slot pair (not just
    /// the concretely-tested ones).
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_structured_slot_sum_binds() {
        const BODY_LEN: usize = 160; // 5 words -> accepts s1+s2 <= 4
        let s1: u16 = kani::any();
        let s2: u16 = kani::any();
        let prog = [FI, (s1 >> 8) as u8, s1 as u8, FI, (s2 >> 8) as u8, s2 as u8];
        let body: [u8; BODY_LEN] = kani::any();
        if let Ok(leaf) = resolve_structured(&prog, &body) {
            // A FieldIdx-terminated program can only yield a static Word.
            assert!(leaf == Leaf::Word(32 * (s1 as usize + s2 as usize)));
        }
    }

    /// ∀ body: an accepted two-hop descent `[FieldIdx(0), FollowOffset,
    /// FieldIdx(1), FollowOffset]` (dynamic tuple at slot 0, dynamic member at
    /// tuple-slot 1 — a currently production-rejected C2 shape) lands at
    /// EXACTLY `off1 + off2`, where
    /// `off1` is the oracle-read offset word at `body[0..32]` and `off2` the
    /// one at `body[off1+32 .. off1+64]` — i.e. the inner offset is applied
    /// relative to the ENCLOSING region base (off1), not absolutely, not
    /// relative to the word it was read from, and the slot reset on descent.
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_structured_two_hop_region_chain_binds() {
        const BODY_LEN: usize = 160;
        let prog = [FI, 0, 0, FO, FI, 0, 1, FO];
        let body: [u8; BODY_LEN] = kani::any();
        if let Ok(Leaf::Dynamic(pos)) = resolve_structured(&prog, &body) {
            let off1 = read_offset_word(&body[0..32])
                .expect("accepted ⇒ the outer offset word was valid");
            let off2 = read_offset_word(&body[off1 + 32..off1 + 64])
                .expect("accepted ⇒ the inner offset word was valid");
            assert!(pos == off1 + off2);
            assert!(pos + 32 <= body.len());
        }
    }

    /// Non-vacuity witness for the two arithmetic laws: concrete bodies where
    /// the slot-sum and the chained descent are accepted at the expected spots.
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_structured_arithmetic_accepts_concrete() {
        // slot sum: [FieldIdx(1), FieldIdx(2)] -> Word(96).
        let sum_prog = [FI, 0, 1, FI, 0, 2];
        let body = [0u8; 160];
        assert!(resolve_structured(&sum_prog, &body) == Ok(Leaf::Word(96)));
        // two-hop: off1 = 32 (word 0), off2 = 64 (word at 64..96) -> pos 96.
        let hop_prog = [FI, 0, 0, FO, FI, 0, 1, FO];
        let mut body2 = [0u8; 160];
        body2[31] = 32; // outer offset word
        body2[95] = 64; // inner offset word at off1+32 = 64
        assert!(resolve_structured(&hop_prog, &body2) == Ok(Leaf::Dynamic(96)));
    }
}
