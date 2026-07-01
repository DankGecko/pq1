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
}

#[cfg(kani)]
mod kani_harness {
    use super::*;

    /// Panic/OOB/overflow freedom over a symbolic program + body: the resolver
    /// declines-to-blind on ANY hostile input rather than crashing, and any
    /// returned leaf position is in-bounds.
    #[kani::proof]
    #[kani::unwind(6)]
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
}
