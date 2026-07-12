//! Sole-dynamic-array (`<arg>.[]`) resolver for the ERC-7730 renderer.
//!
//! This is the load-bearing safety of the dynamic-array walker — the only
//! place the device follows the dynamic calldata TAIL (the slot-confusion
//! "show X, sign Y" attack surface). It is extracted into this host crate
//! (out of the secure-world `formatters.rs`) so it can be bounded-verified
//! with Kani — see the `#[cfg(kani)]` block — rather than only concretely
//! tested. The secure renderer re-exports it verbatim and renders over its
//! `(elems_start, count)` result.
//!
//! ## Safety argument
//!
//! The attacker controls `full_body` (the calldata after the selector); the
//! descriptor (the compiled path program, `static_head_words`) is Merkle-
//! pinned and trusted. `resolve_array` returns the array's `(elems_start,
//! count)` ONLY if the body is canonical for a SOLE dynamic array; otherwise
//! it declines (`Err`). It is **byte-identical-or-stricter** than the EVM ABI
//! decoder on every accepted body, via two exact-placement equalities:
//!
//! * `offset == static_head_words*32` — the array tail begins exactly at the
//!   end of the static head (no aliasing into / overlap with the head), and
//! * `offset + 32 + count*32 == full_body.len()` — the array is the ENTIRE
//!   dynamic tail (no slack, no trailing garbage, no second tail).
//!
//! Combined with the dbgen-side "sole dynamic arg" gate, these pin the
//! array's location so that the offset/length/element words the device reads
//! are exactly the ones the EVM decodes. The offset and length words are read
//! through `walk`'s Kani-proven `read_offset_word` / `read_length_word`
//! (top-28-bytes-zero gates + `MAX_DYNAMIC_LEN`). Every attacker-controlled
//! read is a bounds-checked `.get()` (`None → Reject`) and every arithmetic
//! op is `checked_*` (`overflow → Reject`), so no crafted body panics, slices
//! out of bounds, or overflows.

use pqsigner_tx::typed_call::abi::{read_length_word, read_offset_word, MAX_DYNAMIC_LEN};

use crate::ir::{Erc7730Ir, FieldEntry, PathOp};

use super::RenderErr;

/// Hard cap on how many array elements the renderer will lay out (one page
/// each). Beyond this the field declines-to-blind: a long list is not human-
/// reviewable on a 16-col screen, and it bounds the page budget.
pub const MAX_ARRAY_RENDER: usize = 8;

/// Resolve a sole-dynamic-array (`<arg>.[]`) field against the FULL calldata
/// body. The Kani proof and slot-confusion tests bind its exact whole-tail
/// placement. Multi-dynamic arrays have no production resolver: current IR
/// cannot prove their complete tail topology, so dbgen and the renderer reject
/// them.
pub fn resolve_array(
    field: &FieldEntry<'_>,
    ir: &Erc7730Ir<'_>,
    full_body: &[u8],
    static_head_words: u16,
) -> Result<(usize, usize), RenderErr> {
    // 1. Parse the path: [RootStructured][FieldIdx]*[ArrayAll]. Sum the
    //    FieldIdx slots → the array arg's offset-word slot.
    if field.path_off == 0 {
        return Err(RenderErr::Reject("7730 arr no path"));
    }
    let off = field.path_off as usize;
    let len = *ir
        .pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 arr bad path off"))? as usize;
    let prog = ir
        .pool
        .get(off + 1..off + 1 + len)
        .ok_or(RenderErr::Reject("7730 arr trunc path"))?;
    if prog.first() != Some(&(PathOp::RootStructured as u8)) {
        return Err(RenderErr::Reject("7730 arr bad root"));
    }
    let mut p = 1usize;
    let mut slot: usize = 0;
    loop {
        match prog.get(p) {
            Some(&op) if op == PathOp::FieldIdx as u8 => {
                let a = prog
                    .get(p + 1..p + 3)
                    .ok_or(RenderErr::Reject("7730 arr trunc fieldidx"))?;
                slot = slot
                    .checked_add(u16::from_be_bytes([a[0], a[1]]) as usize)
                    .ok_or(RenderErr::Reject("7730 arr slot ovf"))?;
                p += 3;
            }
            Some(&op) if op == PathOp::ArrayAll as u8 => {
                p += 1;
                break;
            }
            _ => return Err(RenderErr::Reject("7730 arr bad path op")),
        }
    }
    if p != prog.len() {
        return Err(RenderErr::Reject("7730 arr trailing path")); // ArrayAll must be last
    }

    // 2. The offset word must live in the static head (slot-confusion guard,
    //    identical to the scalar path), and the whole head must be present.
    let shw = static_head_words as usize;
    if slot >= shw {
        return Err(RenderErr::Reject("7730 arr slot out of head"));
    }
    let head_end = shw
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 arr head ovf"))?;
    if full_body.len() < head_end {
        return Err(RenderErr::Reject("7730 arr short head"));
    }

    // 3. Read the array arg's offset word via walk's hardened reader.
    let off_word_start = slot
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 arr slot ovf"))?;
    let off_word = full_body
        .get(off_word_start..off_word_start + 32)
        .ok_or(RenderErr::Reject("7730 arr off word"))?;
    let offset = read_offset_word(off_word).ok_or(RenderErr::Reject("7730 arr bad offset"))?;

    // 4. Sole dynamic arg → the tail begins EXACTLY at head-end.
    if offset != head_end {
        return Err(RenderErr::Reject("7730 arr offset != head end"));
    }
    // 5. Length word readable + read via walk's hardened reader + cap.
    let len_end = offset
        .checked_add(32)
        .ok_or(RenderErr::Reject("7730 arr ovf"))?;
    if len_end > full_body.len() {
        return Err(RenderErr::Reject("7730 arr no length"));
    }
    let len_word = full_body
        .get(offset..len_end)
        .ok_or(RenderErr::Reject("7730 arr len word"))?;
    let count = read_length_word(len_word).ok_or(RenderErr::Reject("7730 arr bad length"))?;
    if count > MAX_DYNAMIC_LEN {
        return Err(RenderErr::Reject("7730 arr len cap"));
    }
    let count = count as usize;

    // 6. The array's elements must consume the ENTIRE tail.
    let elems_bytes = count
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 arr ovf"))?;
    let total = len_end
        .checked_add(elems_bytes)
        .ok_or(RenderErr::Reject("7730 arr ovf"))?;
    if total != full_body.len() {
        return Err(RenderErr::Reject("7730 arr not whole tail"));
    }

    // 7. Human / page-budget cap.
    if count > MAX_ARRAY_RENDER {
        return Err(RenderErr::Reject("7730 arr too many elems"));
    }

    Ok((len_end, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ContextKind, HEADER_LEN, SCHEMA_VER};

    /// IR carrying a `Root + FieldIdx(0) + ArrayAll` program at path_off 1.
    fn array_ir() -> std::vec::Vec<u8> {
        // pool: [0xFF filler][len=5][0x10 0x20 0x00 0x00 0x24]
        let pool = [0xFFu8, 5, 0x10, 0x20, 0x00, 0x00, 0x24];
        let pool_len = pool.len() as u16;
        let mut buf = std::vec![0u8; HEADER_LEN];
        buf[0] = SCHEMA_VER;
        buf[1] = 0x01; // CTX_CONTRACT
        buf[126..128].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        buf[128..130].copy_from_slice(&((HEADER_LEN as u16) + pool_len).to_be_bytes());
        buf[130..132].copy_from_slice(&pool_len.to_be_bytes());
        buf[132..134].copy_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&pool);
        buf.push(0u8);
        buf
    }

    fn field() -> FieldEntry<'static> {
        FieldEntry {
            format_op: 0x02,
            label: b"Amount",
            path_off: 1,
            param_off: 0,
        }
    }

    /// `requestWithdrawals`-shaped body: offset(0x40) | owner | length | elems.
    fn body(count: usize) -> std::vec::Vec<u8> {
        let mut b = std::vec::Vec::new();
        let mut w = [0u8; 32];
        w[31] = 64;
        b.extend_from_slice(&w); // offset = 0x40
        b.extend_from_slice(&[0u8; 32]); // owner
        let mut l = [0u8; 32];
        l[28..].copy_from_slice(&(count as u32).to_be_bytes());
        b.extend_from_slice(&l); // length
        for i in 0..count {
            let mut e = [0u8; 32];
            e[31] = i as u8;
            b.extend_from_slice(&e);
        }
        b
    }

    #[test]
    fn accepts_canonical() {
        let ir_bytes = array_ir();
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        assert!(matches!(ir.context_kind, ContextKind::Contract));
        // head = 2 words (offset + owner). canonical 3-element body.
        assert_eq!(resolve_array(&field(), &ir, &body(3), 2).unwrap(), (96, 3));
        // empty array is valid.
        assert_eq!(resolve_array(&field(), &ir, &body(0), 2).unwrap(), (96, 0));
    }

    #[test]
    fn declines_hostile() {
        let ir_bytes = array_ir();
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        let f = field();
        let canon = body(2);
        // offset != head_end
        let mut b = canon.clone();
        b[31] = 96;
        assert!(resolve_array(&f, &ir, &b, 2).is_err());
        // over-claim length
        let mut b = canon.clone();
        b[64 + 31] = 3;
        assert!(resolve_array(&f, &ir, &b, 2).is_err());
        // over the element cap (9 > MAX_ARRAY_RENDER)
        assert!(resolve_array(&f, &ir, &body(9), 2).is_err());
        // short head
        assert!(resolve_array(&f, &ir, &canon[..16], 2).is_err());
        // truncated mid-element
        assert!(resolve_array(&f, &ir, &canon[..canon.len() - 1], 2).is_err());
    }
}

#[cfg(kani)]
mod kani_harnesses {
    //! Bounded verification of the dynamic-array resolver — the slot-confusion
    //! attack surface. `full_body` is the fully-symbolic attacker calldata; the
    //! path program (trusted descriptor) is fixed to the canonical
    //! `Root + FieldIdx(0) + ArrayAll` (a sole dynamic array at head slot 0,
    //! static_head_words = 2 — the Lido `requestWithdrawals(uint256[],address)`
    //! shape). Proves: NO crafted body panics / slices OOB / overflows, and on
    //! ACCEPT the returned element span lies entirely inside `full_body`.
    use super::*;
    use crate::ir::ContextKind;

    fn mk_ir(pool: &[u8]) -> Erc7730Ir<'_> {
        Erc7730Ir {
            schema_ver: SCHEMA_VER_DUMMY,
            context_kind: ContextKind::Contract,
            chain_id: 0,
            contract: [0u8; 20],
            descriptor_hash: [0u8; 32],
            domain_separator: [0u8; 32],
            owner: &[],
            contract_name: &[],
            pool,
            formats: &[],
            raw: &[],
        }
    }
    const SCHEMA_VER_DUMMY: u8 = 0x02;

    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_array_panic_free_and_in_bounds() {
        const N: usize = 160; // head(64) + length word + up to ~2 elements
        let data: [u8; N] = kani::any();
        let blen: usize = kani::any();
        kani::assume(blen <= N);
        let full_body = &data[..blen];

        // Fixed trusted path program: Root + FieldIdx(0) + ArrayAll at off 1.
        let pool = [0xFFu8, 5, 0x10, 0x20, 0x00, 0x00, 0x24];
        let ir = mk_ir(&pool);
        let field = FieldEntry { format_op: 0x02, label: b"a", path_off: 1, param_off: 0 };

        match resolve_array(&field, &ir, full_body, 2) {
            Ok((elems_start, count)) => {
                // The full element span the renderer reads is in-bounds.
                let span = count.checked_mul(32).unwrap();
                let end = elems_start.checked_add(span).unwrap();
                assert!(end <= full_body.len());
                // Exact-tail placement: the array IS the whole tail.
                assert!(end == full_body.len());
                // NOTE: at N=160 a SoleWholeTail admits only count ≤ 2, so an
                // `assert!(count <= MAX_ARRAY_RENDER)` here would be VACUOUS (the
                // count > 8 reject is structurally unreachable). The cap is
                // exercised by the concrete `resolve_array_rejects_over_cap`
                // control below instead (finding §2 #2).
            }
            Err(_) => {}
        }
    }

    /// VALUE-BINDING (2026-07-04): the panic-free harnesses above prove the
    /// accepted `(elems_start, count)` span is in-bounds — but not that it is
    /// the RIGHT span. This binds both halves to independent oracles ∀ bodies:
    /// on accept, `count` equals EXACTLY the length word the hardened reader
    /// sees at the tail (no count drift ⇒ no hidden/extra elements rendered),
    /// and `elems_start` is EXACTLY head_end+32 (offset word == head_end, the
    /// SoleWholeTail pin). Combined with the existing exact-tail equality this
    /// pins the rendered element window byte-for-byte to the ABI's.
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_array_count_binds_to_length_word() {
        const N: usize = 160;
        let data: [u8; N] = kani::any();
        let blen: usize = kani::any();
        kani::assume(blen <= N);
        let full_body = &data[..blen];
        let pool = [0xFFu8, 5, 0x10, 0x20, 0x00, 0x00, 0x24];
        let ir = mk_ir(&pool);
        let field = FieldEntry { format_op: 0x02, label: b"a", path_off: 1, param_off: 0 };
        if let Ok((elems_start, count)) = resolve_array(&field, &ir, full_body, 2) {
            // head_end = static_head_words*32 = 64; offset word pinned to it.
            assert!(read_offset_word(&full_body[0..32]) == Some(64));
            assert!(elems_start == 96); // head_end + the length word
            let oracle_count = read_length_word(&full_body[64..96])
                .expect("accepted ⇒ the length word was valid") as usize;
            assert!(count == oracle_count);
        }
    }

    /// Non-vacuity witness: a canonical 2-element sole-tail body IS accepted
    /// at exactly `(96, 2)` — the count-binding harness is not vacuous.
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_array_count_binding_accepts_concrete() {
        let pool = [0xFFu8, 5, 0x10, 0x20, 0x00, 0x00, 0x24];
        let ir = mk_ir(&pool);
        let field = FieldEntry { format_op: 0x02, label: b"a", path_off: 1, param_off: 0 };
        let mut b = [0u8; 160];
        b[31] = 64; // array offset word = head_end
        b[95] = 2; // length word = 2; elements at 96..160 (exact tail)
        assert!(matches!(resolve_array(&field, &ir, &b, 2), Ok((96, 2))));
    }

    /// Non-vacuity (finding §2 #2): the human/page-budget element cap
    /// (`count > MAX_ARRAY_RENDER` ⇒ Reject) is UNREACHABLE in the symbolic
    /// panic-free harnesses above — at N=160/224 a `SoleWholeTail` admits only
    /// ≤2/≤4 elements, so `count <= MAX_ARRAY_RENDER` there is vacuously true and
    /// deleting the reject kept both green. This concrete control feeds a
    /// well-formed 9-element sole-tail body (array offset 0x40, length word 9,
    /// nine element words = 384 B; `total == len_end(96) + 9*32 == body.len()`,
    /// so it passes the whole-tail gate and reaches step 7) and asserts the cap
    /// fires. Deleting `if count > MAX_ARRAY_RENDER` accepts it ⇒ this FAILS
    /// (`kani_mutations.json: array_element_cap`).
    #[kani::proof]
    #[kani::unwind(34)]
    fn resolve_array_rejects_over_cap() {
        let pool = [0xFFu8, 5, 0x10, 0x20, 0x00, 0x00, 0x24];
        let ir = mk_ir(&pool);
        let field = FieldEntry { format_op: 0x02, label: b"a", path_off: 1, param_off: 0 };
        let mut b = [0u8; 384];
        b[31] = 64; // array offset word = 0x40 (tail begins after the 2 head words)
        b[95] = 9; // length word low byte = 9 (> MAX_ARRAY_RENDER = 8)
        assert!(matches!(
            resolve_array(&field, &ir, &b, 2),
            Err(RenderErr::Reject("7730 arr too many elems"))
        ));
    }
}
