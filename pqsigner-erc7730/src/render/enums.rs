//! Enum-table decoder for the ERC-7730 `enum` formatter (FormatOp 0x08).
//!
//! A field with `"format": "enum"` carries a `PARAM_ENUM_REF` (0x37) TLV
//! whose 2-byte payload is a big-endian offset into [`Erc7730Ir::pool`].
//! At that offset the host emitter (`dbgen::erc7730::encode_enum_table`)
//! interns a value→label table:
//!
//! ```text
//!   [u8 count]                         (number of entries, ≤ 255)
//!   count × {
//!     [u8; 8]  key   (BE u64)          (the on-chain enum value)
//!     [u8]     label_len               (≤ 254)
//!     [u8; label_len] label            (printable ASCII)
//!   }
//! ```
//!
//! The host emits entries sorted by `key`, but this decoder does NOT rely
//! on ordering — it linear-scans, so any ordering still resolves.
//!
//! ## Trust model
//!
//! The table bytes are part of the Merkle-pinned IR, so they are trusted
//! content. The strict bounds / ASCII checks here are defence-in-depth:
//! a malformed table (truncation, non-printable label byte) makes the
//! whole descriptor reject rather than render garbage on the trusted
//! display — the same posture as every other on-device parser. A value
//! the descriptor author did not enumerate is NOT an error: it returns
//! `Ok(None)` and the caller (`render_enum`) declines-to-blind, because
//! showing a bare index ("Mode: 7") under a verified intent banner would
//! be opaque and misreadable (audit M-7).

use super::RenderErr;

/// Enum labels occupy exactly three 16-column value rows.  A shorter label is
/// space-padded; a longer one is refused.  Requiring non-empty, printable,
/// non-space-terminated labels gives that painter one canonical byte spelling.
pub const ENUM_DISPLAY_BYTES: usize = 48;

fn enum_label_is_canonical(label: &[u8]) -> bool {
    !label.is_empty()
        && label.len() <= ENUM_DISPLAY_BYTES
        && label.iter().all(|&b| (0x20..0x7f).contains(&b))
        && label.iter().any(|&b| b != b' ')
        && label.last() != Some(&b' ')
}

fn parse_enum_entry(pool: &[u8], cursor: usize) -> Result<(u64, &[u8], usize), RenderErr> {
    let key_bytes = pool
        .get(cursor..cursor.checked_add(8).ok_or(RenderErr::Reject("7730 enum ovf"))?)
        .ok_or(RenderErr::Reject("7730 enum trunc key"))?;
    let label_len = *pool
        .get(cursor + 8)
        .ok_or(RenderErr::Reject("7730 enum trunc len"))? as usize;
    let label_start = cursor + 9;
    let label_end = label_start
        .checked_add(label_len)
        .ok_or(RenderErr::Reject("7730 enum ovf"))?;
    let label = pool
        .get(label_start..label_end)
        .ok_or(RenderErr::Reject("7730 enum trunc label"))?;
    if label.len() > ENUM_DISPLAY_BYTES {
        return Err(RenderErr::Reject("7730 enum label too long"));
    }
    if !enum_label_is_canonical(label) {
        return Err(RenderErr::Reject("7730 enum label canonical"));
    }
    let mut key = [0u8; 8];
    key.copy_from_slice(key_bytes);
    Ok((u64::from_be_bytes(key), label, label_end))
}

/// Deeply validate an interned enum table, including injectivity of the exact
/// device display.  The table is bounded by the 4 KiB IR cap; the allocation-
/// free O(n²) duplicate check is used only during descriptor preflight and
/// avoids trusting host-side map uniqueness.
pub fn validate_enum_table(pool: &[u8], enum_off: u16) -> Result<(), RenderErr> {
    let off = enum_off as usize;
    let count = *pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 enum off"))? as usize;
    if count == 0 {
        return Err(RenderErr::Reject("7730 enum empty"));
    }

    let mut outer_cursor = off + 1;
    for outer_idx in 0..count {
        let (outer_key, outer_label, next_outer) = parse_enum_entry(pool, outer_cursor)?;
        let mut inner_cursor = off + 1;
        for inner_idx in 0..outer_idx {
            let (inner_key, inner_label, next_inner) = parse_enum_entry(pool, inner_cursor)?;
            if outer_key == inner_key || outer_label == inner_label {
                return Err(RenderErr::Reject("7730 enum non-injective"));
            }
            inner_cursor = next_inner;
            let _ = inner_idx;
        }
        outer_cursor = next_outer;
    }
    Ok(())
}

/// Resolve the 32-byte big-endian ABI word `value` against the enum table
/// interned at `enum_off` inside `pool`.
///
/// * `Ok(Some(label))` — `value` matched an entry; `label` borrows the
///   entry's printable-ASCII display string from `pool`.
/// * `Ok(None)` — the table is structurally valid but `value` is not one
///   of its keys (caller declines-to-blind).
/// * `Err(Reject)` — the table is malformed (offset/length out of range,
///   truncated entry, or a non-printable label byte).
///
/// Enum keys are `u64`; a `value` whose top 24 bytes are non-zero cannot
/// match any key, so it short-circuits to `Ok(None)` (a `uint256` that is
/// simply not in the enum, not a malformed table). The whole table is
/// still walked + validated so a malformed tail entry is caught even when
/// an earlier entry matched.
pub fn lookup_enum_label<'a>(
    pool: &'a [u8],
    enum_off: u16,
    value: &[u8; 32],
) -> Result<Option<&'a [u8]>, RenderErr> {
    validate_enum_table(pool, enum_off)?;
    let off = enum_off as usize;
    let count = *pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 enum off"))? as usize;
    let mut cursor = off + 1;

    // A u64 key can only ever match a value whose high 24 bytes are zero.
    // Read the 32-byte word as three fixed integer windows (each a memcpy
    // + `from_be_bytes`, no per-byte loop) so the high-zero test is a pair
    // of integer compares.
    let hi16 = u128::from_be_bytes(value[0..16].try_into().unwrap());
    let mid8 = u64::from_be_bytes(value[16..24].try_into().unwrap());
    let narrow: Option<u64> = if hi16 == 0 && mid8 == 0 {
        Some(u64::from_be_bytes(value[24..32].try_into().unwrap()))
    } else {
        None
    };

    let mut found: Option<&[u8]> = None;
    for _ in 0..count {
        let (key, label, next) = parse_enum_entry(pool, cursor)?;
        cursor = next;
        // Record the first key match but keep walking to validate the
        // whole table (enum keys are unique by construction).
        if found.is_none() {
            if let Some(k) = narrow {
                if key == k {
                    found = Some(label);
                }
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `[pool]` with a 1-byte `0xFF` filler at offset 0 (mirrors
    /// the host `Pool::new` reservation) and an enum table at offset 1.
    /// Returns `(pool, enum_off)`.
    fn pool_with_table(entries: &[(u64, &str)]) -> (std::vec::Vec<u8>, u16) {
        let mut pool = std::vec![0xFFu8]; // offset-0 filler
        let off = pool.len() as u16;
        pool.push(entries.len() as u8);
        for (k, v) in entries {
            pool.extend_from_slice(&k.to_be_bytes());
            pool.push(v.len() as u8);
            pool.extend_from_slice(v.as_bytes());
        }
        (pool, off)
    }

    fn be32_u64(n: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&n.to_be_bytes());
        b
    }

    #[test]
    fn resolves_matching_value() {
        let (pool, off) = pool_with_table(&[(0, "none"), (1, "deprecated"), (2, "variable")]);
        assert_eq!(
            lookup_enum_label(&pool, off, &be32_u64(2)).unwrap(),
            Some(&b"variable"[..])
        );
        assert_eq!(
            lookup_enum_label(&pool, off, &be32_u64(0)).unwrap(),
            Some(&b"none"[..])
        );
    }

    #[test]
    fn unmatched_value_is_none_not_error() {
        let (pool, off) = pool_with_table(&[(0, "none"), (2, "variable")]);
        assert_eq!(lookup_enum_label(&pool, off, &be32_u64(7)).unwrap(), None);
    }

    #[test]
    fn value_wider_than_u64_is_none() {
        let (pool, off) = pool_with_table(&[(1, "a")]);
        let mut wide = be32_u64(1);
        wide[0] = 0x01; // high byte set → cannot be a u64 key
        assert_eq!(lookup_enum_label(&pool, off, &wide).unwrap(), None);
    }

    #[test]
    fn empty_table_is_none() {
        let (pool, off) = pool_with_table(&[]);
        assert!(lookup_enum_label(&pool, off, &be32_u64(0)).is_err());
    }

    #[test]
    fn offset_out_of_range_rejects() {
        let (pool, _off) = pool_with_table(&[(0, "none")]);
        assert!(matches!(
            lookup_enum_label(&pool, 250, &be32_u64(0)),
            Err(RenderErr::Reject(_))
        ));
    }

    #[test]
    fn truncated_label_rejects() {
        // count=1, key=2, label_len=8 ("variable") but only 4 label bytes.
        let mut pool = std::vec![0xFFu8, 1];
        pool.extend_from_slice(&2u64.to_be_bytes());
        pool.push(8);
        pool.extend_from_slice(b"vari"); // 4 of 8 bytes
        assert!(matches!(
            lookup_enum_label(&pool, 1, &be32_u64(2)),
            Err(RenderErr::Reject(_))
        ));
    }

    #[test]
    fn truncated_key_rejects() {
        // count=1 but fewer than 8 key bytes follow.
        let pool = std::vec![0xFFu8, 1, 0x00, 0x00, 0x02];
        assert!(matches!(
            lookup_enum_label(&pool, 1, &be32_u64(2)),
            Err(RenderErr::Reject(_))
        ));
    }

    #[test]
    fn non_ascii_label_rejects() {
        let mut pool = std::vec![0xFFu8, 1];
        pool.extend_from_slice(&1u64.to_be_bytes());
        pool.push(3);
        pool.extend_from_slice(&[b'a', 0x80, b'c']); // 0x80 non-printable
        // Even a value that doesn't match this entry must reject — the
        // whole table is validated.
        assert!(matches!(
            lookup_enum_label(&pool, 1, &be32_u64(9)),
            Err(RenderErr::Reject(_))
        ));
    }

    #[test]
    fn malformed_tail_rejects_even_after_match() {
        // First entry (key=2) matches and is well-formed; the second is
        // truncated. Full-table validation must still reject.
        let mut pool = std::vec![0xFFu8, 2];
        pool.extend_from_slice(&2u64.to_be_bytes());
        pool.push(3);
        pool.extend_from_slice(b"var");
        pool.extend_from_slice(&5u64.to_be_bytes());
        pool.push(9); // claims 9 label bytes, none follow
        assert!(matches!(
            lookup_enum_label(&pool, 1, &be32_u64(2)),
            Err(RenderErr::Reject(_))
        ));
    }

    #[test]
    fn duplicate_or_padding_equivalent_labels_reject() {
        let (duplicate, off) = pool_with_table(&[(1, "same"), (2, "same")]);
        assert!(validate_enum_table(&duplicate, off).is_err());

        let (padded, off) = pool_with_table(&[(1, "mode"), (2, "mode ")]);
        assert!(validate_enum_table(&padded, off).is_err());
    }

    #[test]
    fn overlong_and_blank_labels_reject() {
        let long = "x".repeat(ENUM_DISPLAY_BYTES + 1);
        let (pool, off) = pool_with_table(&[(1, &long)]);
        assert!(validate_enum_table(&pool, off).is_err());

        let (pool, off) = pool_with_table(&[(1, "   ")]);
        assert!(validate_enum_table(&pool, off).is_err());
    }
}

#[cfg(kani)]
mod kani_harnesses {
    //! Bounded verification of the enum-table decoder over symbolic
    //! (companion-supplied, Merkle-pinned) pool bytes.
    use super::*;

    /// Panic / arithmetic-overflow / slice-OOB freedom over an arbitrary
    /// pool + an in-bounds pool length, with the value held concrete and
    /// `off` pinned to the canonical interned position (1 — dbgen reserves
    /// the 0xFF filler at pool offset 0, so every real `enum_ref` is ≥ 1
    /// and points at a `[count]…` table header).
    ///
    /// Scoping (kept tractable for CBMC, sound for the property):
    /// * `value` is concrete — every pool index (`.get(off)`,
    ///   `.get(cursor..cursor+8)`, `.get(cursor+8)`, the label window) is
    ///   value-INDEPENDENT, so the panic/OOB surface is fully exercised
    ///   with a fixed value; the value-dependent key match + label return
    ///   is verified over a SYMBOLIC value by `enum_single_entry_value_sound`.
    /// * `off` is concrete (1): an `off ≥ pool.len()` is one bounds-checked
    ///   `.get(off) → None → Reject` (trivially safe by inspection); a
    ///   different in-range `off` is the same code shifted. Pinning the
    ///   canonical offset keeps the cursor arithmetic concrete while the
    ///   count / lengths / all pool bytes stay symbolic — the actual OOB
    ///   surface (the table walk over arbitrary content) is unconstrained.
    /// `count` (the table header at `pool[1]`) is bounded so CBMC can
    /// discharge the outer-loop unwinding assertion: a ≤ 16-byte pool
    /// OOB-`Reject`s by the 2nd entry (each entry is ≥ 9 bytes), so the
    /// loop reaches the identical read-past-end surface for any `count`
    /// ≥ 2 — a larger declared count only changes the (unused) loop
    /// counter, not which `.get()` runs. Bounding it keeps the proof
    /// finite without excluding any panic path.
    /// The high-zero check is loop-free (memcpy + integer compares), so the
    /// only unrolled loops are the bounded outer table walk (≤ 4) and the
    /// per-entry label-ASCII scan (≤ the pool's remaining bytes); `unwind(10)`
    /// covers both for a 16-byte pool.
    #[kani::proof]
    #[kani::unwind(10)]
    fn enum_lookup_panic_free() {
        const N: usize = 16;
        let pool: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        kani::assume((pool[1] as usize) <= 4);
        let _ = lookup_enum_label(&pool[..len], 1, &[0u8; 32]);
    }

    /// Value-soundness over a single-entry table pinned at `enum_off = 1`:
    ///   pool[0]      filler
    ///   pool[1] = 1  (count)
    ///   pool[2..10]  key (BE u64)
    ///   pool[10]= 1  (label_len)
    ///   pool[11]     label byte
    /// Accept-with-Some ⟺ the value's low-8 BE bytes equal the table key
    /// AND its high 24 bytes are zero; the returned label is exactly the
    /// in-pool byte. Reconstructs the expected key from the ORIGINAL pool
    /// at the fixed offset, so it cannot pass by re-checking the parser
    /// against itself.
    #[kani::proof]
    #[kani::unwind(28)]
    fn enum_single_entry_value_sound() {
        let mut pool = [0u8; 12];
        pool[0] = 0xFF;
        pool[1] = 1; // count
        // pool[2..10] symbolic key
        for i in 2..10 {
            pool[i] = kani::any();
        }
        pool[10] = 1; // label_len
        let label_byte: u8 = kani::any();
        kani::assume((0x20..0x7f).contains(&label_byte)); // well-formed table
        kani::assume(label_byte != b' '); // canonical, visible one-byte label
        pool[11] = label_byte;
        let value: [u8; 32] = kani::any();

        let mut key = [0u8; 8];
        key.copy_from_slice(&pool[2..10]);
        let table_key = u64::from_be_bytes(key);
        let high_zero = value[..24].iter().all(|&b| b == 0);
        let mut vlo = [0u8; 8];
        vlo.copy_from_slice(&value[24..32]);
        let value_key = u64::from_be_bytes(vlo);

        match lookup_enum_label(&pool, 1, &value) {
            Ok(Some(lbl)) => {
                assert!(high_zero && value_key == table_key);
                assert_eq!(lbl, &pool[11..12]);
            }
            Ok(None) => assert!(!high_zero || value_key != table_key),
            Err(_) => {
                // table is well-formed by construction → no reject path
                assert!(false);
            }
        }
    }

    /// Value-soundness over a TWO-entry table (finding §2 #3). The single-entry
    /// harness above only proves the match where "first match" is trivially the
    /// right entry; with two UNIQUE keys this proves the linear scan returns the
    /// label of the entry whose key ACTUALLY matches — not merely entry 0's
    /// label. A mutation that returns the first entry unconditionally (or always
    /// matches key 0) is caught HERE: a value matching key1 (and not key0)
    /// must return label1. Layout at enum_off = 1:
    ///   pool[1]=2 (count); entry0 pool[2..10]=key0,[10]=1,[11]=label0;
    ///   entry1 pool[12..20]=key1,[20]=1,[21]=label1.
    #[kani::proof]
    #[kani::unwind(28)]
    fn enum_two_entry_value_sound() {
        let mut pool = [0u8; 22];
        pool[0] = 0xFF;
        pool[1] = 2; // count
        for i in 2..10 {
            pool[i] = kani::any();
        }
        pool[10] = 1;
        let label0: u8 = kani::any();
        kani::assume((0x20..0x7f).contains(&label0));
        kani::assume(label0 != b' ');
        pool[11] = label0;
        for i in 12..20 {
            pool[i] = kani::any();
        }
        pool[20] = 1;
        let label1: u8 = kani::any();
        kani::assume((0x20..0x7f).contains(&label1));
        kani::assume(label1 != b' ');
        pool[21] = label1;

        let mut k0 = [0u8; 8];
        k0.copy_from_slice(&pool[2..10]);
        let key0 = u64::from_be_bytes(k0);
        let mut k1 = [0u8; 8];
        k1.copy_from_slice(&pool[12..20]);
        let key1 = u64::from_be_bytes(k1);
        // Enum keys are unique by construction — pin it so at most one entry
        // matches and the returned label is unambiguous.
        kani::assume(key0 != key1);

        let value: [u8; 32] = kani::any();
        let high_zero = value[..24].iter().all(|&b| b == 0);
        let mut vlo = [0u8; 8];
        vlo.copy_from_slice(&value[24..32]);
        let value_key = u64::from_be_bytes(vlo);

        match lookup_enum_label(&pool, 1, &value) {
            Ok(Some(lbl)) => {
                // Accept ⟹ the value matched a key, and the returned label is
                // exactly THAT entry's label (not merely entry 0's).
                assert!(high_zero);
                if value_key == key0 {
                    assert_eq!(lbl, &pool[11..12]); // label0
                } else {
                    assert!(value_key == key1);
                    assert_eq!(lbl, &pool[21..22]); // label1
                }
            }
            Ok(None) => {
                assert!(!high_zero || (value_key != key0 && value_key != key1));
            }
            Err(_) => assert!(false), // well-formed table → no reject path
        }
    }
}
