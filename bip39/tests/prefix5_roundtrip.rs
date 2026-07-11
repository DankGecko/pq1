//! Round-trip + uniqueness invariants for the FSBL-facing prefix table.
//!
//! The FSBL embeds only the base-27-packed prefix table
//! (`WORDLIST_PREFIX5_PACKED`, 3 bytes/entry) to stay inside its flash
//! ceiling. The 8 BIP-39 measurement words it renders on the LCD are looked
//! up via [`word_prefix_at`], which scans the packed table constant-time and
//! decodes the selected 3-byte code back to the 5-byte prefix. For the
//! user-side comparison workflow to be sound, these properties must hold:
//!
//! 1. **Lossless round-trip.** For every index, `word_prefix_at(idx)` decodes
//!    to the byte-exact first 5 bytes of the full word from `WORDLIST`
//!    (zero-padded if shorter than 5 chars). If the packing/decode drifts
//!    from the canonical `wordlist.rs` source, the FSBL would display
//!    different bytes than `fwmeasure` / `./measure.sh` derives — silently
//!    breaking the "the device shows what you'd expect" property.
//!
//! 2. **Uniqueness.** All 2048 decoded prefixes are unique. BIP-39 already
//!    guarantees 4-char uniqueness; the packing is a lossless bijection on
//!    `{0, a..=z}^5`, so it can't reduce that.
//!
//! 3. **Constant-time scan correctness.** `word_prefix_at(idx)` returns the
//!    same bytes as directly decoding `WORDLIST_PREFIX5_PACKED[idx]`, and an
//!    out-of-range index yields a blank (all-zero) prefix.

use sphincs_tz_bip39::{
    firmware_fingerprint_lines, hash_to_word_indices, word_prefix_at, FINGERPRINT_COLS,
    FINGERPRINT_ROWS, WORDLIST, WORDLIST_PREFIX5_PACKED,
};

/// Compute the canonical prefix-5 for a word: first 5 bytes, zero-padded.
fn expected_prefix(word: &str) -> [u8; 5] {
    let b = word.as_bytes();
    let mut p = [0u8; 5];
    for i in 0..5 {
        if i < b.len() {
            p[i] = b[i];
        }
    }
    p
}

/// Reference decode of a packed 3-byte base-27 code back to the 5-byte
/// prefix — an independent mirror of the decode inside `word_prefix_at`, so
/// the constant-time scan is checked against a straight index + decode.
fn unpack(code_bytes: [u8; 3]) -> [u8; 5] {
    let mut code = (u32::from(code_bytes[0]) << 16)
        | (u32::from(code_bytes[1]) << 8)
        | u32::from(code_bytes[2]);
    let mut out = [0u8; 5];
    let mut i = 5;
    while i > 0 {
        i -= 1;
        let sym = (code % 27) as u8;
        code /= 27;
        out[i] = if sym == 0 { 0 } else { b'a' + sym - 1 };
    }
    out
}

#[test]
fn positive_word_prefix_at_round_trips_every_word() {
    // pack (build.rs) → store → scan → decode (word_prefix_at) must equal the
    // canonical first-5-bytes prefix for all 2048 entries.
    for (idx, w) in WORDLIST.iter().enumerate() {
        let expected = expected_prefix(w);
        let actual = word_prefix_at(idx as u16);
        assert_eq!(
            actual, expected,
            "word_prefix_at({}) = {:?} but WORDLIST[{}] = {:?} (expected prefix {:?})",
            idx, actual, idx, w, expected,
        );
    }
}

#[test]
fn positive_packed_table_has_exactly_2048_entries() {
    assert_eq!(
        WORDLIST_PREFIX5_PACKED.len(),
        2048,
        "FSBL render assumes a 2048-entry prefix table",
    );
}

#[test]
fn negative_all_decoded_prefixes_are_unique() {
    // BIP-39 guarantees 4-char uniqueness; the decoded 5-byte prefixes must
    // remain unique (the packing is a bijection, so it cannot collide them).
    let mut sorted: Vec<[u8; 5]> = (0u16..2048).map(word_prefix_at).collect();
    sorted.sort();
    for w in sorted.windows(2) {
        assert_ne!(
            w[0], w[1],
            "prefix collision found: {:?} appears at least twice",
            w[0]
        );
    }
}

#[test]
fn positive_constant_time_scan_matches_direct_index_decode() {
    // The CT scan in word_prefix_at must be byte-identical to directly
    // indexing the packed table and decoding it. This locks in the mask-OR
    // accumulator + the base-27 decode against any future refactor.
    for idx in 0u16..2048 {
        let direct = unpack(WORDLIST_PREFIX5_PACKED[idx as usize]);
        let scanned = word_prefix_at(idx);
        assert_eq!(
            scanned, direct,
            "word_prefix_at({}) = {:?} but decode(WORDLIST_PREFIX5_PACKED[{}]) = {:?}",
            idx, scanned, idx, direct,
        );
    }
}

#[test]
fn negative_word_prefix_at_out_of_range_returns_zero() {
    // For idx >= 2048 the CT scan never matches, so the code stays zero and
    // every symbol decodes to padding. This guarantees an out-of-spec caller
    // doesn't accidentally render some "random" wordlist entry's prefix —
    // they get a blank instead, a recognisable error in the LCD display.
    assert_eq!(word_prefix_at(2048), [0u8; 5]);
    assert_eq!(word_prefix_at(0xFFFF), [0u8; 5]);
}

#[test]
fn positive_first_and_last_entries_are_canonical() {
    // Sanity-pin the canonical first ("abandon") and last ("zoo") entries so
    // a build.rs drift that re-orders the wordlist would trip this test
    // before any user-facing fingerprint diverges. Also covers the two
    // extremes for the packing: a full-length prefix and a short (padded)
    // word.
    assert_eq!(WORDLIST[0], "abandon");
    assert_eq!(word_prefix_at(0), *b"aband");
    assert_eq!(WORDLIST[2047], "zoo");
    assert_eq!(word_prefix_at(2047), [b'z', b'o', b'o', 0, 0]);
}

// ---------------------------------------------------------------------------
// firmware_fingerprint_lines — exact-byte-grid pin (FSBL ↔ measured_boot
// must produce byte-identical LCD rows for the same digest, otherwise the
// user-facing comparison workflow breaks). Unchanged by the packing: the
// decoded output feeds the same renderer.
// ---------------------------------------------------------------------------

#[test]
fn positive_fingerprint_lines_layout_geometry() {
    assert_eq!(FINGERPRINT_ROWS, 4);
    assert_eq!(FINGERPRINT_COLS, 16);
    let rows = firmware_fingerprint_lines(&[0u8; 32]);
    assert_eq!(rows.len(), FINGERPRINT_ROWS);
    assert_eq!(rows[0].len(), FINGERPRINT_COLS);
}

#[test]
fn positive_fingerprint_lines_match_word_prefix_at_for_zero_digest() {
    // For an all-zero digest, hash_to_word_indices returns all-zero
    // indices, so every word is `WORDLIST[0] = "abandon"` → prefix
    // "aband". The grid is therefore deterministic and we can pin it.
    let rows = firmware_fingerprint_lines(&[0u8; 32]);
    // Row 0: "1 aband 5 aband " — 16 cols total.
    //         0123456789012345
    assert_eq!(&rows[0], b"1 aband 5 aband ");
    assert_eq!(&rows[1], b"2 aband 6 aband ");
    assert_eq!(&rows[2], b"3 aband 7 aband ");
    assert_eq!(&rows[3], b"4 aband 8 aband ");
}

#[test]
fn positive_fingerprint_lines_zero_bytes_become_spaces() {
    // Find an index whose word is < 5 chars (e.g. "zoo" at idx 2047).
    // The decode zero-pads short words; firmware_fingerprint_lines must
    // translate those zeros to ASCII spaces so the LCD blits blanks
    // instead of NUL glyphs.
    let prefix = word_prefix_at(2047);
    assert_eq!(prefix, [b'z', b'o', b'o', 0, 0]);

    // Craft a digest whose 11-bit slice 0 == 2047. 2047 = 0x7FF, all
    // bits in the top 11. Big-endian: first 11 bits = `0b11111111111`.
    // 0xFFE0 in the top two bytes covers exactly bits 0..10. Use that
    // for slot 0 and zero for the rest so we know every other word
    // index is 0 ("abandon").
    let mut digest = [0u8; 32];
    digest[0] = 0xFF;
    digest[1] = 0xE0;
    let indices = hash_to_word_indices(&digest);
    assert_eq!(indices[0], 2047, "11-bit slice extraction sanity check");

    let rows = firmware_fingerprint_lines(&digest);
    // Row 0 left column: "1 zoo  " — zoo + 2 trailing spaces, then "  5 ".
    assert_eq!(&rows[0][..8], b"1 zoo   ");
    // Right column stays "aband" (other indices are still 0).
    assert_eq!(&rows[0][8..], b"5 aband ");
}

#[test]
fn positive_fingerprint_lines_left_column_digits_are_1_through_4() {
    let rows = firmware_fingerprint_lines(&[0u8; 32]);
    assert_eq!(rows[0][0], b'1');
    assert_eq!(rows[1][0], b'2');
    assert_eq!(rows[2][0], b'3');
    assert_eq!(rows[3][0], b'4');
}

#[test]
fn positive_fingerprint_lines_right_column_digits_are_5_through_8() {
    let rows = firmware_fingerprint_lines(&[0u8; 32]);
    assert_eq!(rows[0][8], b'5');
    assert_eq!(rows[1][8], b'6');
    assert_eq!(rows[2][8], b'7');
    assert_eq!(rows[3][8], b'8');
}

#[test]
fn positive_fingerprint_lines_are_ascii_printable() {
    // Every byte in the rendered grid must be ASCII printable space
    // (0x20) or higher. NUL bytes would blit as solid blocks via the
    // 5x8 font's index-0 glyph, which is NOT what the user expects.
    let rows = firmware_fingerprint_lines(&[0xAB; 32]);
    for (r, row) in rows.iter().enumerate() {
        for (c, &b) in row.iter().enumerate() {
            assert!(
                (0x20..=0x7E).contains(&b),
                "row {} col {} byte 0x{:02x} is not ASCII printable",
                r,
                c,
                b
            );
        }
    }
}
