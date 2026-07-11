//! Byte-identity between `fwmeasure` host output and the FSBL OLED.
//!
//! The user-facing workflow rests on this property:
//!
//!   `./measure.sh` (or `cargo run -p fwmeasure -- secure.elf`) prints
//!   8 BIP-39 words. FSBL displays the same 8 words (5-char prefix) on
//!   the OLED. If the two diverge for the same firmware image, the
//!   user-side comparison silently fails — they'd accept a "valid"
//!   release whose on-device bytes are different.
//!
//! These tests assert the agreement at the protocol level using
//! `sphincs_tz_bip39::firmware_fingerprint_lines` (the SAME pure
//! function the FSBL uses) and compare its output against fwmeasure's
//! own stdout. The contract:
//!
//!   * for each of 8 words, the 5-char prefix in
//!     `firmware_fingerprint_lines(digest)` equals the first 5 chars of
//!     the word printed by `fwmeasure <elf>` at the same position.
//!
//! Slot-image variant: the test crafts an ELF, runs `fwmeasure` for
//! the digest + words, then derives the 5-char prefix grid via
//! `firmware_fingerprint_lines` over the SAME digest. Equality of the
//! word-prefix slices proves nothing has drifted.

mod common;

use common::{minimal_elf, parse_words, run_fwmeasure};
use sha2::{Digest, Sha256};
use sphincs_tz_bip39::firmware_fingerprint_lines;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_tmp(prefix: &str, bytes: &[u8]) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = env::temp_dir().join(format!(
        "fwmeasure-byte-identity-{}-{}-{}.elf",
        prefix,
        std::process::id(),
        ts
    ));
    fs::write(&path, bytes).expect("writing temp ELF");
    path
}

/// Extract the 5-char left-column word starting at `[2..7]` of the
/// FSBL render grid for word slot `slot` (0..4). Mirrors the layout
/// in `bip39/src/lib.rs::firmware_fingerprint_lines`.
fn fsbl_left_prefix(rows: &[[u8; 16]; 4], row: usize) -> [u8; 5] {
    let mut p = [0u8; 5];
    p.copy_from_slice(&rows[row][2..7]);
    p
}

fn fsbl_right_prefix(rows: &[[u8; 16]; 4], row: usize) -> [u8; 5] {
    let mut p = [0u8; 5];
    p.copy_from_slice(&rows[row][10..15]);
    p
}

#[test]
fn positive_fsbl_prefixes_match_fwmeasure_word_prefixes() {
    // A non-trivial payload + flash window.
    let payload: Vec<u8> = (0..200u8).collect();
    let base: u32 = 0x0800_0000;
    let end: u32 = base + 0x100; // 256 bytes total measurement region
    let elf = minimal_elf(base, &payload, end);
    let path = write_tmp("fwmeasure_fsbl_agree", &elf);

    let out = run_fwmeasure([path.as_os_str()]);
    assert!(
        out.status.success(),
        "fwmeasure exited non-zero: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    let words = parse_words(&stdout);
    assert_eq!(words.len(), 8, "fwmeasure must emit 8 words");

    // Reconstruct the same digest fwmeasure computed, then run the
    // SAME pure function FSBL uses.
    let mut expected = vec![0xFFu8; (end - base) as usize];
    expected[..payload.len()].copy_from_slice(&payload);
    let digest: [u8; 32] = Sha256::digest(&expected).into();
    let rows = firmware_fingerprint_lines(&digest);

    // Slots 0..=3 are the left column (rows 0..=3); slots 4..=7 are the
    // right column.
    for slot in 0..8 {
        let (_, word) = &words[slot];
        let prefix = if slot < 4 {
            fsbl_left_prefix(&rows, slot)
        } else {
            fsbl_right_prefix(&rows, slot - 4)
        };
        let word_first5: Vec<u8> = word
            .bytes()
            .take(5)
            .chain(std::iter::repeat(b' '))
            .take(5)
            .collect();
        // Trailing zero-pad from the decoded packed prefix is rendered as ASCII
        // space by firmware_fingerprint_lines. fwmeasure's full word
        // is followed by no trailing chars (we just took the first 5),
        // so a < 5 char word like "act" yields "act  " (with 2 spaces).
        let mut padded = [b' '; 5];
        for (i, &b) in word_first5.iter().enumerate() {
            padded[i] = b;
        }
        assert_eq!(
            prefix, padded,
            "slot {} ({:?}): FSBL prefix {:?} differs from fwmeasure first-5 chars {:?}",
            slot, word, prefix, padded
        );
    }
}

#[test]
fn positive_fsbl_grid_byte_identical_across_two_runs() {
    // Determinism: same digest → same rows. Locks against any
    // accidentally non-deterministic state in firmware_fingerprint_lines.
    let digest = [0x42u8; 32];
    let a = firmware_fingerprint_lines(&digest);
    let b = firmware_fingerprint_lines(&digest);
    assert_eq!(a, b);
}

#[test]
fn positive_different_digests_yield_different_grids() {
    // Confidence check: two different digests produce different grids.
    let a = firmware_fingerprint_lines(&[0x00u8; 32]);
    let b = firmware_fingerprint_lines(&[0xFFu8; 32]);
    assert_ne!(a, b);
}
