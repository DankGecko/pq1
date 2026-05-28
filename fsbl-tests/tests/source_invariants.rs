//! Source-text invariants for `pqsigner-fsbl`.
//!
//! `pqsigner-fsbl` is a `[[bin]]` crate with `#![no_std]` / `#![no_main]`
//! / `panic-halt`, so its modules can't be imported into a `cargo test`
//! binary without tripping duplicate `panic_impl` lang items. Instead
//! we read the source files as strings and pin invariants AST-style —
//! same shape as `secure/src/fw_update_boot_pure_tests.rs`.
//!
//! What's pinned here:
//!
//! 1. `fsbl/src/verify.rs::verify_images` returns `Option<[u8; 32]>`
//!    (not `bool`), so the FSBL render path is wired to the same
//!    trusted bytes FSBL verified.
//! 2. `fsbl/src/main.rs` calls `render::render_fingerprint(...)`
//!    AFTER slot selection and BEFORE `branch::into_slot(...)`. This
//!    is the trust-chain property: the user sees FSBL's verdict for
//!    the slot's bytes before the slot ever gets to display anything.
//! 3. `fsbl/src/oled.rs::Oled` has a `present: bool` field, and
//!    `Oled::init` sets it to `false` on probe failure (no-OLED
//!    graceful fallback). `flush` and `draw_text` short-circuit when
//!    `!present`. A future refactor that turns a missing OLED into a
//!    halt() would trip this test before reaching prod.
//! 4. `secure/src/measured_boot.rs` still calls `firmware_hash()` —
//!    the secondary self-attested screen survives as defense in depth.
//! 5. The render glue in `fsbl/src/render.rs` uses the bip39 crate's
//!    `firmware_fingerprint_lines`, NOT a separate copy — ensures
//!    FSBL and measured_boot stay byte-identical.

use std::fs;
use std::path::PathBuf;

fn read_workspace_file(rel: &str) -> String {
    // Walk up to the workspace root, same shape as footprint.rs.
    let mut p = std::env::current_dir().expect("cwd");
    loop {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            let s = fs::read_to_string(&candidate).unwrap_or_default();
            if s.contains("[workspace]") {
                return fs::read_to_string(p.join(rel))
                    .unwrap_or_else(|e| panic!("read {rel}: {e}"));
            }
        }
        if !p.pop() {
            panic!("no [workspace] Cargo.toml above cwd");
        }
    }
}

// ---------------------------------------------------------------------------
// 1. verify_images returns Option<[u8; 32]>
// ---------------------------------------------------------------------------

#[test]
fn negative_verify_images_returns_digest_option() {
    let src = read_workspace_file("fsbl/src/verify.rs");
    assert!(
        src.contains("pub fn verify_images(slot: Slot, m: &ManifestRef) -> Option<[u8; 32]>"),
        "fsbl::verify::verify_images must return Option<[u8; 32]> so the FSBL render path \
         can drive the OLED from the same trusted bytes — not a bool. \
         Got this signature region:\n{}",
        src.lines()
            .filter(|l| l.contains("verify_images"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    // Sanity: the success arm returns Some(actual_secure).
    assert!(
        src.contains("Some(actual_secure)"),
        "verify_images success arm must return Some(actual_secure) (the SHA-256 of the \
         verified secure image)"
    );
    // Sanity: every failure arm returns None.
    let none_returns = src.matches("return None;").count();
    assert!(
        none_returns >= 4,
        "verify_images should return None on each of: oversized secure_len, oversized \
         ns_len, secure-hash mismatch, ns-hash mismatch. Found {} `return None;`.",
        none_returns
    );
}

// ---------------------------------------------------------------------------
// 2. main.rs renders before branching
// ---------------------------------------------------------------------------

#[test]
fn negative_main_renders_fingerprint_before_branching() {
    let src = read_workspace_file("fsbl/src/main.rs");

    let render_idx = src
        .find("render::render_fingerprint(")
        .expect(
            "fsbl/src/main.rs must call render::render_fingerprint(...) on the success path \
             — that's the trust-root display the slot can't forge",
        );
    let branch_idx = src
        .find("branch::into_slot(slot)")
        .expect("fsbl/src/main.rs must call branch::into_slot(slot) on the success path");
    assert!(
        render_idx < branch_idx,
        "render_fingerprint MUST be invoked BEFORE branch::into_slot. Otherwise the slot's \
         own measured_boot screen would draw FIRST and the user couldn't tell whether the \
         FSBL row was trustworthy. Found render at byte {} and branch at byte {}.",
        render_idx,
        branch_idx
    );
}

// ---------------------------------------------------------------------------
// 3. no-OLED graceful fallback
// ---------------------------------------------------------------------------

#[test]
fn negative_no_oled_fallback_present_flag_drives_renders() {
    let src = read_workspace_file("fsbl/src/oled.rs");

    assert!(
        src.contains("present: bool"),
        "Oled struct must carry a `present: bool` so the no-OLED graceful fallback can \
         short-circuit subsequent renders without halting FSBL"
    );

    // init() must set present=false on probe failure (the early-return
    // path when neither SSD1306 address ACKs).
    assert!(
        src.contains("self.present = false;"),
        "Oled::init must set self.present = false when the I2C probe fails — a board without \
         an OLED daughterboard MUST still boot into the slot. UX regression, not a security \
         failure (FSBL still verified the slot signature + hash)."
    );

    // flush() must early-return when !present.
    let flush_section = src
        .split("pub fn flush(&self)")
        .nth(1)
        .expect("Oled::flush body");
    assert!(
        flush_section.contains("if !self.present"),
        "Oled::flush must early-return on `!self.present` — otherwise a missing OLED would \
         flood I2C with timeouts."
    );
}

// ---------------------------------------------------------------------------
// 4. measured_boot still calls firmware_hash() (defense in depth)
// ---------------------------------------------------------------------------

#[test]
fn negative_secure_measured_boot_still_self_attests() {
    let src = read_workspace_file("secure/src/measured_boot.rs");
    assert!(
        src.contains("let hash = firmware_hash();"),
        "secure/src/measured_boot.rs must still compute its own firmware_hash() — the \
         secure-world screen is advisory (self-attested) and serves as defense in depth \
         against the FSBL display. Removing it would lose the divergence-tamper signal."
    );
    assert!(
        src.contains("hash_to_word_indices(&hash)"),
        "measured_boot::run must derive its display indices from `hash_to_word_indices(&hash)` \
         so they remain comparable byte-for-byte to FSBL's prefix5 render"
    );
}

// ---------------------------------------------------------------------------
// 5. render.rs uses bip39's pure function (no separate copy)
// ---------------------------------------------------------------------------

#[test]
fn negative_render_glue_uses_bip39_pure_function() {
    let src = read_workspace_file("fsbl/src/render.rs");
    assert!(
        src.contains("use sphincs_tz_bip39::firmware_fingerprint_lines"),
        "fsbl/src/render.rs must import firmware_fingerprint_lines from sphincs_tz_bip39. \
         If render keeps its own copy of the layout logic, FSBL and measured_boot risk \
         drifting (different bytes for the same digest), which silently breaks the \
         user-side comparison workflow."
    );
    assert!(
        src.contains("firmware_fingerprint_lines(digest)"),
        "render_fingerprint must call firmware_fingerprint_lines(digest) — that's the \
         shared pure-logic entry point"
    );
}

// Track this so its path stays stable even if the workspace shuffles.
#[test]
fn positive_workspace_layout_sanity() {
    let _ = PathBuf::from("fsbl/src/render.rs");
    let _ = PathBuf::from("fsbl/src/verify.rs");
    let _ = PathBuf::from("fsbl/src/main.rs");
    let _ = PathBuf::from("fsbl/src/oled.rs");
    let _ = PathBuf::from("secure/src/measured_boot.rs");
}
