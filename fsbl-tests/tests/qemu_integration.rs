//! QEMU integration tests for the FSBL fingerprint screen.
//!
//! These tests are **`#[ignore]`d placeholders**: they document the
//! shape of the empirical proofs the plan calls for, but the QEMU
//! harness work required to run them (auto-spawn `qemu-system-arm
//! -M mps2-an505`, capture OLED frames via the `ui-capture` feature,
//! drive the `CMD_FW_BEGIN`/`CHUNK*`/`COMMIT` flow via the in-tree
//! e2e USB-mailbox test driver) is non-trivial and out of scope for
//! the initial FSBL-display PR. They run only under `cargo test --
//! --ignored`.
//!
//! The **structural** equivalents of these properties are already
//! checked unconditionally:
//!
//!   * `firmware_fingerprint_lines` matches `fwmeasure` output —
//!     `fwmeasure/tests/byte_identity.rs::positive_fsbl_prefixes_
//!     match_fwmeasure_word_prefixes`.
//!   * FSBL renders BEFORE `branch::into_slot` —
//!     `fsbl-tests/tests/source_invariants.rs::negative_main_renders_
//!     fingerprint_before_branching`.
//!   * `measured_boot::run` survives as defense in depth —
//!     `fsbl-tests/tests/source_invariants.rs::negative_secure_measured_
//!     boot_still_self_attests`.
//!
//! Together those prove: a) FSBL's displayed bytes derive from the
//! verified slot digest, b) the slot has no opportunity to overwrite
//! FSBL's row before the user sees it. The QEMU tests below are the
//! empirical demonstration of the same property; they're a "would
//! be nice" rather than a "must have" for landing the PR.

/// Empirical proof that the FSBL OLED row equals the secure-world's
/// `measured_boot::run` row for the same slot. Spawns QEMU, captures
/// the SHA-256 of the OLED frame at two points (just before
/// `branch::into_slot`; during `measured_boot::run`), asserts equality.
#[test]
#[ignore = "needs QEMU harness — see module docs"]
fn qemu_fsbl_frame_matches_secure_world_frame() {
    // TODO: spawn `qemu-system-arm -M mps2-an505 -kernel <bundled-fsbl> -kernel-options ...`
    // TODO: enable `ui-capture` feature in the secure build
    // TODO: read frame hashes from semihosting output
    // TODO: assert frame_fsbl == frame_secure_world
}

/// Empirical proof that "subsequent updates cannot fake the words":
/// pre-stage two different signed `secure.elf` images. Boot QEMU,
/// capture FSBL row as baseline. Drive `CMD_FW_BEGIN`/`CHUNK*`/`COMMIT`
/// (via the in-tree USB-mailbox test driver) to install the alternate
/// image. Reboot. Assert the FSBL row differs from the baseline.
#[test]
#[ignore = "needs QEMU + signed-image fixtures — see module docs"]
fn qemu_fsbl_row_changes_after_alternate_image_install() {
    // TODO: pre-stage `secure_a.elf` and `secure_b.elf` (different builds)
    // TODO: boot QEMU with `secure_a.elf` as the active slot — capture FSBL row
    // TODO: drive CMD_FW_BEGIN/CHUNK*/COMMIT with `secure_b.elf` → inactive slot
    // TODO: reboot, capture FSBL row → must differ from the first capture
    // TODO: assert captured row matches `firmware_fingerprint_lines(sha256(secure_b))`
}

/// Planned experiment showing that a malicious slot's `measured_boot::run`
/// cannot forge the legacy bench-FSBL fingerprint. It becomes production
/// trust-root evidence only after the approved FSBL geometry and immutable
/// option-byte ceremony close. Build a secure-world variant
/// under a hidden `cfg(test_malicious_slot)` flag that hard-codes a
/// fake `firmware_hash()` return value. Boot under QEMU. Assert:
///   * FSBL's frame matches `fwmeasure(real_bytes)` (bench parity holds),
///   * `measured_boot::run`'s frame matches the fake hardcoded value
///     (the lie is visible — divergence is the tamper signal).
#[test]
#[ignore = "needs QEMU + cfg(test_malicious_slot) variant — see module docs"]
fn qemu_malicious_slot_cannot_forge_fsbl_row() {
    // TODO: build secure-world with `--cfg test_malicious_slot` overriding firmware_hash()
    // TODO: boot QEMU, capture both rows
    // TODO: assert FSBL row == fwmeasure(real_bytes)
    // TODO: assert secure-world row == hardcoded fake
    // TODO: assert the two rows DIVERGE → the slot lies, FSBL stays truthful
}
