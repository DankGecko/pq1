//! Host-compilable render substrate for the ERC-7730 (and shared) display path.
//!
//! [`primitives`] holds the pure row-buffer byte-writers — amount/decimal
//! scaling, address truncation, hex, chain/ticker naming — that the on-device
//! renderers in `secure/src/tx/display/` call to fill a single
//! `[u8; DISPLAY_COLS]` row. They were extracted out of the secure crate's
//! `#[cfg(not(test))]`-gated `tx::display` tree (which is gated only because it
//! imports the hardware-only `crate::ui`) so they can be **host-fuzzed** — see
//! `fuzz/fuzz_targets/erc7730_display_primitives.rs`. `overflow-checks = true`
//! in the firmware profile turns any arithmetic slip in the amount writers on
//! an attacker-controlled `U256` (the value comes from calldata) into a panic =
//! DoS, and the descriptor-side resolvers this crate already fuzzes never
//! exercise that byte arithmetic — so this is the highest-panic-density code on
//! the render path.
//!
//! The secure crate re-exports this module verbatim
//! (`secure/src/tx/display/primitives.rs` → `pub use
//! pqsigner_erc7730::display::primitives::*`), so the ~17 on-device call sites
//! and the `display_under_test` host-test scaffold both resolve here unchanged.
//!
//! The heavier `Pages`/`MAX_PAGES` buffer + the per-`FormatOp` dispatch that
//! emits into it stay in the secure crate for now: `Pages` is written directly
//! (over 400 `.buf`/`.len` field accesses) by the whole `tx::display` renderer
//! tree, so host-linking the full dispatch is a `pub(super)→pub` field widening
//! plus moving `Pages` + the five ERC-7730 render files — a larger, separate
//! follow-up (scoped in `docs/erc7730-renderer-fuzzability.md`), not a wall.

pub mod primitives;

/// Logical display width in cells. MUST equal the secure crate's
/// `crate::ui::DISPLAY_COLS`: the row buffers the on-device renderers pass to
/// [`primitives`] are `[u8; ui::DISPLAY_COLS]`, and Rust arrays are matched by
/// their concrete length — a mismatch would be a hard type error at the shim,
/// not silent, but pin it here so the two constants can never drift unnoticed.
pub const DISPLAY_COLS: usize = 16;

// Compile-time tripwire mirroring `secure/src/ui_under_test`'s assert that the
// secure-side constant is 16. If either side changes, one of the two asserts
// fires and forces a coordinated update.
const _: () = assert!(DISPLAY_COLS == 16);
