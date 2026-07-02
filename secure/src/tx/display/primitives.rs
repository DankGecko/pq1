//! Row-level formatting helpers shared by every renderer in this
//! directory — **re-export shim** over `pqsigner_erc7730::display::primitives`.
//!
//! The pure-logic byte-writers (amount/decimal scaling, address truncation,
//! hex, chain/ticker naming) were extracted into the host crate so they can be
//! host-fuzzed — `overflow-checks = true` makes any arithmetic slip on an
//! attacker-controlled `U256` (from calldata) a panic = DoS, and the moved
//! writers are the highest-panic-density code on the render path. See
//! `fuzz/fuzz_targets/erc7730_display_primitives.rs` and
//! `docs/erc7730-renderer-fuzzability.md`. Every sibling renderer under
//! `display::` keeps calling `super::primitives::*` unchanged; the row buffers
//! they pass are `[u8; ui::DISPLAY_COLS]` (= `[u8; 16]`), the same concrete type
//! the moved helpers take (`[u8; pqsigner_erc7730::display::DISPLAY_COLS]`).
//!
//! Design rules for every helper (enforced in the host crate, restated here so
//! call-site authors see them):
//!
//! * **Never silently truncate a number.** The trusted display treats a
//!   truncated value as dangerous as a wrong one — return `false` /
//!   `AmountFit::Overflow` and let the caller render a visible warning.
//! * **No panics on any input** (including attacker-supplied values).
//! * **Left-aligned, space-padded rows.** Every helper takes a
//!   `&mut [u8; DISPLAY_COLS]` and writes exactly one row's worth of ASCII.

pub use pqsigner_erc7730::display::primitives::*;
