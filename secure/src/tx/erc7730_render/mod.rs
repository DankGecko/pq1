//! Re-export shim over `pqsigner_erc7730::render`.
//!
//! The pure-logic pieces of the ERC-7730 renderer that do NOT depend on
//! the display layer (`Pages`, `crate::ui::*`) — the TLV parameter parser
//! and the visibility evaluator — were extracted into the host crate so
//! host-test builds (which gate out `tx::display`) and bounded
//! verification (`cargo kani -p pqsigner-erc7730`) can exercise them
//! without secure-world deps.
//!
//! Existing call sites reach through this shim
//! (`crate::tx::erc7730_render::{RenderErr, params, visibility}`) rather
//! than naming the workspace crate directly, symmetric to
//! `secure/src/tx/erc7730.rs` re-exporting the rest of the crate. The
//! UI-bound formatters / nested-calldata recursor remain under
//! `crate::tx::display::erc7730::`.

pub use pqsigner_erc7730::render::{enums, params, visibility, RenderErr};
