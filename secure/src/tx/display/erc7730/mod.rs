//! ERC-7730 clear-signing renderer — **re-export shim**.
//!
//! The renderer (dispatch → field iteration → `Pages` emission: the former
//! `mod.rs` + `formatters.rs` + `intent.rs` + `nested.rs` + `calldata_nested.rs`
//! in this directory) moved into `pqsigner_erc7730::display::render` so the full
//! per-`FormatOp` dispatch can be host-linked and fuzzed — see
//! `docs/erc7730-renderer-fuzzability.md` and
//! `fuzz/fuzz_targets/erc7730_render_dispatch.rs`. It renders over the shared
//! host `Pages` (`crate::tx::display::Pages`, re-exported from the same crate).
//!
//! This shim re-exports the three render entry points the secure world calls
//! (`pick_sign_pages` for the on-chain UserOp path, `cmd_sign_offchain` for the
//! EIP-1271 / EIP-712 paths); everything else in the renderer is internal to the
//! host crate.

pub use pqsigner_erc7730::display::render::{
    render_erc7730_eip712_pages, render_erc7730_eip712_pages_v3, render_erc7730_pages,
};
