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
//! This shim exposes four render entry points to the secure module and its host
//! tests (`pick_sign_pages` for the signer-bound on-chain UserOp path,
//! `cmd_sign_offchain` for EIP-1271 / EIP-712, plus the generic contract entry
//! used by focused host tests); everything else is internal to the host crate.

pub use pqsigner_erc7730::display::render::{
    render_erc7730_eip712_pages, render_erc7730_eip712_pages_v3,
    render_erc7730_pages_with_signer,
};
#[allow(unused_imports)]
pub use pqsigner_erc7730::display::render::render_erc7730_pages;
