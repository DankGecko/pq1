//! Pure-logic Phase 2 typed-call calldata decoder — text-signature
//! parser + strict Solidity-ABI walker.
//!
//! These two passes were extracted here, verbatim and behaviour-
//! identical, out of `secure/src/tx/typed_call/{parser,abi}.rs` so the
//! WYSIWYS clear-sign decode path can be host-compiled and bounded-
//! verified with Kani (`cargo kani -p pqsigner-tx`) without the
//! secure-world `no_main` binary constraint. The firmware-side files now
//! re-export these modules unchanged, so the renderer
//! (`crate::tx::display::typed_call`) and the existing host test suite
//! (the `data/selectors.json` round-trip fixture and the ~50 parser /
//! walker unit tests, which stay in `secure/` because they resolve
//! `CARGO_MANIFEST_DIR`) keep working.
//!
//! Dependency closure is pure: [`parser`] has zero external deps;
//! [`abi`] reaches only [`crate::erc20::calldata`] (same crate) and
//! [`pqsigner_tx_core::eip1559::U256`] (an existing dependency). No
//! crypto, no hardware, no zk.

pub mod abi;
pub mod parser;
