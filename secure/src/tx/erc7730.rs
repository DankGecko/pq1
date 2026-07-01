//! Re-export shim over `pqsigner-erc7730`.
//!
//! Symmetric to `secure/src/tx/mod.rs` re-exporting `pqsigner-tx-core`
//! and `secure/src/erc20/mod.rs` re-exporting `pqsigner-tx::erc20`.
//! Existing call sites (`crate::tx::erc7730::verify_erc7730_bundle`)
//! reach through this shim rather than naming the workspace crate
//! directly, so a future move of the crate's path doesn't ripple
//! into the secure code.
//!
//! The shim also funnels the firmware-pinned Merkle root through a
//! thin wrapper so call sites don't have to reach into `db_roots`
//! every time.

pub use pqsigner_erc7730::binding::{
    cross_check_contract, cross_check_eip712, BindingError,
};
pub use pqsigner_erc7730::bundle::{
    leaf_hash, verify_erc7730_bundle, BundleError, VerifiedDescriptor,
    MAX_ERC7730_BUNDLE_LEN, MAX_PROOF_DEPTH,
};
pub use pqsigner_erc7730::ir::{
    ContextKind, Erc7730Ir, FieldEntry, FieldIter, FormatHeader, FormatIter,
    FormatOp, IrError, PathOp, Visibility, HEADER_LEN, MAX_FIELDS_PER_FORMAT,
    MAX_FORMATS, MAX_IR_LEN, MAX_NESTING, MAX_POOL_ENTRY_LEN, SCHEMA_VER,
};
// NOTE: the Phase-3 `walker::{resolve_program, resolve_path, path_bytes, WalkerCtx}`
// is deliberately NOT re-exported. The live render path walks paths via the local
// `display::erc7730::formatters` resolvers + `render::resolve`, and the walker's
// extraction-op wire encoding (`ArrayIdx = u32`, `ArraySlice = u32+u32`) is
// INCOMPATIBLE with the live Tier B tokenPath encoding (`ArrayIdx = u16`,
// `ArraySlice = u16+u16+from_end`). Re-exporting it onto the firmware surface would
// invite a confirm-vs-execute desync — see `pqsigner-erc7730/src/walker.rs` header.
pub use pqsigner_erc7730::abi::{
    container_field, AbiField, AbiNode, AbiValue, AbiView, ContainerView,
};
