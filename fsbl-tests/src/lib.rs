//! Host-only test support for `pqsigner-fsbl`.
//!
//! Nothing in this crate is linked into the immutable bootloader.  In
//! addition to the integration tests in `tests/`, it contains independent
//! executable models of frozen architecture contracts that are deliberately
//! kept out of production until their physical backends are selected and
//! reviewed.

pub mod rollback_model;
