//! Safe-native owner / module / guard / fallback operation decoder.
//!
//! Thin re-export shim. The strict selector + fixed-arg classifier, its
//! `SafeMgmtOp` / `ThresholdValue` types, and the `page_count` helper
//! were extracted, verbatim and behaviour-identical, into the
//! host-compilable [`pqsigner_tx::safe_mgmt`] crate module so they can be
//! bounded-verified with Kani (`cargo kani -p pqsigner-tx` — decode
//! soundness: a `Some(op)` result is the verbatim canonical decode of
//! the original calldata at the correct in-bounds offsets, with each
//! address word canonical and each threshold faithful; plus
//! selector-gating reject — see `pqsigner_tx::safe_mgmt::verification`)
//! and exercised by the same host unit tests.
//!
//! Re-exported here unchanged so every caller — the outer Safe-tx
//! renderer ([`crate::tx::display::safe_mgmt`]), the per-record
//! classifier in [`super::multi_send`], [`crate::tx::display::safe_display`],
//! [`super::extra_tests`], and the render pure-tests — keeps working
//! against the `crate::tx::eip712::safe::mgmt_decode::{…}` path.
//!
//! Pure-logic counterpart to the gated renderer at
//! [`crate::tx::display::safe_mgmt`]. Fires when the outer Safe-tx render
//! sees `canonical.to == canonical.safe_address` and `raw_data[0..4]`
//! matches one of the eight Safe v1.3.0+ singleton selectors. The
//! cryptographic bind between `raw_data` and the on-chain `safeTxHash` is
//! established upstream in [`super::verify`]; by the time this module sees
//! `raw_data` it is byte-equivalent to what the on-chain Safe will
//! execute once threshold approvals collect.

pub use pqsigner_tx::safe_mgmt::{classify_safe_mgmt, page_count, SafeMgmtOp, ThresholdValue};
