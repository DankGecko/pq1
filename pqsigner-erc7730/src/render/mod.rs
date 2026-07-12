//! Pure-logic pieces of the ERC-7730 renderer that do NOT depend on the
//! display layer (`Pages`, `crate::ui::*`).
//!
//! Extracted from `secure/src/tx/erc7730_render/` into this host crate so
//! host-test builds and bounded verification (`cargo kani -p
//! pqsigner-erc7730`) can exercise the TLV parameter parser and the
//! visibility evaluator without secure-world (no_main / hardware) deps.
//! The secure crate re-exports this module verbatim via
//! `secure/src/tx/erc7730_render/mod.rs`, so every existing call site
//! (`crate::tx::erc7730_render::{RenderErr, params, visibility}`) keeps
//! resolving unchanged. The UI-bound formatters / nested-calldata
//! recursor remain under `secure/src/tx/display/erc7730::`.

pub mod array;
pub mod enums;
pub mod nested;
pub mod params;
pub mod resolve;
pub mod visibility;

/// Why the ERC-7730 renderer refused to take responsibility for this
/// transaction.
///
/// The secure-world dispatcher treats every variant from a verified,
/// transaction-bound descriptor as a hard refusal. Independently, its pinned
/// known-call filter refuses a registry-declared `(chain, contract, selector)` when the
/// companion omitted or failed to verify the descriptor. These variants are
/// therefore diagnostic categories, not downgrade permission.
#[derive(Debug, PartialEq, Eq)]
pub enum RenderErr {
    /// Descriptor is structurally fine but disagrees with the inbound
    /// transaction in a way that the renderer cannot paper over: a
    /// `MustMatch` value failed, a TLV blob is malformed, the walker
    /// returned an error, the inbound calldata won't decode against
    /// the format's positional schema, etc. Caller surfaces the
    /// `&'static str` reason on a `ui::show_status` banner and refuses.
    Reject(&'static str),
    /// No matching format header for the inbound `(selector |
    /// primary-type-hash[..4])`. A verified descriptor has nothing honest to
    /// draw, so the secure dispatcher refuses.
    NoFormat,
    /// Output overflowed the fixed `Pages` budget. The secure dispatcher
    /// refuses rather than hiding descriptor fields behind blind-sign.
    PageBudget,
}
