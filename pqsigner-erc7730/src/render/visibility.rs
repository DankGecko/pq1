//! ERC-7730 §"Conditional Visibility" — render-time evaluator.
//!
//! Per the Phase 4 plan (`~/.claude/plans/fully-implement-phase-4-
//! nested-puppy.md` §"Visibility semantics"), the five `Visibility`
//! variants collapse as follows:
//!
//! | Variant    | Phase 4 behaviour                                    |
//! |------------|------------------------------------------------------|
//! | Always     | Render unconditionally.                              |
//! | Never      | Skip; walker NOT invoked.                            |
//! | Optional   | Render (Phase 5 compact-mode toggle differentiates). |
//! | IfNotIn    | Render. Value list not yet wire-encoded by `dbgen`.  |
//! | MustMatch  | Reject. Value list not yet wire-encoded by `dbgen`.  |
//!
//! The current `dbgen::erc7730::compile_params` writes only a 1-byte
//! VISIBILITY TLV payload; sub-TLV for value lists is a Phase 5 wire
//! extension. Until that lands, `MustMatch` carries the descriptor's
//! *intent* without the mechanism to enforce it. Rather than silently
//! pretend a rule is satisfied, we reject. The secure dispatcher surfaces a
//! status banner and hard-refuses a verified/known call; it does not downgrade
//! that tuple to blind-sign.
//!
//! Once the value-list extension ships, `IfNotIn` / `MustMatch` will
//! consult `params.visibility_values` (a `[u8 count][u8 elem_len][bytes
//! ; count * elem_len]` sub-TLV) and compare against the resolved
//! [`crate::abi::AbiValue`] via byte-wise canonical encoding.

use crate::{abi::AbiValue, ir::Visibility};

use super::params::ParamSet;

/// What the visibility evaluator tells the formatter dispatcher.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Walk the path, format the value, append the page.
    Render,
    /// Skip this field — don't walk, don't format.
    Skip,
    /// Descriptor disagrees with the inbound tx — the caller surfaces
    /// `RenderErr::Reject(reason)` and refuses the verified/known call.
    Reject(&'static str),
}

/// Decide whether to render the field, given its parameter set and the
/// (optional) already-walked value. `resolved` is `None` for `Always`
/// / `Never` (cheap pre-walk decision) and `Some(value)` for the
/// IfNotIn / MustMatch branches that depend on the resolved value.
///
/// The caller is responsible for invoking the walker only when the
/// decision actually needs the value (the API encodes that by accepting
/// `Option<AbiValue>` rather than forcing the caller to walk first).
///
/// Convenience wrapper around [`should_render_with_mode`] that pins
/// the compact-mode flag off. Existing call sites that don't yet plumb
/// the toggle through keep working unchanged.
pub fn should_render(
    params: &ParamSet<'_>,
    resolved: Option<&AbiValue<'_>>,
) -> Action {
    should_render_with_mode(params, resolved, /* compact = */ false)
}

/// Phase 5 item 10 — explicit compact-mode toggle.
///
/// When `compact == true`, fields marked `Visibility::Optional` skip
/// rather than render. Phase 4 collapsed Optional → Always; this
/// distinguishes them again under an opt-in setting. The on-wire byte
/// is unchanged — only the renderer's interpretation differs.
///
/// `compact == true` is retained for design and proof work. The selected
/// product renderer wires a private compile-fenced `false`: dbgen currently
/// gives Optional fields completeness credit as displayed, so exposing a UI
/// or call-site toggle before #383's compiler/profile proof would create
/// signed-but-unshown operands.
pub fn should_render_with_mode(
    params: &ParamSet<'_>,
    resolved: Option<&AbiValue<'_>>,
    compact: bool,
) -> Action {
    match params.visibility {
        Visibility::Always => Action::Render,
        Visibility::Never => Action::Skip,
        // Phase 5 item 10: under compact mode, Optional fields skip.
        // Default (compact == false) preserves Phase 4 behaviour of
        // rendering Optional unconditionally so existing fixtures stay
        // byte-identical.
        Visibility::Optional => {
            if compact {
                Action::Skip
            } else {
                Action::Render
            }
        }
        Visibility::IfNotIn => {
            // Without a value list (Phase 5+) there is nothing to filter
            // against. Render — matches the seed-corpus's pragmatic
            // behaviour of treating "IfNotIn no list" as "always show".
            // The `_ = resolved` placeholder reminds Step 3 (and Phase
            // 5) not to drop the parameter from the call site when the
            // sub-TLV lands.
            let _ = (params.visibility_values, resolved);
            Action::Render
        }
        Visibility::MustMatch => {
            // Conservative choice — see the module comment.
            //
            // Once Phase 5 lands the value-list sub-TLV, swap the
            // unconditional reject for: walk `resolved`, scan
            // `params.visibility_values` for an equal canonical
            // encoding, render on match, reject on mismatch.
            let _ = (params.visibility_values, resolved);
            Action::Reject("7730 must-match unsupported")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params_with(v: Visibility) -> ParamSet<'static> {
        let mut p = ParamSet::default();
        p.visibility = v;
        p
    }

    #[test]
    fn always_renders_without_value() {
        let p = params_with(Visibility::Always);
        assert_eq!(should_render(&p, None), Action::Render);
    }

    #[test]
    fn never_skips() {
        let p = params_with(Visibility::Never);
        assert_eq!(should_render(&p, None), Action::Skip);
    }

    #[test]
    fn optional_renders_in_phase_4() {
        let p = params_with(Visibility::Optional);
        assert_eq!(should_render(&p, None), Action::Render);
    }

    #[test]
    fn optional_skips_under_compact_mode() {
        let p = params_with(Visibility::Optional);
        assert_eq!(
            should_render_with_mode(&p, None, true),
            Action::Skip,
            "Phase 5 item 10: compact mode skips Optional fields"
        );
    }

    #[test]
    fn always_still_renders_under_compact_mode() {
        let p = params_with(Visibility::Always);
        assert_eq!(should_render_with_mode(&p, None, true), Action::Render);
    }

    #[test]
    fn never_still_skips_under_compact_mode() {
        let p = params_with(Visibility::Never);
        assert_eq!(should_render_with_mode(&p, None, true), Action::Skip);
    }

    #[test]
    fn compact_mode_does_not_change_must_match_reject() {
        let p = params_with(Visibility::MustMatch);
        match should_render_with_mode(&p, None, true) {
            Action::Reject(_) => (),
            other => panic!("expected Reject under compact mode, got {:?}", other),
        }
    }

    #[test]
    fn page_count_compact_lt_full_when_optional_present() {
        // Synthetic mini-descriptor: 1 Always + 1 Optional + 1 Always.
        // Full mode renders all three; compact mode renders 2.
        let always = params_with(Visibility::Always);
        let optional = params_with(Visibility::Optional);
        let mut full_count = 0;
        let mut compact_count = 0;
        for p in [&always, &optional, &always] {
            if matches!(should_render_with_mode(p, None, false), Action::Render) {
                full_count += 1;
            }
            if matches!(should_render_with_mode(p, None, true), Action::Render) {
                compact_count += 1;
            }
        }
        assert_eq!(full_count, 3);
        assert_eq!(compact_count, 2);
        assert!(
            compact_count < full_count,
            "Compact rendering must drop ≥1 page when descriptor has Optional fields"
        );
    }

    #[test]
    fn if_not_in_renders_when_no_value_list() {
        let p = params_with(Visibility::IfNotIn);
        assert_eq!(should_render(&p, None), Action::Render);
    }

    #[test]
    fn must_match_rejects_in_phase_4() {
        let p = params_with(Visibility::MustMatch);
        match should_render(&p, None) {
            Action::Reject(_) => (),
            other => panic!("expected Reject, got {:?}", other),
        }
    }
}

#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    /// Action variant discriminant — compares at the variant level
    /// without touching the `Reject` `&'static str` payload. Comparing
    /// the `&str` directly makes CBMC unwind `memcmp` over a fat-pointer
    /// length it can't statically bound; the action *variant* (Render /
    /// Skip / Reject) is the behavioural contract here, and the exact
    /// banner literal is a code constant pinned by the unit tests
    /// (`must_match_rejects_in_phase_4`).
    fn variant_code(a: &Action) -> u8 {
        match a {
            Action::Render => 0,
            Action::Skip => 1,
            Action::Reject(_) => 2,
        }
    }

    /// Totality + spec-conformance of the visibility evaluator.
    ///
    /// For every byte that decodes to a valid `Visibility` (the IR/param
    /// parser rejects out-of-range bytes upstream — see
    /// `params::kani_harnesses::params_visibility_gate_and_value_sound`)
    /// and both compact-mode settings, `should_render_with_mode` is total
    /// (never panics) and returns EXACTLY the documented action variant.
    /// Exhaustive over the full `(visibility, compact)` domain.
    ///
    /// Honest scope (finding §2 info): `want` below re-expresses the documented
    /// truth table, so this is a SPEC-CONFORMANCE check (the evaluator matches
    /// its truth table), not an independent property. For `IfNotIn`/`MustMatch`
    /// that table is the value-INDEPENDENT Phase-4 placeholder (`IfNotIn` renders
    /// unconditionally, `MustMatch` always rejects — the value-list hide is not
    /// yet wire-encoded; see the module header), so this certifies the current
    /// fail-closed no-op semantics, NOT a value-based hide control.
    #[kani::proof]
    fn should_render_with_mode_total_and_spec() {
        let vb: u8 = kani::any();
        let compact: bool = kani::any();
        if let Ok(v) = Visibility::try_from(vb) {
            let mut params = ParamSet::default();
            params.visibility = v;
            // `resolved` is discarded by the evaluator in every arm, so
            // `None` is representative of the whole `Option<&AbiValue>`
            // domain for the totality + spec claim.
            let got = variant_code(&should_render_with_mode(&params, None, compact));
            let want = match v {
                Visibility::Always => 0,                       // Render
                Visibility::Never => 1,                        // Skip
                Visibility::Optional => {
                    if compact {
                        1 // Skip
                    } else {
                        0 // Render
                    }
                }
                Visibility::IfNotIn => 0,                      // Render
                Visibility::MustMatch => 2,                    // Reject
            };
            assert_eq!(got, want);
        }
    }
}
