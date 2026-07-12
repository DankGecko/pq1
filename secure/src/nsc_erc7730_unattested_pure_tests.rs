//! Host-side regression tests for the `erc7730-dev-unattested` Cargo
//! feature (Phase 5 item 3).
//!
//! The actual renderer behaviour (a "DEV UNATTESTED" warning page
//! prepended to the intent banner) lives inside the gated `tx::display`
//! tree, which is `#[cfg(not(test))]` because the production module
//! depends on hardware-only `crate::ui::*` bindings. The tests here
//! therefore exercise the wiring via source-text inspection:
//!
//!   1. `secure/Cargo.toml` declares the feature.
//!   2. `secure/src/nsc/mod.rs` carries the `mode-production` +
//!      `erc7730-dev-unattested` mutual-exclusion `compile_error!`.
//!   3. generated `secure/src/db_roots.rs` ties a dev-unattested root to the
//!      warning feature even for non-production direct-Cargo builds.
//!   4. `secure/src/tx/display/erc7730/intent.rs` exports an
//!      `INTENT_BANNER_PAGES` const whose value tracks the feature
//!      gate (1 default, 2 under the feature).
//!
//! When the on-target firmware build pulls the feature in, the
//! source-text invariants below stay green AND the firmware crate
//! cross-compiles for `thumbv8m.main-none-eabi`. When the production
//! build drops the feature, the source-text still pins the no-feature
//! const at 1. The production fence (test #2) is verified at the build
//! invocation level (a `cargo check --features
//! mode-production,erc7730-dev-unattested` MUST fail loudly).

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const NSC_MOD_RS: &str = include_str!("nsc/mod.rs");
const DB_ROOTS_RS: &str = include_str!("db_roots.rs");
const INTENT_RS: &str = include_str!("../../pqsigner-erc7730/src/display/render/intent.rs");

#[test]
fn cargo_toml_declares_erc7730_dev_unattested_feature() {
    // The feature now propagates to the host crate that owns the intent
    // renderer (`erc7730-dev-unattested = ["pqsigner-erc7730/..."]`), so match
    // the declaration prefix rather than the empty-list literal.
    assert!(
        CARGO_TOML.contains("erc7730-dev-unattested = ["),
        "secure/Cargo.toml must declare the `erc7730-dev-unattested` feature \
         (Phase 5 item 3 of `docs/archive/handoff-erc7730-phase5.md`)."
    );
}

#[test]
fn nsc_mod_has_mode_production_mutual_exclusion_fence() {
    // The dedicated fence block (mode-production + erc7730-dev-unattested
    // mutually exclusive) appears verbatim in nsc/mod.rs.
    assert!(
        NSC_MOD_RS.contains("mode-production and erc7730-dev-unattested"),
        "secure/src/nsc/mod.rs must `compile_error!` when both \
         `mode-production` and `erc7730-dev-unattested` are enabled \
         (Phase 5 item 3). Mirror the existing `debug-log` / `e2e-test` \
         / `mock-se` / `otp-hardcoded-master-key` / `ui-capture` fences."
    );
    // The fence is `cfg(all(feature = "mode-production", feature =
    // "erc7730-dev-unattested"))` — confirm BOTH feature names appear
    // in the same #[cfg(all(...))] block.
    let block_marker = "#[cfg(all(\n    feature = \"mode-production\",\n    feature = \"erc7730-dev-unattested\"";
    assert!(
        NSC_MOD_RS.contains(block_marker),
        "Fence must be a `#[cfg(all(feature = \"mode-production\", feature = \"erc7730-dev-unattested\"))]` block"
    );
}

#[test]
fn generated_root_requires_warning_feature_for_dev_provenance() {
    // Unlike secret-leaking debug/test features, the provenance-warning
    // feature is valid on an explicitly non-production hardware build. The
    // generated root file is the stronger gate: it requires the warning for
    // the exact dev-unattested root and independently rejects that root under
    // mode-production.
    assert!(
        DB_ROOTS_RS.contains(
            "the pinned ERC-7730 catalogue is dev-unattested; enable \
             erc7730-dev-unattested"
        ),
        "generated db_roots.rs must require the trusted-display warning for \
         a dev-unattested production-shaped catalogue"
    );
    assert!(
        DB_ROOTS_RS.contains(
            "mode-production cannot embed the dev-unattested ERC-7730 catalogue"
        ),
        "generated db_roots.rs must fail closed when mode-production selects \
         a dev-unattested catalogue"
    );
}

#[test]
fn intent_banner_page_count_const_present() {
    assert!(
        INTENT_RS.contains("pub const INTENT_BANNER_PAGES: usize = 2;"),
        "intent.rs must expose INTENT_BANNER_PAGES = 2 under the \
         erc7730-dev-unattested feature."
    );
    assert!(
        INTENT_RS.contains("pub const INTENT_BANNER_PAGES: usize = 1;"),
        "intent.rs must expose INTENT_BANNER_PAGES = 1 without the \
         erc7730-dev-unattested feature."
    );
    // Both `cfg(feature = ...)` and `cfg(not(feature = ...))` arms
    // must be present so swapping the feature flag changes which
    // const survives the cfg.
    assert!(
        INTENT_RS.contains("#[cfg(feature = \"erc7730-dev-unattested\")]"),
        "INTENT_BANNER_PAGES = 2 must be gated on the feature."
    );
    assert!(
        INTENT_RS.contains("#[cfg(not(feature = \"erc7730-dev-unattested\"))]"),
        "INTENT_BANNER_PAGES = 1 must be the no-feature default."
    );
}

#[test]
fn intent_banner_renders_warning_row_under_dev_unattested() {
    // The renderer body itself is gated out of test mode (display is
    // `#[cfg(not(test))]`), so this is a source-text check: the
    // intent.rs body contains the warning text exactly once under
    // `#[cfg(feature = "erc7730-dev-unattested")]`.
    assert!(
        INTENT_RS.contains("** DEV BUILD **"),
        "intent.rs must render a `** DEV BUILD **` row when the \
         erc7730-dev-unattested feature is on."
    );
    assert!(
        INTENT_RS.contains("Unattested") && INTENT_RS.contains("descriptor"),
        "intent.rs warning row must say `Unattested descriptor`."
    );
}
