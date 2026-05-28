//! Stress-test registration: `stress_test!` macro + the catalog
//! aggregation that the runner iterates.
//!
//! Tests live in `tests/<category>.rs`. Each test is a `pub static`
//! declared via the `stress_test!` macro. `tests/mod.rs::ALL_TESTS`
//! lists every test in run order; this file re-exposes that slice as
//! `CATALOG` to the runner.
//!
//! ## Macro contract
//!
//! ```ignore
//! stress_test!(MY_TEST, "my_test_name", Tier::Safe, my_test_fn);
//! ```
//!
//! - `MY_TEST` — the static's identifier in this module's namespace.
//! - `"my_test_name"` — the user-facing name (matched by
//!   `SE050_STRESS_ONLY` and printed in PASS/FAIL lines). Convention:
//!   `<category>_<verb>_<subject>`.
//! - `Tier::Safe | Tier::Destructive` — see `mod.rs::Tier`.
//! - `my_test_fn` — a `fn(&mut StressCtx) -> StressResult` in scope.
//!
//! The macro is intentionally thin — it's a typing-saver + a semantic
//! signal ("this is a stress test"). Adding per-test budgets / metadata
//! later is a single-place change here.

/// Declares a stress test as a `pub static` in the calling module.
///
/// See module docs for the macro contract.
#[macro_export]
macro_rules! stress_test {
    ($static_name:ident, $name:expr, $tier:expr, $fn_ident:expr) => {
        pub static $static_name: $crate::se050_stress::StressTest =
            $crate::se050_stress::StressTest {
                name: $name,
                tier: $tier,
                run: $fn_ident,
            };
    };
}
