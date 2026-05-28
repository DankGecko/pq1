//! Stress-test catalog by category.
//!
//! Each category file (`scp03.rs`, `userid.rs`, …) declares each test
//! as a `pub static FOO: StressTest = …` (via the `stress_test!`
//! macro). This file lists every test once in `ALL_TESTS` — that is
//! the canonical run order.
//!
//! Adding a new test = (a) write fn + `stress_test!` in the
//! appropriate category file, (b) append `&category::FOO,` to
//! `ALL_TESTS` below.
//!
//! Adding a NEW category = drop a new file under `tests/`, add `mod
//! <name>;` below, append the new tests to `ALL_TESTS`.

use super::StressTest;

pub mod scp03;
pub mod userid;
pub mod trng;
pub mod object;
pub mod audit;

/// The runner-visible test catalog. Order shown to the user (BEGIN
/// 001/008, …) matches order here. Safe-tier first, destructive last.
pub static ALL_TESTS: &[&StressTest] = &[
    // ----- Safe -----
    &scp03::HANDSHAKE_REPEAT,
    &scp03::APDU_BURST,
    &audit::SCP03_RESPONSE_ENCRYPTION_VERIFY,
    &object::EXTENDED_LC_BOUNDARY,
    &scp03::WTX_ENDURANCE,
    &trng::QUALITY_BASIC,
    // ----- Destructive -----
    &audit::USERID_NO_ADMIN_DELETE,
    &userid::SILICON_LOCKOUT,
];
