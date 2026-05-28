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
/// 001/0NN, …) matches order here. Safe-tier first, destructive last.
pub static ALL_TESTS: &[&StressTest] = &[
    // ----- Safe -----
    &scp03::HANDSHAKE_REPEAT,
    &scp03::APDU_BURST,
    &audit::SCP03_RESPONSE_ENCRYPTION_VERIFY,
    &audit::AUDIT_UNAUTH_READ_REFUSED,
    &object::EXTENDED_LC_BOUNDARY,
    &scp03::WTX_ENDURANCE,
    &trng::QUALITY_BASIC,
    &userid::PIN_ATTRIBUTE_READ_REFUSED_ON_USER_USERID,
    // ----- Destructive -----
    &audit::USERID_NO_ADMIN_DELETE,
    &audit::AUDIT_ADMIN_PASSIVE_READ_REFUSED,
    &audit::AUDIT_ADMIN_CANNOT_ROTATE_USER_PIN,
    &audit::AUDIT_DATA_SUBSTITUTION_CHIP_LEVEL,
    &userid::PIN_COUNTER_RESETS_ON_CORRECT_PIN,
    &userid::PIN_COUNTER_PERSISTS_ACROSS_REINIT,
    &userid::PIN_LOCKOUT_PERSISTS_ACROSS_REINIT,
    &userid::PIN_UNLIMITED_NO_LOCKOUT,
    &userid::SILICON_LOCKOUT,
];
