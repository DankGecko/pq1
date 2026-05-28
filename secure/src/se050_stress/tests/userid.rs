//! UserID PIN-counter behavior under stress.
//!
//! Tests in this category are `Tier::Destructive` — they drive a test
//! UserID to its silicon-enforced lockout state. The runner's per-test
//! teardown cleans up the stranded OIDs via admin auth.

use crate::stress_test;
use crate::se050::apdu::Se050Error;
use crate::se050_stress::{StressCtx, StressError, StressResult, Tier};
use crate::se050_stress::ctx::AdminPolicy;

// ---------------------------------------------------------------------------
// 8. userid_silicon_lockout
// ---------------------------------------------------------------------------

/// Provision a UserID with `max_attempts = 3`, then VERIFY with wrong
/// PINs until the chip refuses to accept any more. The 4th attempt
/// must return `Se050Error::AuthMethodBlocked` (driver's mapping of
/// SW=0x6986 per `apdu.rs:42-54`). Logs the actual SW seen so a future
/// chip-firmware revision that changed the lockout SW would be caught.
///
/// Side-effects: leaves a locked UserID at `0x7B5E_<id>_01` until the
/// runner's admin sweep cleans it up.
fn silicon_lockout(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let correct_pin: [u8; 8] = *b"stress01";
    let wrong_pin:   [u8; 8] = *b"WRONGwro";

    // Best-effort cleanup of any leftover from a prior run.
    ctx.delete_scratch(target)?;

    ctx.provision_test_userid(target, &correct_pin, 3, AdminPolicy::WithAdminDelete)?;

    // First wrong-PIN sequence: 1, 2, 3 — driver must return
    // `PinIncorrect` (counter still has room).
    for i in 0..3 {
        ctx.set_iter(i);
        let r = ctx.open_user_session(target, &wrong_pin);
        match r {
            Err(StressError::Driver(Se050Error::PinIncorrect)) => { /* expected */ }
            Err(StressError::Driver(Se050Error::Status(sw))) => {
                secure_log!(
                    "[S][stress][userid-lockout] iter={} unexpected SW=0x{:04x} (want PinIncorrect)",
                    i, sw,
                );
                return Err(StressError::UnexpectedSw {
                    what: "wrong-PIN should map to PinIncorrect",
                    sw,
                });
            }
            Err(StressError::Driver(Se050Error::AuthMethodBlocked)) => {
                // Lockout fired earlier than expected — silicon is
                // counting differently than the driver assumes.
                secure_log!(
                    "[S][stress][userid-lockout] EARLY lockout at iter={}",
                    i,
                );
                return Err(StressError::Assertion {
                    what: "lockout before max_attempts",
                    iter: i,
                });
            }
            Ok(sid) => {
                ctx.close_session(&sid);
                return Err(StressError::Assertion {
                    what: "wrong PIN should not open session",
                    iter: i,
                });
            }
            Err(other) => return Err(other),
        }
    }

    // 4th wrong attempt: lockout SW. Capture the actual SW so we can
    // confirm 0x6986 (`AuthMethodBlocked`) is in fact what silicon
    // returns — per `apdu.rs:42-54` this is documented-by-deduction
    // and on-silicon verification is the closing step.
    ctx.set_iter(3);
    let r = ctx.open_user_session(target, &wrong_pin);
    match r {
        Err(StressError::Driver(Se050Error::AuthMethodBlocked)) => {
            secure_log!(
                "[S][stress][userid-lockout] lockout fired on 4th wrong PIN (driver mapped 0x6986 → AuthMethodBlocked)",
            );
        }
        Err(StressError::Driver(Se050Error::Status(sw))) => {
            secure_log!(
                "[S][stress][userid-lockout] 4th-attempt SW=0x{:04x} (driver did NOT map to AuthMethodBlocked — update apdu.rs:42-54)",
                sw,
            );
            return Err(StressError::UnexpectedSw {
                what: "lockout SW not matched by driver",
                sw,
            });
        }
        Err(StressError::Driver(Se050Error::PinIncorrect)) => {
            return Err(StressError::Assertion {
                what: "lockout did not trigger after max_attempts wrong",
                iter: 3,
            });
        }
        Ok(sid) => {
            ctx.close_session(&sid);
            return Err(StressError::Assertion {
                what: "wrong-PIN session opened on locked UserID",
                iter: 3,
            });
        }
        Err(other) => return Err(other),
    }

    // Cross-check: even the CORRECT PIN must now be refused.
    let r = ctx.open_user_session(target, &correct_pin);
    match r {
        Err(StressError::Driver(Se050Error::AuthMethodBlocked)) => Ok(()),
        Err(StressError::Driver(Se050Error::Status(sw))) => {
            // Some chips return the lockout SW; others might return a
            // distinct "counter exhausted" SW. Accept ANY non-9000 SW
            // here but log it.
            secure_log!(
                "[S][stress][userid-lockout] correct-PIN-after-lockout SW=0x{:04x} (any non-9000 acceptable)",
                sw,
            );
            Ok(())
        }
        Ok(sid) => {
            ctx.close_session(&sid);
            Err(StressError::Assertion {
                what: "locked UserID accepted correct PIN",
                iter: 0,
            })
        }
        Err(other) => Err(other),
    }
}
stress_test!(SILICON_LOCKOUT, "userid_silicon_lockout", Tier::Destructive, silicon_lockout);

// ---------------------------------------------------------------------------
// P1. pin_counter_resets_on_correct_pin
// ---------------------------------------------------------------------------

/// Verify the load-bearing claim behind `Se050::remaining`'s
/// "resets to MAX on every successful unlock" commentary
/// (`mod.rs:142-150`): a successful VERIFY zeroes the chip's
/// `auth_attempts` counter. AN12413 §4.7.1.5 specifies this; if the
/// chip ever stops, the firmware's attempt budget drifts out of sync
/// with the silicon and lockout fires unexpectedly mid-session.
///
/// **Probe redesign (A1 silicon finding, 2026-05-28).**
/// `ReadObjectAttributes` is not policy-gate-independent on
/// B-U585I-IOT02A (`docs/se050-silicon-findings.md` §2) — the chip
/// returns SW=0x6986 on a freshly-provisioned user-policy-gated
/// UserID. We therefore cannot read `auth_attempts` directly to
/// inspect the counter; instead this test infers the reset via burn
/// arithmetic:
///
///  - Provision UserID with `max_attempts = 5`.
///  - Burn 3 wrong PINs (counter 0 → 3). Each must return
///    `PinIncorrect`; `burn_wrong_pin` asserts that internally.
///  - Submit the CORRECT PIN (must open a session — verifies success).
///  - Burn 4 wrong PINs.
///    * If the counter was reset (claim holds): counter advances
///      0 → 4, every attempt returns `PinIncorrect`.
///    * If the counter was NOT reset: counter advances 3 → 4 →
///      LOCKED, so the 2nd post-success burn surfaces
///      `AuthMethodBlocked`. `burn_wrong_pin` catches that and
///      returns `"lockout fired earlier than expected"`.
///
/// PASS = both burns complete without lockout.
/// FAIL = 2nd burn hits `AuthMethodBlocked` (counter not reset), or
/// the success step itself fails (lockout fired during the first
/// burn — UserID config wrong).
fn pin_counter_resets_on_correct_pin(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let correct: [u8; 8] = *b"pintest1";
    let wrong:   [u8; 8] = *b"WRONG!!!";

    ctx.delete_scratch(target)?;
    ctx.provision_test_userid(target, &correct, 5, AdminPolicy::WithAdminDelete)?;

    // Burn 3 wrong (counter 0 → 3, still below max=5).
    ctx.burn_wrong_pin(target, &wrong, 3)?;

    // Correct PIN — must succeed, and (per the claim) zero the counter.
    let sid = ctx.open_user_session(target, &correct)?;
    ctx.close_session(&sid);

    // Burn 4 more wrong. With the counter at 0 (reset) the chip has
    // 5 slots to spare; with the counter at 3 (no reset) it locks on
    // the 2nd burn — `burn_wrong_pin` reports
    // `"lockout fired earlier than expected"` if `AuthMethodBlocked`
    // surfaces inside the loop.
    ctx.burn_wrong_pin(target, &wrong, 4)?;

    // Final correct PIN confirms the UserID is still healthy — i.e.
    // the chip didn't silently drift the counter past max either.
    let sid = ctx.open_user_session(target, &correct)?;
    ctx.close_session(&sid);

    secure_log!(
        "[S][stress][pin-p1] PASS — successful VERIFY zeroes auth_attempts \
         (3 burn + success + 4 burn + success, no lockout)"
    );
    Ok(())
}
stress_test!(PIN_COUNTER_RESETS_ON_CORRECT_PIN, "pin_counter_resets_on_correct_pin", Tier::Destructive, pin_counter_resets_on_correct_pin);

// ---------------------------------------------------------------------------
// P2. pin_counter_persists_across_reinit
// ---------------------------------------------------------------------------

/// `Se050::reinit()` closes the SCP03 session, performs a T=1'
/// interface reset, runs SELECT, and re-establishes SCP03 with a fresh
/// nonce + key derivation — the closest software-only emulation of a
/// power cycle the bench supports (the SE050 VCC is not GPIO-controlled
/// on this board). The chip's NVM-backed `auth_attempts` counter MUST
/// persist across this sequence — if it didn't, an attacker could
/// brute-force a 4-digit PIN with ≤10⁴ wrong attempts simply by
/// power-cycling between every few tries.
///
/// **Probe redesign (A1, 2026-05-28).** Same constraint as P1 — we
/// cannot read `auth_attempts` directly, so persistence is inferred via
/// burn arithmetic across the reinit:
///
///  - Provision UserID with `max_attempts = 5`.
///  - Burn 4 wrong PINs (counter 0 → 4). Each `PinIncorrect`.
///  - `Se050::reinit()` (simulated power cycle).
///  - Burn 1 more wrong PIN.
///    * If the counter persisted (claim holds): counter goes 4 → 5,
///      returns `PinIncorrect` — the 5th and final allowed wrong.
///    * If the counter reset: counter goes 0 → 1, also returns
///      `PinIncorrect`. Indistinguishable yet — but the next probe
///      separates them.
///  - Burn 1 more wrong PIN.
///    * Counter-persisted case: counter at 5, locked → returns
///      `AuthMethodBlocked`.
///    * Counter-reset case: counter goes 1 → 2, returns
///      `PinIncorrect`.
///
/// PASS = the 6th total wrong PIN (1st post-reinit) is `PinIncorrect`,
/// and the 7th total wrong PIN (2nd post-reinit) is `AuthMethodBlocked`.
/// FAIL = the 7th wrong PIN is `PinIncorrect` (counter reset across
/// reinit — brute-force protection silicon claim violated) or any
/// earlier wrong PIN already triggers lockout (max_attempts not 5).
fn pin_counter_persists_across_reinit(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let correct: [u8; 8] = *b"pintest2";
    let wrong:   [u8; 8] = *b"WRONG!!!";

    ctx.delete_scratch(target)?;
    ctx.provision_test_userid(target, &correct, 5, AdminPolicy::WithAdminDelete)?;

    // Pre-reinit: burn 4 wrong (counter 0 → 4, one slot remaining).
    ctx.burn_wrong_pin(target, &wrong, 4)?;

    // Tear down + re-establish SCP03 (closest to a power cycle this
    // board supports). Persistent NVM (auth_attempts, the UserID
    // object itself) must survive.
    ctx.se().reinit()?;

    // Post-reinit attempt #1: the LAST allowed wrong if the counter
    // persisted. Must surface as PinIncorrect (counter going 4 → 5).
    ctx.set_iter(0);
    match ctx.open_user_session(target, &wrong) {
        Err(StressError::Driver(Se050Error::PinIncorrect)) => {
            secure_log!(
                "[S][stress][pin-p2] post-reinit wrong #1: PinIncorrect (counter advanced normally)"
            );
        }
        Err(StressError::Driver(Se050Error::AuthMethodBlocked)) => {
            secure_log!(
                "[S][stress][pin-p2] post-reinit wrong #1 already locked — counter advanced past 5 \
                 (chip lost a slot in pre-burn, or max_attempts != 5)"
            );
            return Err(StressError::Assertion {
                what: "lockout fired earlier than expected",
                iter: 0,
            });
        }
        Ok(sid) => {
            ctx.close_session(&sid);
            return Err(StressError::Assertion {
                what: "wrong PIN opened session post-reinit",
                iter: 0,
            });
        }
        Err(other) => return Err(other),
    }

    // Post-reinit attempt #2: distinguishes persisted-counter vs reset.
    //   Persisted (counter=5 now): AuthMethodBlocked — PASS.
    //   Reset (counter=2 now):     PinIncorrect — FAIL, the silicon
    //                              dropped the brute-force barrier.
    ctx.set_iter(1);
    match ctx.open_user_session(target, &wrong) {
        Err(StressError::Driver(Se050Error::AuthMethodBlocked)) => {
            secure_log!(
                "[S][stress][pin-p2] post-reinit wrong #2: AuthMethodBlocked — \
                 counter persisted across reinit (5 wrong total locks the UserID)"
            );
        }
        Err(StressError::Driver(Se050Error::PinIncorrect)) => {
            secure_log!(
                "[S][stress][pin-p2] CRITICAL — counter RESET across reinit; \
                 brute-force protection silicon claim violated"
            );
            return Err(StressError::Assertion {
                what: "auth_attempts not preserved across reinit — brute-force protection silicon claim violated",
                iter: 1,
            });
        }
        Ok(sid) => {
            ctx.close_session(&sid);
            return Err(StressError::Assertion {
                what: "wrong PIN opened session on locked UserID",
                iter: 1,
            });
        }
        Err(other) => return Err(other),
    }

    secure_log!("[S][stress][pin-p2] PASS — auth_attempts NVM-durable across SCP03/T=1' reinit");
    Ok(())
}
stress_test!(PIN_COUNTER_PERSISTS_ACROSS_REINIT, "pin_counter_persists_across_reinit", Tier::Destructive, pin_counter_persists_across_reinit);

// ---------------------------------------------------------------------------
// P3. pin_lockout_persists_across_reinit
// ---------------------------------------------------------------------------

/// Drive a `max_attempts=3` UserID to lockout, run `Se050::reinit()`,
/// then attempt both a wrong-PIN and the correct-PIN. Both MUST be
/// refused (the lockout is permanent; only `factory_reset_admin` + a
/// fresh provisioning under a new OID range recovers).
///
/// Adversarial framing: an attacker who desolders the chip and burns
/// 10 wrong PINs against the production USERID_OBJ should NOT be able
/// to recover by power-cycling — the silicon must keep the lock
/// across cold-boot.
///
/// PASS = post-reinit wrong-PIN AND correct-PIN both return
/// `AuthMethodBlocked` (or any non-9000 SW).
/// FAIL = either submit opens a session, OR returns `PinIncorrect`
/// (which would imply the counter reset and we got an attempt back).
fn pin_lockout_persists_across_reinit(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let correct: [u8; 8] = *b"pintest3";
    let wrong:   [u8; 8] = *b"WRONG!!!";

    ctx.delete_scratch(target)?;
    ctx.provision_test_userid(target, &correct, 3, AdminPolicy::WithAdminDelete)?;

    // Burn the budget — 3 wrong, then 1 lockout-confirming wrong.
    ctx.burn_wrong_pin(target, &wrong, 3)?;
    match ctx.open_user_session(target, &wrong) {
        Err(StressError::Driver(Se050Error::AuthMethodBlocked)) => {
            secure_log!("[S][stress][pin-p3] lockout fired on 4th wrong PIN as expected");
        }
        Err(StressError::Driver(Se050Error::Status(sw))) => {
            secure_log!(
                "[S][stress][pin-p3] 4th wrong PIN returned SW=0x{:04x} (driver didn't map → AuthMethodBlocked); treating as lockout",
                sw,
            );
        }
        other => {
            secure_log!("[S][stress][pin-p3] 4th wrong PIN returned unexpected: {:?}", other);
            return Err(StressError::Assertion {
                what: "lockout did not fire after max_attempts wrong PINs",
                iter: 0,
            });
        }
    }

    // The simulated power cycle.
    ctx.se().reinit()?;

    // Post-reinit attempt #1: wrong PIN must still be refused.
    let post_wrong = ctx.open_user_session(target, &wrong);
    match post_wrong {
        Err(StressError::Driver(Se050Error::AuthMethodBlocked)) => {
            secure_log!("[S][stress][pin-p3] post-reinit wrong PIN: AuthMethodBlocked (good)");
        }
        Err(StressError::Driver(Se050Error::PinIncorrect)) => {
            secure_log!(
                "[S][stress][pin-p3] CRITICAL: post-reinit wrong PIN returned PinIncorrect — counter RESET across reinit",
            );
            return Err(StressError::Assertion {
                what: "lockout did not persist across reinit — desolder-bench attacker could brute-force",
                iter: 0,
            });
        }
        Err(StressError::Driver(Se050Error::Status(sw))) => {
            secure_log!(
                "[S][stress][pin-p3] post-reinit wrong PIN returned SW=0x{:04x} (non-9000 — lockout effectively holds)",
                sw,
            );
        }
        Ok(sid) => {
            ctx.close_session(&sid);
            secure_log!(
                "[S][stress][pin-p3] CRITICAL: post-reinit wrong PIN OPENED a session — chip is broken",
            );
            return Err(StressError::Assertion {
                what: "wrong PIN opened session after lockout",
                iter: 0,
            });
        }
        Err(other) => {
            secure_log!("[S][stress][pin-p3] post-reinit wrong PIN returned: {:?}", other);
            return Err(other);
        }
    }

    // Post-reinit attempt #2: CORRECT PIN must STILL be refused.
    let post_correct = ctx.open_user_session(target, &correct);
    match post_correct {
        Err(StressError::Driver(Se050Error::AuthMethodBlocked)) => {
            secure_log!("[S][stress][pin-p3] post-reinit correct PIN: AuthMethodBlocked (lockout permanent)");
            Ok(())
        }
        Err(StressError::Driver(Se050Error::Status(sw))) => {
            secure_log!(
                "[S][stress][pin-p3] post-reinit correct PIN returned SW=0x{:04x} (any non-9000 acceptable)",
                sw,
            );
            Ok(())
        }
        Ok(sid) => {
            ctx.close_session(&sid);
            secure_log!(
                "[S][stress][pin-p3] CRITICAL: locked UserID accepted CORRECT PIN after reinit — lockout reverted",
            );
            Err(StressError::Assertion {
                what: "correct PIN opened session on locked UserID after reinit",
                iter: 0,
            })
        }
        Err(other) => Err(other),
    }
}
stress_test!(PIN_LOCKOUT_PERSISTS_ACROSS_REINIT, "pin_lockout_persists_across_reinit", Tier::Destructive, pin_lockout_persists_across_reinit);

// ---------------------------------------------------------------------------
// P4. pin_attribute_read_refused_on_user_userid (A1 regression validator)
// ---------------------------------------------------------------------------

/// **Repurposed (A1, 2026-05-28).** The original P4 asserted
/// "`ReadObjectAttributes` does NOT consume PIN-counter slots" —
/// the load-bearing claim behind invoking it during the boot-time
/// MCU↔SE050 attempt-counter reconcile. The first silicon run
/// (`docs/se050-silicon-findings.md` §2) showed B-U585I-IOT02A
/// refuses the read entirely (SW=0x6986) on a UserID gated by the
/// standard two-entry policy
/// `(self → ALLOW_WRITE|ALLOW_DELETE|REQUIRE_SM,
///  admin → ALLOW_DELETE|REQUIRE_SM)` — making "does it consume
/// slots?" untestable, because the read can't proceed in the first
/// place. `Se050::pin_attempt_count_raw` was updated to return
/// `None` for the production `USERID_OBJ` (boot-time reconcile silently
/// skips the SE050 leg; OPTIGA + MCU page-124 legs cover).
///
/// This test is repurposed as the silicon regression check: assert
/// that `ReadObjectAttributes` is in fact refused on a fresh
/// user-PIN-gated UserID. If a future chip-firmware revision starts
/// honouring attribute reads on this policy, the test surfaces it
/// and the boot-time reconcile design can be revisited to use the
/// real path again.
///
/// PASS = `try_read_userid_attempts` returns `None` (driver helper
/// maps the policy-denial SW to `None`).
/// FAIL = the helper returns `Some(_)` (chip allowed the read — the
/// A1 finding no longer holds; revisit
/// `Se050::pin_attempt_count_raw`).
fn pin_attribute_read_refused_on_user_userid(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let correct: [u8; 8] = *b"pintest4";

    ctx.delete_scratch(target)?;
    ctx.provision_test_userid(target, &correct, 5, AdminPolicy::WithAdminDelete)?;

    // The driver helper maps any error (including SW=0x6986 policy
    // denial) to None. A1 silicon truth says this returns None on the
    // standard two-entry user policy.
    let r = ctx.read_userid_attempts(target);
    match r {
        None => {
            secure_log!(
                "[S][stress][pin-p4] PASS — ReadObjectAttributes refused on user-policy UserID \
                 (A1 silicon truth confirmed: boot-time reconcile correctly skips SE050 leg)"
            );
            Ok(())
        }
        Some((auth, max)) => {
            secure_log!(
                "[S][stress][pin-p4] UNEXPECTED — ReadObjectAttributes returned \
                 (auth_attempts={}, max_attempts={}) on a user-policy UserID. \
                 A1 finding no longer applies — re-enable the SE050 leg of the \
                 boot-time reconcile via `Se050::pin_attempt_count_raw` \
                 (see `mod.rs:485-522`).",
                auth, max,
            );
            Err(StressError::Assertion {
                what: "ReadObjectAttributes succeeded on user-PIN-gated UserID — A1 finding no longer holds",
                iter: 0,
            })
        }
    }
}
stress_test!(PIN_ATTRIBUTE_READ_REFUSED_ON_USER_USERID, "pin_attribute_read_refused_on_user_userid", Tier::Safe, pin_attribute_read_refused_on_user_userid);

// ---------------------------------------------------------------------------
// P5. pin_unlimited_no_lockout (S-7a silicon closure)
// ---------------------------------------------------------------------------

/// **S-7a silicon closure.** Provision a UserID via
/// `write_userid_unlimited` (i.e. `TAG_MAX_ATTEMPTS` omitted from the
/// APDU per AN12413 §4.7.1.5 "unlimited" encoding), then burn 100
/// wrong PINs in a loop. EVERY attempt MUST return `PinIncorrect`.
/// A single `AuthMethodBlocked` anywhere in the loop falsifies the
/// unlimited claim and means the silicon enforces an implicit cap —
/// which would break the production `ADMIN_WIPE_OBJ`,
/// `DURESS_USERID_OBJ`, and test admin UserIDs (`mod.rs:482-510` doc
/// enumerates all three).
///
/// 100 attempts is intentionally chosen below the `write_userid`
/// bounded ceiling of 255 (per AN12413 §4.7.1.5 Table 98 + the S-7a
/// guard at `apdu.rs:474`) so the test stays fast (~5-10 s on
/// silicon) but well above any single-digit / small-bound value the
/// chip might silently translate the omitted-TLV form into. A chip
/// that treated the omitted TLV as "max=10" would fire lockout by
/// iteration 11 and FAIL the test loudly.
///
/// **Probe redesign (A1, 2026-05-28).** The prior version asserted
/// `(auth=0, max=0)` via `ReadObjectAttributes` to detect the
/// "unlimited" wire marker; per A1 silicon truth, that read returns
/// SW=0x6986 on user-PIN-gated UserIDs, so the marker is no longer
/// directly inspectable. Behavioural inference covers the same
/// ground: 100 consecutive `PinIncorrect`s is incompatible with any
/// `max_attempts ≤ 100` setting, and a final correct PIN proves the
/// UserID is still authenticatable (i.e. neither the marker nor the
/// counter has saturated into a soft-locked state).
///
/// PASS = the 100-burn loop completes (every iteration
/// `PinIncorrect`), then the correct PIN opens a session.
/// FAIL = `AuthMethodBlocked` somewhere in the loop (implicit cap
/// exists), or the post-burn correct PIN is refused (silicon silently
/// dropped the UserID into a soft-locked state).
fn pin_unlimited_no_lockout(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let correct: [u8; 8] = *b"pintestu";
    let wrong:   [u8; 8] = *b"WRONG_xx";
    const BURN_COUNT: usize = 100;

    ctx.delete_scratch(target)?;
    ctx.provision_test_userid_unlimited(target, &correct, AdminPolicy::WithAdminDelete)?;

    // Burn 100 wrong PINs. `burn_wrong_pin` asserts each iteration
    // returns PinIncorrect — a single AuthMethodBlocked is the S-7a
    // silicon-side regression we're testing for.
    ctx.burn_wrong_pin(target, &wrong, BURN_COUNT)?;

    // Correct PIN MUST still authenticate after 100 wrong attempts —
    // proves the chip didn't silently soft-lock and that the unlimited
    // marker survives the burn run.
    let sid = ctx.open_user_session(target, &correct)?;
    ctx.close_session(&sid);

    secure_log!(
        "[S][stress][pin-p5] PASS — {} consecutive wrong PINs returned PinIncorrect (no lockout), \
         correct PIN still opens a session afterwards. S-7a silicon claim VERIFIED.",
        BURN_COUNT,
    );
    Ok(())
}
stress_test!(PIN_UNLIMITED_NO_LOCKOUT, "pin_unlimited_no_lockout", Tier::Destructive, pin_unlimited_no_lockout);
