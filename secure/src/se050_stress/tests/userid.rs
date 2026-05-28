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
/// Side-effects: leaves a locked UserID at `0x7B5F_08_01` until the
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

/// Burn 2 wrong PINs on a `max_attempts=5` UserID, read the counter
/// via `ReadObjectAttributes` (which does not itself burn a slot —
/// that property is verified by P4 below), then submit the CORRECT
/// PIN. AN12413 §4.7.1.5 specifies that a successful VERIFY zeroes
/// `auth_attempts`, so the counter MUST report 0 used after the
/// success. This is the load-bearing claim behind
/// `Se050::remaining`'s "resets to MAX on every successful unlock"
/// commentary at `mod.rs:142-150` — if the chip ever stops doing
/// this, the firmware's attempt budget drifts out of sync with the
/// silicon and lockout fires unexpectedly mid-session.
///
/// PASS = post-success attribute read shows `auth_attempts == 0`.
/// FAIL = counter still shows the burned attempts, or attribute
/// read returns `None` (object disappeared somehow).
fn pin_counter_resets_on_correct_pin(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let correct: [u8; 8] = *b"pintest1";
    let wrong:   [u8; 8] = *b"WRONG!!!";

    ctx.delete_scratch(target)?;
    ctx.provision_test_userid(target, &correct, 5, AdminPolicy::WithAdminDelete)?;

    // Pre-check: counter starts at 0.
    let pre = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "attribute read returned None pre-burn", iter: 0 })?;
    if pre.0 != 0 {
        secure_log!(
            "[S][stress][pin-p1] pre-burn auth_attempts={} (expected 0)",
            pre.0,
        );
        return Err(StressError::Assertion {
            what: "auth_attempts != 0 on fresh UserID",
            iter: 0,
        });
    }
    if pre.1 != 5 {
        secure_log!(
            "[S][stress][pin-p1] pre-burn max_attempts={} (expected 5)",
            pre.1,
        );
        return Err(StressError::Assertion {
            what: "max_attempts != requested value",
            iter: 0,
        });
    }

    // Burn 2 wrong attempts.
    ctx.burn_wrong_pin(target, &wrong, 2)?;

    // Counter should now read 2.
    let mid = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "attribute read returned None mid-test", iter: 0 })?;
    secure_log!(
        "[S][stress][pin-p1] after 2 wrong: auth_attempts={} (expected 2)",
        mid.0,
    );
    if mid.0 != 2 {
        return Err(StressError::Assertion {
            what: "auth_attempts != 2 after burning 2 wrong PINs",
            iter: 0,
        });
    }

    // Submit CORRECT PIN — must reset the counter.
    let sid = ctx.open_user_session(target, &correct)?;
    ctx.close_session(&sid);

    let post = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "attribute read returned None post-success", iter: 0 })?;
    secure_log!(
        "[S][stress][pin-p1] after correct PIN: auth_attempts={} (expected 0)",
        post.0,
    );
    if post.0 != 0 {
        return Err(StressError::Assertion {
            what: "auth_attempts != 0 after successful VERIFY — chip does not zero counter on success",
            iter: 0,
        });
    }

    secure_log!("[S][stress][pin-p1] PASS — successful VERIFY zeroes auth_attempts");
    Ok(())
}
stress_test!(PIN_COUNTER_RESETS_ON_CORRECT_PIN, "pin_counter_resets_on_correct_pin", Tier::Destructive, pin_counter_resets_on_correct_pin);

// ---------------------------------------------------------------------------
// P2. pin_counter_persists_across_reinit
// ---------------------------------------------------------------------------

/// Burn 2 wrong PINs, then invoke `Se050::reinit()` — which closes the
/// SCP03 session, performs a T=1' interface reset, runs SELECT, and
/// re-establishes SCP03 with a fresh nonce + key derivation. This is
/// the closest software-only emulation of a power cycle the bench
/// supports (the SE050 VCC is not GPIO-controlled on this board). The
/// chip's NVM-backed `auth_attempts` counter MUST persist across this
/// sequence — if it didn't, an attacker could brute-force a 4-digit
/// PIN with ≤10⁴ wrong attempts simply by power-cycling between every
/// few tries.
///
/// PASS = post-reinit attribute read reports the same `auth_attempts`
/// as the pre-reinit read.
/// FAIL = counter resets to 0 or shows a different non-2 value (NVM
/// not durable, or reinit accidentally resets the chip's session-
/// independent state).
fn pin_counter_persists_across_reinit(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let correct: [u8; 8] = *b"pintest2";
    let wrong:   [u8; 8] = *b"WRONG!!!";

    ctx.delete_scratch(target)?;
    ctx.provision_test_userid(target, &correct, 5, AdminPolicy::WithAdminDelete)?;

    ctx.burn_wrong_pin(target, &wrong, 2)?;

    let pre = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "pre-reinit attribute read returned None", iter: 0 })?;
    if pre.0 != 2 {
        secure_log!("[S][stress][pin-p2] pre-reinit auth_attempts={} (expected 2)", pre.0);
        return Err(StressError::Assertion {
            what: "pre-reinit auth_attempts != 2",
            iter: 0,
        });
    }

    // Tear down + re-establish SCP03 (closest to a power cycle this
    // board supports). Persistent NVM (auth_attempts, the UserID
    // object itself) must survive.
    ctx.se().reinit()?;

    let post = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "post-reinit attribute read returned None — object lost", iter: 0 })?;

    secure_log!(
        "[S][stress][pin-p2] post-reinit auth_attempts={} (expected 2 — must survive SCP03 reset)",
        post.0,
    );

    if post.0 != 2 {
        return Err(StressError::Assertion {
            what: "auth_attempts not preserved across reinit — brute-force protection silicon claim violated",
            iter: 0,
        });
    }
    if post.1 != pre.1 {
        secure_log!(
            "[S][stress][pin-p2] max_attempts drifted: pre={} post={}",
            pre.1, post.1,
        );
        return Err(StressError::Assertion {
            what: "max_attempts drifted across reinit",
            iter: 0,
        });
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
// P4. pin_attribute_read_does_not_burn
// ---------------------------------------------------------------------------

/// Burn 2 wrong PINs, then issue 5 back-to-back `ReadObjectAttributes`
/// against the same UserID, then burn 1 more wrong PIN. The chip MUST
/// still treat the 3rd wrong PIN as wrong-attempt #3 (not "wrong-
/// attempt #8" or "lockout") — i.e. attribute reads do not consume
/// PIN-counter slots. This is the load-bearing claim behind
/// `Se050::pin_attempt_count_raw` being safe to invoke during the
/// boot-time reconcile against the MCU page-124 counter (`mod.rs:485-
/// 522` doc).
///
/// PASS = post-attribute-read wrong PIN returns `PinIncorrect`
/// (counter at 3/5 — burn drove it from 2 to 3, no extra slots
/// consumed by the 5 attribute reads), and a follow-up attribute
/// read shows `auth_attempts == 3`.
/// FAIL = lockout fires early, or attribute read reports >3 used.
fn pin_attribute_read_does_not_burn(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let correct: [u8; 8] = *b"pintest4";
    let wrong:   [u8; 8] = *b"WRONG!!!";
    const ATTR_READS: usize = 5;

    ctx.delete_scratch(target)?;
    ctx.provision_test_userid(target, &correct, 5, AdminPolicy::WithAdminDelete)?;

    ctx.burn_wrong_pin(target, &wrong, 2)?;

    let after_burn = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "attribute read returned None mid-test", iter: 0 })?;
    if after_burn.0 != 2 {
        secure_log!("[S][stress][pin-p4] after 2 burn: auth_attempts={} (expected 2)", after_burn.0);
        return Err(StressError::Assertion {
            what: "pre-attribute-flood counter != 2",
            iter: 0,
        });
    }

    // Flood with attribute reads — none of these should consume a slot.
    for i in 0..ATTR_READS {
        ctx.set_iter(i as u32);
        let r = ctx.read_userid_attempts(target);
        if r.is_none() {
            return Err(StressError::Assertion {
                what: "attribute read returned None during flood",
                iter: i as u32,
            });
        }
    }

    let after_flood = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "post-flood attribute read returned None", iter: 0 })?;
    secure_log!(
        "[S][stress][pin-p4] after {} attribute reads: auth_attempts={} (expected 2)",
        ATTR_READS, after_flood.0,
    );
    if after_flood.0 != 2 {
        return Err(StressError::Assertion {
            what: "attribute reads burned PIN-counter slots",
            iter: 0,
        });
    }

    // One more wrong PIN — should be wrong-attempt #3, NOT lockout.
    ctx.set_iter(99);
    match ctx.open_user_session(target, &wrong) {
        Err(StressError::Driver(Se050Error::PinIncorrect)) => {
            secure_log!("[S][stress][pin-p4] 3rd wrong PIN after flood: PinIncorrect (counter advanced normally)");
        }
        Err(StressError::Driver(Se050Error::AuthMethodBlocked)) => {
            return Err(StressError::Assertion {
                what: "lockout fired early — attribute reads must have burned slots",
                iter: 99,
            });
        }
        Err(other) => return Err(other),
        Ok(sid) => {
            ctx.close_session(&sid);
            return Err(StressError::Assertion {
                what: "wrong PIN opened session",
                iter: 99,
            });
        }
    }

    let final_attempts = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "final attribute read returned None", iter: 0 })?;
    secure_log!(
        "[S][stress][pin-p4] final auth_attempts={} (expected 3 — i.e. only the burn'd wrong PINs counted)",
        final_attempts.0,
    );
    if final_attempts.0 != 3 {
        return Err(StressError::Assertion {
            what: "final counter != 3 (attribute reads did burn slots, or chip miscounts)",
            iter: 0,
        });
    }

    secure_log!("[S][stress][pin-p4] PASS — ReadObjectAttributes does not consume PIN-counter slots");
    Ok(())
}
stress_test!(PIN_ATTRIBUTE_READ_DOES_NOT_BURN, "pin_attribute_read_does_not_burn", Tier::Destructive, pin_attribute_read_does_not_burn);

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
/// Additional assertions layered into the same probe (one
/// silicon round-trip apiece on top of the burn):
///  - Pre-burn `(auth=0, max=0)` — the (0,0) attribute reading is the
///    wire signal for "this UserID is unlimited".
///  - Post-burn `max=0` (silicon doesn't mutate the unlimited marker
///    on VERIFY failures) and `auth ≥ BURN_COUNT/2` (counter is
///    actively advancing, not stuck at 0 or saturated low).
///  - Correct PIN still authenticates AND resets `auth=0` (the
///    "successful VERIFY zeroes counter" claim P1 verified on a
///    bounded UserID — assert it holds on unlimited too).
///
/// PASS = all of the above hold; "unlimited" is semantically truly
/// unlimited on this silicon. Production unlimited-UserID code paths
/// are silicon-validated.
/// FAIL = lockout fires, the unlimited marker mutates, the counter
/// stalls, or the correct PIN is rejected. Any of these means
/// production unlimited-UserID code paths are unsafe on this
/// specific chip and need a workaround before shipping.
fn pin_unlimited_no_lockout(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let correct: [u8; 8] = *b"pintestu";
    let wrong:   [u8; 8] = *b"WRONG_xx";
    const BURN_COUNT: usize = 100;

    ctx.delete_scratch(target)?;
    ctx.provision_test_userid_unlimited(target, &correct, AdminPolicy::WithAdminDelete)?;

    // Pre-burn: attribute read MUST show (auth=0, max=0).
    let pre = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "pre-burn attribute read returned None", iter: 0 })?;
    secure_log!(
        "[S][stress][pin-p5] pre-burn (auth_attempts={}, max_attempts={}) — expected (0, 0)",
        pre.0, pre.1,
    );
    if pre.0 != 0 || pre.1 != 0 {
        return Err(StressError::Assertion {
            what: "fresh unlimited UserID's attributes != (0, 0)",
            iter: 0,
        });
    }

    // Burn 100 wrong PINs. `burn_wrong_pin` asserts each iteration
    // returns PinIncorrect — a single AuthMethodBlocked is the S-7a
    // silicon-side regression we're testing for.
    ctx.burn_wrong_pin(target, &wrong, BURN_COUNT)?;

    // Post-burn: unlimited marker intact + counter advancing.
    let post = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "post-burn attribute read returned None", iter: 0 })?;
    secure_log!(
        "[S][stress][pin-p5] after {} wrong PINs: (auth_attempts={}, max_attempts={})",
        BURN_COUNT, post.0, post.1,
    );
    if post.1 != 0 {
        return Err(StressError::Assertion {
            what: "max_attempts mutated during burns — silicon silently altered the unlimited marker",
            iter: 0,
        });
    }
    if (post.0 as usize) < BURN_COUNT / 2 {
        return Err(StressError::Assertion {
            what: "auth_attempts not advancing — counter stuck while burning wrong PINs",
            iter: 0,
        });
    }

    // Correct PIN MUST still authenticate AND reset auth_attempts to 0.
    let sid = ctx.open_user_session(target, &correct)?;
    ctx.close_session(&sid);

    let after_correct = ctx.read_userid_attempts(target)
        .ok_or(StressError::Assertion { what: "post-correct attribute read returned None", iter: 0 })?;
    secure_log!(
        "[S][stress][pin-p5] after correct PIN: (auth_attempts={}, max_attempts={}) — expected (0, 0)",
        after_correct.0, after_correct.1,
    );
    if after_correct.0 != 0 {
        return Err(StressError::Assertion {
            what: "correct PIN did not reset auth_attempts on unlimited UserID",
            iter: 0,
        });
    }
    if after_correct.1 != 0 {
        return Err(StressError::Assertion {
            what: "max_attempts mutated through the VERIFY-success path",
            iter: 0,
        });
    }

    secure_log!(
        "[S][stress][pin-p5] PASS — {} consecutive wrong PINs returned PinIncorrect (no lockout), \
         counter advanced 0 → {}, marker stayed unlimited, correct PIN reset counter to 0. \
         S-7a silicon claim VERIFIED.",
        BURN_COUNT, post.0,
    );
    Ok(())
}
stress_test!(PIN_UNLIMITED_NO_LOCKOUT, "pin_unlimited_no_lockout", Tier::Destructive, pin_unlimited_no_lockout);
