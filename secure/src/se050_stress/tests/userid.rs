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
