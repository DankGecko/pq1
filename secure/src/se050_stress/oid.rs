//! SE050 object-ID carve-out for the stress harness.
//!
//! Layout — every OID the harness ever touches is in `0x7B5F_*`:
//!
//! ```text
//!   0x7B5F_00A0  STRESS_ADMIN_USERID  unlimited attempts, HW-root PIN
//!   0x7B5F_NN00..0x7B5F_NNFF   test #NN (1..=255) — 256 OIDs
//! ```
//!
//! That's well above existing per-test e2e ranges
//! (`0x7B07_*`, `0x7B09_*`, `0x7B0A_*`, `0x7B0B_*`) and decisively above
//! the v6 production range (`0x7B10_*`), so a stress run never collides
//! with real provisioning. The second nibble (`F`) is the literal
//! "stress" marker.

use crate::se050::Se050;
use crate::se050::apdu;

/// Base address of the stress carve-out range. Helper functions
/// elsewhere assume `STRESS_BASE & 0xFFFF_0000 == 0x7B5F_0000`.
pub const STRESS_BASE: u32 = 0x7B5F_0000;

/// Stress-admin UserID. Unlimited attempts, PIN derived from
/// `hw::secret_keys::se050_admin_pin()` (BHK-rooted in the shipping
/// configuration, otherwise OTP/DHUK-rooted — every variant is per-
/// device deterministic so the same firmware re-derives the same PIN
/// across reboots and reflashes). Holds admin-delete authority over
/// every OID in `0x7B5F_*`, so the runner can always clean up after a
/// crashed test.
pub const STRESS_ADMIN_USERID: u32 = STRESS_BASE | 0x00A0;

/// Compute the OID for slot `slot` of test `test_id`.
/// `test_id ∈ 1..=255`, `slot ∈ 0..=255`. Test 0 is reserved (used for
/// the admin UserID's own sub-range).
#[inline]
pub const fn scratch_oid(test_id: u16, slot: u8) -> u32 {
    STRESS_BASE | (((test_id as u32) & 0xFF) << 8) | (slot as u32)
}

/// `(low, high_inclusive)` OID bounds for a single test's sub-range.
#[inline]
pub const fn scratch_range(test_id: u16) -> (u32, u32) {
    let lo = STRESS_BASE | (((test_id as u32) & 0xFF) << 8);
    (lo, lo | 0xFF)
}

/// Result of an admin sweep — how many OIDs were cleared vs. left
/// behind. Failures are best-effort; the runner logs them and proceeds.
pub struct SweepReport {
    pub cleared: u16,
    pub failed: u16,
}

/// Top-of-run sweep: clears every OID in `0x7B5F_*` that the stress-
/// admin session can reach. Provisions the stress-admin UserID first if
/// it doesn't yet exist (idempotent). Best-effort — on failure the
/// runner still tries the test, since per-test setup also tries to
/// clean its own range.
pub fn admin_sweep_all(se: &mut Se050) -> SweepReport {
    let mut rep = SweepReport { cleared: 0, failed: 0 };
    let pin = match crate::hw::secret_keys::se050_admin_pin() {
        Ok(p) => p,
        Err(_) => {
            secure_log!("[S][stress] sweep: se050_admin_pin unavailable");
            return rep;
        }
    };

    unsafe {
        // Idempotent provisioning of the stress admin. If the OID
        // already exists, skip provisioning.
        {
            let (t1, scp03) = se.t1_scp03_mut();
            let exists = apdu::check_exists(t1, scp03, STRESS_ADMIN_USERID)
                .unwrap_or(false);
            if !exists {
                if let Err(e) = apdu::write_userid_unlimited(
                    t1, scp03, STRESS_ADMIN_USERID, &pin, None,
                ) {
                    secure_log!("[S][stress] sweep: provision STRESS_ADMIN failed: {:?}", e);
                    return rep;
                }
            }
        }

        // Open admin session.
        let sid = {
            let (t1, scp03) = se.t1_scp03_mut();
            match apdu::create_session(t1, scp03, STRESS_ADMIN_USERID) {
                Ok(s) => s,
                Err(e) => {
                    secure_log!("[S][stress] sweep: create_session failed: {:?}", e);
                    return rep;
                }
            }
        };
        {
            let (t1, scp03) = se.t1_scp03_mut();
            if let Err(e) = apdu::verify_session(t1, scp03, &sid, &pin) {
                secure_log!("[S][stress] sweep: verify_session failed: {:?}", e);
                let _ = apdu::close_session(t1, scp03, &sid);
                return rep;
            }
        }

        // Sweep every test sub-range (1..=255). `check_exists` is
        // unauthenticated and cheap; only OIDs that exist cost a
        // delete APDU.
        for test_id in 1u16..=255 {
            let (lo, hi) = scratch_range(test_id);
            for oid in lo..=hi {
                let (t1, scp03) = se.t1_scp03_mut();
                if apdu::check_exists(t1, scp03, oid).unwrap_or(false) {
                    match apdu::delete_object_authed(t1, scp03, &sid, oid) {
                        Ok(()) => rep.cleared += 1,
                        Err(_) => rep.failed += 1,
                    }
                }
            }
        }

        let (t1, scp03) = se.t1_scp03_mut();
        let _ = apdu::close_session(t1, scp03, &sid);
    }
    rep
}

/// Per-test sweep: clear just one test's 256-OID sub-range. Called
/// after each test (PASS or FAIL) so the next test starts clean.
pub fn admin_sweep_test_range(se: &mut Se050, test_id: u16) -> SweepReport {
    let mut rep = SweepReport { cleared: 0, failed: 0 };
    let pin = match crate::hw::secret_keys::se050_admin_pin() {
        Ok(p) => p,
        Err(_) => return rep,
    };

    unsafe {
        let (lo, hi) = scratch_range(test_id);

        // Quick scan first — if the sub-range is empty, skip the
        // session machinery entirely.
        let mut any = false;
        for oid in lo..=hi {
            let (t1, scp03) = se.t1_scp03_mut();
            if apdu::check_exists(t1, scp03, oid).unwrap_or(false) {
                any = true;
                break;
            }
        }
        if !any {
            return rep;
        }

        let sid = {
            let (t1, scp03) = se.t1_scp03_mut();
            match apdu::create_session(t1, scp03, STRESS_ADMIN_USERID) {
                Ok(s) => s,
                Err(_) => return rep,
            }
        };
        {
            let (t1, scp03) = se.t1_scp03_mut();
            if apdu::verify_session(t1, scp03, &sid, &pin).is_err() {
                let _ = apdu::close_session(t1, scp03, &sid);
                return rep;
            }
        }

        for oid in lo..=hi {
            let (t1, scp03) = se.t1_scp03_mut();
            if apdu::check_exists(t1, scp03, oid).unwrap_or(false) {
                match apdu::delete_object_authed(t1, scp03, &sid, oid) {
                    Ok(()) => rep.cleared += 1,
                    Err(_) => rep.failed += 1,
                }
            }
        }
        let (t1, scp03) = se.t1_scp03_mut();
        let _ = apdu::close_session(t1, scp03, &sid);
    }
    rep
}
