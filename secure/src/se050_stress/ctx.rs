//! `StressCtx` — the API stress tests are written against.
//!
//! Wraps the live `Se050` driver with helpers for:
//! - Computing scratch OIDs in this test's reserved sub-range.
//! - Writing/reading/deleting scratch data objects (admin-gated, so
//!   they're reclaimable on test failure).
//! - Provisioning test UserIDs and opening user / admin sessions.
//! - Asserting equality, status words, and conditions in a way that
//!   produces structured `StressError` values the runner can log.
//! - Iteration tracking so "fails on iter 47/256" is recoverable.
//! - Typed wrappers around the unsafe `apdu::*` helpers so tests stay
//!   readable and the split-borrow on `Se050.{t1,scp03}` is funneled
//!   through one place.
//!
//! **Adding a helper is a forward-compatible change.** Existing tests
//! ignore methods they don't call; new methods slot in here.

use crate::se050::Se050;
use crate::se050::apdu::{self, Se050Error};
use crate::se050::scp03::Scp03Session;
use crate::se050::t1oi2c::T1State;

use super::oid;
use super::{StressError, StressResult};

pub type SessionId = [u8; 8];

/// Two-entry policy selector for `provision_test_userid`.
///
/// `WithAdminDelete` — gate the UserID with the standard two-entry
/// policy (self + stress-admin DELETE). Lets the runner clean up a
/// crashed test via admin auth.
///
/// `WithoutAdminEntry` — emit ONLY the self-policy entry (no admin
/// fallback). Used by `audit::userid_no_admin_delete` to prove the
/// S-6 fix: a UserID created without an admin entry cannot be
/// admin-deleted.
#[derive(Clone, Copy)]
pub enum AdminPolicy {
    WithAdminDelete,
    WithoutAdminEntry,
}

pub struct StressCtx<'a> {
    se: &'a mut Se050,
    test_id: u16,
    iter: u32,
}

impl<'a> StressCtx<'a> {
    pub fn new(se: &'a mut Se050, test_id: u16) -> Self {
        Self { se, test_id, iter: 0 }
    }

    // -------- OID layout --------

    /// OID for slot `slot` of this test's sub-range
    /// (= `0x7B5F_<test_id><slot>`).
    #[inline]
    pub fn oid(&self, slot: u8) -> u32 {
        oid::scratch_oid(self.test_id, slot)
    }

    // -------- Scratch object I/O (admin-gated for clean teardown) --------

    /// Write a binary object at `target`, gated solely by stress-admin
    /// auth. Reads/writes go through the admin session in
    /// `read_scratch` / `delete_scratch`, so the runner always has a
    /// path to clean up even if a test panics.
    pub fn write_scratch(&mut self, target: u32, data: &[u8]) -> StressResult {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::write_binary_gated(
                t1, scp03, target, data, oid::STRESS_ADMIN_USERID, None,
            )?;
        }
        Ok(())
    }

    /// Read a previously-written scratch object via admin auth.
    /// Returns the number of bytes written into `out`.
    pub fn read_scratch(&mut self, target: u32, out: &mut [u8]) -> Result<usize, StressError> {
        let pin = self.admin_pin()?;
        unsafe {
            let sid = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::create_session(t1, scp03, oid::STRESS_ADMIN_USERID)?
            };
            {
                let (t1, scp03) = self.se.t1_scp03_mut();
                if let Err(e) = apdu::verify_session(t1, scp03, &sid, &pin) {
                    let _ = apdu::close_session(t1, scp03, &sid);
                    return Err(e.into());
                }
            }
            let n = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::read_authed(t1, scp03, &sid, target, out)?
            };
            let (t1, scp03) = self.se.t1_scp03_mut();
            let _ = apdu::close_session(t1, scp03, &sid);
            Ok(n)
        }
    }

    /// Delete a scratch object via admin auth. Idempotent (missing OID
    /// is a no-op).
    pub fn delete_scratch(&mut self, target: u32) -> StressResult {
        let pin = self.admin_pin()?;
        unsafe {
            let present = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::check_exists(t1, scp03, target).unwrap_or(false)
            };
            if !present {
                return Ok(());
            }
            let sid = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::create_session(t1, scp03, oid::STRESS_ADMIN_USERID)?
            };
            {
                let (t1, scp03) = self.se.t1_scp03_mut();
                if apdu::verify_session(t1, scp03, &sid, &pin).is_err() {
                    let _ = apdu::close_session(t1, scp03, &sid);
                    return Ok(());
                }
            }
            {
                let (t1, scp03) = self.se.t1_scp03_mut();
                let _ = apdu::delete_object_authed(t1, scp03, &sid, target);
            }
            let (t1, scp03) = self.se.t1_scp03_mut();
            let _ = apdu::close_session(t1, scp03, &sid);
        }
        Ok(())
    }

    // -------- UserID provisioning + sessions --------

    /// Provision a test UserID. `max_attempts ∈ 1..=255`. `policy`
    /// chooses whether to attach the stress-admin delete entry.
    pub fn provision_test_userid(
        &mut self,
        target: u32,
        pin: &[u8],
        max_attempts: u16,
        policy: AdminPolicy,
    ) -> StressResult {
        let admin_entry = match policy {
            AdminPolicy::WithAdminDelete => Some(oid::STRESS_ADMIN_USERID),
            AdminPolicy::WithoutAdminEntry => None,
        };
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::write_userid(t1, scp03, target, pin, max_attempts, admin_entry)?;
        }
        Ok(())
    }

    /// Open + verify a session against `userid_oid`.
    pub fn open_user_session(
        &mut self,
        userid_oid: u32,
        pin: &[u8],
    ) -> Result<SessionId, StressError> {
        unsafe {
            let sid = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::create_session(t1, scp03, userid_oid)?
            };
            {
                let (t1, scp03) = self.se.t1_scp03_mut();
                if let Err(e) = apdu::verify_session(t1, scp03, &sid, pin) {
                    let _ = apdu::close_session(t1, scp03, &sid);
                    return Err(e.into());
                }
            }
            Ok(sid)
        }
    }

    /// Open + verify a session against the stress-admin UserID.
    pub fn open_admin_session(&mut self) -> Result<SessionId, StressError> {
        let pin = self.admin_pin()?;
        self.open_user_session(oid::STRESS_ADMIN_USERID, &pin)
    }

    /// Close a session (idempotent — SE050 just no-ops on stale IDs).
    pub fn close_session(&mut self, sid: &SessionId) {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            let _ = apdu::close_session(t1, scp03, sid);
        }
    }

    // -------- Typed APDU wrappers for tests --------

    /// `check_exists` on an arbitrary OID, no auth.
    pub fn check_exists(&mut self, target: u32) -> Result<bool, Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::check_exists(t1, scp03, target)
        }
    }

    /// Delete an object through an existing authenticated session.
    pub fn delete_authed(&mut self, sid: &SessionId, target: u32) -> Result<(), Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::delete_object_authed(t1, scp03, sid, target)
        }
    }

    // -------- Assertion helpers --------

    pub fn assert_true(&self, what: &'static str, cond: bool) -> StressResult {
        if cond {
            Ok(())
        } else {
            Err(StressError::Assertion { what, iter: self.iter })
        }
    }

    pub fn assert_eq(
        &self,
        what: &'static str,
        got: &[u8],
        expected: &[u8],
    ) -> StressResult {
        if got.len() != expected.len() {
            return Err(StressError::Assertion { what, iter: self.iter });
        }
        for (g, e) in got.iter().zip(expected.iter()) {
            if g != e {
                return Err(StressError::Mismatch {
                    what,
                    expected: *e,
                    got: *g,
                });
            }
        }
        Ok(())
    }

    pub fn assert_ne(
        &self,
        what: &'static str,
        a: &[u8],
        b: &[u8],
    ) -> StressResult {
        if a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y) {
            return Err(StressError::Assertion { what, iter: self.iter });
        }
        Ok(())
    }

    pub fn assert_sw_eq(
        &self,
        what: &'static str,
        sw: u16,
        expected: u16,
    ) -> StressResult {
        if sw == expected {
            Ok(())
        } else {
            Err(StressError::UnexpectedSw { what, sw })
        }
    }

    // -------- Iteration tracking --------

    pub fn set_iter(&mut self, n: u32) {
        self.iter = n;
    }

    pub fn iter(&self) -> u32 {
        self.iter
    }

    // -------- Low-level escape hatches --------

    /// Split-borrow accessor: `(t1, scp03)`. Use when a test needs to
    /// call `apdu::*` helpers directly that aren't covered by the
    /// typed wrappers above. The pair lives for the duration of the
    /// returned lifetime; pass both to a single APDU call, drop them,
    /// then re-acquire if more APDUs are needed.
    pub fn t1_scp03(&mut self) -> (&mut T1State, &mut Scp03Session) {
        self.se.t1_scp03_mut()
    }

    /// Snapshot of SCP03 session keys / counter for tests that just
    /// want to inspect handshake outputs without holding a borrow.
    /// Cheap: `s_enc` / `s_mac` / `s_rmac` are 16 bytes each.
    pub fn scp03_snapshot(&mut self) -> Scp03Snapshot {
        let (_, scp03) = self.se.t1_scp03_mut();
        Scp03Snapshot {
            s_enc: scp03.s_enc,
            s_mac: scp03.s_mac,
            s_rmac: scp03.s_rmac,
            mcv: scp03.mcv,
            counter: scp03.counter,
            active: scp03.active,
        }
    }

    /// Send a raw APDU through the SCP03 wrap path. Returns the
    /// unwrapped response body length (SW is stripped — non-9000 SWs
    /// surface as `Se050Error::Status(sw)`).
    pub fn raw_apdu(
        &mut self,
        apdu_bytes: &[u8],
        resp_buf: &mut [u8],
    ) -> Result<usize, Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::send_apdu(t1, scp03, apdu_bytes, resp_buf)
        }
    }

    /// Mutable access to the underlying SE050 — for tests that want to
    /// call `se.random(...)`, `se.reinit(...)`, `se.pin_attempt_count_
    /// raw(...)`, etc.
    pub fn se(&mut self) -> &mut Se050 {
        self.se
    }

    // -------- Private helpers --------

    fn admin_pin(&self) -> Result<[u8; 16], StressError> {
        crate::hw::secret_keys::se050_admin_pin().map_err(|_| StressError::Assertion {
            what: "se050_admin_pin unavailable",
            iter: self.iter,
        })
    }
}

/// Read-only snapshot of `Scp03Session` state — useful for tests that
/// compare derived session keys across handshakes without keeping a
/// mutable borrow on the chip handle.
#[derive(Debug)]
pub struct Scp03Snapshot {
    pub s_enc: [u8; 16],
    pub s_mac: [u8; 16],
    pub s_rmac: [u8; 16],
    pub mcv: [u8; 16],
    pub counter: [u8; 16],
    pub active: bool,
}
