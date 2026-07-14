//! First-boot provisioning state machine — pure, resumable (host-testable).
//!
//! Work-todo #36 Phase B: after the RDP-2 self-lock, rotate the SE pairing
//! secrets off the factory transport keysets to final BHK-/salted-DHUK-rooted
//! secrets. The ceremony must survive power loss at any point, so every step
//! is idempotent + resumable and its completion is recorded **commit-LAST**
//! in the page-127 journal ([`super::journal`]).
//!
//! This module is the pure control flow only: it drives the hardware through
//! the [`FirstBootHw`] seam and never touches flash / the SEs / the display
//! directly. That keeps the whole resume matrix host-testable with a scripted
//! fake (see the tests), while the real implementation lives in `first_boot::
//! mod` behind the `stm32u585` + `rdp2-self-lock` gates.

#![allow(dead_code)]

use super::journal::{
    DONE_ALL, DONE_BHK, DONE_OPTIGA_PBS, DONE_SE050_ADMIN, DONE_SE050_KEYS, STEP_ALL_DONE,
    STEP_BHK, STEP_OPTIGA_PBS, STEP_SE050_ADMIN, STEP_SE050_KEYS,
};

/// Numbered step of the first-boot ceremony (1-indexed for the fault screen).
/// `Preconditions`/`Finalize` bracket the four rotation steps.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FirstBootStep {
    /// Phase A: pre-lock option-byte verification + the RDP-2 burn.
    Lock = 0,
    Preconditions = 1,
    Bhk = 2,
    Se050Keys = 3,
    Se050Admin = 4,
    OptigaPbs = 5,
    Finalize = 6,
}

impl FirstBootStep {
    #[must_use]
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// Total step count for the "X/N" fault line.
    pub const TOTAL: u8 = 6;
}

/// Numbered first-boot error, kept **disjoint** from `FactoryErrorCode`
/// (0x01xx–0x07xx) by living in 0x08xx–0x0Fxx. Values are STABLE across
/// firmware versions so old field-failure photos stay interpretable.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum FirstBootError {
    // Phase A (pre-lock) — halt UNLOCKED, unit stays returnable.
    /// Option bytes / OTP / journal pages don't match the ship profile.
    ObProfileMismatch = 0x0801,
    /// The RDP=0xCC program / OPTSTRT sequence reported an error.
    RdpProgramFailed = 0x0802,

    // Phase B (post-lock) — RMA / retry.
    /// OTP master is blank — the factory must burn it; first boot must not.
    OtpMasterNotBurned = 0x0811,
    /// SAES Tier-1 (DHUK) self-check failed.
    SaesDead = 0x0812,
    /// BHK provision / load-lock / self-test failed.
    BhkProvisionFailed = 0x0821,
    /// Page-126 refused programming (bench program-hostility) — silicon RMA.
    BhkPageHostile = 0x0822,
    /// SE050 SCP03 session could not be established under FINAL or TRANSPORT.
    Se050EstablishFailed = 0x0831,
    /// SE050 GP PUT KEY (transport → final) failed.
    Se050PutKeyFailed = 0x0832,
    /// Re-establish under the FINAL keyset did not confirm.
    Se050KeyConfirmFailed = 0x0833,
    /// SE050 admin credential re-key (delete + recreate) failed.
    Se050AdminRekeyFailed = 0x0841,
    /// The TRNG salt could not be persisted to the journal before use.
    OptigaSaltPersistFailed = 0x0851,
    /// OPTIGA SetData(E140) of the final PBS failed.
    OptigaSetDataFailed = 0x0852,
    /// Re-shield under the FINAL PBS did not confirm.
    OptigaConfirmFailed = 0x0853,
    /// A journal step-marker write failed.
    JournalWriteFailed = 0x0861,
    /// The SEs are not in the expected factory transport state (e.g. a transit
    /// attacker pre-rotated them) — never fall back to vendor defaults.
    UnexpectedState = 0x08F0,
}

impl FirstBootError {
    #[must_use]
    pub const fn raw(self) -> u16 {
        self as u16
    }
}

/// A terminal first-boot fault: which step failed + the numbered code.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FirstBootFault {
    pub step: FirstBootStep,
    pub code: FirstBootError,
}

impl FirstBootFault {
    #[must_use]
    pub const fn new(step: FirstBootStep, code: FirstBootError) -> Self {
        Self { step, code }
    }
}

/// The hardware seam the Phase-B state machine drives. Every method is a
/// durable, resumable operation; the pure `run` below sequences them and
/// records progress via `commit_step` / `commit_salt`.
///
/// Implementations MUST make the rotation methods idempotent + two-phase
/// (confirm the NEW keyset works before considering the OLD dead; on resume
/// try FINAL first, fall back to TRANSPORT) — see the real impl in
/// `first_boot::mod`.
pub trait FirstBootHw {
    /// Current journal state (re-scanned from page 127).
    fn journal(&self) -> super::journal::JournalState;
    /// Append a step-completion marker (commit-LAST).
    fn commit_step(&mut self, step_id: u8) -> Result<(), FirstBootError>;
    /// Persist the TRNG salt (commit-LAST, BEFORE it is used to derive the PBS).
    fn commit_salt(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError>;

    /// Precondition: the factory-burned OTP master is present.
    fn otp_master_burned(&self) -> bool;
    /// Precondition: SAES Tier-1 (DHUK) is alive.
    fn saes_alive(&self) -> bool;

    /// BHK first-write: erase-and-reprovision UNCONDITIONALLY (anti-pre-plant),
    /// then load-lock + self-test.
    fn bhk_provision_and_lock(&mut self) -> Result<(), FirstBootError>;
    /// Rotate SE050 SCP03 transport → final (two-phase confirm).
    fn se050_rotate_scp03(&mut self) -> Result<(), FirstBootError>;
    /// Re-key the SE050 admin credential transport → final.
    fn se050_rekey_admin(&mut self) -> Result<(), FirstBootError>;
    /// Draw a fresh 32-byte TRNG salt.
    fn trng_salt(&mut self) -> Result<[u8; 32], FirstBootError>;
    /// Rotate the OPTIGA PBS transport → salted-final (two-phase confirm).
    fn optiga_rotate_pbs(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError>;

    /// UI hook: entering `step` (`resuming` = we've been here before).
    fn ui_step(&mut self, step: FirstBootStep, resuming: bool);
}

/// Run the Phase-B ceremony to completion (or the first fault). `Ok(())`
/// means the journal now reads `ALL_DONE` and normal boot may proceed to the
/// seed wizard.
///
/// Resumability: each step is guarded on its journal marker, so a boot that
/// re-enters after a power loss skips every already-committed step and
/// resumes at the first incomplete one. The single writer within a run is us,
/// so the completed-set is tracked locally after the initial scan.
pub fn run(hw: &mut dyn FirstBootHw) -> Result<(), FirstBootFault> {
    // Step 1 — preconditions (read-only; run every boot, no marker).
    if !hw.otp_master_burned() {
        return Err(FirstBootFault::new(
            FirstBootStep::Preconditions,
            FirstBootError::OtpMasterNotBurned,
        ));
    }
    if !hw.saes_alive() {
        return Err(FirstBootFault::new(
            FirstBootStep::Preconditions,
            FirstBootError::SaesDead,
        ));
    }

    let js = hw.journal();
    let resuming = !js.is_blank();
    let mut done = js.done;
    let mut salt = js.salt;

    // Step 2 — BHK first-write (anti-pre-plant erase-and-reprovision).
    if done & DONE_BHK == 0 {
        hw.ui_step(FirstBootStep::Bhk, resuming);
        hw.bhk_provision_and_lock()
            .map_err(|e| FirstBootFault::new(FirstBootStep::Bhk, e))?;
        hw.commit_step(STEP_BHK)
            .map_err(|e| FirstBootFault::new(FirstBootStep::Bhk, e))?;
        done |= DONE_BHK;
    }

    // Step 3 — SE050 SCP03 rotation transport → final.
    if done & DONE_SE050_KEYS == 0 {
        hw.ui_step(FirstBootStep::Se050Keys, resuming);
        hw.se050_rotate_scp03()
            .map_err(|e| FirstBootFault::new(FirstBootStep::Se050Keys, e))?;
        hw.commit_step(STEP_SE050_KEYS)
            .map_err(|e| FirstBootFault::new(FirstBootStep::Se050Keys, e))?;
        done |= DONE_SE050_KEYS;
    }

    // Step 4 — SE050 admin credential re-key transport → final.
    if done & DONE_SE050_ADMIN == 0 {
        hw.ui_step(FirstBootStep::Se050Admin, resuming);
        hw.se050_rekey_admin()
            .map_err(|e| FirstBootFault::new(FirstBootStep::Se050Admin, e))?;
        hw.commit_step(STEP_SE050_ADMIN)
            .map_err(|e| FirstBootFault::new(FirstBootStep::Se050Admin, e))?;
        done |= DONE_SE050_ADMIN;
    }

    // Step 5 — OPTIGA PBS rotation transport → salted-final. The salt is
    // committed to the journal BEFORE use so a resume derives the SAME final
    // PBS (a fresh salt each attempt would strand the E140 write).
    if done & DONE_OPTIGA_PBS == 0 {
        hw.ui_step(FirstBootStep::OptigaPbs, resuming);
        let s = match salt {
            Some(s) => s,
            None => {
                let s = hw
                    .trng_salt()
                    .map_err(|e| FirstBootFault::new(FirstBootStep::OptigaPbs, e))?;
                hw.commit_salt(&s)
                    .map_err(|e| FirstBootFault::new(FirstBootStep::OptigaPbs, e))?;
                salt = Some(s);
                s
            }
        };
        hw.optiga_rotate_pbs(&s)
            .map_err(|e| FirstBootFault::new(FirstBootStep::OptigaPbs, e))?;
        hw.commit_step(STEP_OPTIGA_PBS)
            .map_err(|e| FirstBootFault::new(FirstBootStep::OptigaPbs, e))?;
        done |= DONE_OPTIGA_PBS;
    }

    // Step 6 — finalize.
    if done & DONE_ALL == 0 {
        hw.commit_step(STEP_ALL_DONE)
            .map_err(|e| FirstBootFault::new(FirstBootStep::Finalize, e))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::journal::{self, PAGE_QWS, QW};
    use super::*;
    use std::panic::{self, AssertUnwindSafe};
    use std::vec::Vec;

    /// Panic payload used to simulate a power loss at a chosen op boundary.
    const POWERCUT: &str = "POWERCUT";

    /// Scripted `FirstBootHw` fake. The `page` (journal) and the SE-state
    /// flags persist across a simulated reset; `cut_at` injects a panic after
    /// the N-th durable op to model a power cut at that boundary.
    struct FakeHw {
        page: Vec<u8>, // 512*16 journal image; survives "reset"
        // Simulated durable SE / BHK state (persists across reset).
        bhk_final: bool,
        se050_keys_final: bool,
        se050_admin_final: bool,
        optiga_pbs_final: bool,
        // Preconditions / injected failures.
        otp_burned: bool,
        saes_ok: bool,
        fail: Option<FirstBootError>,
        fail_on_step: Option<u8>,
        // Deterministic "TRNG" salt (varies per test, not per call).
        salt_source: [u8; 32],
        // Power-cut injection.
        ops: usize,
        cut_at: Option<usize>,
        // Bookkeeping.
        bhk_calls: usize,
        scp03_calls: usize,
        admin_calls: usize,
        optiga_calls: usize,
    }

    impl FakeHw {
        fn new() -> Self {
            FakeHw {
                page: std::vec![0xFFu8; PAGE_QWS * QW],
                bhk_final: false,
                se050_keys_final: false,
                se050_admin_final: false,
                optiga_pbs_final: false,
                otp_burned: true,
                saes_ok: true,
                fail: None,
                fail_on_step: None,
                salt_source: [0x5Au8; 32],
                ops: 0,
                cut_at: None,
                bhk_calls: 0,
                scp03_calls: 0,
                admin_calls: 0,
                optiga_calls: 0,
            }
        }

        /// Register a durable op; panic (simulate reset) if this is the cut op.
        fn tick(&mut self) {
            self.ops += 1;
            if Some(self.ops) == self.cut_at {
                panic!("{POWERCUT}");
            }
        }

        fn journal_done(&self) -> u32 {
            journal::scan(&self.page).done
        }

        fn append(&mut self, rec: &[u8; QW]) -> Result<(), FirstBootError> {
            let idx = journal::scan(&self.page).next_free;
            if idx >= PAGE_QWS {
                return Err(FirstBootError::JournalWriteFailed);
            }
            self.page[idx * QW..idx * QW + QW].copy_from_slice(rec);
            Ok(())
        }
    }

    impl FirstBootHw for FakeHw {
        fn journal(&self) -> journal::JournalState {
            journal::scan(&self.page)
        }
        fn commit_step(&mut self, step_id: u8) -> Result<(), FirstBootError> {
            let rec = journal::encode_step(step_id);
            self.append(&rec)?; // durable first
            self.tick(); // then a cut here loses nothing (marker persisted)
            Ok(())
        }
        fn commit_salt(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError> {
            let recs = journal::encode_salt(salt);
            for r in &recs {
                self.append(r)?;
            }
            self.tick();
            Ok(())
        }
        fn otp_master_burned(&self) -> bool {
            self.otp_burned
        }
        fn saes_alive(&self) -> bool {
            self.saes_ok
        }
        fn bhk_provision_and_lock(&mut self) -> Result<(), FirstBootError> {
            assert_eq!(
                self.journal_done() & DONE_BHK,
                0,
                "BHK step re-run after its marker was committed"
            );
            self.bhk_calls += 1;
            self.tick(); // cut before the durable effect
            if self.fail_on_step == Some(2) {
                return Err(self.fail.unwrap());
            }
            self.bhk_final = true; // idempotent durable effect
            self.tick(); // cut after the effect, before commit
            Ok(())
        }
        fn se050_rotate_scp03(&mut self) -> Result<(), FirstBootError> {
            assert_eq!(self.journal_done() & DONE_SE050_KEYS, 0, "SCP03 re-run after commit");
            self.scp03_calls += 1;
            self.tick();
            if self.fail_on_step == Some(3) {
                return Err(self.fail.unwrap());
            }
            self.se050_keys_final = true;
            self.tick();
            Ok(())
        }
        fn se050_rekey_admin(&mut self) -> Result<(), FirstBootError> {
            assert_eq!(self.journal_done() & DONE_SE050_ADMIN, 0, "admin re-run after commit");
            self.admin_calls += 1;
            self.tick();
            if self.fail_on_step == Some(4) {
                return Err(self.fail.unwrap());
            }
            self.se050_admin_final = true;
            self.tick();
            Ok(())
        }
        fn trng_salt(&mut self) -> Result<[u8; 32], FirstBootError> {
            self.tick();
            Ok(self.salt_source)
        }
        fn optiga_rotate_pbs(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError> {
            assert_eq!(self.journal_done() & DONE_OPTIGA_PBS, 0, "PBS re-run after commit");
            // The salt handed to us MUST be the persisted one (deterministic
            // final PBS across resumes).
            assert_eq!(salt, &self.salt_source, "rotation used a non-persisted salt");
            self.optiga_calls += 1;
            self.tick();
            if self.fail_on_step == Some(5) {
                return Err(self.fail.unwrap());
            }
            self.optiga_pbs_final = true;
            self.tick();
            Ok(())
        }
        fn ui_step(&mut self, _step: FirstBootStep, _resuming: bool) {}
    }

    fn all_final(hw: &FakeHw) -> bool {
        hw.bhk_final
            && hw.se050_keys_final
            && hw.se050_admin_final
            && hw.optiga_pbs_final
            && hw.journal().all_done()
    }

    #[test]
    fn clean_run_completes() {
        let mut hw = FakeHw::new();
        assert_eq!(run(&mut hw), Ok(()));
        assert!(all_final(&hw));
        // Each rotation step ran exactly once on a clean run.
        assert_eq!(hw.bhk_calls, 1);
        assert_eq!(hw.scp03_calls, 1);
        assert_eq!(hw.admin_calls, 1);
        assert_eq!(hw.optiga_calls, 1);
    }

    #[test]
    fn idempotent_second_run_is_noop() {
        let mut hw = FakeHw::new();
        assert_eq!(run(&mut hw), Ok(()));
        let (b, s, a, o) = (hw.bhk_calls, hw.scp03_calls, hw.admin_calls, hw.optiga_calls);
        // Re-run on a fully-provisioned device: every step guarded off.
        assert_eq!(run(&mut hw), Ok(()));
        assert_eq!((hw.bhk_calls, hw.scp03_calls, hw.admin_calls, hw.optiga_calls), (b, s, a, o));
    }

    #[test]
    fn precondition_faults_are_rma() {
        let mut hw = FakeHw::new();
        hw.otp_burned = false;
        assert_eq!(
            run(&mut hw),
            Err(FirstBootFault::new(FirstBootStep::Preconditions, FirstBootError::OtpMasterNotBurned))
        );

        let mut hw = FakeHw::new();
        hw.saes_ok = false;
        assert_eq!(
            run(&mut hw),
            Err(FirstBootFault::new(FirstBootStep::Preconditions, FirstBootError::SaesDead))
        );
    }

    #[test]
    fn step_failure_surfaces_step_and_code() {
        let mut hw = FakeHw::new();
        hw.fail_on_step = Some(3);
        hw.fail = Some(FirstBootError::Se050PutKeyFailed);
        assert_eq!(
            run(&mut hw),
            Err(FirstBootFault::new(FirstBootStep::Se050Keys, FirstBootError::Se050PutKeyFailed))
        );
        // BHK completed and is durable; the failed step left no marker.
        assert!(hw.journal().has(DONE_BHK));
        assert!(!hw.journal().has(DONE_SE050_KEYS));
    }

    /// Drive one cut+resume cycle: run with `cut_at`, swallow the powercut
    /// panic, then resume (no cut) to completion. Returns the fake for asserts.
    fn cut_then_resume(cut_at: usize) -> FakeHw {
        let mut hw = FakeHw::new();
        hw.cut_at = Some(cut_at);

        // Suppress the default panic printout for the injected powercut.
        let prev = panic::take_hook();
        panic::set_hook(std::boxed::Box::new(|_| {}));
        let res = panic::catch_unwind(AssertUnwindSafe(|| run(&mut hw)));
        panic::set_hook(prev);

        match res {
            Ok(r) => {
                // No cut fired (cut_at past the op count) — must have completed.
                assert_eq!(r, Ok(()), "uncut run must complete");
            }
            Err(payload) => {
                // The formatted `panic!` yields a `String` payload; accept both.
                let msg = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<std::string::String>().map(|s| s.as_str()))
                    .unwrap_or("");
                assert_eq!(msg, POWERCUT, "only the injected powercut may unwind");
            }
        }

        // Resume: same device (page + SE flags persisted), no more cuts.
        hw.cut_at = None;
        assert_eq!(run(&mut hw), Ok(()), "resume after cut@{cut_at} must complete");
        hw
    }

    #[test]
    fn power_cut_at_every_boundary_converges() {
        // A clean run performs this many durable ticks; cut at each one.
        let total_ops = {
            let mut hw = FakeHw::new();
            let _ = run(&mut hw);
            hw.ops
        };
        assert!(total_ops >= 10, "expected a healthy number of op boundaries");

        for cut in 1..=total_ops + 1 {
            let hw = cut_then_resume(cut);
            assert!(all_final(&hw), "cut@{cut} did not converge to ALL_DONE");
            // Anti-pre-plant / idempotence: no step ran more than twice
            // (once pre-cut without a committed marker, once on resume).
            assert!(hw.bhk_calls <= 2, "cut@{cut}: BHK ran {} times", hw.bhk_calls);
            assert!(hw.scp03_calls <= 2, "cut@{cut}: SCP03 ran {} times", hw.scp03_calls);
            assert!(hw.admin_calls <= 2, "cut@{cut}: admin ran {} times", hw.admin_calls);
            assert!(hw.optiga_calls <= 2, "cut@{cut}: OPTIGA ran {} times", hw.optiga_calls);
        }
    }

    #[test]
    fn salt_persisted_before_use_survives_cut() {
        // Find the op index of the salt commit, cut right after it, and assert
        // the resume reuses the SAME salt (does not regenerate).
        let mut hw = FakeHw::new();
        hw.salt_source = [0x9Cu8; 32];
        // Run until the salt lands in the journal, then inspect.
        let _ = run(&mut hw);
        assert_eq!(hw.journal().salt, Some([0x9Cu8; 32]));
        // A fresh device, cut somewhere inside the OPTIGA step, must still end
        // with exactly the persisted salt (optiga_rotate_pbs asserts salt match).
        for cut in 1..=hw.ops + 1 {
            let mut h = FakeHw::new();
            h.salt_source = [0x9Cu8; 32];
            h.cut_at = Some(cut);
            let prev = panic::take_hook();
            panic::set_hook(std::boxed::Box::new(|_| {}));
            let _ = panic::catch_unwind(AssertUnwindSafe(|| run(&mut h)));
            panic::set_hook(prev);
            h.cut_at = None;
            assert_eq!(run(&mut h), Ok(()));
            if let Some(s) = h.journal().salt {
                assert_eq!(s, [0x9Cu8; 32], "cut@{cut}: salt changed across resume");
            }
        }
    }
}
