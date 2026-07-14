//! First-boot self-provisioning (work-todo #36) — RDP-2 self-lock + on-device
//! rotation of the SE pairing secrets off the factory transport keysets.
//!
//! **Factory ⇄ first-boot split (authoritative — mirror in the docs):**
//! the factory flashes the batch-uniform image, sets the option-byte profile
//! (everything EXCEPT RDP), burns the per-device OTP master, and provisions
//! the SE-internal structure + irreversible locks onto per-device *transport*
//! keysets (public-by-assumption, rooted in the OTP master). The device ships
//! at RDP-0. On the **first field boot** this module verifies that ship state,
//! self-locks RDP-2, then rotates the transport keysets to final BHK-/salted-
//! DHUK-rooted secrets — before the seed wizard. See
//! `docs/provisioning/first-boot-provisioning.md`.
//!
//! Structure:
//! - [`journal`] — pure page-127 commit-LAST log codec (host-tested).
//! - [`state`] — pure resumable state machine over the [`state::FirstBootHw`]
//!   seam (host-tested with a scripted fake + power-cut matrix).
//! - the hardware glue (real `FirstBootHw` impl + the two boot entry points)
//!   lives below, gated on `stm32u585` + `rdp2-self-lock`, and is the only
//!   part that touches flash / the SEs / the display.

pub mod journal;
pub mod state;

// --- hardware glue (real silicon, feature-gated) ---------------------------
// The `run_pre_lock_and_maybe_lock` / `run_post_lock_provisioning` entry
// points and the real `FirstBootHw` implementation are added below under
// `#[cfg(all(not(test), feature = "rdp2-self-lock"))]` (the feature implies
// `stm32u585` transitively via `bhk` → `saes-dhuk`).

/// Scan the page-127 journal and return the persisted TRNG salt iff the whole
/// first-boot ceremony has completed (`ALL_DONE`). Used by
/// `secret_keys::current_pbs` to decide whether the OPTIGA driver pairs with
/// the salted-final PBS or the pre-rotation value. Reads memory-mapped flash
/// directly (no stack copy of the 8 KB page).
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
#[must_use]
pub fn journal_salt_if_all_done() -> Option<[u8; 32]> {
    // SAFETY: page 127 (KEY_PAGE) is a fixed 8 KB in-flash region, owned
    // outright by this journal; this is a read-only view.
    let page = unsafe {
        core::slice::from_raw_parts(
            crate::hw::flash::KEY_PAGE_ADDR as *const u8,
            journal::PAGE_QWS * journal::QW,
        )
    };
    let st = journal::scan(page);
    if st.all_done() {
        st.salt
    } else {
        None
    }
}

/// Has the first-boot ceremony fully completed (journal `ALL_DONE`)? Used by
/// `main` to gate the every-boot BHK provision/load block: pre-`ALL_DONE` the
/// BHK is owned by Phase B (journal-gated, anti-pre-plant), so the every-boot
/// block must stand down to avoid a stale double-lock.
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
#[must_use]
pub fn journal_all_done() -> bool {
    // `journal_page()` is defined in the Phase A/B section below (forward
    // reference is fine at module scope).
    journal::scan(journal_page()).all_done()
}

// ===========================================================================
// Phase A (pre-lock) + Phase B (post-lock) entry points + the real
// `FirstBootHw` implementation. Only compiled for the shipping self-lock
// feature. `rdp2-self-lock` implies `stm32u585` (via `bhk` → `saes-dhuk`), so
// these are real-silicon paths.
// ===========================================================================

#[cfg(all(not(test), feature = "rdp2-self-lock"))]
use state::{FirstBootError, FirstBootHw, FirstBootStep};

/// Read the 8 KB page-127 journal as a memory-mapped slice (no stack copy).
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
fn journal_page() -> &'static [u8] {
    // SAFETY: page 127 (KEY_PAGE) is a fixed 8 KB in-flash region owned
    // outright by the first-boot journal; this is a read-only view.
    unsafe {
        core::slice::from_raw_parts(
            crate::hw::flash::KEY_PAGE_ADDR as *const u8,
            journal::PAGE_QWS * journal::QW,
        )
    }
}

/// Render a numbered fault + park. `EXXXX` is the stable [`FirstBootError`]
/// code (0x08xx–0x0Fxx, disjoint from `FactoryErrorCode`); a field owner
/// photographs it for the vendor error-code → diagnosis table.
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
fn halt_first_boot(code: FirstBootError) -> ! {
    #[cfg(feature = "debug-log")]
    secure_log!("[first_boot] FAULT code={:#06x} — HALT", code.raw());

    // "EXXXX HALT" — pure ASCII, fits the 16-col row.
    let raw = code.raw();
    let hex = b"0123456789ABCDEF";
    let mut line = [0u8; 16];
    line[0] = b'E';
    line[1] = hex[((raw >> 12) & 0xF) as usize];
    line[2] = hex[((raw >> 8) & 0xF) as usize];
    line[3] = hex[((raw >> 4) & 0xF) as usize];
    line[4] = hex[(raw & 0xF) as usize];
    line[5..10].copy_from_slice(b" HALT");
    let sub = core::str::from_utf8(&line[..10]).unwrap_or("HALT");
    crate::ui::show_status("FIRST BOOT FAIL", sub);

    loop {
        cortex_m::asm::wfi();
    }
}

/// **Phase A** (work-todo #36): runs at earliest boot when RDP != Level 2.
/// Verifies the ship option-byte profile + blank per-device pages, warns the
/// user, then programs RDP=0xCC (which resets the MCU). Returns normally only
/// when the device is ALREADY locked (RDP-2) — i.e. every boot after the
/// first — so the caller continues into Phase B / normal boot. A profile
/// mismatch halts UNLOCKED (the unit stays returnable/reflashable — never turn
/// a bad flash into an RDP-2 brick).
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
pub fn run_pre_lock_and_maybe_lock() {
    use crate::hw::flash;
    use sphincs_tz_shared::lockdown::{self, RdpLevel};

    // Idempotence: already locked → normal boot (this check runs every boot).
    if flash::rdp_level() == RdpLevel::L2 {
        return;
    }

    // Verify the published ship option-byte profile (TZEN / SECWM / SECBOOTADD0
    // / WRP1A / OEM-locks). A mismatch means this is not a genuine RDP-0 ship
    // unit (or a transit attacker tampered with the option bytes).
    if lockdown::verify_ship_profile(
        flash::optr_raw(),
        flash::secwm1r1_raw(),
        flash::secwm2r1_raw(),
        flash::secboot_add0_reg(),
        flash::wrp1ar_raw(),
        flash::oem_lock_status_raw(),
        &lockdown::SHIP_PROFILE_U585,
    )
    .is_err()
    {
        halt_first_boot(FirstBootError::ObProfileMismatch);
    }

    // Blank-check the per-device pages 123..=127 BEFORE locking: a pre-planted
    // page-127 journal salt would otherwise yield a predictable final PBS
    // (#36 hardening #3), and a planted journal would spoof "already done".
    for page in 123..=127u32 {
        if !flash::is_secure_page_blank(page) {
            halt_first_boot(FirstBootError::ObProfileMismatch);
        }
    }

    // Trusted-UI warning before the irreversible step. Rendered once, then the
    // burn runs immediately (no input wait) to keep the pre-lock window tiny.
    crate::ui::show_status("FIRST BOOT", "DO NOT POWER OFF");
    // (BOR/VBUS power-stability check is a silicon-validation refinement — see
    // the #36 runbook; BOR is configured via the shipped option-byte profile.)

    // Program RDP=0xCC → OBL_LAUNCH. On success this resets the MCU and never
    // returns; it only returns on a pre-launch error.
    // SAFETY: the ship profile + blank per-device pages are verified above.
    if unsafe { flash::program_rdp_level2_and_launch() }.is_err() {
        halt_first_boot(FirstBootError::RdpProgramFailed);
    }
    // Unreachable on success (the device reset). If OBL_LAUNCH somehow failed
    // to reset, park rather than continue below RDP-2.
    loop {
        cortex_m::asm::wfe();
    }
}

/// The real [`FirstBootHw`] over the dual-SE + the platform HW modules.
#[cfg(all(not(test), feature = "rdp2-self-lock", feature = "dual-se"))]
struct FirstBootHwImpl<'a> {
    se: &'a mut crate::dual_se::DualSecureElement,
}

#[cfg(all(not(test), feature = "rdp2-self-lock", feature = "dual-se"))]
impl FirstBootHw for FirstBootHwImpl<'_> {
    fn journal(&self) -> journal::JournalState {
        journal::scan(journal_page())
    }

    fn commit_step(&mut self, step_id: u8) -> Result<(), FirstBootError> {
        let idx = self.journal().next_free;
        let rec = journal::encode_step(step_id);
        // SAFETY: append at the scanned `next_free` (currently-erased QW).
        unsafe { crate::hw::flash::write_journal_qw(idx, &rec) }
            .map_err(|_| FirstBootError::JournalWriteFailed)
    }

    fn commit_salt(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError> {
        let recs = journal::encode_salt(salt);
        let mut idx = self.journal().next_free;
        for r in &recs {
            // SAFETY: consecutive erased QWs from `next_free` (data, data, hdr).
            unsafe { crate::hw::flash::write_journal_qw(idx, r) }
                .map_err(|_| FirstBootError::JournalWriteFailed)?;
            idx += 1;
        }
        Ok(())
    }

    fn otp_master_burned(&self) -> bool {
        crate::hw::otp::is_device_master_burned()
    }

    fn saes_alive(&self) -> bool {
        crate::hw::saes::self_test().is_ok()
    }

    fn bhk_provision_and_lock(&mut self) -> Result<(), FirstBootError> {
        // Anti-pre-plant (#36 hardening #2): erase page 126 UNCONDITIONALLY so
        // a known BHK planted at RDP-0 (which survives RDP 0→2, no mass-erase)
        // is destroyed before we provision a fresh TRNG BHK. `bhk::provision`
        // refuses a non-blank page, so the erase must precede it.
        const BHK_PAGE: u32 = 126; // = bhk::BHK_PAGE_NUM (wrapped BHK store)
        // SAFETY: single-threaded secure world; page 126 is the BHK store.
        unsafe {
            crate::hw::flash::erase_secure_page(BHK_PAGE)
                .map_err(|_| FirstBootError::BhkPageHostile)?;
            crate::hw::bhk::provision().map_err(|_| FirstBootError::BhkProvisionFailed)?;
            crate::hw::bhk::load_and_lock().map_err(|_| FirstBootError::BhkProvisionFailed)?;
        }
        Ok(())
    }

    fn se050_rotate_scp03(&mut self) -> Result<(), FirstBootError> {
        self.se
            .se050
            .rotate_scp03_transport_to_final()
            .map_err(|_| FirstBootError::Se050EstablishFailed)
    }

    fn se050_rekey_admin(&mut self) -> Result<(), FirstBootError> {
        self.se
            .se050
            .rekey_admin_transport_to_final()
            .map_err(|_| FirstBootError::Se050AdminRekeyFailed)
    }

    fn trng_salt(&mut self) -> Result<[u8; 32], FirstBootError> {
        let mut salt = [0u8; 32];
        crate::rng_strong::fill(&mut salt).map_err(|_| FirstBootError::OptigaSaltPersistFailed)?;
        Ok(salt)
    }

    fn optiga_rotate_pbs(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError> {
        self.se
            .optiga
            .rotate_pbs_to_salted(salt)
            .map_err(|_| FirstBootError::OptigaSetDataFailed)
    }

    fn ui_step(&mut self, _step: FirstBootStep, resuming: bool) {
        if resuming {
            crate::ui::show_status("RECOVERING", "DO NOT POWER OFF");
        } else {
            crate::ui::show_status("FIRST BOOT SETUP", "DO NOT POWER OFF");
        }
    }
}

/// **Phase B** (work-todo #36): post-lock, journaled, resumable provisioning.
/// Runs after the RDP-2 self-lock, BEFORE first PIN entry / the seed wizard.
/// A completed ceremony (journal `ALL_DONE`) returns immediately; otherwise it
/// resumes the state machine and either completes or halts on a numbered RMA.
#[cfg(all(not(test), feature = "rdp2-self-lock", feature = "dual-se"))]
pub fn run_post_lock_provisioning(se: &mut crate::dual_se::DualSecureElement) {
    let js = journal::scan(journal_page());
    if js.all_done() {
        return;
    }

    // Resume-load the BHK: if the BHK step already committed on a prior boot
    // but the whole ceremony hasn't (so the every-boot BHK block in `main` is
    // still gated OFF), the BHK is on flash but NOT yet loaded into the TAMP
    // backup registers this boot — and step 3 derives BHK-rooted SE050 keys.
    // Load + lock it now (exactly once per boot; step 2 owns the first-time
    // provision, so these two paths never both run in one boot).
    if js.has(journal::DONE_BHK) {
        // SAFETY: BHK was provisioned on a prior boot; load into TAMP + lock.
        if unsafe { crate::hw::bhk::load_and_lock() }.is_err() {
            halt_first_boot(FirstBootError::BhkProvisionFailed);
        }
    }

    let mut hw = FirstBootHwImpl { se };
    if let Err(fault) = state::run(&mut hw) {
        halt_first_boot(fault.code);
    }
    // Ok → journal ALL_DONE; boot continues to the seed wizard.
}
