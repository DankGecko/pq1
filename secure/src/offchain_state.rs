//! Feature-agnostic facade over per-slot off-chain sig counter storage.
//!
//! On real STM32U585 hardware (`stm32u585` feature present, where
//! `crate::hw::flash` is available) every call routes
//! into the flash-backed log-structured store on bank-1 page 123 — the
//! durable, power-loss-tolerant implementation. On QEMU and other host
//! / non-flash builds the calls go to a SRAM-backed mock that lives in
//! a single static, zeroised on power cycle. The mock has the same
//! externally visible semantics (monotonic counters, slot registration,
//! gap enforcement) so the gateway commands and tests do not need to
//! know which backend is active.
//!
//! Why a facade and not a direct cfg-flag inside `hw::flash`? The `hw`
//! module itself is feature-gated (`#[cfg(feature = "stm32u585")]`),
//! so `crate::hw::flash` simply does not exist on a default QEMU build.
//! Touching `crate::hw::*` directly from `crate::nsc::cmd_sign_*` would
//! force every QEMU build to also enable an unrelated hardware
//! feature. Routing through this thin shim keeps the gateway path
//! buildable on every config the project supports.

/// Compute the 8-byte flash key for a `(account_index, chain_id, slot_index)`
/// tuple.
pub fn slot_key_compute(account_index: u8, chain_id: u64, slot_index: u32) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([account_index]);
    h.update(chain_id.to_be_bytes());
    h.update(slot_index.to_be_bytes());
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

/// Hard cap on the number of **distinct** slot keys the per-slot off-chain
/// journal will ever create. A brand-new slot is refused once this many are
/// already live; updates to an *already-present* slot are always allowed.
///
/// **Why this exists (page-123 exhaustion → permanent-brick fix; see
/// `docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md`).** The flash backend
/// stores the journal as a log on a single 512-quad-word page (`OFFCHAIN_CAPACITY`
/// in `hw::flash`). Compaction (`hw::flash::compact_page`) *fail-closes* — by the
/// HIGH-1/F3 anti-rollback design it refuses (never erases) — when the page holds
/// more distinct slots than its SRAM projection table (`MAX_ACTIVE_SLOTS = 256`)
/// or when the post-compaction projection would not fit the page. Once that state
/// is reached the page is permanently un-writable, and because *every* sign path
/// writes the page after computing its signature, the device can no longer produce
/// any signature for any slot — a permanent, seed-survivable brick. An untrusted
/// companion could reach it by spraying distinct `(account,chain,slot)` tuples via
/// `CMD_OFFCHAIN_SYNC`.
///
/// **Why 128 is provably un-wedgeable.** A slot occupies at most 3 quad-words after
/// compaction (one each COUNT / USEROP / USEROP_SIGS). Capping distinct slots at
/// `D` guarantees compaction can never fail iff `D * 3 <= 512` (replay space) **and**
/// `D <= 256` (projection table). `128 * 3 = 384 <= 512` (≥128 QW of headroom) and
/// `128 <= 256`, so compaction is impossible to wedge by construction. 128 also
/// matches the host/QEMU mock backend's table size, so both backends enforce the
/// identical numeric budget. The structural maximum is 170 (`170 * 3 = 510 <= 512`).
///
/// This is a **device-lifetime** budget on distinct tuples ever used — slots are
/// never evicted (`userop_sigs` is non-evictable; evicting it would reset the
/// few-time-key margin, weakening HIGH-1/F3). At the cap, new-slot creation fails
/// *gracefully* (existing slots keep signing; no brick).
pub const MAX_DISTINCT_SLOTS: usize = 128;

/// Policy decision shared by both storage backends: may a durable write that
/// would create a **new** distinct slot proceed?
///
/// `already_present` ⇒ always `true` (an update to a known slot never grows the
/// distinct-slot set, so it can never push the page toward the un-compactable
/// state). Otherwise it is allowed only while `distinct_live < MAX_DISTINCT_SLOTS`.
/// Pure and host-testable; the flash `write_entry` chokepoint and the mock backend
/// both gate new-slot creation through it (see [`MAX_DISTINCT_SLOTS`]).
#[must_use]
pub fn may_create_distinct_slot(distinct_live: usize, already_present: bool) -> bool {
    already_present || distinct_live < MAX_DISTINCT_SLOTS
}

/// Physical page-123 capacity in 16-byte quad-words.
///
/// This mirrors `hw::flash::OFFCHAIN_CAPACITY`. Keeping the value public here
/// lets the host backend and the forced-path preflight apply the same bound
/// without making the hardware-only flash module part of the host build.
#[cfg(any(feature = "erc7730-forced-blind", test))]
pub const OFFCHAIN_CAPACITY_QWS: usize = 512;

/// Maximum number of page-123 appends made by one steady-state forced Type-2
/// path. Depending on the relative COUNT/USEROP high-water marks the first
/// append is either a COUNT promotion or a USEROP update; the second is the
/// durable USEROP_SIGS tally.
#[cfg(any(feature = "erc7730-forced-blind", test))]
pub const FORCED_CAPACITY_REQUIRED_APPENDS: usize = 2;

#[cfg(any(feature = "erc7730-forced-blind", test))]
const FORCED_CAPACITY_DOMAIN: &[u8] = b"PQSigner/forced-blind/page123-capacity/v1";

#[cfg(feature = "erc7730-forced-blind")]
const CFI_CAPACITY_SNAPSHOT_A: u32 = 0x6E25_A94C;
#[cfg(feature = "erc7730-forced-blind")]
const CFI_CAPACITY_SNAPSHOT_B: u32 = 0xB1DA_56C3;
#[cfg(feature = "erc7730-forced-blind")]
const CFI_CAPACITY_SNAPSHOT_AGREE: u32 = 0x43F7_C218;
#[cfg(feature = "erc7730-forced-blind")]
const CFI_CAPACITY_RECEIPT_A: u32 = 0x9C18_75E2;
#[cfg(feature = "erc7730-forced-blind")]
const CFI_CAPACITY_RECEIPT_B: u32 = 0x27E4_8B5D;
#[cfg(feature = "erc7730-forced-blind")]
const CFI_CAPACITY_RECEIPT_AGREE: u32 = 0xD85B_34A1;
#[cfg(feature = "erc7730-forced-blind")]
const CFI_CAPACITY_VERDICT: u32 = 0x51A6_ED97;
#[cfg(feature = "erc7730-forced-blind")]
const CFI_CAPACITY_PUBLISH: u32 = 0xAE59_1268;
#[cfg(feature = "erc7730-forced-blind")]
pub(crate) const CFI_FORCED_CAPACITY_EXPECTED: u32 = crate::cfi_expected!(
    CFI_CAPACITY_SNAPSHOT_A,
    CFI_CAPACITY_SNAPSHOT_B,
    CFI_CAPACITY_SNAPSHOT_AGREE,
    CFI_CAPACITY_RECEIPT_A,
    CFI_CAPACITY_RECEIPT_B,
    CFI_CAPACITY_RECEIPT_AGREE,
    CFI_CAPACITY_VERDICT,
    CFI_CAPACITY_PUBLISH,
);

/// A complete, read-only projection of page 123 used by the forced-flow
/// capacity gate. The backend must derive this from one full scan; it must not
/// repair, compact, erase, or append while producing the snapshot.
#[cfg(any(feature = "erc7730-forced-blind", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForcedCapacitySnapshot {
    /// Exact digest of the backend state that produced this projection.
    pub state_sha256: [u8; 32],
    /// Number of distinct live slot keys in the complete projection.
    pub distinct_live: usize,
    /// Number of QWs a safe compaction would replay.
    pub projected_live_qws: usize,
    /// Number of currently erased QWs available without compaction.
    pub blank_qws: usize,
    /// Whether the requested slot is already present.
    pub slot_present: bool,
}

/// Fail-closed reasons returned by the forced page-123 capacity preflight.
#[cfg(any(feature = "erc7730-forced-blind", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForcedCapacityError {
    /// The hardware journal was non-canonical, corrupt, or could not be fully
    /// projected without losing state.
    InvalidProjection,
    /// Two independently initialized read-only scans disagreed.
    SnapshotDisagreement,
    /// Forced steady-state Type-2 signing cannot create slot registration.
    /// The normal Type-1 rotation path must have registered the slot first.
    SlotUnregistered,
    /// The forced commit would need page-123 compaction. Forced signing
    /// refuses this until the journal has crash-atomic compaction.
    CompactionRequired,
    /// The projected live set plus both reserved writes exceeds page geometry.
    InsufficientCapacity,
}

/// Request-bound evidence that page 123 can accept the complete forced
/// steady-state commit sequence.
///
/// The receipt deliberately contains no self-authorizing boolean. A caller
/// gets a value only after the full projection and exact capacity relations
/// pass. Re-running [`forced_capacity_preflight`] immediately before signing
/// must reproduce this value byte-for-byte for the same request digest.
#[cfg(any(feature = "erc7730-forced-blind", test))]
#[derive(Debug, Eq, PartialEq)]
pub struct ForcedCapacityReceipt {
    request_digest: [u8; 32],
    state_sha256: [u8; 32],
    receipt_sha256: [u8; 32],
    distinct_live: u16,
    projected_live_qws: u16,
    blank_qws: u16,
    slot_present: u8,
    requires_compaction: u8,
}

#[cfg(any(feature = "erc7730-forced-blind", test))]
impl ForcedCapacityReceipt {
    #[must_use]
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    #[must_use]
    pub const fn state_sha256(&self) -> &[u8; 32] {
        &self.state_sha256
    }

    #[must_use]
    pub const fn receipt_sha256(&self) -> &[u8; 32] {
        &self.receipt_sha256
    }

    #[must_use]
    pub const fn distinct_live(&self) -> u16 {
        self.distinct_live
    }

    #[must_use]
    pub const fn projected_live_qws(&self) -> u16 {
        self.projected_live_qws
    }

    #[must_use]
    pub const fn blank_qws(&self) -> u16 {
        self.blank_qws
    }

    #[must_use]
    pub const fn slot_present(&self) -> bool {
        self.slot_present == 1
    }

    #[must_use]
    pub const fn requires_compaction(&self) -> bool {
        self.requires_compaction == 1
    }
}

/// FI-hardened equality proof for the two independent final USEROP_SIGS
/// reads performed after every page-123 mutation in the forced path.
///
/// Kept beside the host-testable counter policy so rollback, disagreement,
/// inflation, and corrupt-read sentinels exercise the exact production
/// predicate rather than a test-only mirror.
#[cfg(any(feature = "erc7730-forced-blind", test))]
#[inline(never)]
pub fn forced_final_tally_pair_proof(expected: u64, tally_a: u64, tally_b: u64) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(tally_a) == core::hint::black_box(expected)
            && core::hint::black_box(tally_b) == core::hint::black_box(expected)
            && core::hint::black_box(tally_a) != u64::MAX
    })
}

/// Validate one complete projection and bind it to one forced request.
///
/// This is kept pure so the exact 127/128 distinct-slot and 510/511 projected-
/// QW boundaries are executable on the host. The production entry point below
/// first requires two identical backend snapshots.
#[cfg(any(feature = "erc7730-forced-blind", test))]
pub fn forced_capacity_receipt_from_snapshot(
    slot_key: &[u8; 8],
    request_digest: &[u8; 32],
    snapshot: ForcedCapacitySnapshot,
) -> Result<ForcedCapacityReceipt, ForcedCapacityError> {
    use sha2::{Digest, Sha256};

    if snapshot.distinct_live > MAX_DISTINCT_SLOTS
        || snapshot.projected_live_qws > OFFCHAIN_CAPACITY_QWS
        || snapshot.blank_qws > OFFCHAIN_CAPACITY_QWS
    {
        return Err(ForcedCapacityError::InvalidProjection);
    }
    if !snapshot.slot_present {
        return Err(ForcedCapacityError::SlotUnregistered);
    }
    let projected_after = snapshot
        .projected_live_qws
        .checked_add(FORCED_CAPACITY_REQUIRED_APPENDS)
        .ok_or(ForcedCapacityError::InsufficientCapacity)?;
    if projected_after > OFFCHAIN_CAPACITY_QWS {
        return Err(ForcedCapacityError::InsufficientCapacity);
    }

    let requires_compaction = snapshot.blank_qws < FORCED_CAPACITY_REQUIRED_APPENDS;
    if requires_compaction {
        return Err(ForcedCapacityError::CompactionRequired);
    }
    let distinct_live = u16::try_from(snapshot.distinct_live)
        .map_err(|_| ForcedCapacityError::InvalidProjection)?;
    let projected_live_qws = u16::try_from(snapshot.projected_live_qws)
        .map_err(|_| ForcedCapacityError::InvalidProjection)?;
    let blank_qws =
        u16::try_from(snapshot.blank_qws).map_err(|_| ForcedCapacityError::InvalidProjection)?;
    let slot_present = u8::from(snapshot.slot_present);
    let requires_compaction_u8 = u8::from(requires_compaction);

    let mut hash = Sha256::new();
    hash.update(FORCED_CAPACITY_DOMAIN);
    hash.update(request_digest);
    hash.update(slot_key);
    hash.update(snapshot.state_sha256);
    hash.update(distinct_live.to_be_bytes());
    hash.update(projected_live_qws.to_be_bytes());
    hash.update(blank_qws.to_be_bytes());
    hash.update([slot_present, requires_compaction_u8]);
    hash.update((FORCED_CAPACITY_REQUIRED_APPENDS as u16).to_be_bytes());
    let mut receipt_sha256 = [0u8; 32];
    receipt_sha256.copy_from_slice(&hash.finalize());

    Ok(ForcedCapacityReceipt {
        request_digest: *request_digest,
        state_sha256: snapshot.state_sha256,
        receipt_sha256,
        distinct_live,
        projected_live_qws,
        blank_qws,
        slot_present,
        requires_compaction: requires_compaction_u8,
    })
}

/// Obtain two independent full read-only page-123 projections and mint the
/// request-bound forced-capacity receipt only when they agree exactly.
///
/// The caller must volatile-initialize `verdict_out` to FAIL and independently
/// require both an OK verdict and [`CFI_FORCED_CAPACITY_EXPECTED`]. Returning a
/// receipt is not authority by itself. Snapshot agreement and the final
/// request-bound receipt are each redundantly checked before volatile
/// publication.
///
/// # Safety
///
/// The flash backend performs volatile reads from the secure page-123 mapping.
/// The mock backend reads its process-global SRAM table. Neither backend writes
/// state. The caller must serialize this with page-123 mutators, as all current
/// synchronous NSC handlers already do.
#[cfg(feature = "erc7730-forced-blind")]
#[inline(never)]
pub unsafe fn forced_capacity_preflight(
    slot_key: &[u8; 8],
    request_digest: &[u8; 32],
    verdict_out: &mut u32,
    cfi: &mut crate::fi::CfiCounter,
) -> Result<ForcedCapacityReceipt, ForcedCapacityError> {
    let first = unsafe { backend::forced_capacity_snapshot(slot_key)? };
    cfi.bump(CFI_CAPACITY_SNAPSHOT_A);
    crate::fi::wait_random();
    let second = unsafe { backend::forced_capacity_snapshot(slot_key)? };
    cfi.bump(CFI_CAPACITY_SNAPSHOT_B);
    let snapshots_agree = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(first) == core::hint::black_box(second)
    });
    cfi.bump(CFI_CAPACITY_SNAPSHOT_AGREE);

    let receipt_a = forced_capacity_receipt_from_snapshot(slot_key, request_digest, first)?;
    cfi.bump(CFI_CAPACITY_RECEIPT_A);
    crate::fi::wait_random();
    let receipt_b = forced_capacity_receipt_from_snapshot(
        core::hint::black_box(slot_key),
        core::hint::black_box(request_digest),
        core::hint::black_box(second),
    )?;
    cfi.bump(CFI_CAPACITY_RECEIPT_B);
    let receipts_agree = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(&receipt_a) == core::hint::black_box(&receipt_b)
    });
    cfi.bump(CFI_CAPACITY_RECEIPT_AGREE);

    let verdict = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(snapshots_agree) == crate::fi::OK_SENTINEL
            && core::hint::black_box(receipts_agree) == crate::fi::OK_SENTINEL
    });
    cfi.bump(CFI_CAPACITY_VERDICT);
    // SAFETY: `verdict_out` is a unique valid mutable reference supplied by
    // the caller. Volatile publication keeps the caller readback independent
    // from this function's local SSA verdict.
    unsafe { core::ptr::write_volatile(verdict_out, verdict) };
    cfi.bump(CFI_CAPACITY_PUBLISH);

    if verdict == crate::fi::OK_SENTINEL {
        Ok(receipt_a)
    } else {
        Err(ForcedCapacityError::SnapshotDisagreement)
    }
}

/// Hard ceiling on any per-slot off-chain counter a durable write may store.
///
/// **Why this exists (value-inflation → consent-free durable slot brick; see
/// `docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md`).** The untrusted
/// companion supplies the `target_count` written to `last_userop` by
/// `CMD_OFFCHAIN_SYNC`, and that value is promoted verbatim into the monotonic
/// `offchain` counter by the sign paths' repair branch
/// (`offchain_count_promote_to`). The combined-cap gates
/// (`cmd_sign_userop`/`cmd_sign_offchain`) refuse **every** future signature for
/// a slot once `userop_sigs + offchain >= MAX_SLOT_USES`. Because the counters are
/// monotonic with no reset path (invariant #7) and the flash key is seed-
/// independent, an un-clamped write of `>= MAX_SLOT_USES` is a **permanent,
/// seed-survivable, consent-free brick** of that slot. Clamping every durable
/// write to this ceiling makes that state unreachable: a clamped counter always
/// leaves the slot with at least one usable signature, so reaching the cap
/// requires a real, user-confirmed signature — never a bare sync APDU.
///
/// **Why `MAX_SLOT_USES - 1` is exactly right (never rejects a legitimate sync).**
/// The on-chain combined cap is strict — `slotUses + offchainSigCount < MAX_SLOT_USES`
/// (invariant #7) — so a truthful on-chain `offchainSigCount` (the only value a
/// legitimate sync mirrors) can never exceed `MAX_SLOT_USES - 1`. The clamp
/// therefore only ever clips a value the chain itself would reject, and is a
/// no-op for every honest flow. At the ceiling the slot is still signable (both
/// gates admit `offchain <= MAX_SLOT_USES - 1`); one more real signature reaches
/// the legitimate exhausted state at `MAX_SLOT_USES`.
pub const OFFCHAIN_COUNT_CEILING: u64 = sphincs_tz_shared::MAX_SLOT_USES - 1;

/// Clamp a companion- or snapshot-supplied off-chain counter to
/// [`OFFCHAIN_COUNT_CEILING`]. Single source of truth for the value-inflation
/// brick defence: every durable writer of the `offchain` / `last_userop`
/// counters funnels through this so a single missed site cannot re-open the hole
/// (defence in depth — the source-side clamp in `cmd_offchain_sync`, the two
/// flash setters, and both mock-backend setters all call it). Pure and
/// host-testable.
#[inline]
#[must_use]
pub const fn clamp_offchain_count(count: u64) -> u64 {
    if count > OFFCHAIN_COUNT_CEILING {
        OFFCHAIN_COUNT_CEILING
    } else {
        count
    }
}

#[cfg(feature = "stm32u585")]
mod backend {
    pub unsafe fn offchain_count_read(slot_key: &[u8; 8]) -> u64 {
        crate::hw::flash::offchain_count_read(slot_key)
    }
    pub unsafe fn last_userop_count_read(slot_key: &[u8; 8]) -> u64 {
        crate::hw::flash::last_userop_count_read(slot_key)
    }
    pub unsafe fn offchain_count_is_registered(slot_key: &[u8; 8]) -> bool {
        crate::hw::flash::offchain_count_is_registered(slot_key)
    }
    pub unsafe fn offchain_count_register_slot(slot_key: &[u8; 8]) -> Result<(), ()> {
        crate::hw::flash::offchain_count_register_slot(slot_key)
    }
    pub unsafe fn offchain_count_bump(slot_key: &[u8; 8], new_count: u64) -> Result<(), ()> {
        crate::hw::flash::offchain_count_bump(slot_key, new_count)
    }
    pub unsafe fn offchain_count_promote_to(
        slot_key: &[u8; 8],
        target: u64,
    ) -> Result<(), ()> {
        crate::hw::flash::offchain_count_promote_to(slot_key, target)
    }
    pub unsafe fn last_userop_count_set(slot_key: &[u8; 8], count: u64) -> Result<(), ()> {
        crate::hw::flash::last_userop_count_set(slot_key, count)
    }
    pub unsafe fn userop_sigs_read(slot_key: &[u8; 8]) -> u64 {
        crate::hw::flash::userop_sigs_read(slot_key)
    }
    pub unsafe fn userop_sigs_bump(slot_key: &[u8; 8], new_count: u64) -> Result<(), ()> {
        crate::hw::flash::userop_sigs_bump(slot_key, new_count)
    }

    #[cfg(feature = "erc7730-forced-blind")]
    pub unsafe fn forced_capacity_snapshot(
        slot_key: &[u8; 8],
    ) -> Result<super::ForcedCapacitySnapshot, super::ForcedCapacityError> {
        // SAFETY: the facade's caller serializes this read-only page scan with
        // all page-123 writers.
        unsafe { crate::hw::flash::forced_capacity_snapshot(slot_key) }
    }
}

#[cfg(not(feature = "stm32u585"))]
mod backend {
    //! SRAM-backed mock used by QEMU. Storage is a fixed-size table of
    //! `(slot_key, offchain, last_userop, userop_sigs)` records. Lost on
    //! power cycle, which exactly mirrors the seed-restore semantics —
    //! a fresh-from-seed firmware has no flash record of any slot.
    //!
    //! **F13:** registration is derived from RECORD EXISTENCE (`find().is_some()`),
    //! not a separate `registered` flag. In production flash a slot is
    //! "registered" iff any page-123 journal entry exists for it, and EVERY
    //! value-write (`bump`/`promote_to`/`last_userop_count_set`/
    //! `userop_sigs_bump`) creates such an entry. The pre-F13 mock set
    //! `registered` only on an explicit `register_slot` call, so a value-write
    //! that registers the slot in flash left the mock reporting unregistered —
    //! a host-vs-flash drift that let invariant-#9 host tests pass where
    //! production would behave differently. Deriving from `used` removes that
    //! drift. Tests that want to simulate a recovery call
    //! `crate::offchain_state::reset_for_test()`.

    // Table size IS the distinct-slot cap on this backend: `allocate` (only
    // reached for an absent slot) returns `None` once every entry is `used`,
    // so a brand-new slot is refused at exactly `MAX_DISTINCT_SLOTS` distinct
    // keys while updates to existing slots still succeed — the same numeric
    // budget the flash backend enforces via `may_create_distinct_slot`. Single
    // source of truth: [`super::MAX_DISTINCT_SLOTS`].
    const MAX_SLOTS: usize = super::MAX_DISTINCT_SLOTS;

    #[derive(Clone, Copy)]
    struct Entry {
        slot_key: [u8; 8],
        offchain: u64,
        last_userop: u64,
        userop_sigs: u64,
        used: bool,
    }

    static mut TABLE: [Entry; MAX_SLOTS] = [Entry {
        slot_key: [0u8; 8],
        offchain: 0,
        last_userop: 0,
        userop_sigs: 0,
        used: false,
    }; MAX_SLOTS];

    unsafe fn find(slot_key: &[u8; 8]) -> Option<usize> {
        let table = &*core::ptr::addr_of!(TABLE);
        for (i, e) in table.iter().enumerate() {
            if e.used && &e.slot_key == slot_key {
                return Some(i);
            }
        }
        None
    }

    unsafe fn allocate(slot_key: &[u8; 8]) -> Option<usize> {
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        for (i, e) in table.iter_mut().enumerate() {
            if !e.used {
                e.slot_key = *slot_key;
                e.offchain = 0;
                e.last_userop = 0;
                e.userop_sigs = 0;
                e.used = true;
                return Some(i);
            }
        }
        None
    }

    pub unsafe fn offchain_count_read(slot_key: &[u8; 8]) -> u64 {
        match find(slot_key) {
            Some(i) => (*core::ptr::addr_of!(TABLE))[i].offchain,
            None => 0,
        }
    }

    pub unsafe fn last_userop_count_read(slot_key: &[u8; 8]) -> u64 {
        match find(slot_key) {
            Some(i) => (*core::ptr::addr_of!(TABLE))[i].last_userop,
            None => 0,
        }
    }

    pub unsafe fn offchain_count_is_registered(slot_key: &[u8; 8]) -> bool {
        // F13: registration == record existence, matching production flash
        // (any page-123 journal entry => registered). Every value-write
        // allocates an entry, so this reports the same truth flash would.
        find(slot_key).is_some()
    }

    pub unsafe fn offchain_count_register_slot(slot_key: &[u8; 8]) -> Result<(), ()> {
        // F13: registering just ensures an entry exists (the production journal
        // would gain a record); existence is what `is_registered` reads.
        match find(slot_key) {
            Some(_) => Ok(()),
            None => allocate(slot_key).map(|_| ()).ok_or(()),
        }
    }

    pub unsafe fn offchain_count_bump(slot_key: &[u8; 8], new_count: u64) -> Result<(), ()> {
        let idx = match find(slot_key) {
            Some(i) => i,
            None => allocate(slot_key).ok_or(())?,
        };
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        if new_count <= table[idx].offchain {
            return Err(());
        }
        table[idx].offchain = new_count;
        Ok(())
    }

    /// Mirror of `flash::offchain_count_promote_to` — set the per-slot
    /// off-chain counter to at least `target`. Idempotent.
    pub unsafe fn offchain_count_promote_to(
        slot_key: &[u8; 8],
        target: u64,
    ) -> Result<(), ()> {
        // Value-inflation brick defence: clamp before storing, mirroring the
        // flash backend (see `super::OFFCHAIN_COUNT_CEILING`).
        let target = super::clamp_offchain_count(target);
        let idx = match find(slot_key) {
            Some(i) => i,
            None => allocate(slot_key).ok_or(())?,
        };
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        if target > table[idx].offchain {
            table[idx].offchain = target;
        }
        Ok(())
    }

    pub unsafe fn last_userop_count_set(slot_key: &[u8; 8], count: u64) -> Result<(), ()> {
        // Value-inflation brick defence: clamp the companion-supplied floor
        // before storing, mirroring the flash backend (see
        // `super::OFFCHAIN_COUNT_CEILING`).
        let count = super::clamp_offchain_count(count);
        let idx = match find(slot_key) {
            Some(i) => i,
            None => allocate(slot_key).ok_or(())?,
        };
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        // Tolerant of `count < last_userop`: no-op rather than error,
        // mirroring the flash-backed semantics so a stale caller
        // cannot brick the slot.
        if count > table[idx].last_userop {
            table[idx].last_userop = count;
        }
        Ok(())
    }

    /// Mirror of `flash::userop_sigs_read` (MEDIUM-2).
    pub unsafe fn userop_sigs_read(slot_key: &[u8; 8]) -> u64 {
        match find(slot_key) {
            Some(i) => (*core::ptr::addr_of!(TABLE))[i].userop_sigs,
            None => 0,
        }
    }

    /// Mirror of `flash::userop_sigs_bump` (MEDIUM-2). Monotonic: `Err`
    /// if `new_count <= current` so the caller's `current + 1` only fails
    /// on a logic error.
    pub unsafe fn userop_sigs_bump(slot_key: &[u8; 8], new_count: u64) -> Result<(), ()> {
        let idx = match find(slot_key) {
            Some(i) => i,
            None => allocate(slot_key).ok_or(())?,
        };
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        if new_count <= table[idx].userop_sigs {
            return Err(());
        }
        table[idx].userop_sigs = new_count;
        Ok(())
    }

    #[cfg(any(feature = "erc7730-forced-blind", test))]
    pub unsafe fn forced_capacity_snapshot(
        slot_key: &[u8; 8],
    ) -> Result<super::ForcedCapacitySnapshot, super::ForcedCapacityError> {
        use sha2::{Digest, Sha256};

        let table = unsafe { &*core::ptr::addr_of!(TABLE) };
        let mut state = Sha256::new();
        state.update(b"PQSigner/offchain-state/mock-capacity/v1");
        let mut distinct_live = 0usize;
        let mut slot_present = false;
        for entry in table {
            state.update([u8::from(entry.used)]);
            state.update(entry.slot_key);
            state.update(entry.offchain.to_be_bytes());
            state.update(entry.last_userop.to_be_bytes());
            state.update(entry.userop_sigs.to_be_bytes());
            if entry.used {
                distinct_live += 1;
                slot_present |= &entry.slot_key == slot_key;
            }
        }
        if distinct_live > super::MAX_DISTINCT_SLOTS {
            return Err(super::ForcedCapacityError::InvalidProjection);
        }

        // The SRAM backend has no append log. Model its safe compacted image
        // conservatively as all three possible QWs per live slot; this is the
        // same upper bound used to select MAX_DISTINCT_SLOTS and never grants
        // more capacity than the hardware projection.
        let projected_live_qws = distinct_live
            .checked_mul(3)
            .ok_or(super::ForcedCapacityError::InvalidProjection)?;
        let blank_qws = super::OFFCHAIN_CAPACITY_QWS
            .checked_sub(projected_live_qws)
            .ok_or(super::ForcedCapacityError::InvalidProjection)?;
        let mut state_sha256 = [0u8; 32];
        state_sha256.copy_from_slice(&state.finalize());
        Ok(super::ForcedCapacitySnapshot {
            state_sha256,
            distinct_live,
            projected_live_qws,
            blank_qws,
            slot_present,
        })
    }

    /// Test-only: clear the SRAM mock to simulate a power cycle / seed
    /// restoration. Never compiled into a real firmware — guarded by
    /// `e2e-test`.
    #[cfg(feature = "e2e-test")]
    pub unsafe fn reset_for_test() {
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        for e in table.iter_mut() {
            *e = Entry {
                slot_key: [0u8; 8],
                offchain: 0,
                last_userop: 0,
                userop_sigs: 0,
                used: false,
            };
        }
    }
}

pub use backend::*;
