//! Terminal forced-blind branch for `CMD_SIGN_USEROP`.
//!
//! This module is reachable only from the direct, steady-state Type-2 handler
//! after that handler has completed its ordinary wire, EntryPoint, sender,
//! trailer, Safe, and CoW classification.  It never participates in batch,
//! off-chain, EIP-712, deployment, or rotation commands.
//!
//! The branch is deliberately terminal: affirmative exact membership in the
//! firmware-embedded refused-known P73K set enters one fixed raw ceremony and
//! returns from the command.  No failure below may fall back to an ordinary
//! renderer or a weaker signing route.

use sphincs_tz_shared::{
    NscStatus, APPROVE_HASH_SELECTOR, EXEC_TRANSACTION_SELECTOR, GPV2_SETTLEMENT_ADDRESS,
    MAX_SIGN_RESPONSE_LEN, MULTISEND_CALL_ONLY_ADDRESSES, MULTI_SEND_SELECTOR,
    SET_PRE_SIGNATURE_SELECTOR, SIG_WRAPPER_LEN,
};
use zeroize::{Zeroize, Zeroizing};

use super::ptr_validate::validate_ns_write_ptr;
use super::state::{CachedSlot, ForcedAttemptPhase};
use super::{GatewayArgs, SIGN_SNAP_BUF};
use crate::aa::userop::{
    compute_sphincs_digest_v06, reconstruct_execute_calldata, sha256_bytes,
    AaUserOpParamsV06Sha256, ENTRY_POINT_V06, SHA256_EMPTY,
};
use crate::tx::display::forced_blind::{
    consume_forced_receipts_once, forced_transcript_proof, render_forced_transcript, FinalReceipt,
    ForcedTranscriptInput, WarningReceipt, FORCED_TRANSCRIPT_PAGES, FORCED_WARNING_PAGES,
};
use crate::tx::eip1559::{Eip1559Tx, U256};

/// Exact fixed response for a steady Type-2 forced sign:
/// count(8) || init_len(4=0) || type1_len(4=0) ||
/// type2_len(4=4128) || type2_wrapper(4128).
pub(super) const FORCED_SIGN_RESPONSE_LEN: usize = 8 + 4 + 4 + 4 + SIG_WRAPPER_LEN;
const _: () = assert!(FORCED_SIGN_RESPONSE_LEN == 4_148);
const _: () = assert!(FORCED_SIGN_RESPONSE_LEN <= MAX_SIGN_RESPONSE_LEN);

const CFI_PREFLIGHT_ELIGIBILITY: u32 = 0x19A7_4C32;
const CFI_PREFLIGHT_COUNTERS: u32 = 0xE658_B3CD;
const CFI_PREFLIGHT_DIGEST: u32 = 0x42D9_71A6;
const CFI_PREFLIGHT_CAPACITY: u32 = 0xBD26_8E59;
const CFI_PREFLIGHT_KEY: u32 = 0x73C4_1AF0;
const CFI_PREFLIGHT_RATE: u32 = 0x8C3B_E50F;
const CFI_PREFLIGHT_TRANSCRIPT: u32 = 0x2E91_D647;
const CFI_ATTEMPT_CHARGED: u32 = 0xD16E_29B8;
const CFI_WARNING_RECEIPT: u32 = 0x57A3_C18D;
const CFI_FINAL_RECEIPT: u32 = 0xA85C_3E72;
const CFI_RECHECK_ELIGIBILITY: u32 = 0x34F2_8B61;
const CFI_RECHECK_COUNTERS: u32 = 0xCB0D_749E;
const CFI_RECHECK_DIGEST: u32 = 0x6D58_A2C7;
const CFI_RECHECK_CAPACITY: u32 = 0x92A7_5D38;
const CFI_RECHECK_RATE: u32 = 0x1BC6_E94A;
const CFI_RECEIPTS_CONSUMED: u32 = 0xE439_16B5;
const CFI_CANDIDATE_CONSUMED: u32 = 0x4F82_D3A9;
const CFI_SIGN_VERIFIED: u32 = 0xB07D_2C56;
const CFI_TALLY_DURABLE: u32 = 0x25E9_87C3;
const CFI_RELEASE_GATE: u32 = 0xDA16_783C;

const CFI_PREWARNING_EXPECTED: u32 = crate::cfi_expected!(
    CFI_PREFLIGHT_ELIGIBILITY,
    CFI_PREFLIGHT_COUNTERS,
    CFI_PREFLIGHT_DIGEST,
    CFI_PREFLIGHT_CAPACITY,
    CFI_PREFLIGHT_KEY,
    CFI_PREFLIGHT_RATE,
    CFI_PREFLIGHT_TRANSCRIPT,
);
const CFI_PRESIGN_EXPECTED: u32 = crate::cfi_expected!(
    CFI_PREFLIGHT_ELIGIBILITY,
    CFI_PREFLIGHT_COUNTERS,
    CFI_PREFLIGHT_DIGEST,
    CFI_PREFLIGHT_CAPACITY,
    CFI_PREFLIGHT_KEY,
    CFI_PREFLIGHT_RATE,
    CFI_PREFLIGHT_TRANSCRIPT,
    CFI_ATTEMPT_CHARGED,
    CFI_WARNING_RECEIPT,
    CFI_FINAL_RECEIPT,
    CFI_RECHECK_ELIGIBILITY,
    CFI_RECHECK_COUNTERS,
    CFI_RECHECK_DIGEST,
    CFI_RECHECK_CAPACITY,
    CFI_RECHECK_RATE,
    CFI_RECEIPTS_CONSUMED,
    CFI_CANDIDATE_CONSUMED,
);
const CFI_PRERELEASE_EXPECTED: u32 = crate::cfi_expected!(
    CFI_PREFLIGHT_ELIGIBILITY,
    CFI_PREFLIGHT_COUNTERS,
    CFI_PREFLIGHT_DIGEST,
    CFI_PREFLIGHT_CAPACITY,
    CFI_PREFLIGHT_KEY,
    CFI_PREFLIGHT_RATE,
    CFI_PREFLIGHT_TRANSCRIPT,
    CFI_ATTEMPT_CHARGED,
    CFI_WARNING_RECEIPT,
    CFI_FINAL_RECEIPT,
    CFI_RECHECK_ELIGIBILITY,
    CFI_RECHECK_COUNTERS,
    CFI_RECHECK_DIGEST,
    CFI_RECHECK_CAPACITY,
    CFI_RECHECK_RATE,
    CFI_RECEIPTS_CONSUMED,
    CFI_CANDIDATE_CONSUMED,
    CFI_SIGN_VERIFIED,
    CFI_TALLY_DURABLE,
);
const CFI_RELEASE_EXPECTED: u32 = crate::cfi_expected!(
    CFI_PREFLIGHT_ELIGIBILITY,
    CFI_PREFLIGHT_COUNTERS,
    CFI_PREFLIGHT_DIGEST,
    CFI_PREFLIGHT_CAPACITY,
    CFI_PREFLIGHT_KEY,
    CFI_PREFLIGHT_RATE,
    CFI_PREFLIGHT_TRANSCRIPT,
    CFI_ATTEMPT_CHARGED,
    CFI_WARNING_RECEIPT,
    CFI_FINAL_RECEIPT,
    CFI_RECHECK_ELIGIBILITY,
    CFI_RECHECK_COUNTERS,
    CFI_RECHECK_DIGEST,
    CFI_RECHECK_CAPACITY,
    CFI_RECHECK_RATE,
    CFI_RECEIPTS_CONSUMED,
    CFI_CANDIDATE_CONSUMED,
    CFI_SIGN_VERIFIED,
    CFI_TALLY_DURABLE,
    CFI_RELEASE_GATE,
);

/// Closed result of forced classification.  `ContinueOrdinary` preserves the
/// pre-existing renderer for calls outside F or excluded semantic surfaces;
/// `Fatal` is reserved for a malformed embedded artifact or proof
/// disagreement.  Only `Candidate` enters this module's terminal signer.
pub(super) enum ForcedRoute {
    ContinueOrdinary,
    Candidate(ForcedEligibility),
    Fatal,
}

/// Positive exact-F evidence.  It is intentionally private and non-Copy.
pub(super) struct ForcedEligibility {
    chain_id: u64,
    target: [u8; 20],
    selector: [u8; 4],
}

/// Values already frozen by the direct handler.  There is no host text,
/// descriptor, resolver, selector name, or alternate response mode here.
pub(super) struct ForcedRequest<'a> {
    pub(super) account_index: u32,
    pub(super) slot_index: u32,
    pub(super) sender: [u8; 20],
    pub(super) chain_id: u64,
    pub(super) nonce: [u8; 32],
    pub(super) call_gas_limit: [u8; 32],
    pub(super) verification_gas_limit: [u8; 32],
    pub(super) pre_verification_gas: [u8; 32],
    pub(super) max_fee_per_gas: [u8; 32],
    pub(super) max_priority_fee_per_gas: [u8; 32],
    pub(super) target: [u8; 20],
    pub(super) value: [u8; 32],
    pub(super) tx: &'a Eip1559Tx,
    pub(super) calldata: &'a [u8],
}

/// Determine whether an absent-descriptor request may enter the terminal
/// forced branch.  The caller supplies `clean_metadata_absence` only for an
/// explicit, in-bounds zero-length ERC-7730 field; a missing/truncated field is
/// not authority even though the legacy optional parser continues to accept it
/// for ordinary signing.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(super) fn classify(
    clean_metadata_absence: bool,
    single_steady_type2: bool,
    paymaster_empty: bool,
    safe_or_cow_evidence_present: bool,
    chain_id: u64,
    target: &[u8; 20],
    calldata: &[u8],
) -> ForcedRoute {
    if !clean_metadata_absence || calldata.len() < 4 {
        return ForcedRoute::ContinueOrdinary;
    }

    let selector = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let parsed = match pqsigner_erc7730::forced_eligible::ForcedEligibleSet::from_bytes(
        &crate::db_roots::PQSIGNER_ERC7730_FORCED_ELIGIBLE_SET,
    ) {
        Ok(set) => set,
        Err(_) => return ForcedRoute::Fatal,
    };
    if !parsed.contains(chain_id, target, &selector) {
        return ForcedRoute::ContinueOrdinary;
    }

    // These surfaces may still use their existing richer ordinary renderer,
    // but exact-F membership must never turn them into forced blind.
    let protected_selector = selector == APPROVE_HASH_SELECTOR
        || selector == EXEC_TRANSACTION_SELECTOR
        || selector == SET_PRE_SIGNATURE_SELECTOR
        || selector == MULTI_SEND_SELECTOR;
    let protected_target = *target == GPV2_SETTLEMENT_ADDRESS
        || MULTISEND_CALL_ONLY_ADDRESSES
            .iter()
            .any(|address| address == target);
    if !single_steady_type2
        || !paymaster_empty
        || safe_or_cow_evidence_present
        || protected_selector
        || protected_target
    {
        return ForcedRoute::ContinueOrdinary;
    }

    let mut verdict = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique initialized local.  Volatile fail-in means a skipped
    // proof call cannot inherit an affirmative register value.
    unsafe { core::ptr::write_volatile(&mut verdict, crate::fi::FAIL_SENTINEL) };
    let mut cfi = crate::fi::CfiCounter::new();
    crate::tx::erc7730::prove_forced_eligible_contract_call(
        chain_id,
        target,
        &selector,
        &mut verdict,
        &mut cfi,
    );
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: local remains live and the proof borrow ended.
    let published = unsafe { core::ptr::read_volatile(&verdict) };
    if published != crate::fi::OK_SENTINEL
        || cfi.check_into_sentinel(crate::tx::erc7730::CFI_FORCED_ELIGIBLE_EXPECTED)
            != crate::fi::OK_SENTINEL
    {
        return ForcedRoute::Fatal;
    }

    ForcedRoute::Candidate(ForcedEligibility {
        chain_id,
        target: *target,
        selector,
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CounterSnapshot {
    local_offchain: u64,
    last_userop: u64,
    userop_sigs: u64,
    new_offchain_count: u64,
}

struct ForcedPrepared {
    transcript: ForcedTranscriptInput,
    request_digest: [u8; 32],
    slot_key: [u8; 8],
    counters: CounterSnapshot,
    capacity: crate::offchain_state::ForcedCapacityReceipt,
    rate: crate::sign_rate::ForcedRateReceipt,
}

const CANDIDATE_LIVE: u32 = 0xA6C9_3C53;
const CANDIDATE_CONSUMED: u32 = 0x5936_C3AC;

/// Request-bound, exact-once permit minted only after every deterministic
/// preflight succeeds.  Drop invalidates it on every return path.
struct ForcedCandidate {
    state: u32,
    state_inv: u32,
    eligibility: ForcedEligibility,
    request_digest: [u8; 32],
}

impl ForcedCandidate {
    fn new(eligibility: ForcedEligibility, request_digest: [u8; 32]) -> Self {
        Self {
            state: CANDIDATE_LIVE,
            state_inv: !CANDIDATE_LIVE,
            eligibility,
            request_digest,
        }
    }

    fn digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    #[inline(never)]
    fn consume(&mut self, request_digest: &[u8; 32]) -> u32 {
        let state = unsafe { core::ptr::read_volatile(&self.state) };
        let state_inv = unsafe { core::ptr::read_volatile(&self.state_inv) };
        let mut diff = 0u8;
        for index in 0..32 {
            diff |= self.request_digest[index] ^ request_digest[index];
        }
        if crate::fi::check_true_into_sentinel(|| {
            state == CANDIDATE_LIVE && state_inv == !CANDIDATE_LIVE && diff == 0
        }) != crate::fi::OK_SENTINEL
        {
            return crate::fi::FAIL_SENTINEL;
        }
        unsafe {
            core::ptr::write_volatile(&mut self.state, CANDIDATE_CONSUMED);
            core::ptr::write_volatile(&mut self.state_inv, !CANDIDATE_CONSUMED);
        }
        let state = unsafe { core::ptr::read_volatile(&self.state) };
        let state_inv = unsafe { core::ptr::read_volatile(&self.state_inv) };
        crate::fi::check_true_into_sentinel(|| {
            state == CANDIDATE_CONSUMED && state_inv == !CANDIDATE_CONSUMED
        })
    }
}

impl Drop for ForcedCandidate {
    fn drop(&mut self) {
        unsafe {
            core::ptr::write_volatile(&mut self.state, 0);
            core::ptr::write_volatile(&mut self.state_inv, 0);
            for byte in &mut self.request_digest {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Wipes the shared request snapshot on every terminal forced return.  The
/// outer handler's ordinary success-only cleanup is bypassed by this branch.
struct ForcedCleanup;

impl Drop for ForcedCleanup {
    fn drop(&mut self) {
        // SAFETY: the outer HandlerGuard and single dispatcher make this the
        // sole live sign handler; no peer can access the shared snapshot.
        unsafe {
            let buf = &mut *core::ptr::addr_of_mut!(SIGN_SNAP_BUF);
            for byte in buf.iter_mut() {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[inline(never)]
fn prove_eligibility(eligibility: &ForcedEligibility, request: &ForcedRequest<'_>) -> bool {
    if eligibility.chain_id != request.chain_id
        || eligibility.target != request.target
        || request.calldata.len() < 4
        || eligibility.selector != request.calldata[..4]
    {
        return false;
    }
    let Ok(set) = pqsigner_erc7730::forced_eligible::ForcedEligibleSet::from_bytes(
        &crate::db_roots::PQSIGNER_ERC7730_FORCED_ELIGIBLE_SET,
    ) else {
        return false;
    };
    if !set.contains(request.chain_id, &request.target, &eligibility.selector) {
        return false;
    }

    let mut verdict = crate::fi::FAIL_SENTINEL;
    unsafe { core::ptr::write_volatile(&mut verdict, crate::fi::FAIL_SENTINEL) };
    let mut cfi = crate::fi::CfiCounter::new();
    crate::tx::erc7730::prove_forced_eligible_contract_call(
        request.chain_id,
        &request.target,
        &eligibility.selector,
        &mut verdict,
        &mut cfi,
    );
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let published = unsafe { core::ptr::read_volatile(&verdict) };
    published == crate::fi::OK_SENTINEL
        && cfi.check_into_sentinel(crate::tx::erc7730::CFI_FORCED_ELIGIBLE_EXPECTED)
            == crate::fi::OK_SENTINEL
}

#[inline(never)]
fn prove_candidate_eligibility(candidate: &ForcedCandidate, request: &ForcedRequest<'_>) -> bool {
    prove_eligibility(&candidate.eligibility, request)
}

/// Read-only, independently repeated few-time-key projection.  This function
/// never repairs/promotes the journal; any write before physical consent would
/// make a hostile warning request persistent.
#[inline(never)]
unsafe fn read_counter_snapshot(slot_key: &[u8; 8]) -> Result<CounterSnapshot, NscStatus> {
    let local_a = unsafe { crate::offchain_state::offchain_count_read(slot_key) };
    crate::fi::wait_random();
    let local_b = unsafe { crate::offchain_state::offchain_count_read(slot_key) };
    if local_a != local_b || local_a == u64::MAX {
        return Err(NscStatus::InternalError);
    }

    let last_a = unsafe { crate::offchain_state::last_userop_count_read(slot_key) };
    crate::fi::wait_random();
    let last_b = unsafe { crate::offchain_state::last_userop_count_read(slot_key) };
    if last_a != last_b || last_a == u64::MAX {
        return Err(NscStatus::InternalError);
    }

    let tally_a = unsafe { crate::offchain_state::userop_sigs_read(slot_key) };
    crate::fi::wait_random();
    let tally_b = unsafe { crate::offchain_state::userop_sigs_read(slot_key) };
    if tally_a != tally_b || tally_a == u64::MAX {
        return Err(NscStatus::InternalError);
    }

    let effective = crate::aa::offchain_gate::effective_offchain_count(local_a, last_a);
    if !crate::aa::offchain_gate::userop_cap_ok(effective, tally_a) {
        return Err(NscStatus::OffchainCapExceeded);
    }
    crate::fi::wait_random();
    let effective_check = crate::aa::offchain_gate::effective_offchain_count(
        core::hint::black_box(local_b),
        core::hint::black_box(last_b),
    );
    if effective != effective_check
        || !crate::aa::offchain_gate::userop_cap_ok(effective_check, core::hint::black_box(tally_b))
    {
        return Err(NscStatus::InternalError);
    }

    Ok(CounterSnapshot {
        local_offchain: local_a,
        last_userop: last_a,
        userop_sigs: tally_a,
        new_offchain_count: effective,
    })
}

/// Own the 4,352-byte canonical execute buffer only in this non-inlined frame.
/// It ends before the 1,988-byte page set is created and is invoked again only
/// after that page-owning consent frame has returned.
#[inline(never)]
fn compute_type2_digest(
    request: &ForcedRequest<'_>,
    new_offchain_count: u64,
) -> Result<[u8; 32], NscStatus> {
    let owner_index = u64::from(request.slot_index) + 1;
    let execute = reconstruct_execute_calldata(
        owner_index,
        new_offchain_count,
        request.tx,
        request.calldata,
    )
    .map_err(|_| NscStatus::CryptoError)?;
    let call_digest = sha256_bytes(execute.as_slice());
    let params = AaUserOpParamsV06Sha256 {
        sender: request.sender,
        entry_point: ENTRY_POINT_V06,
        chain_id: request.chain_id,
        nonce: U256(request.nonce),
        init_code_digest: SHA256_EMPTY,
        call_gas_limit: U256(request.call_gas_limit),
        verification_gas_limit: U256(request.verification_gas_limit),
        pre_verification_gas: U256(request.pre_verification_gas),
        max_fee_per_gas: U256(request.max_fee_per_gas),
        max_priority_fee_per_gas: U256(request.max_priority_fee_per_gas),
        paymaster_and_data_digest: SHA256_EMPTY,
    };
    Ok(compute_sphincs_digest_v06(&params, &call_digest))
}

fn transcript_input(
    request: &ForcedRequest<'_>,
    new_offchain_count: u64,
    final_type2_digest: [u8; 32],
) -> ForcedTranscriptInput {
    ForcedTranscriptInput {
        account_index: request.account_index,
        slot_index: request.slot_index,
        signer: request.sender,
        target: request.target,
        chain_id: request.chain_id,
        selector: [
            request.calldata[0],
            request.calldata[1],
            request.calldata[2],
            request.calldata[3],
        ],
        calldata_len: request.calldata.len() as u32,
        new_offchain_count,
        value: request.value,
        nonce: request.nonce,
        max_fee_per_gas: request.max_fee_per_gas,
        max_priority_fee_per_gas: request.max_priority_fee_per_gas,
        call_gas_limit: request.call_gas_limit,
        verification_gas_limit: request.verification_gas_limit,
        pre_verification_gas: request.pre_verification_gas,
        erc8213_calldata_digest: pqsigner_tx_core::erc8213::calldata_digest(request.calldata),
        final_type2_digest,
    }
}

#[inline(never)]
unsafe fn capacity_receipt(
    slot_key: &[u8; 8],
    request_digest: &[u8; 32],
) -> Result<crate::offchain_state::ForcedCapacityReceipt, NscStatus> {
    let mut verdict = crate::fi::FAIL_SENTINEL;
    unsafe { core::ptr::write_volatile(&mut verdict, crate::fi::FAIL_SENTINEL) };
    let mut cfi = crate::fi::CfiCounter::new();
    let receipt = unsafe {
        crate::offchain_state::forced_capacity_preflight(
            slot_key,
            request_digest,
            &mut verdict,
            &mut cfi,
        )
    }
    .map_err(|_| NscStatus::OffchainCapExceeded)?;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let published = unsafe { core::ptr::read_volatile(&verdict) };
    if published != crate::fi::OK_SENTINEL
        || cfi.check_into_sentinel(crate::offchain_state::CFI_FORCED_CAPACITY_EXPECTED)
            != crate::fi::OK_SENTINEL
    {
        return Err(NscStatus::InternalError);
    }
    Ok(receipt)
}

/// Complete key derivation/cache population before the severe warning.  This
/// is SRAM-only preparation; no page-123 or other persistent state is touched.
#[inline(never)]
unsafe fn ensure_slot_key(request: &ForcedRequest<'_>) -> Result<(), NscStatus> {
    let master_secret: Zeroizing<[u8; 32]> =
        Zeroizing::new(super::state::peek_state(|state| state.master_secret));
    let mut entropy_blob = Zeroizing::new([0u8; 64]);
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let secure_element = unsafe { &mut *core::ptr::addr_of_mut!(crate::SE) };
        secure_element
            .read_entropy_blob(&mut *entropy_blob)
            .map_err(|_| NscStatus::InternalError)?
    };
    let entropy = Zeroizing::new(
        crate::crypto::decrypt_entropy_blob(&entropy_blob[..entropy_blob_len], &*master_secret)
            .map_err(|_| NscStatus::CryptoError)?,
    );
    let slot_master = Zeroizing::new(crate::crypto::slot_master_entropy_from_entropy(
        &*entropy,
        request.account_index,
    ));

    let need_keygen = match unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) } {
        Some(cached) => {
            cached.account_index != request.account_index
                || cached.chain_id != request.chain_id
                || cached.slot_index != request.slot_index
        }
        None => true,
    };
    if need_keygen {
        crate::ui::show_progress("Forced keygen", 0);
        let (key, _, _) = crate::crypto::derive_c10_slot_keypair_with_progress(
            &*slot_master,
            request.chain_id,
            request.slot_index,
            forced_keygen_progress,
        );
        unsafe {
            *core::ptr::addr_of_mut!(super::state::SLOT_CACHE) = Some(CachedSlot {
                account_index: request.account_index,
                chain_id: request.chain_id,
                slot_index: request.slot_index,
                key,
            });
        }
        super::state::with_state(|state| {
            state.slot_master_entropy.zeroize();
            crate::fi::zeroize_barrier();
            state.slot_master_entropy = *slot_master;
            state.slot_master_derived.set_true();
        });
    }

    let identity_a = match unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) } {
        Some(cached) => (cached.account_index, cached.chain_id, cached.slot_index),
        None => return Err(NscStatus::InternalError),
    };
    crate::fi::wait_random();
    let identity_b = match unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) } {
        Some(cached) => (cached.account_index, cached.chain_id, cached.slot_index),
        None => return Err(NscStatus::InternalError),
    };
    let expected = (request.account_index, request.chain_id, request.slot_index);
    if identity_a != expected || identity_b != expected {
        return Err(NscStatus::InternalError);
    }
    Ok(())
}

fn forced_keygen_progress(percent: u8) {
    crate::ui::show_progress("Forced keygen", percent);
}

struct PoisonPages(crate::tx::display::Pages);

impl Drop for PoisonPages {
    fn drop(&mut self) {
        self.0.volatile_poison_and_reset();
    }
}

struct CollectedConsent {
    deadline: crate::timeout::ForcedDeadline,
    warning: WarningReceipt,
    final_receipt: FinalReceipt,
}

#[inline(never)]
fn collect_consent(
    transcript: &ForcedTranscriptInput,
    request_digest: &[u8; 32],
    flow_cfi: &mut crate::fi::CfiCounter,
) -> Result<CollectedConsent, NscStatus> {
    use crate::ui::confirm::{confirm_forced_checked, ForcedConfirmResult};

    let mut gas_cfi = crate::fi::CfiCounter::new();
    let mut pages = PoisonPages(
        render_forced_transcript(transcript, &mut gas_cfi).map_err(|_| NscStatus::InternalError)?,
    );
    if pages.0.len != FORCED_TRANSCRIPT_PAGES
        || forced_transcript_proof(&pages.0, transcript) != crate::fi::OK_SENTINEL
    {
        return Err(NscStatus::InternalError);
    }
    flow_cfi.bump(CFI_PREFLIGHT_TRANSCRIPT);
    if flow_cfi.check_into_sentinel(CFI_PREWARNING_EXPECTED) != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }

    let mut warning = WarningReceipt::default();
    warning.fail_initialize();
    let mut final_receipt = FinalReceipt::default();
    final_receipt.fail_initialize();

    // Start conservatively just before the charge, so the measured interval
    // begins no later than the Armed -> Spent transition.  No host-visible UI
    // occurs between these two operations.
    let deadline =
        crate::timeout::ForcedDeadline::start_verified().map_err(|_| NscStatus::InternalError)?;
    let charged =
        super::state::with_state(|state| state.forced_attempt.charge_forced_attempt_for_warning());
    if charged != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }
    flow_cfi.bump(CFI_ATTEMPT_CHARGED);

    let mut deadline_expired = || deadline.expired_verified().unwrap_or(true);
    let (warning_result, warning_sentinel) =
        confirm_forced_checked(&FORCED_WARNING_PAGES, &mut deadline_expired);
    match warning_result {
        ForcedConfirmResult::Confirmed => {}
        ForcedConfirmResult::Cancelled => return Err(NscStatus::UserRejected),
        ForcedConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            return Err(NscStatus::IdleWipe);
        }
        ForcedConfirmResult::DeadlineExpired => return Err(NscStatus::InternalError),
    }
    warning
        .record_confirmed(
            request_digest,
            true,
            warning_sentinel,
            &mut deadline_expired,
        )
        .map_err(|_| NscStatus::InternalError)?;
    if warning.completion_proof(request_digest) != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }
    flow_cfi.bump(CFI_WARNING_RECEIPT);

    // Re-prove the complete fixed grid at the exact final-confirm boundary.
    if deadline_expired() || forced_transcript_proof(&pages.0, transcript) != crate::fi::OK_SENTINEL
    {
        return Err(NscStatus::InternalError);
    }
    let (final_result, final_sentinel) =
        confirm_forced_checked(pages.0.as_slice(), &mut deadline_expired);
    match final_result {
        ForcedConfirmResult::Confirmed => {}
        ForcedConfirmResult::Cancelled => return Err(NscStatus::UserRejected),
        ForcedConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            return Err(NscStatus::IdleWipe);
        }
        ForcedConfirmResult::DeadlineExpired => return Err(NscStatus::InternalError),
    }
    final_receipt
        .record_confirmed(
            &warning,
            request_digest,
            true,
            final_sentinel,
            &mut deadline_expired,
        )
        .map_err(|_| NscStatus::InternalError)?;
    if warning.completion_proof(request_digest) != crate::fi::OK_SENTINEL
        || final_receipt.completion_proof(request_digest) != crate::fi::OK_SENTINEL
    {
        return Err(NscStatus::InternalError);
    }
    flow_cfi.bump(CFI_FINAL_RECEIPT);

    // Force the poison before returning so the parent frame can reconstruct
    // the 4,352-byte calldata without a live Pages allocation.
    pages.0.volatile_poison_and_reset();
    Ok(CollectedConsent {
        deadline,
        warning,
        final_receipt,
    })
}

/// Persist the signature-use tally before any output release.  The tally is
/// written first, so a later high-water repair failure cannot erase evidence
/// that the key was used.  The second write is either COUNT promotion or
/// USEROP publication; never both, keeping the frozen two-append capacity
/// projection exact as an upper bound.
#[inline(never)]
unsafe fn commit_durable_tally(
    slot_key: &[u8; 8],
    counters: CounterSnapshot,
) -> Result<(), NscStatus> {
    let next_tally = counters
        .userop_sigs
        .checked_add(1)
        .ok_or(NscStatus::InternalError)?;
    unsafe { crate::offchain_state::userop_sigs_bump(slot_key, next_tally) }
        .map_err(|_| NscStatus::InternalError)?;
    let tally_a = unsafe { crate::offchain_state::userop_sigs_read(slot_key) };
    crate::fi::wait_random();
    let tally_b = unsafe { crate::offchain_state::userop_sigs_read(slot_key) };
    if tally_a != next_tally || tally_b != next_tally {
        return Err(NscStatus::InternalError);
    }

    if counters.new_offchain_count > counters.local_offchain {
        unsafe {
            crate::offchain_state::offchain_count_promote_to(slot_key, counters.new_offchain_count)
        }
        .map_err(|_| NscStatus::InternalError)?;
    } else if counters.new_offchain_count > counters.last_userop {
        unsafe {
            crate::offchain_state::last_userop_count_set(slot_key, counters.new_offchain_count)
        }
        .map_err(|_| NscStatus::InternalError)?;
    }

    let local = unsafe { crate::offchain_state::offchain_count_read(slot_key) };
    let last = unsafe { crate::offchain_state::last_userop_count_read(slot_key) };
    if crate::aa::offchain_gate::effective_offchain_count(local, last)
        != counters.new_offchain_count
    {
        return Err(NscStatus::InternalError);
    }
    Ok(())
}

#[inline(never)]
unsafe fn publish_forced_response(
    args: &GatewayArgs,
    new_offchain_count: u64,
    wrapper: &[u8; SIG_WRAPPER_LEN],
    deadline: &crate::timeout::ForcedDeadline,
    flow_cfi: &mut crate::fi::CfiCounter,
) -> Result<(), NscStatus> {
    if flow_cfi.check_into_sentinel(CFI_PRERELEASE_EXPECTED) != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }

    // Retain the legacy full-maximum pointer proof, then independently bind
    // the exact fixed forced extent.  Both are repeated around a randomized
    // gap before the irreversible first byte write.
    let full_a = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)
    });
    let exact_a = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, FORCED_SIGN_RESPONSE_LEN)
    });
    crate::fi::wait_random();
    let full_b = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)
    });
    let exact_b = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, FORCED_SIGN_RESPONSE_LEN)
    });
    let window_a = deadline
        .release_window_open_verified()
        .map_err(|_| NscStatus::InternalError)?;
    crate::fi::wait_random();
    let window_b = deadline
        .release_window_open_verified()
        .map_err(|_| NscStatus::InternalError)?;
    if full_a != crate::fi::OK_SENTINEL
        || full_b != crate::fi::OK_SENTINEL
        || exact_a != crate::fi::OK_SENTINEL
        || exact_b != crate::fi::OK_SENTINEL
        || !window_a
        || !window_b
    {
        return Err(NscStatus::InvalidPointer);
    }
    flow_cfi.bump(CFI_RELEASE_GATE);
    if flow_cfi.check_into_sentinel(CFI_RELEASE_EXPECTED) != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }

    // This is the explicit irreversible release point.  A hostile NS DMA bus
    // master may observe every byte as it lands; later scrub is diagnostic,
    // never revocation.
    let out = args.arg1 as *mut u8;
    let count = new_offchain_count.to_be_bytes();
    let type2_len = (SIG_WRAPPER_LEN as u32).to_be_bytes();
    for position in 0..FORCED_SIGN_RESPONSE_LEN {
        let byte = match position {
            0..=7 => count[position],
            8..=15 => 0,
            16..=19 => type2_len[position - 16],
            _ => wrapper[position - 20],
        };
        unsafe { core::ptr::write_volatile(out.add(position), byte) };
    }

    // Diagnostic only: bytes may already have escaped through hostile DMA.
    // Scrub the exact current extent and reset rather than claiming rollback.
    if deadline.expired_verified().unwrap_or(true) {
        for index in 0..FORCED_SIGN_RESPONSE_LEN {
            unsafe { core::ptr::write_volatile(out.add(index), 0) };
        }
        super::zeroize_sensitive_state();
        cortex_m::peripheral::SCB::sys_reset();
    }
    Ok(())
}

fn forced_sign_progress(percent: u8) {
    crate::ui::show_progress("Forced C10 sign", percent);
}

/// Consume one exact-F candidate through the fixed ceremony, sign once, tally
/// durably, and release one exact 4,148-byte response.  Every return is
/// terminal to the outer command; callers must never resume ordinary dispatch.
///
/// # Safety
///
/// Called inside `cmd_sign_userop::run` while its HandlerGuard owns the
/// single-threaded dispatcher.  `args.arg1` passed both top-of-handler pointer
/// gates; this function independently repeats the full and exact gates at the
/// irreversible publication boundary.
#[inline(never)]
pub(super) unsafe fn run(
    args: &GatewayArgs,
    eligibility: ForcedEligibility,
    request: ForcedRequest<'_>,
) -> u32 {
    let _cleanup = ForcedCleanup;
    let mut flow_cfi = crate::fi::CfiCounter::new();

    if !prove_eligibility(&eligibility, &request) {
        crate::ui::show_status("Forced refused", "eligibility fault");
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_PREFLIGHT_ELIGIBILITY);

    let armed = super::state::peek_state(|state| state.forced_attempt.phase());
    if armed != Ok(ForcedAttemptPhase::Armed) {
        if armed.is_err() {
            super::zeroize_sensitive_state();
        }
        crate::ui::show_status("Forced refused", "PIN unlock needed");
        return NscStatus::UserRejected as u32;
    }

    let slot_key = crate::offchain_state::slot_key_compute(
        request.account_index as u8,
        request.chain_id,
        request.slot_index,
    );
    let counters = match unsafe { read_counter_snapshot(&slot_key) } {
        Ok(snapshot) => snapshot,
        Err(status) => return status as u32,
    };
    flow_cfi.bump(CFI_PREFLIGHT_COUNTERS);

    let final_digest = match compute_type2_digest(&request, counters.new_offchain_count) {
        Ok(digest) => digest,
        Err(status) => return status as u32,
    };
    let transcript = transcript_input(&request, counters.new_offchain_count, final_digest);
    let request_digest = match transcript.request_digest() {
        Ok(digest) => digest,
        Err(_) => return NscStatus::InternalError as u32,
    };
    flow_cfi.bump(CFI_PREFLIGHT_DIGEST);

    let capacity = match unsafe { capacity_receipt(&slot_key, &request_digest) } {
        Ok(receipt) => receipt,
        Err(status) => return status as u32,
    };
    flow_cfi.bump(CFI_PREFLIGHT_CAPACITY);

    if unsafe { ensure_slot_key(&request) }.is_err() {
        return NscStatus::CryptoError as u32;
    }
    flow_cfi.bump(CFI_PREFLIGHT_KEY);

    let rate = match crate::sign_rate::forced_rate_preflight(&request_digest) {
        Ok(receipt) => receipt,
        Err(_) => return NscStatus::CryptoError as u32,
    };
    flow_cfi.bump(CFI_PREFLIGHT_RATE);

    let prepared = ForcedPrepared {
        transcript,
        request_digest,
        slot_key,
        counters,
        capacity,
        rate,
    };
    let mut candidate = ForcedCandidate::new(eligibility, prepared.request_digest);
    let mut consent = match collect_consent(&prepared.transcript, candidate.digest(), &mut flow_cfi)
    {
        Ok(consent) => consent,
        Err(status) => return status as u32,
    };

    // Everything below is nonblocking and independently re-derived from the
    // frozen S-world snapshot before the sole key-use call.
    if !prove_candidate_eligibility(&candidate, &request) {
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_RECHECK_ELIGIBILITY);

    let counters_check = match unsafe { read_counter_snapshot(&prepared.slot_key) } {
        Ok(snapshot) => snapshot,
        Err(status) => return status as u32,
    };
    if counters_check != prepared.counters {
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_RECHECK_COUNTERS);

    let digest_check = match compute_type2_digest(&request, prepared.counters.new_offchain_count) {
        Ok(digest) => digest,
        Err(status) => return status as u32,
    };
    let transcript_check =
        transcript_input(&request, prepared.counters.new_offchain_count, digest_check);
    let request_digest_check = match transcript_check.request_digest() {
        Ok(digest) => digest,
        Err(_) => return NscStatus::InternalError as u32,
    };
    if digest_check != prepared.transcript.final_type2_digest
        || request_digest_check != prepared.request_digest
        || request_digest_check != *candidate.digest()
    {
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_RECHECK_DIGEST);

    let capacity_check =
        match unsafe { capacity_receipt(&prepared.slot_key, &request_digest_check) } {
            Ok(receipt) => receipt,
            Err(status) => return status as u32,
        };
    if capacity_check != prepared.capacity {
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_RECHECK_CAPACITY);

    if crate::sign_rate::forced_rate_recheck(&prepared.rate, &request_digest_check).is_err() {
        return NscStatus::CryptoError as u32;
    }
    flow_cfi.bump(CFI_RECHECK_RATE);

    let mut deadline_expired = || consent.deadline.expired_verified().unwrap_or(true);
    if deadline_expired()
        || consent.warning.completion_proof(&request_digest_check) != crate::fi::OK_SENTINEL
        || consent
            .final_receipt
            .completion_proof(&request_digest_check)
            != crate::fi::OK_SENTINEL
    {
        return NscStatus::InternalError as u32;
    }
    if consume_forced_receipts_once(
        &mut consent.warning,
        &mut consent.final_receipt,
        &request_digest_check,
        &mut deadline_expired,
    ) != crate::fi::OK_SENTINEL
    {
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_RECEIPTS_CONSUMED);

    if super::state::peek_state(|state| state.forced_attempt.phase())
        != Ok(ForcedAttemptPhase::Spent)
        || candidate.consume(&request_digest_check) != crate::fi::OK_SENTINEL
    {
        super::zeroize_sensitive_state();
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_CANDIDATE_CONSUMED);
    if flow_cfi.check_into_sentinel(CFI_PRESIGN_EXPECTED) != crate::fi::OK_SENTINEL
        || deadline_expired()
    {
        return NscStatus::InternalError as u32;
    }

    let signature = {
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot = match cached {
            Some(cached)
                if cached.account_index == request.account_index
                    && cached.chain_id == request.chain_id
                    && cached.slot_index == request.slot_index =>
            {
                &cached.key
            }
            _ => return NscStatus::InternalError as u32,
        };
        match crate::crypto::c10_sign_verified_forced_with_progress(
            slot,
            &digest_check,
            forced_sign_progress,
            &prepared.rate,
            &request_digest_check,
        ) {
            Ok(signature) => signature,
            Err(_) => {
                // The shared signer can reject before its first key use
                // (rate/RNG preparation) or after one or both fault-hardened
                // signing passes.  Its intentionally narrow error type does
                // not expose that distinction.  Conservatively consume the
                // frozen durable use here: a preparation failure may
                // over-count one user-visible, twice-confirmed attempt, but
                // an actual few-time-key use can never escape the journal.
                // No response bytes are reachable from this arm.
                let _ = unsafe { commit_durable_tally(&prepared.slot_key, prepared.counters) };
                super::zeroize_sensitive_state();
                return NscStatus::CryptoError as u32;
            }
        }
    };

    let outer_verified = {
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot = match cached {
            Some(cached)
                if cached.account_index == request.account_index
                    && cached.chain_id == request.chain_id
                    && cached.slot_index == request.slot_index =>
            {
                &cached.key
            }
            _ => return NscStatus::InternalError as u32,
        };
        let first = sphincs_c10::verify(slot.pk_seed(), slot.pk_root(), &digest_check, &signature);
        crate::fi::wait_random();
        let second = sphincs_c10::verify(slot.pk_seed(), slot.pk_root(), &digest_check, &signature);
        crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(first) && core::hint::black_box(second)
        }) == crate::fi::OK_SENTINEL
    };

    // Once the shared verified signer returns Ok, key use is established.
    // Persist the frozen +1 tally even if the outer defence-in-depth verify
    // detects a later fault; output remains withheld on every failure.
    if !outer_verified {
        let _ = unsafe { commit_durable_tally(&prepared.slot_key, prepared.counters) };
        super::zeroize_sensitive_state();
        return NscStatus::CryptoError as u32;
    }
    flow_cfi.bump(CFI_SIGN_VERIFIED);

    let mut wrapper = Zeroizing::new([0u8; SIG_WRAPPER_LEN]);
    super::sig_wrapper::encode_signature_wrapper(
        &mut *wrapper,
        u64::from(request.slot_index) + 1,
        &signature,
    );
    if unsafe { commit_durable_tally(&prepared.slot_key, prepared.counters) }.is_err() {
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_TALLY_DURABLE);

    // Expiry during the expensive signature still preserves the durable key-
    // use tally but withholds every response byte.
    if deadline_expired() {
        return NscStatus::InternalError as u32;
    }
    if let Err(status) = unsafe {
        publish_forced_response(
            args,
            prepared.counters.new_offchain_count,
            &*wrapper,
            &consent.deadline,
            &mut flow_cfi,
        )
    } {
        return status as u32;
    }

    wrapper.zeroize();
    crate::fi::zeroize_barrier();
    crate::timeout::reset_activity();
    crate::ui::show_status("Forced signed", "UNVERIFIED CALL");
    NscStatus::Ok as u32
}
