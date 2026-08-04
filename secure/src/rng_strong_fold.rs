//! Pure per-chunk SE-entropy fold for [`crate::rng_strong`].
//!
//! Split out of `rng_strong.rs` because that module is
//! `#[cfg(not(test))]` (it calls the hardware `crate::rng` /
//! source-specific SE accessors), while this fold is pure logic the host test
//! suite can — and must — exercise directly (finding F27).

use zeroize::Zeroize;

/// Smallest health-checkable source contribution. OPTIGA already has an
/// 8-byte minimum request; keeping every fold chunk at least this large also
/// makes the legitimate all-zero/equal-stream collision probability ≤ 2^-64.
pub(crate) const MIN_SOURCE_BLOCK: usize = 8;
const MAX_SOURCE_BLOCK: usize = 32;

const SOURCE_HISTORY_EMPTY: u32 = 0;
const SOURCE_HISTORY_POISONED: u32 = crate::fi::FAIL_SENTINEL;
const SOURCE_HISTORY_READY: u32 = crate::fi::OK_SENTINEL;

/// Last independently accepted response from each physical secure-element
/// TRNG. Production keeps one instance in secure SRAM behind the strong-RNG
/// call lock; tests use an explicit local instance.
///
/// Comparing the shared prefix is intentional for different request lengths:
/// a stuck chip that returns one fixed stream truncated to the APDU's requested
/// length must not evade the continuous repetition test at a chunk boundary.
pub(crate) struct SourceRepeatState {
    optiga: [u8; MAX_SOURCE_BLOCK],
    se050: [u8; MAX_SOURCE_BLOCK],
    len: usize,
    status: u32,
}

impl SourceRepeatState {
    pub(crate) const fn new() -> Self {
        Self {
            optiga: [0; MAX_SOURCE_BLOCK],
            se050: [0; MAX_SOURCE_BLOCK],
            len: 0,
            status: SOURCE_HISTORY_EMPTY,
        }
    }
}

/// Keep the final chunk health-checkable instead of emitting a 1..7-byte tail.
/// Kept as an externally visible, out-of-line artifact boundary so whole-
/// program LTO cannot infer the current callers' ≤32-byte range and erase the
/// generic 33/40/48/65-byte partition. The volatile argument read also keeps
/// the runtime decision present in optimized ARM code. This exports only a
/// pure length calculation, not an entropy or privilege boundary.
#[inline(never)]
#[export_name = "pqsigner_rng_source_chunk_len"]
pub(crate) extern "C" fn source_chunk_len(remaining: usize) -> usize {
    // SAFETY: `remaining_live` is a valid stack local. This is intentionally
    // an optimization barrier: linked-artifact support for generic lengths is
    // part of the strong-RNG contract, not merely a source-level property.
    let remaining_live = remaining;
    let remaining = unsafe { core::ptr::read_volatile(&remaining_live) };
    if remaining > MAX_SOURCE_BLOCK && remaining - MAX_SOURCE_BLOCK < MIN_SOURCE_BLOCK {
        remaining - MIN_SOURCE_BLOCK
    } else {
        remaining.min(MAX_SOURCE_BLOCK)
    }
}

/// Publish success only for a memory-safe, health-checkable chunk shape.
///
/// This is intentionally separate from [`source_chunk_len`]. If the selector
/// call or its clamp is skipped in optimized ARM code, the caller still owns a
/// fail-initialized receipt that is checked before any 32-byte scratch slice is
/// formed. Any safe partition is acceptable; every non-final remainder must
/// retain at least [`MIN_SOURCE_BLOCK`] bytes for the next health check.
#[inline(never)]
fn validate_source_chunk_len_into(remaining: usize, len: usize, receipt: &mut u32) {
    // SAFETY: unique caller-owned receipt. A skipped validator remains fail.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }

    // SAFETY: independent observations of stack-backed arguments prevent the
    // optimizer from treating the selector result as inherently bounded.
    let remaining_a = unsafe { core::ptr::read_volatile(&remaining) };
    let len_a = unsafe { core::ptr::read_volatile(&len) };
    if len_a < MIN_SOURCE_BLOCK || len_a > MAX_SOURCE_BLOCK || len_a > remaining_a {
        return;
    }
    if len_a != remaining_a && remaining_a - len_a < MIN_SOURCE_BLOCK {
        return;
    }

    crate::fi::wait_random();
    let remaining_b = unsafe { core::ptr::read_volatile(&remaining) };
    let len_b = unsafe { core::ptr::read_volatile(&len) };
    if len_b < MIN_SOURCE_BLOCK || len_b > MAX_SOURCE_BLOCK || len_b > remaining_b {
        return;
    }
    if len_b != remaining_b && remaining_b - len_b < MIN_SOURCE_BLOCK {
        return;
    }

    // SAFETY: both independent shape checks passed; sole success store.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum SeSource {
    Optiga,
    Se050,
}

/// Independently prove that all three source blocks are present, nonzero, and
/// pairwise different before mixing them.
///
/// The caller executes this full volatile scan twice with a fresh fail receipt
/// each time. Therefore one skipped load/backedge/comparison cannot promote an
/// absent or cancelling source: the other scan still rejects. Exact progress
/// also prevents an overlong or shortened health scan from returning success.
#[inline(never)]
fn verify_source_health_into(
    platform: &[u8],
    optiga: &[u8],
    se050: &[u8],
    optiga_ok: bool,
    se050_ok: bool,
    history: &SourceRepeatState,
    receipt: &mut u32,
) {
    // SAFETY: unique caller-owned receipt. A skipped verifier remains fail.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    if platform.is_empty() || platform.len() != optiga.len() || platform.len() != se050.len() {
        return;
    }

    // A failed history publication is sticky until reset. Continuing with a
    // partially updated previous-response record would silently disable the
    // continuous repetition test on the next secret draw.
    let history_status = unsafe { core::ptr::read_volatile(&history.status) };
    let history_len = unsafe { core::ptr::read_volatile(&history.len) };
    let history_overlap = if history_status == SOURCE_HISTORY_EMPTY {
        0
    } else if history_status == SOURCE_HISTORY_READY
        && history_len >= MIN_SOURCE_BLOCK
        && history_len <= MAX_SOURCE_BLOCK
    {
        core::cmp::min(history_len, platform.len())
    } else {
        return;
    };

    let mut processed = 0usize;
    unsafe {
        core::ptr::write_volatile(&mut processed, 0);
    }
    let mut platform_nonzero = 0u8;
    let mut optiga_nonzero = 0u8;
    let mut se050_nonzero = 0u8;
    let mut optiga_se050_differ = 0u8;
    let mut platform_optiga_differ = 0u8;
    let mut platform_se050_differ = 0u8;
    let mut optiga_history_differ = 0u8;
    let mut se050_history_differ = 0u8;
    for i in 0..platform.len() {
        // SAFETY: all lengths were checked equal. Volatile loads make this an
        // observation independent of the source drivers and later mixer.
        let p = unsafe { core::ptr::read_volatile(platform.as_ptr().add(i)) };
        let o = unsafe { core::ptr::read_volatile(optiga.as_ptr().add(i)) };
        let s = unsafe { core::ptr::read_volatile(se050.as_ptr().add(i)) };
        platform_nonzero |= p;
        optiga_nonzero |= o;
        se050_nonzero |= s;
        optiga_se050_differ |= o ^ s;
        platform_optiga_differ |= p ^ o;
        platform_se050_differ |= p ^ s;
        if i < history_overlap {
            let previous_optiga =
                unsafe { core::ptr::read_volatile(history.optiga.as_ptr().add(i)) };
            let previous_se050 = unsafe { core::ptr::read_volatile(history.se050.as_ptr().add(i)) };
            optiga_history_differ |= o ^ previous_optiga;
            se050_history_differ |= s ^ previous_se050;
        }
        unsafe {
            core::ptr::write_volatile(&mut processed, i + 1);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    // SAFETY: deliberate live observations of scan progress and draw results.
    let processed = unsafe { core::ptr::read_volatile(&processed) };
    let optiga_ok = unsafe { core::ptr::read_volatile(&optiga_ok) };
    let se050_ok = unsafe { core::ptr::read_volatile(&se050_ok) };
    if processed != platform.len()
        || !optiga_ok
        || !se050_ok
        || platform_nonzero == 0
        || optiga_nonzero == 0
        || se050_nonzero == 0
        || optiga_se050_differ == 0
        || platform_optiga_differ == 0
        || platform_se050_differ == 0
        || (history_overlap != 0 && optiga_history_differ == 0)
        || (history_overlap != 0 && se050_history_differ == 0)
    {
        return;
    }

    // SAFETY: exact scan and all independent source predicates passed.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Atomically publish the current secure-element responses as the next
/// continuous-repetition baseline.
///
/// `status` is poisoned before either copy. Any interrupted or fault-shortened
/// publication therefore makes all later strong-RNG calls fail closed until a
/// reset, instead of comparing against a partially updated history. The exact
/// copy helper owns caller receipts, progress, and independent readback.
#[inline(never)]
fn commit_source_history_into(
    optiga: &[u8],
    expected_optiga_source_slot: *const *const u8,
    expected_optiga_destination_slot: *const *const u8,
    se050: &[u8],
    expected_se050_source_slot: *const *const u8,
    expected_se050_destination_slot: *const *const u8,
    history: &mut SourceRepeatState,
    receipt: &mut u32,
) {
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
        core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_POISONED);
        core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_POISONED);
    }
    if optiga.len() < MIN_SOURCE_BLOCK
        || optiga.len() > MAX_SOURCE_BLOCK
        || optiga.len() != se050.len()
    {
        return;
    }

    let len = optiga.len();
    let mut optiga_copy_receipt = crate::fi::FAIL_SENTINEL;
    crate::rng_exact::copy_exact_into(
        optiga.as_ptr(),
        expected_optiga_source_slot,
        len,
        history.optiga.as_mut_ptr(),
        0,
        expected_optiga_destination_slot,
        len,
        &mut optiga_copy_receipt,
    );
    if unsafe { core::ptr::read_volatile(&optiga_copy_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&optiga_copy_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }

    let mut se050_copy_receipt = crate::fi::FAIL_SENTINEL;
    crate::rng_exact::copy_exact_into(
        se050.as_ptr(),
        expected_se050_source_slot,
        len,
        history.se050.as_mut_ptr(),
        0,
        expected_se050_destination_slot,
        len,
        &mut se050_copy_receipt,
    );
    if unsafe { core::ptr::read_volatile(&se050_copy_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&se050_copy_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }

    // Duplicate volatile publication prevents one omitted stack/static store
    // from leaving a successful receipt bound to stale metadata.
    unsafe {
        core::ptr::write_volatile(&mut history.len, len);
        core::ptr::write_volatile(&mut history.len, len);
        core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_READY);
        core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_READY);
    }
    if unsafe { core::ptr::read_volatile(&history.len) } != len
        || unsafe { core::ptr::read_volatile(&history.status) } != SOURCE_HISTORY_READY
    {
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&history.len) } != len
        || unsafe { core::ptr::read_volatile(&history.status) } != SOURCE_HISTORY_READY
    {
        return;
    }
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Independently prove that the newly published repetition baseline is the
/// current OPTIGA and SE050 response pair.
///
/// This check deliberately lives outside the copying helper's pointer-binding
/// path. A skipped callee prologue move could otherwise redirect both the
/// expected publication and live copy through one stale register. Two exact
/// volatile scans bind READY status to the caller's still-live source blocks.
#[inline(never)]
fn verify_committed_source_history_into(
    optiga: &[u8],
    se050: &[u8],
    history: &SourceRepeatState,
    receipt: &mut u32,
) {
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    if optiga.len() < MIN_SOURCE_BLOCK
        || optiga.len() > MAX_SOURCE_BLOCK
        || optiga.len() != se050.len()
    {
        return;
    }
    let len = optiga.len();
    if unsafe { core::ptr::read_volatile(&history.len) } != len
        || unsafe { core::ptr::read_volatile(&history.status) } != SOURCE_HISTORY_READY
    {
        return;
    }
    let mut processed_a = 0usize;
    let mut diff_a = 0u8;
    for i in 0..len {
        diff_a |= unsafe {
            core::ptr::read_volatile(history.optiga.as_ptr().add(i))
                ^ core::ptr::read_volatile(optiga.as_ptr().add(i))
                | core::ptr::read_volatile(history.se050.as_ptr().add(i))
                    ^ core::ptr::read_volatile(se050.as_ptr().add(i))
        };
        unsafe {
            core::ptr::write_volatile(&mut processed_a, i + 1);
        }
    }
    if unsafe { core::ptr::read_volatile(&processed_a) } != len || diff_a != 0 {
        return;
    }

    crate::fi::wait_random();

    if unsafe { core::ptr::read_volatile(&history.len) } != len
        || unsafe { core::ptr::read_volatile(&history.status) } != SOURCE_HISTORY_READY
    {
        return;
    }
    let mut processed_b = 0usize;
    let mut diff_b = 0u8;
    for i in 0..len {
        diff_b |= unsafe {
            core::ptr::read_volatile(history.optiga.as_ptr().add(i))
                ^ core::ptr::read_volatile(optiga.as_ptr().add(i))
                | core::ptr::read_volatile(history.se050.as_ptr().add(i))
                    ^ core::ptr::read_volatile(se050.as_ptr().add(i))
        };
        unsafe {
            core::ptr::write_volatile(&mut processed_b, i + 1);
        }
    }
    if unsafe { core::ptr::read_volatile(&processed_b) } != len || diff_b != 0 {
        return;
    }

    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// One exact volatile all-zero scan. The outer helper invokes this twice so a
/// single omitted load, branch, or backedge cannot authorize an all-zero key.
#[inline(never)]
fn verify_nonzero_output_into(buf: &[u8], receipt: &mut u32) {
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    if buf.is_empty() {
        return;
    }
    let mut processed = 0usize;
    unsafe {
        core::ptr::write_volatile(&mut processed, 0);
    }
    let mut nonzero = 0u8;
    for i in 0..buf.len() {
        nonzero |= unsafe { core::ptr::read_volatile(buf.as_ptr().add(i)) };
        unsafe {
            core::ptr::write_volatile(&mut processed, i + 1);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    if unsafe { core::ptr::read_volatile(&processed) } != buf.len() || nonzero == 0 {
        return;
    }
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Publish success only after two independent exact scans prove the completed
/// three-source output is nonzero. The caller owns and checks `receipt`, so an
/// omitted call remains an explicit failure rather than a stale ABI result.
#[inline(never)]
pub(crate) fn verify_nonzero_output_twice_into(buf: &[u8], receipt: &mut u32) {
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    let mut scan_receipt = crate::fi::FAIL_SENTINEL;
    verify_nonzero_output_into(buf, &mut scan_receipt);
    if unsafe { core::ptr::read_volatile(&scan_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }
    crate::fi::wait_random();
    unsafe {
        core::ptr::write_volatile(&mut scan_receipt, crate::fi::FAIL_SENTINEL);
    }
    verify_nonzero_output_into(buf, &mut scan_receipt);
    if unsafe { core::ptr::read_volatile(&scan_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Publish success only when a volatile byte-completion state equals its
/// expected exact length twice around a randomized delay.
///
/// This check is independent of the outer chunk-loop backedge. If that branch
/// is fault-skipped after a proper prefix, execution falls through here with a
/// short `completed_bytes` value and cannot reach the fold-success store.
#[inline(never)]
fn verify_exact_completion_into(
    completed_bytes: &usize,
    expected_bytes: usize,
    completion_receipt: &mut u32,
) {
    // SAFETY: unique caller-owned receipt. A skipped whole call therefore
    // leaves the caller's matching fail initialization in place.
    unsafe {
        core::ptr::write_volatile(completion_receipt, crate::fi::FAIL_SENTINEL);
    }
    // SAFETY: deliberate independent reads of live volatile progress state.
    if unsafe { core::ptr::read_volatile(completed_bytes) } != expected_bytes {
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(completed_bytes) } != expected_bytes {
        return;
    }
    // SAFETY: exact completion was observed twice; this is the only success
    // publication in the helper.
    unsafe {
        core::ptr::write_volatile(completion_receipt, crate::fi::OK_SENTINEL);
    }
}

/// Publish the next verified byte prefix after one complete three-source
/// chunk.
///
/// `completed_bytes` is both the loop cursor and the independent completion
/// record. Keeping one canonical volatile value prevents a skipped spill of a
/// separately maintained `off + len` from reusing a prior stack frame's final
/// offset. The caller fail-initializes and checks `progress_receipt`, so an
/// omitted call cannot advance the loop. Within the helper, two independent
/// snapshots bind the current cursor, chunk shape, and checked next offset
/// before duplicate volatile publication and readback.
#[inline(never)]
fn publish_verified_progress_into(
    completed_bytes: *mut usize,
    current_off: usize,
    chunk_len: usize,
    expected_total: usize,
    mixed_bytes: *const usize,
    progress_receipt: &mut u32,
) {
    // SAFETY: unique caller-owned receipt. If the helper returns early, or its
    // sole success store is omitted, the caller observes failure.
    unsafe {
        core::ptr::write_volatile(progress_receipt, crate::fi::FAIL_SENTINEL);
    }

    // Keep the two caller-provided pointers in distinct raw-pointer slots.
    // References would make a fault-created alias between the mutable cursor
    // and immutable mixer counter optimizer-invalid before this function got
    // a chance to reject it. Two independently emitted volatile snapshots and
    // alias checks make one skipped pointer setup / compare / branch fail
    // closed. A corrupted non-stack pointer may fault while read below; that
    // is fail-stop and cannot publish the receipt.
    let completed_pointer_slot = completed_bytes;
    let mixed_pointer_slot = mixed_bytes;
    let completed_ptr_a = unsafe { core::ptr::read_volatile(&completed_pointer_slot) };
    let mixed_ptr_a = unsafe { core::ptr::read_volatile(&mixed_pointer_slot) };
    if core::ptr::eq(completed_ptr_a.cast_const(), mixed_ptr_a) {
        return;
    }

    // Take the first value snapshot through volatile observations so this
    // proof is independent of the caller's loop-control SSA and pre-draw
    // spills.
    let completed_a = unsafe { core::ptr::read_volatile(completed_ptr_a) };
    let current_a = unsafe { core::ptr::read_volatile(&current_off) };
    let len_a = unsafe { core::ptr::read_volatile(&chunk_len) };
    let total_a = unsafe { core::ptr::read_volatile(&expected_total) };
    let mixed_a = unsafe { core::ptr::read_volatile(mixed_ptr_a) };
    let next_a = match current_a.checked_add(len_a) {
        Some(next) => next,
        None => return,
    };
    if completed_a != current_a
        || mixed_a != len_a
        || len_a < MIN_SOURCE_BLOCK
        || len_a > MAX_SOURCE_BLOCK
        || next_a > total_a
        || (next_a != total_a && total_a - next_a < MIN_SOURCE_BLOCK)
    {
        return;
    }

    crate::fi::wait_random();

    // Recompute from fresh observations. A single skipped load, add, compare,
    // or rejection branch in either pass cannot authorize a stale cursor.
    let completed_ptr_b = unsafe { core::ptr::read_volatile(&completed_pointer_slot) };
    let mixed_ptr_b = unsafe { core::ptr::read_volatile(&mixed_pointer_slot) };
    if !core::ptr::eq(completed_ptr_b, completed_ptr_a)
        || !core::ptr::eq(mixed_ptr_b, mixed_ptr_a)
        || core::ptr::eq(completed_ptr_b.cast_const(), mixed_ptr_b)
    {
        return;
    }
    let completed_b = unsafe { core::ptr::read_volatile(completed_ptr_b) };
    let current_b = unsafe { core::ptr::read_volatile(&current_off) };
    let len_b = unsafe { core::ptr::read_volatile(&chunk_len) };
    let total_b = unsafe { core::ptr::read_volatile(&expected_total) };
    let mixed_b = unsafe { core::ptr::read_volatile(mixed_ptr_b) };
    let next_b = match current_b.checked_add(len_b) {
        Some(next) => next,
        None => return,
    };
    if completed_b != current_b
        || mixed_b != len_b
        || len_b < MIN_SOURCE_BLOCK
        || len_b > MAX_SOURCE_BLOCK
        || next_b > total_b
        || (next_b != total_b && total_b - next_b < MIN_SOURCE_BLOCK)
        || next_b != next_a
    {
        return;
    }

    // Duplicate volatile stores make one omitted progress publication
    // insufficient. Read back twice around a delay before minting success.
    unsafe {
        core::ptr::write_volatile(completed_ptr_a, next_a);
        core::ptr::write_volatile(completed_ptr_b, next_b);
    }
    if unsafe { core::ptr::read_volatile(completed_ptr_a) } != next_a {
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(completed_ptr_b) } != next_b {
        return;
    }

    // SAFETY: both cursor/shape proofs and both publication readbacks passed.
    unsafe {
        core::ptr::write_volatile(progress_receipt, crate::fi::OK_SENTINEL);
    }
}

/// Prove that one completed output chunk is exactly the platform baseline XOR
/// both independently checked secure-element blocks.
///
/// This is deliberately a non-inlined, caller-receipt operation. A fault that
/// exits the preceding XOR loop early must leave at least one byte relation
/// unequal; a fault that exits this verification loop early leaves
/// `processed` short. Volatile reads keep LLVM from proving the relation from
/// the immediately preceding stores and deleting the check. The caller runs
/// this operation twice around a randomized delay, with a fresh fail receipt
/// each time, before advancing the chunk offset.
#[inline(never)]
fn verify_mixed_chunk_into(
    mixed: &[u8],
    platform: &[u8],
    optiga: &[u8],
    se050: &[u8],
    mix_receipt: &mut u32,
) {
    // SAFETY: unique caller-owned stack slot. If this whole call is skipped,
    // the caller's matching fail-initialization remains authoritative.
    unsafe {
        core::ptr::write_volatile(mix_receipt, crate::fi::FAIL_SENTINEL);
    }
    if mixed.is_empty()
        || mixed.len() != platform.len()
        || mixed.len() != optiga.len()
        || mixed.len() != se050.len()
    {
        return;
    }

    let mut processed = 0u32;
    // SAFETY: unique stack local. Publishing progress on every iteration makes
    // a fault-shortened loop observable after optimization.
    unsafe {
        core::ptr::write_volatile(&mut processed, 0);
    }
    let mut diff = 0u8;
    for i in 0..mixed.len() {
        // SAFETY: all four slices have the same checked length. Volatile reads
        // prevent the optimizer from replacing this independent readback with
        // the SSA values used by the preceding XOR loop.
        let relation = unsafe {
            core::ptr::read_volatile(mixed.as_ptr().add(i))
                ^ core::ptr::read_volatile(platform.as_ptr().add(i))
                ^ core::ptr::read_volatile(optiga.as_ptr().add(i))
                ^ core::ptr::read_volatile(se050.as_ptr().add(i))
        };
        diff |= relation;
        // SAFETY: same unique progress slot; `i < 32`, so conversion/addition
        // are exact on every supported target.
        unsafe {
            core::ptr::write_volatile(&mut processed, i as u32 + 1);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: deliberate independent observation of the volatile loop receipt.
    let processed = unsafe { core::ptr::read_volatile(&processed) };
    if processed != mixed.len() as u32 || diff != 0 {
        return;
    }

    // SAFETY: this is the only success publication, reached after exact data
    // relation and exact loop-cardinality checks both passed.
    unsafe {
        core::ptr::write_volatile(mix_receipt, crate::fi::OK_SENTINEL);
    }
}

/// XOR-fold the OPTIGA and SE050 streams into `buf`, one ≤32-byte chunk
/// at a time (steps 2 and 3 of `rng_strong::fill`). The two draws stay
/// separate until both have independent success/nonzero receipts, so a
/// skipped or zero-returning chip cannot hide behind the other chip's bytes.
///
/// Finding F27: each source block is zeroed before EVERY draw. Reusing a
/// previous chunk's block would fold old bytes into a later chunk, so a repeat
/// fault could cancel an SE contribution for the tail while the STM32 bytes
/// kept the final all-zero gate green.
///
/// Any pair of equal nonzero streams is also rejected. Although equality can occur by
/// chance, its probability for the minimum production request (8 bytes) is
/// negligible; accepting it would let two stuck/replayed sources cancel to a
/// one-source result.
///
/// `fold_receipt` is fail-initialized on entry and is promoted to
/// [`crate::fi::OK_SENTINEL`] only by falling through the all-chunks-success
/// path. Each normally returning chunk must first prove that its mixer executed
/// exactly `len` output stores, then pass two independent exact-mix readbacks
/// before its offset advances. A failed draw or returning completion/mix proof
/// wipes `buf` and every scratch block. Fault-forced out-of-bounds execution is
/// fail-stop and cannot publish success, but local slice wiping is not claimed
/// after a bounds panic or hard fault.
pub(crate) fn fold_se_sources(
    buf: &mut [u8],
    mut draw: impl FnMut(SeSource, &mut [u8]) -> bool,
    history: &mut SourceRepeatState,
    fold_receipt: &mut u32,
) {
    // SAFETY: unique caller-owned stack local. Re-initialize here as well as at
    // the call site so either a skipped call or a stale receipt fails closed.
    unsafe {
        core::ptr::write_volatile(fold_receipt, crate::fi::FAIL_SENTINEL);
    }
    if !buf.is_empty() && buf.len() < MIN_SOURCE_BLOCK {
        buf.zeroize();
        crate::fi::zeroize_barrier();
        return;
    }
    let mut optiga_block = [0u8; 32];
    let mut se050_block = [0u8; 32];
    let mut platform_block = [0u8; 32];
    let mut completed_bytes = usize::MAX;
    let mut progress_init_receipt = crate::fi::FAIL_SENTINEL;
    unsafe {
        core::ptr::write_volatile(&mut progress_init_receipt, crate::fi::FAIL_SENTINEL);
    }
    crate::rng_exact::initialize_exact_progress_into(
        &mut completed_bytes,
        &mut progress_init_receipt,
    );
    if unsafe { core::ptr::read_volatile(&progress_init_receipt) } != crate::fi::OK_SENTINEL {
        buf.zeroize();
        crate::fi::zeroize_barrier();
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&progress_init_receipt) } != crate::fi::OK_SENTINEL {
        buf.zeroize();
        crate::fi::zeroize_barrier();
        return;
    }
    loop {
        // The verified completion record is also the sole loop cursor. If this
        // load is faulted to a stale prefix, the post-mix progress helper still
        // compares it with the independently initialized canonical record.
        let off = unsafe { core::ptr::read_volatile(&completed_bytes) };
        if off >= buf.len() {
            break;
        }
        let remaining = buf.len() - off;
        // Do not leave a 1..7-byte tail: per-chunk zero/equality health checks
        // would then cause an avoidable 2^-8..2^-56 false-reject rate. Borrow
        // from this chunk so every nonempty chunk remains at least 8 bytes.
        let len = source_chunk_len(remaining);
        let mut chunk_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut chunk_receipt, crate::fi::FAIL_SENTINEL);
        }
        validate_source_chunk_len_into(remaining, len, &mut chunk_receipt);
        if unsafe { core::ptr::read_volatile(&chunk_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&chunk_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        // F27: fresh, zeroed blocks for THIS chunk (see fn doc).
        optiga_block[..len].fill(0);
        se050_block[..len].fill(0);
        platform_block[..len].fill(0);
        // Snapshot this chunk's actual platform contribution before either SE
        // draw. Zeroing first makes a skipped/partial snapshot fail the
        // platform-nonzero or exact-mix checks instead of reusing a prior chunk.
        platform_block[..len].copy_from_slice(&buf[off..off + len]);

        // Call both sources once. Do not short-circuit the second draw based on
        // the first result: the acceptance gate below owns the decision and
        // requires both receipts plus both nonzero scratch blocks.
        let optiga_ok = draw(SeSource::Optiga, &mut optiga_block[..len]);
        let se050_ok = draw(SeSource::Se050, &mut se050_block[..len]);

        // Execute the entire volatile source-health scan twice. Each source
        // must both report success and have changed its independently-zeroed
        // scratch, and no pair may cancel. A fresh fail receipt binds each
        // independent scan to its exact loop cardinality.
        let mut source_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut source_receipt, crate::fi::FAIL_SENTINEL);
        }
        verify_source_health_into(
            &platform_block[..len],
            &optiga_block[..len],
            &se050_block[..len],
            optiga_ok,
            se050_ok,
            history,
            &mut source_receipt,
        );
        if unsafe { core::ptr::read_volatile(&source_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        unsafe {
            core::ptr::write_volatile(&mut source_receipt, crate::fi::FAIL_SENTINEL);
        }
        verify_source_health_into(
            &platform_block[..len],
            &optiga_block[..len],
            &se050_block[..len],
            optiga_ok,
            se050_ok,
            history,
            &mut source_receipt,
        );
        if unsafe { core::ptr::read_volatile(&source_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }

        // The current source pair has now been observed and accepted twice.
        // Make the old repetition baseline unusable before ANY later operation
        // that can return. Otherwise a failed endpoint publication could forget
        // this newly observed B while leaving READY(A), allowing stuck B to pass
        // the next call's comparison against stale A. Duplicate volatile stores
        // keep one omitted store from preserving READY.
        unsafe {
            core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_POISONED);
            core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_POISONED);
        }

        // Bind each history-copy endpoint before entering the publisher. The
        // live source/destination pointers are rematerialized at the later
        // copy call, so one omitted caller-side setup cannot redirect both the
        // expected and live observations to the same stale buffer.
        let mut published_history_optiga_source = core::ptr::null();
        let mut history_optiga_source_receipt = crate::fi::FAIL_SENTINEL;
        crate::rng_exact::publish_region_pointer_into(
            optiga_block.as_ptr(),
            &mut published_history_optiga_source,
            &mut history_optiga_source_receipt,
        );
        if unsafe { core::ptr::read_volatile(&history_optiga_source_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&history_optiga_source_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }

        let mut published_history_se050_source = core::ptr::null();
        let mut history_se050_source_receipt = crate::fi::FAIL_SENTINEL;
        crate::rng_exact::publish_region_pointer_into(
            se050_block.as_ptr(),
            &mut published_history_se050_source,
            &mut history_se050_source_receipt,
        );
        if unsafe { core::ptr::read_volatile(&history_se050_source_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&history_se050_source_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }

        let mut published_history_optiga_destination = core::ptr::null();
        let mut history_optiga_destination_receipt = crate::fi::FAIL_SENTINEL;
        crate::rng_exact::publish_region_pointer_into(
            history.optiga.as_ptr(),
            &mut published_history_optiga_destination,
            &mut history_optiga_destination_receipt,
        );
        if unsafe { core::ptr::read_volatile(&history_optiga_destination_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&history_optiga_destination_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }

        let mut published_history_se050_destination = core::ptr::null();
        let mut history_se050_destination_receipt = crate::fi::FAIL_SENTINEL;
        crate::rng_exact::publish_region_pointer_into(
            history.se050.as_ptr(),
            &mut published_history_se050_destination,
            &mut history_se050_destination_receipt,
        );
        if unsafe { core::ptr::read_volatile(&history_se050_destination_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&history_se050_destination_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }

        // Advance the per-source continuous-repetition baseline only after
        // two complete health scans. The caller already poisoned history before
        // the fallible endpoint setup above; a fault-shortened publication is
        // therefore sticky-fatal and leaves no successful output.
        let mut history_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut history_receipt, crate::fi::FAIL_SENTINEL);
        }
        commit_source_history_into(
            &optiga_block[..len],
            core::ptr::addr_of!(published_history_optiga_source),
            core::ptr::addr_of!(published_history_optiga_destination),
            &se050_block[..len],
            core::ptr::addr_of!(published_history_se050_source),
            core::ptr::addr_of!(published_history_se050_destination),
            history,
            &mut history_receipt,
        );
        if unsafe { core::ptr::read_volatile(&history_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&history_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }

        // Re-prove the committed bytes against the caller's still-live source
        // blocks through an independent helper. This catches a fault-created
        // correlated redirection that happens to satisfy the copy helper's
        // pointer bindings.
        let mut history_relation_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(
                &mut history_relation_receipt,
                crate::fi::FAIL_SENTINEL,
            );
        }
        verify_committed_source_history_into(
            &optiga_block[..len],
            &se050_block[..len],
            history,
            &mut history_relation_receipt,
        );
        if unsafe { core::ptr::read_volatile(&history_relation_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&history_relation_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }

        // Each source is folded exactly once, and only after both receipts.
        // Publish the number of output stores independently of the compiler's
        // loop-control SSA. Besides detecting a shortened loop, this catches a
        // skipped decrement/backedge fault that performs byte `len` as an
        // out-of-chunk extra store before falling through.
        let mut mixed_bytes = 0usize;
        unsafe {
            core::ptr::write_volatile(&mut mixed_bytes, 0);
        }
        for i in 0..len {
            buf[off + i] ^= optiga_block[i];
            buf[off + i] ^= se050_block[i];
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            // SAFETY: unique stack progress slot. This volatile publication is
            // deliberately after the output store. A normal early fallthrough
            // leaves a short value. A fault that instead makes the optimized
            // loop run beyond its safe bound is fail-stop (bounds panic/hard
            // fault) and cannot publish a fold receipt; it is not a returning
            // rejection path and therefore cannot promise local slice wiping.
            unsafe {
                core::ptr::write_volatile(&mut mixed_bytes, i + 1);
            }
        }

        // The bytewise verifier is intentionally limited to the current slice,
        // so it cannot observe an extra store into the following chunk. Bind
        // entry to both verifiers to an exact mixer-local store count first.
        let mut mixer_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut mixer_receipt, crate::fi::FAIL_SENTINEL);
        }
        verify_exact_completion_into(&mixed_bytes, len, &mut mixer_receipt);
        if unsafe { core::ptr::read_volatile(&mixer_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&mixer_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }

        // Bind offset advancement and the outer OK receipt to the exact
        // bytewise relation `mixed == platform XOR OPTIGA XOR SE050`. Each call
        // owns fail-initialization, loop-cardinality proof, volatile readback,
        // and success publication. Two calls prevent a single fault inside one
        // verifier from becoming an acceptance decision.
        let mut mix_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut mix_receipt, crate::fi::FAIL_SENTINEL);
        }
        verify_mixed_chunk_into(
            &buf[off..off + len],
            &platform_block[..len],
            &optiga_block[..len],
            &se050_block[..len],
            &mut mix_receipt,
        );
        if unsafe { core::ptr::read_volatile(&mix_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        unsafe {
            core::ptr::write_volatile(&mut mix_receipt, crate::fi::FAIL_SENTINEL);
        }
        verify_mixed_chunk_into(
            &buf[off..off + len],
            &platform_block[..len],
            &optiga_block[..len],
            &se050_block[..len],
            &mut mix_receipt,
        );
        if unsafe { core::ptr::read_volatile(&mix_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        // Advance only through a fail-initialized out-of-line receipt after
        // both exact-mix proofs. In particular, no pre-draw `off + len` spill
        // can become the next loop cursor or final completion evidence.
        let mut progress_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut progress_receipt, crate::fi::FAIL_SENTINEL);
        }
        publish_verified_progress_into(
            core::ptr::addr_of_mut!(completed_bytes),
            off,
            len,
            buf.len(),
            core::ptr::addr_of!(mixed_bytes),
            &mut progress_receipt,
        );
        if unsafe { core::ptr::read_volatile(&progress_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        // Defense in depth against any wrong-target progress publication at
        // the raw-pointer call boundary. This proof is separate from the
        // publisher and must observe the canonical cursor at exactly off+len
        // before the next iteration can begin.
        let expected_next = match off.checked_add(len) {
            Some(next) if next <= buf.len() => next,
            _ => {
                buf.zeroize();
                optiga_block.zeroize();
                se050_block.zeroize();
                platform_block.zeroize();
                crate::fi::zeroize_barrier();
                return;
            }
        };
        let mut published_completion_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(
                &mut published_completion_receipt,
                crate::fi::FAIL_SENTINEL,
            );
        }
        verify_exact_completion_into(
            &completed_bytes,
            expected_next,
            &mut published_completion_receipt,
        );
        if unsafe { core::ptr::read_volatile(&published_completion_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&published_completion_receipt) }
            != crate::fi::OK_SENTINEL
        {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&progress_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            optiga_block.zeroize();
            se050_block.zeroize();
            platform_block.zeroize();
            crate::fi::zeroize_barrier();
            return;
        }
    }

    // Do not infer success merely from falling through the outer loop: a
    // skipped/inverted backedge can reach here after a proper prefix. Bind the
    // fold receipt to an independent exact volatile completion proof first.
    let mut completion_receipt = crate::fi::FAIL_SENTINEL;
    unsafe {
        core::ptr::write_volatile(&mut completion_receipt, crate::fi::FAIL_SENTINEL);
    }
    verify_exact_completion_into(&completed_bytes, buf.len(), &mut completion_receipt);
    if unsafe { core::ptr::read_volatile(&completion_receipt) } != crate::fi::OK_SENTINEL {
        buf.zeroize();
        optiga_block.zeroize();
        se050_block.zeroize();
        platform_block.zeroize();
        crate::fi::zeroize_barrier();
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&completion_receipt) } != crate::fi::OK_SENTINEL {
        buf.zeroize();
        optiga_block.zeroize();
        se050_block.zeroize();
        platform_block.zeroize();
        crate::fi::zeroize_barrier();
        return;
    }
    optiga_block.zeroize();
    se050_block.zeroize();
    platform_block.zeroize();
    crate::fi::zeroize_barrier();
    // SAFETY: unique caller-owned stack local. This store is unconditional on
    // the only path that completed every chunk after both codegen-stable
    // receipt checks. Failure paths returned above with a wiped output.
    unsafe {
        core::ptr::write_volatile(fold_receipt, crate::fi::OK_SENTINEL);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        fold_se_sources, publish_verified_progress_into, source_chunk_len,
        verify_committed_source_history_into, verify_exact_completion_into,
        verify_mixed_chunk_into, verify_nonzero_output_twice_into, SeSource, SourceRepeatState,
        MIN_SOURCE_BLOCK, SOURCE_HISTORY_POISONED, SOURCE_HISTORY_READY,
    };

    fn fold_succeeded(buf: &mut [u8], draw: impl FnMut(SeSource, &mut [u8]) -> bool) -> bool {
        let mut history = SourceRepeatState::new();
        fold_succeeded_with_history(buf, draw, &mut history)
    }

    fn fold_succeeded_with_history(
        buf: &mut [u8],
        draw: impl FnMut(SeSource, &mut [u8]) -> bool,
        history: &mut SourceRepeatState,
    ) -> bool {
        let mut receipt = crate::fi::FAIL_SENTINEL;
        fold_se_sources(buf, draw, history, &mut receipt);
        receipt == crate::fi::OK_SENTINEL
    }

    fn mix_receipt(mixed: &[u8], platform: &[u8], optiga: &[u8], se050: &[u8]) -> u32 {
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_mixed_chunk_into(mixed, platform, optiga, se050, &mut receipt);
        receipt
    }

    fn completion_receipt(completed: usize, expected: usize) -> u32 {
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_exact_completion_into(&completed, expected, &mut receipt);
        receipt
    }

    fn progress_receipt_with_mixed(
        completed: &mut usize,
        current: usize,
        len: usize,
        total: usize,
        mixed: usize,
    ) -> u32 {
        let mut receipt = crate::fi::FAIL_SENTINEL;
        publish_verified_progress_into(
            core::ptr::addr_of_mut!(*completed),
            current,
            len,
            total,
            core::ptr::addr_of!(mixed),
            &mut receipt,
        );
        receipt
    }

    fn progress_receipt(completed: &mut usize, current: usize, len: usize, total: usize) -> u32 {
        progress_receipt_with_mixed(completed, current, len, total, len)
    }

    fn nonzero_receipt(buf: &[u8]) -> u32 {
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_nonzero_output_twice_into(buf, &mut receipt);
        receipt
    }

    #[test]
    fn exact_completion_receipt_rejects_every_prefix_and_overshoot() {
        for total in [0usize, 8, 31, 32, 33, 40, 48, 63, 64, 65, 96] {
            for prefix in 0..total {
                assert_eq!(
                    completion_receipt(prefix, total),
                    crate::fi::FAIL_SENTINEL,
                    "proper prefix {prefix}/{total} must not complete the fold"
                );
            }
            assert_eq!(
                completion_receipt(total, total),
                crate::fi::OK_SENTINEL,
                "exact completion {total}/{total} must pass"
            );
            assert_eq!(
                completion_receipt(total.saturating_add(1), total),
                crate::fi::FAIL_SENTINEL,
                "overshoot must not satisfy exact completion"
            );
        }
    }

    #[test]
    fn exact_mixer_completion_rejects_the_48_byte_trace_one_byte_overshoot() {
        // In a 48-byte request, a faulted first 32-byte mixer iteration count
        // of 33 means byte 32 was modified before the 16-byte tail snapshotted
        // its platform baseline. The per-chunk relation alone cannot see that
        // history; this exact pre-verifier gate must reject it.
        assert_eq!(completion_receipt(33, 32), crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verified_progress_rejects_stale_prior_frame_offset() {
        // Models the freeze11 instruction-omission trace: the canonical record
        // was freshly initialized for this call, but an old cursor spill still
        // says the prior 64-byte call had reached its second chunk.
        let mut completed = 0usize;
        assert_eq!(
            progress_receipt(&mut completed, 32, 32, 64),
            crate::fi::FAIL_SENTINEL
        );
        assert_eq!(completed, 0, "stale cursor must not advance completion");
    }

    #[test]
    fn verified_progress_publishes_each_exact_chunk_in_order() {
        let mut completed = 0usize;
        assert_eq!(
            progress_receipt(&mut completed, 0, 32, 64),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(completed, 32);
        assert_eq!(
            progress_receipt(&mut completed, 32, 32, 64),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(completed, 64);
    }

    #[test]
    fn omitted_progress_publisher_leaves_caller_receipt_failed() {
        let mut progress_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut progress_receipt, crate::fi::FAIL_SENTINEL);
        }
        // Intentionally omit `publish_verified_progress_into`, matching a
        // skipped BL at the production call site.
        assert_eq!(progress_receipt, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verified_progress_rejects_metadata_not_bound_to_mixer_count() {
        let mut completed = 0usize;
        assert_eq!(
            progress_receipt_with_mixed(&mut completed, 0, 8, 8, 32),
            crate::fi::FAIL_SENTINEL
        );
        assert_eq!(completed, 0);
    }

    #[test]
    fn verified_progress_rejects_fault_created_cursor_mixer_alias() {
        let mut aliased = 32usize;
        let mut receipt = crate::fi::FAIL_SENTINEL;
        publish_verified_progress_into(
            core::ptr::addr_of_mut!(aliased),
            32,
            32,
            64,
            core::ptr::addr_of!(aliased),
            &mut receipt,
        );
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
        assert_eq!(aliased, 32, "an aliased publisher must not advance either slot");
    }

    #[test]
    fn final_output_receipt_rejects_empty_and_all_zero_buffers() {
        assert_eq!(nonzero_receipt(&[]), crate::fi::FAIL_SENTINEL);
        for len in [8usize, 16, 32, 33, 48, 64, 65] {
            let zeros = std::vec![0u8; len];
            assert_eq!(nonzero_receipt(&zeros), crate::fi::FAIL_SENTINEL);
            let mut nonzero = zeros;
            nonzero[len - 1] = 1;
            assert_eq!(nonzero_receipt(&nonzero), crate::fi::OK_SENTINEL);
        }
    }

    #[test]
    fn committed_history_relation_rejects_either_corrupted_source_baseline() {
        let optiga = [0x22u8; MIN_SOURCE_BLOCK];
        let se050 = [0x44u8; MIN_SOURCE_BLOCK];
        let mut history = SourceRepeatState::new();
        history.optiga[..MIN_SOURCE_BLOCK].copy_from_slice(&optiga);
        history.se050[..MIN_SOURCE_BLOCK].copy_from_slice(&se050);
        history.len = MIN_SOURCE_BLOCK;
        history.status = SOURCE_HISTORY_READY;

        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_committed_source_history_into(&optiga, &se050, &history, &mut receipt);
        assert_eq!(receipt, crate::fi::OK_SENTINEL);

        history.optiga[3] ^= 1;
        receipt = crate::fi::OK_SENTINEL;
        verify_committed_source_history_into(&optiga, &se050, &history, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
        history.optiga[3] ^= 1;

        history.se050[5] ^= 1;
        receipt = crate::fi::OK_SENTINEL;
        verify_committed_source_history_into(&optiga, &se050, &history, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn exact_mix_receipt_accepts_only_the_full_three_source_relation() {
        let platform = [0x11u8; 32];
        let optiga = [0x22u8; 32];
        let se050 = [0x44u8; 32];
        let mixed = [0x11 ^ 0x22 ^ 0x44; 32];
        assert_eq!(
            mix_receipt(&mixed, &platform, &optiga, &se050),
            crate::fi::OK_SENTINEL
        );

        let mut only_first_byte_mixed = platform;
        only_first_byte_mixed[0] ^= optiga[0] ^ se050[0];
        assert_eq!(
            mix_receipt(&only_first_byte_mixed, &platform, &optiga, &se050),
            crate::fi::FAIL_SENTINEL,
            "a fault-shortened XOR loop must not mint the completion receipt"
        );

        let mut one_optiga_xor_missing = mixed;
        one_optiga_xor_missing[17] ^= optiga[17];
        assert_eq!(
            mix_receipt(&one_optiga_xor_missing, &platform, &optiga, &se050),
            crate::fi::FAIL_SENTINEL,
            "omitting either source from any changed byte must fail readback"
        );
    }

    #[test]
    fn exact_mix_receipt_fail_initializes_and_rejects_shape_mismatch() {
        let mut receipt = crate::fi::OK_SENTINEL;
        verify_mixed_chunk_into(&[1u8; 8], &[1u8; 7], &[2u8; 8], &[3u8; 8], &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);

        receipt = crate::fi::OK_SENTINEL;
        verify_mixed_chunk_into(&[], &[], &[], &[], &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    /// F27 regression: each chunk of a multi-chunk fill must fold its
    /// OWN fresh SE block. If the fold reused the previous chunk's block (the
    /// F27 bug), the tail would silently re-fold chunk 1's stream.
    #[test]
    fn fold_se_blocks_each_chunk_folds_fresh_block_only() {
        // Two scripted SE streams: chunk 1 (32 B) and chunk 2 (16 B).
        let s1 = [0xA5u8; 32];
        let s2 = [0x5Au8; 16];
        let t1 = [0x3Cu8; 32];
        let t2 = [0xC3u8; 16];
        let mut optiga_chunks = [&s1[..], &s2[..]].into_iter();
        let mut se050_chunks = [&t1[..], &t2[..]].into_iter();
        let mut draw = |source: SeSource, block: &mut [u8]| match source {
            SeSource::Optiga => {
                let s = optiga_chunks.next().expect("exactly one draw per chunk");
                assert_eq!(s.len(), block.len());
                block.copy_from_slice(s);
                true
            }
            SeSource::Se050 => {
                let s = se050_chunks.next().expect("exactly one draw per chunk");
                assert_eq!(s.len(), block.len());
                block.copy_from_slice(s);
                true
            }
        };

        // 48-byte request → two chunks (32 + 16).
        let platform = [0x11u8; 48];
        let mut buf = platform;
        assert!(fold_succeeded(&mut buf, &mut draw));

        let mut expected = platform;
        for i in 0..32 {
            expected[i] ^= s1[i] ^ t1[i];
        }
        for i in 0..16 {
            expected[32 + i] ^= s2[i] ^ t2[i];
        }
        assert_eq!(buf, expected);
        // The explicit F27 violation shape: the tail must NOT carry
        // chunk 1's stream folded in alongside chunk 2's.
        for i in 0..16 {
            assert_ne!(buf[32 + i], platform[32 + i] ^ s1[i] ^ s2[i] ^ t2[i]);
        }
    }

    /// A failed draw aborts the fold immediately (production treats an
    /// absent SE contribution as fatal) and wipes the platform baseline.
    #[test]
    fn fold_se_blocks_stops_at_first_failed_draw() {
        let mut optiga_calls = 0usize;
        let mut se050_calls = 0usize;
        let mut buf = [0x11u8; 48];
        let ok = fold_succeeded(&mut buf, &mut |source, block: &mut [u8]| match source {
            SeSource::Optiga => {
                optiga_calls += 1;
                false
            }
            SeSource::Se050 => {
                se050_calls += 1;
                block.fill(0x5A);
                true
            }
        });
        assert!(!ok);
        assert_eq!(optiga_calls, 1);
        assert_eq!(se050_calls, 1, "both mandatory sources are sampled once");
        assert_eq!(buf, [0u8; 48]);
    }

    /// Chunk boundaries: a 32-byte request folds exactly one block; an
    /// empty buffer performs no draw at all.
    #[test]
    fn fold_se_blocks_chunk_boundaries() {
        let mut optiga_calls = 0usize;
        let mut se050_calls = 0usize;
        let mut buf = [0x11u8; 32];
        assert!(fold_succeeded(&mut buf, &mut |source, block: &mut [u8]| {
            assert_eq!(block.len(), 32);
            match source {
                SeSource::Optiga => {
                    optiga_calls += 1;
                    block.fill(0xA5);
                }
                SeSource::Se050 => {
                    se050_calls += 1;
                    block.fill(0x5A);
                }
            }
            true
        }));
        assert_eq!(optiga_calls, 1);
        assert_eq!(se050_calls, 1);

        let mut empty = [0u8; 0];
        assert!(fold_succeeded(
            &mut empty,
            &mut |_source, _block: &mut [u8]| {
                optiga_calls += 1;
                true
            }
        ));
        assert_eq!(optiga_calls, 1, "empty buffer must not draw");
    }

    #[test]
    fn fold_se_sources_never_creates_a_subminimum_tail() {
        let mut lengths = std::vec::Vec::new();
        let mut optiga_draws = 0u8;
        let mut se050_draws = 0u8;
        let mut buf = [0x11u8; 33];
        assert!(fold_succeeded(&mut buf, |source, block| {
            if source == SeSource::Optiga {
                lengths.push(block.len());
                optiga_draws = optiga_draws.wrapping_add(1);
                block.fill(0x22u8.wrapping_add(optiga_draws));
            } else {
                se050_draws = se050_draws.wrapping_add(1);
                block.fill(0x44u8.wrapping_add(se050_draws));
            }
            true
        }));
        assert_eq!(lengths, [25, 8]);

        let mut too_short = [0x11u8; MIN_SOURCE_BLOCK - 1];
        let mut calls = 0usize;
        assert!(!fold_succeeded(&mut too_short, |_source, _block| {
            calls += 1;
            true
        }));
        assert_eq!(calls, 0);
        assert_eq!(too_short, [0u8; MIN_SOURCE_BLOCK - 1]);

        assert_eq!(source_chunk_len(48), 32);
        assert_eq!(source_chunk_len(65), 32);
        assert_eq!(source_chunk_len(33), 25);
        assert_eq!(source_chunk_len(40), 32);
    }

    #[test]
    fn fold_rejects_one_replayed_physical_source_across_chunks() {
        let mut optiga_calls = 0u8;
        let mut se050_calls = 0u8;
        let mut buf = [0x11u8; 64];
        assert!(!fold_succeeded(&mut buf, |source, block| {
            match source {
                SeSource::Optiga => {
                    optiga_calls = optiga_calls.wrapping_add(1);
                    block.fill(0x22); // stuck/replayed on chunk two
                }
                SeSource::Se050 => {
                    se050_calls = se050_calls.wrapping_add(1);
                    block.fill(0x44u8.wrapping_add(se050_calls));
                }
            }
            true
        }));
        assert_eq!(optiga_calls, 2);
        assert_eq!(se050_calls, 2);
        assert_eq!(buf, [0u8; 64]);
    }

    #[test]
    fn fold_rejects_replayed_source_across_calls_and_different_lengths() {
        let mut history = SourceRepeatState::new();
        let mut first = [0x11u8; 32];
        assert!(fold_succeeded_with_history(
            &mut first,
            |source, block| {
                block.fill(match source {
                    SeSource::Optiga => 0x22,
                    SeSource::Se050 => 0x44,
                });
                true
            },
            &mut history,
        ));

        let mut second = [0x12u8; 8];
        assert!(!fold_succeeded_with_history(
            &mut second,
            |source, block| {
                block.fill(match source {
                    SeSource::Optiga => 0x23,
                    SeSource::Se050 => 0x44, // repeated shared prefix
                });
                true
            },
            &mut history,
        ));
        assert_eq!(second, [0u8; 8]);
    }

    /// Model a fault that omits `commit_source_history_into` after the current
    /// source blocks passed both health scans. The caller-side poison must be
    /// sticky, so a source that repeats the newly observed B on the next call
    /// cannot be accepted against the older A baseline.
    #[test]
    fn omitted_history_commit_poison_rejects_next_repeated_source() {
        let mut history = SourceRepeatState::new();
        let mut first = [0x11u8; 32];
        assert!(fold_succeeded_with_history(
            &mut first,
            |source, block| {
                block.fill(match source {
                    SeSource::Optiga => 0x22,
                    SeSource::Se050 => 0x44,
                });
                true
            },
            &mut history,
        ));

        // Exact state left by the production caller when the publisher's BL
        // is omitted: fail receipt plus duplicate caller-owned poison stores.
        unsafe {
            core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_POISONED);
            core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_POISONED);
        }

        let mut retry = [0x12u8; 32];
        assert!(!fold_succeeded_with_history(
            &mut retry,
            |source, block| {
                block.fill(match source {
                    SeSource::Optiga => 0x23,
                    SeSource::Se050 => 0x45,
                });
                true
            },
            &mut history,
        ));
        assert_eq!(retry, [0u8; 32]);
    }

    /// Regression for an optimized-ARM stale destination-offset trace in the
    /// second history copy. The exact copier must reject the mismatch without
    /// treating the fault-derived pointer as a cleanup target: clearing the
    /// poison to EMPTY would disable the next-call repetition baseline.
    #[test]
    fn rejected_history_destination_redirect_cannot_clear_poison() {
        let mut history = SourceRepeatState::new();
        let mut first = [0x11u8; MIN_SOURCE_BLOCK];
        assert!(fold_succeeded_with_history(
            &mut first,
            |source, block| {
                block.fill(match source {
                    SeSource::Optiga => 0x22,
                    SeSource::Se050 => 0x44,
                });
                true
            },
            &mut history,
        ));

        // Model the publisher after the next OPTIGA baseline copy succeeded
        // and after both caller/publisher poison stores, immediately before a
        // stale offset redirects the SE050 copy to `history.status`.
        let optiga_b = [0x23u8; MIN_SOURCE_BLOCK];
        let se050_b = [0x45u8; MIN_SOURCE_BLOCK];
        history.optiga[..MIN_SOURCE_BLOCK].copy_from_slice(&optiga_b);
        unsafe {
            core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_POISONED);
            core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_POISONED);
        }
        let history_se050_base = history.se050.as_mut_ptr();
        let redirected_status = core::ptr::addr_of_mut!(history.status).cast::<u8>();
        let stale_offset = (redirected_status as usize).wrapping_sub(history_se050_base as usize);
        let expected_source = se050_b.as_ptr();
        let expected_destination = history_se050_base.cast_const();
        let mut copy_receipt = crate::fi::FAIL_SENTINEL;
        crate::rng_exact::copy_exact_into(
            se050_b.as_ptr(),
            core::ptr::addr_of!(expected_source),
            core::mem::size_of::<u32>(),
            history_se050_base,
            stale_offset,
            core::ptr::addr_of!(expected_destination),
            core::mem::size_of::<u32>(),
            &mut copy_receipt,
        );
        assert_eq!(copy_receipt, crate::fi::FAIL_SENTINEL);
        assert_eq!(history.status, SOURCE_HISTORY_POISONED);

        let mut retry = [0x12u8; MIN_SOURCE_BLOCK];
        assert!(!fold_succeeded_with_history(
            &mut retry,
            |source, block| {
                block.copy_from_slice(match source {
                    SeSource::Optiga => &optiga_b,
                    SeSource::Se050 => &se050_b,
                });
                true
            },
            &mut history,
        ));
        assert_eq!(retry, [0u8; MIN_SOURCE_BLOCK]);
    }

    /// A backend that reports success without changing the fresh-zero scratch
    /// did not contribute entropy. Reject before touching platform bytes.
    #[test]
    fn fold_se_blocks_rejects_zero_contribution_without_xor() {
        let mut buf = [0x11u8; 32];
        assert!(!fold_succeeded(&mut buf, |source, block| {
            if source == SeSource::Se050 {
                block.fill(0x5A);
            }
            true
        }));
        assert_eq!(buf, [0u8; 32]);
    }

    #[test]
    fn fold_se_sources_rejects_each_missing_or_equal_leg() {
        for missing in 0..2 {
            let mut buf = [0x11u8; 32];
            let ok = fold_succeeded(&mut buf, |source, block| {
                match source {
                    SeSource::Optiga if missing != 0 => block.fill(0xA5),
                    SeSource::Se050 if missing != 1 => block.fill(0x5A),
                    _ => {}
                }
                true
            });
            assert!(!ok);
            assert_eq!(buf, [0u8; 32]);
        }

        let mut equal = [0x11u8; 32];
        assert!(!fold_succeeded(&mut equal, |_source, block| {
            block.fill(0xA5);
            true
        }));
        assert_eq!(equal, [0u8; 32]);

        let mut platform_equals_optiga = [0x11u8; 32];
        assert!(!fold_succeeded(
            &mut platform_equals_optiga,
            |source, block| {
                block.fill(match source {
                    SeSource::Optiga => 0x11,
                    SeSource::Se050 => 0x44,
                });
                true
            }
        ));
        assert_eq!(platform_equals_optiga, [0u8; 32]);

        let mut platform_equals_se050 = [0x11u8; 32];
        assert!(!fold_succeeded(
            &mut platform_equals_se050,
            |source, block| {
                block.fill(match source {
                    SeSource::Optiga => 0x22,
                    SeSource::Se050 => 0x11,
                });
                true
            }
        ));
        assert_eq!(platform_equals_se050, [0u8; 32]);

        let mut zero_platform = [0u8; 32];
        assert!(!fold_succeeded(&mut zero_platform, |source, block| {
            block.fill(match source {
                SeSource::Optiga => 0x22,
                SeSource::Se050 => 0x44,
            });
            true
        }));
        assert_eq!(zero_platform, [0u8; 32]);
    }

    #[test]
    fn fold_se_sources_mixes_platform_optiga_se050_once() {
        let mut optiga_calls = 0usize;
        let mut se050_calls = 0usize;
        let mut buf = [0x11u8; 32];
        assert!(fold_succeeded(&mut buf, |source, block| {
            match source {
                SeSource::Optiga => {
                    optiga_calls += 1;
                    block.fill(0x22);
                }
                SeSource::Se050 => {
                    se050_calls += 1;
                    block.fill(0x44);
                }
            }
            true
        }));
        assert_eq!(buf, [0x11 ^ 0x22 ^ 0x44; 32]);
        assert_eq!(optiga_calls, 1);
        assert_eq!(se050_calls, 1);
    }

    #[test]
    fn fold_multi_chunk_every_byte_matches_platform_optiga_se050() {
        let mut platform = [0u8; 65];
        for (i, byte) in platform.iter_mut().enumerate() {
            *byte = 0x80u8.wrapping_add(i as u8);
        }
        let mut buf = platform;
        let mut optiga_chunks = 0u8;
        let mut se050_chunks = 0u8;
        assert!(fold_succeeded(&mut buf, |source, block| {
            match source {
                SeSource::Optiga => {
                    optiga_chunks = optiga_chunks.wrapping_add(1);
                    for (i, byte) in block.iter_mut().enumerate() {
                        *byte = 0x11u8
                            .wrapping_add(optiga_chunks)
                            .wrapping_add((i as u8).wrapping_mul(3));
                    }
                }
                SeSource::Se050 => {
                    se050_chunks = se050_chunks.wrapping_add(1);
                    for (i, byte) in block.iter_mut().enumerate() {
                        *byte = 0x51u8
                            .wrapping_add(se050_chunks)
                            .wrapping_add((i as u8).wrapping_mul(5));
                    }
                }
            }
            true
        }));
        assert_eq!(optiga_chunks, 3);
        assert_eq!(se050_chunks, 3);

        let chunk_lengths = [32usize, 25, 8];
        let mut off = 0usize;
        for (chunk_index, len) in chunk_lengths.into_iter().enumerate() {
            for i in 0..len {
                let optiga = 0x11u8
                    .wrapping_add(chunk_index as u8 + 1)
                    .wrapping_add((i as u8).wrapping_mul(3));
                let se050 = 0x51u8
                    .wrapping_add(chunk_index as u8 + 1)
                    .wrapping_add((i as u8).wrapping_mul(5));
                assert_eq!(buf[off + i], platform[off + i] ^ optiga ^ se050);
                assert_ne!(buf[off + i], platform[off + i]);
                assert_ne!(buf[off + i], platform[off + i] ^ optiga);
                assert_ne!(buf[off + i], platform[off + i] ^ se050);
            }
            off += len;
        }
        assert_eq!(off, buf.len());
    }

    #[test]
    fn fold_se_sources_failure_overwrites_stale_ok_and_wipes_partial_output() {
        let mut receipt = crate::fi::OK_SENTINEL;
        let mut history = SourceRepeatState::new();
        let mut optiga_calls = 0usize;
        let mut buf = [0x11u8; 48];
        fold_se_sources(
            &mut buf,
            |source, block| {
                match source {
                    SeSource::Optiga => {
                        optiga_calls += 1;
                        block.fill(0x22u8.wrapping_add(optiga_calls as u8));
                    }
                    SeSource::Se050 => {
                        block.fill(0x44u8.wrapping_add(optiga_calls as u8));
                        if optiga_calls == 2 {
                            return false;
                        }
                    }
                }
                true
            },
            &mut history,
            &mut receipt,
        );

        assert_eq!(optiga_calls, 2, "failure occurs after one folded chunk");
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
        assert_eq!(buf, [0u8; 48], "no partially three-source buffer escapes");
    }
}
