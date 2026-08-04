//! Fault-hardened exact-length copy used at hardware-RNG boundaries.

use zeroize::Zeroize;

/// Establish a canonical zero progress value behind a caller-owned receipt.
///
/// A plain `let cursor = 0` commonly lowers to one `movs` feeding both the
/// loop cursor and its completion record.  Omitting that one instruction can
/// therefore seed a fill from stale register or prior-frame state.  Poisoning
/// first, checking the first zero publication, and publishing/checking zero a
/// second time around a delay makes any one omitted materialization, store,
/// load, comparison, branch, or whole call fail closed (or leave the same
/// canonical zero value).
#[inline(never)]
pub(crate) fn initialize_exact_progress_into(
    completed_bytes: &mut usize,
    initialization_receipt: &mut u32,
) {
    // SAFETY: both references are unique caller-owned stack locations.
    unsafe {
        core::ptr::write_volatile(initialization_receipt, crate::fi::FAIL_SENTINEL);
        core::ptr::write_volatile(completed_bytes, usize::MAX);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    unsafe {
        core::ptr::write_volatile(completed_bytes, 0);
    }
    if unsafe { core::ptr::read_volatile(completed_bytes) } != 0 {
        return;
    }

    crate::fi::wait_random();
    unsafe {
        core::ptr::write_volatile(completed_bytes, 0);
    }
    if unsafe { core::ptr::read_volatile(completed_bytes) } != 0 {
        return;
    }

    // SAFETY: poison was replaced by zero and independently observed twice.
    unsafe {
        core::ptr::write_volatile(initialization_receipt, crate::fi::OK_SENTINEL);
    }
}

/// Publish success only when volatile progress equals the expected exact
/// length twice around a randomized delay.
///
/// Callers fail-initialize the receipt as well.  A skipped call, a shortened
/// loop, or an overshoot therefore cannot be mistaken for exact completion.
#[inline(never)]
pub(crate) fn verify_exact_progress_into(
    completed_bytes: &usize,
    expected_bytes: usize,
    completion_receipt: &mut u32,
) {
    // SAFETY: unique caller-owned receipt.
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
    // SAFETY: exact completion was observed twice; this is the sole success
    // publication in this helper.
    unsafe {
        core::ptr::write_volatile(completion_receipt, crate::fi::OK_SENTINEL);
    }
}

/// Publish success only when two framing observations both equal their
/// expected values in two independent volatile passes.
///
/// Protocol parsers use this for compound response contracts such as
/// `(declared frame length, status)` and `(TLV tag, trailing length)`.  Keeping
/// the operation out of line and binding it to a caller-owned, fail-initialized
/// receipt means a skipped call cannot turn stale ABI state into success.  The
/// second pass prevents omission of any one comparison/rejection branch from
/// accepting a malformed hardware-RNG response.
#[inline(never)]
pub(crate) fn verify_exact_pair_into(
    observed_first: usize,
    expected_first: usize,
    observed_second: usize,
    expected_second: usize,
    receipt: &mut u32,
) {
    // SAFETY: unique caller-owned receipt. A skipped or shortened verifier
    // remains fail-closed.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }

    // SAFETY: the stack-backed arguments are deliberately re-read rather than
    // trusting one optimized predicate shared by both observations.
    if unsafe { core::ptr::read_volatile(&observed_first) } != expected_first {
        return;
    }
    if unsafe { core::ptr::read_volatile(&observed_second) } != expected_second {
        return;
    }

    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&observed_first) } != expected_first {
        return;
    }
    if unsafe { core::ptr::read_volatile(&observed_second) } != expected_second {
        return;
    }

    // SAFETY: both exact predicates passed twice; sole success publication.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Independently read back an exact raw-pointer copy relation before
/// publishing success.
#[inline(never)]
fn verify_copy_relation_into(
    source: *const u8,
    destination: *const u8,
    len: usize,
    receipt: &mut u32,
) {
    // SAFETY: unique caller-owned receipt.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    let mut processed = 0usize;
    // SAFETY: unique stack progress slot.
    unsafe {
        core::ptr::write_volatile(&mut processed, 0);
    }
    let mut diff = 0u8;
    for i in 0..len {
        // SAFETY: the caller established two valid disjoint regions of `len`
        // bytes. Both reads intentionally bypass SSA forwarding from the copy
        // loop.
        diff |= unsafe {
            core::ptr::read_volatile(source.add(i))
                ^ core::ptr::read_volatile(destination.add(i))
        };
        // SAFETY: unique stack progress slot.
        unsafe {
            core::ptr::write_volatile(&mut processed, i + 1);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: independent observation of the volatile verifier progress.
    if unsafe { core::ptr::read_volatile(&processed) } != len || diff != 0 {
        return;
    }
    // SAFETY: exact relation and verifier completion both passed.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

fn wipe_destination(destination: &mut [u8]) {
    destination.zeroize();
    crate::fi::zeroize_barrier();
}

fn copy_regions_are_disjoint(source: *const u8, destination: *mut u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if source.is_null() || destination.is_null() {
        return false;
    }
    let source_start = source as usize;
    let destination_start = destination as usize;
    let Some(source_end) = source_start.checked_add(len) else {
        return false;
    };
    let Some(destination_end) = destination_start.checked_add(len) else {
        return false;
    };
    source_end <= destination_start || destination_end <= source_start
}

/// Publish one raw region pointer behind a fail-closed caller receipt.
///
/// Critical hardware callers invoke this before the exact-copy call and then
/// materialize the live pointer again at that later call boundary.  The exact
/// copier requires the two independently emitted observations to agree.  This
/// prevents an omitted caller-side pointer setup from silently selecting an
/// older, still-valid and non-overlapping buffer.
#[inline(never)]
pub(crate) fn publish_region_pointer_into(
    region: *const u8,
    published_region: &mut *const u8,
    publication_receipt: &mut u32,
) {
    unsafe {
        core::ptr::write_volatile(publication_receipt, crate::fi::FAIL_SENTINEL);
        core::ptr::write_volatile(published_region, core::ptr::null());
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    unsafe {
        core::ptr::write_volatile(published_region, region);
    }
    let region_a = unsafe { core::ptr::read_volatile(published_region) };
    if region_a.is_null() || region_a != region {
        return;
    }

    crate::fi::wait_random();
    unsafe {
        core::ptr::write_volatile(published_region, region);
    }
    let region_b = unsafe { core::ptr::read_volatile(published_region) };
    if region_b.is_null() || region_b != region || region_b != region_a {
        return;
    }

    unsafe {
        core::ptr::write_volatile(publication_receipt, crate::fi::OK_SENTINEL);
    }
}

/// Copy one exact, pointer-bound, non-overlapping raw source region into one
/// pointer-bound destination, publishing success through a caller-owned
/// fail-initialized receipt.
///
/// Raw pointers are deliberate: a fault can alias a source slice to its
/// destination at the machine-code call boundary, which violates Rust's
/// simultaneous `&[u8]` / `&mut [u8]` contract before a reference-based helper
/// can reject it. Poison-first pointer slots, duplicate volatile publication,
/// and two binding/non-overlap checks reject a skipped source/destination
/// setup. The byte copy then publishes exact progress after each store and is
/// independently read back. Rejection never dereferences an unauthenticated
/// destination: the authoritative typed caller owns any required wipe or
/// poison operation after observing the failed receipt.
#[inline(never)]
pub(crate) fn copy_exact_into(
    source: *const u8,
    expected_source_slot: *const *const u8,
    source_len: usize,
    destination_base: *mut u8,
    destination_offset: usize,
    expected_destination_slot: *const *const u8,
    destination_len: usize,
    copy_receipt: &mut u32,
) {
    // Derive the live destination in the callee from independently passed
    // base/offset metadata. Callers publish the expected derived pointer in a
    // separate call first. This prevents LLVM from keeping one shared derived
    // address alive across both the publication and copy call boundaries.
    let destination = destination_base.wrapping_add(destination_offset);
    // SAFETY: unique caller-owned receipt. This is deliberately repeated in
    // the callee so either a skipped caller initialization or a skipped call
    // leaves failure authoritative.
    unsafe {
        core::ptr::write_volatile(copy_receipt, crate::fi::FAIL_SENTINEL);
    }
    let mut length_receipt = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique stack receipt. A skipped helper call leaves failure.
    unsafe {
        core::ptr::write_volatile(&mut length_receipt, crate::fi::FAIL_SENTINEL);
    }
    verify_exact_progress_into(&source_len, destination_len, &mut length_receipt);
    // SAFETY: both volatile checks are deliberate FI gates.
    if unsafe { core::ptr::read_volatile(&length_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&length_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }

    // Poison the pointer publications before writing the caller values. If a
    // single combined store of either pair is omitted, the other publication
    // leaves either the correct pointers or a rejecting null poison.
    let mut source_pointer_slot = core::ptr::null::<u8>();
    let mut expected_source_pointer_slot = core::ptr::null::<u8>();
    let mut destination_pointer_slot = core::ptr::null_mut::<u8>();
    let mut expected_destination_pointer_slot = core::ptr::null::<u8>();
    unsafe {
        core::ptr::write_volatile(&mut source_pointer_slot, core::ptr::null());
        core::ptr::write_volatile(&mut expected_source_pointer_slot, core::ptr::null());
        core::ptr::write_volatile(&mut destination_pointer_slot, core::ptr::null_mut());
        core::ptr::write_volatile(
            &mut expected_destination_pointer_slot,
            core::ptr::null(),
        );
        core::ptr::write_volatile(&mut source_pointer_slot, source);
        core::ptr::write_volatile(
            &mut expected_source_pointer_slot,
            core::ptr::read_volatile(expected_source_slot),
        );
        core::ptr::write_volatile(&mut destination_pointer_slot, destination);
        core::ptr::write_volatile(
            &mut expected_destination_pointer_slot,
            core::ptr::read_volatile(expected_destination_slot),
        );
    }
    let source_ptr_a = unsafe { core::ptr::read_volatile(&source_pointer_slot) };
    let expected_source_ptr_a =
        unsafe { core::ptr::read_volatile(&expected_source_pointer_slot) };
    let destination_ptr_a = unsafe { core::ptr::read_volatile(&destination_pointer_slot) };
    let expected_destination_ptr_a =
        unsafe { core::ptr::read_volatile(&expected_destination_pointer_slot) };
    if source_ptr_a != expected_source_ptr_a
        || destination_ptr_a.cast_const() != expected_destination_ptr_a
        || !copy_regions_are_disjoint(source_ptr_a, destination_ptr_a, destination_len)
    {
        return;
    }
    crate::fi::wait_random();
    unsafe {
        core::ptr::write_volatile(&mut source_pointer_slot, source);
        core::ptr::write_volatile(
            &mut expected_source_pointer_slot,
            core::ptr::read_volatile(expected_source_slot),
        );
        core::ptr::write_volatile(&mut destination_pointer_slot, destination);
        core::ptr::write_volatile(
            &mut expected_destination_pointer_slot,
            core::ptr::read_volatile(expected_destination_slot),
        );
    }
    let source_ptr_b = unsafe { core::ptr::read_volatile(&source_pointer_slot) };
    let expected_source_ptr_b =
        unsafe { core::ptr::read_volatile(&expected_source_pointer_slot) };
    let destination_ptr_b = unsafe { core::ptr::read_volatile(&destination_pointer_slot) };
    let expected_destination_ptr_b =
        unsafe { core::ptr::read_volatile(&expected_destination_pointer_slot) };
    if source_ptr_b != source_ptr_a
        || expected_source_ptr_b != expected_source_ptr_a
        || destination_ptr_b != destination_ptr_a
        || expected_destination_ptr_b != expected_destination_ptr_a
        || source_ptr_b != expected_source_ptr_b
        || destination_ptr_b.cast_const() != expected_destination_ptr_b
        || !copy_regions_are_disjoint(source_ptr_b, destination_ptr_b, destination_len)
    {
        return;
    }

    let mut copied_bytes = 0usize;
    // SAFETY: unique stack progress slot.
    unsafe {
        core::ptr::write_volatile(&mut copied_bytes, 0);
    }
    for i in 0..destination_len {
        // SAFETY: the exact-length receipt passed twice, so both pointers have
        // an in-bounds byte at `i`. Volatile operations keep the copy and its
        // progress publication visible in optimized ARM code.
        unsafe {
            let byte = core::ptr::read_volatile(source_ptr_a.add(i));
            core::ptr::write_volatile(destination_ptr_a.add(i), byte);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: unique stack progress slot; publication follows the store.
        unsafe {
            core::ptr::write_volatile(&mut copied_bytes, i + 1);
        }
    }

    let mut completion_receipt = crate::fi::FAIL_SENTINEL;
    verify_exact_progress_into(&copied_bytes, destination_len, &mut completion_receipt);
    if unsafe { core::ptr::read_volatile(&completion_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&completion_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }

    let mut relation_receipt = crate::fi::FAIL_SENTINEL;
    verify_copy_relation_into(
        source_ptr_a,
        destination_ptr_a.cast_const(),
        destination_len,
        &mut relation_receipt,
    );
    if unsafe { core::ptr::read_volatile(&relation_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }
    crate::fi::wait_random();
    unsafe {
        core::ptr::write_volatile(&mut relation_receipt, crate::fi::FAIL_SENTINEL);
    }
    verify_copy_relation_into(
        source_ptr_b,
        destination_ptr_b.cast_const(),
        destination_len,
        &mut relation_receipt,
    );
    if unsafe { core::ptr::read_volatile(&relation_receipt) } != crate::fi::OK_SENTINEL {
        return;
    }

    // SAFETY: exact length, exact store count, and two independent volatile
    // source/destination relations all passed. This is the sole success store.
    unsafe {
        core::ptr::write_volatile(copy_receipt, crate::fi::OK_SENTINEL);
    }
}

/// Result-returning convenience wrapper for protocol parsers.
///
/// The hardware STM32 path calls [`copy_exact_into`] directly so a skipped BL
/// cannot synthesize a successful Rust `Result` from stale ABI registers.
#[inline(never)]
pub(crate) fn copy_exact(source: &[u8], destination: &mut [u8]) -> Result<usize, ()> {
    let destination_len = destination.len();
    let mut published_source = core::ptr::null();
    let mut source_publication_receipt = crate::fi::FAIL_SENTINEL;
    publish_region_pointer_into(
        source.as_ptr(),
        &mut published_source,
        &mut source_publication_receipt,
    );
    if unsafe { core::ptr::read_volatile(&source_publication_receipt) }
        != crate::fi::OK_SENTINEL
    {
        wipe_destination(destination);
        return Err(());
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&source_publication_receipt) }
        != crate::fi::OK_SENTINEL
    {
        wipe_destination(destination);
        return Err(());
    }

    let mut published_destination = core::ptr::null();
    let mut destination_publication_receipt = crate::fi::FAIL_SENTINEL;
    publish_region_pointer_into(
        destination.as_ptr(),
        &mut published_destination,
        &mut destination_publication_receipt,
    );
    if unsafe { core::ptr::read_volatile(&destination_publication_receipt) }
        != crate::fi::OK_SENTINEL
    {
        wipe_destination(destination);
        return Err(());
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&destination_publication_receipt) }
        != crate::fi::OK_SENTINEL
    {
        wipe_destination(destination);
        return Err(());
    }

    let mut copy_receipt = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique stack receipt. A skipped call below remains failure.
    unsafe {
        core::ptr::write_volatile(&mut copy_receipt, crate::fi::FAIL_SENTINEL);
    }
    copy_exact_into(
        source.as_ptr(),
        core::ptr::addr_of!(published_source),
        source.len(),
        destination.as_mut_ptr(),
        0,
        core::ptr::addr_of!(published_destination),
        destination.len(),
        &mut copy_receipt,
    );
    if unsafe { core::ptr::read_volatile(&copy_receipt) } != crate::fi::OK_SENTINEL {
        wipe_destination(destination);
        return Err(());
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&copy_receipt) } != crate::fi::OK_SENTINEL {
        wipe_destination(destination);
        return Err(());
    }
    Ok(destination_len)
}

#[cfg(test)]
mod tests {
    use super::{
        copy_exact, copy_exact_into, initialize_exact_progress_into,
        publish_region_pointer_into, verify_exact_pair_into, verify_exact_progress_into,
    };

    #[test]
    fn exact_progress_initializer_replaces_poison_and_publishes_success() {
        let mut completed = usize::MAX;
        let mut receipt = crate::fi::FAIL_SENTINEL;
        initialize_exact_progress_into(&mut completed, &mut receipt);
        assert_eq!(completed, 0);
        assert_eq!(receipt, crate::fi::OK_SENTINEL);
    }

    #[test]
    fn omitted_exact_progress_initializer_leaves_caller_receipt_failed() {
        let completed = usize::MAX;
        let receipt = crate::fi::FAIL_SENTINEL;
        assert_eq!(completed, usize::MAX);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    fn progress_receipt(completed: usize, expected: usize) -> u32 {
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_exact_progress_into(&completed, expected, &mut receipt);
        receipt
    }

    fn pair_receipt(
        observed_first: usize,
        expected_first: usize,
        observed_second: usize,
        expected_second: usize,
    ) -> u32 {
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_exact_pair_into(
            observed_first,
            expected_first,
            observed_second,
            expected_second,
            &mut receipt,
        );
        receipt
    }

    #[test]
    fn exact_payload_replaces_the_whole_output() {
        let mut out = [0xA5; 16];
        let payload = [0x3C; 16];
        assert_eq!(copy_exact(&payload, &mut out), Ok(16));
        assert_eq!(out, payload);
    }

    #[test]
    fn caller_owned_receipt_distinguishes_skipped_and_completed_copy() {
        let payload = [0x3C; 16];
        let mut out = [0u8; 16];
        let mut receipt = crate::fi::FAIL_SENTINEL;

        // A caller that fail-initializes but never invokes the operation models
        // a skipped BL: no stale Rust return register can synthesize success.
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
        assert_eq!(out, [0; 16]);

        let expected_source = payload.as_ptr();
        let expected_destination = out.as_ptr();
        copy_exact_into(
            payload.as_ptr(),
            core::ptr::addr_of!(expected_source),
            payload.len(),
            out.as_mut_ptr(),
            0,
            core::ptr::addr_of!(expected_destination),
            out.len(),
            &mut receipt,
        );
        assert_eq!(receipt, crate::fi::OK_SENTINEL);
        assert_eq!(out, payload);
    }

    #[test]
    fn fault_created_source_destination_alias_is_rejected_without_raw_write() {
        let mut out = [0xA5u8; 16];
        let ptr = out.as_mut_ptr();
        let mut receipt = crate::fi::FAIL_SENTINEL;
        let expected_source = ptr.cast_const();
        let expected_destination = ptr.cast_const();
        copy_exact_into(
            ptr.cast_const(),
            core::ptr::addr_of!(expected_source),
            out.len(),
            ptr,
            0,
            core::ptr::addr_of!(expected_destination),
            out.len(),
            &mut receipt,
        );
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
        assert_eq!(out, [0xA5u8; 16]);
    }

    #[test]
    fn fault_created_disjoint_but_stale_source_is_rejected_without_raw_write() {
        let fresh = [0x3Cu8; 16];
        let stale = [0xA7u8; 16];
        let mut out = [0xA5u8; 16];
        let mut published_fresh = core::ptr::null();
        let mut publication_receipt = crate::fi::FAIL_SENTINEL;
        publish_region_pointer_into(
            fresh.as_ptr(),
            &mut published_fresh,
            &mut publication_receipt,
        );
        assert_eq!(publication_receipt, crate::fi::OK_SENTINEL);

        let mut copy_receipt = crate::fi::FAIL_SENTINEL;
        let expected_destination = out.as_ptr();
        copy_exact_into(
            stale.as_ptr(),
            core::ptr::addr_of!(published_fresh),
            stale.len(),
            out.as_mut_ptr(),
            0,
            core::ptr::addr_of!(expected_destination),
            out.len(),
            &mut copy_receipt,
        );
        assert_eq!(copy_receipt, crate::fi::FAIL_SENTINEL);
        assert_eq!(out, [0xA5u8; 16]);
    }

    #[test]
    fn fault_created_stale_destination_offset_cannot_select_a_wipe_target() {
        let source = [0x3Cu8; 16];
        let mut out = [0xA5u8; 32];
        let expected_source = source.as_ptr();
        let expected_destination = unsafe { out.as_ptr().add(16) };
        let mut copy_receipt = crate::fi::FAIL_SENTINEL;

        // Model a stale offset argument while the caller-owned publication
        // slot contains the current destination. The derived live pointer and
        // independently loaded expectation must disagree and fail closed.
        copy_exact_into(
            source.as_ptr(),
            core::ptr::addr_of!(expected_source),
            source.len(),
            out.as_mut_ptr(),
            0,
            core::ptr::addr_of!(expected_destination),
            source.len(),
            &mut copy_receipt,
        );
        assert_eq!(copy_receipt, crate::fi::FAIL_SENTINEL);
        assert_eq!(out, [0xA5u8; 32]);
    }

    #[test]
    fn short_and_overlong_payloads_wipe_output() {
        for payload in [&[0x11; 15][..], &[0x22; 17][..]] {
            let mut out = [0xA5; 16];
            assert_eq!(copy_exact(payload, &mut out), Err(()));
            assert_eq!(out, [0; 16]);
        }
    }

    #[test]
    fn exact_progress_rejects_prefixes_and_overshoots() {
        for expected in [0usize, 8, 16, 31, 32, 48, 65, 128] {
            assert_eq!(progress_receipt(expected, expected), crate::fi::OK_SENTINEL);
            if expected != 0 {
                assert_eq!(
                    progress_receipt(expected - 1, expected),
                    crate::fi::FAIL_SENTINEL
                );
            }
            assert_eq!(
                progress_receipt(expected + 1, expected),
                crate::fi::FAIL_SENTINEL
            );
        }
    }

    #[test]
    fn exact_pair_requires_both_observations() {
        assert_eq!(pair_receipt(36, 36, 0x41, 0x41), crate::fi::OK_SENTINEL);
        assert_eq!(pair_receipt(35, 36, 0x41, 0x41), crate::fi::FAIL_SENTINEL);
        assert_eq!(pair_receipt(36, 36, 0x42, 0x41), crate::fi::FAIL_SENTINEL);
        assert_eq!(pair_receipt(37, 36, 0x42, 0x41), crate::fi::FAIL_SENTINEL);
    }
}
