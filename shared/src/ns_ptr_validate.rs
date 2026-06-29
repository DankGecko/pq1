//! Pure, host-verifiable NS-pointer range-validation arithmetic.
//!
//! Extracted **verbatim and behaviour-identical** from
//! `secure/src/nsc/ptr_validate.rs` (window-check half) and
//! `secure/src/nsc/ns_ptr.rs` (volatile copy half) so the security-
//! critical NS-pointer TOCTOU gate can be host-compiled and:
//!
//!   * bounded-verified with Kani (`cargo kani -p sphincs-tz-shared`) —
//!     the `#[cfg(kani)] mod verification` harnesses prove the
//!     *soundness* direction of the window check (see below); and
//!   * run under Miri tree-borrows (`cargo +nightly miri test -p
//!     sphincs-tz-shared`) — the `#[cfg(test)] mod tests` exercise the
//!     `read_volatile` / `write_volatile` / `from_raw_parts` copy
//!     primitives over a real allocation, which the secure crate
//!     structurally cannot do (its `addr` is a `u32` that can never hold
//!     a 64-bit host pointer — which is exactly why the existing
//!     `make miri` ns_ptr pass never derefs).
//!
//! The firmware keeps a single source of truth: `ptr_validate.rs`'s
//! `validate_ns_{read,write}_ptr` call [`ns_read_window_ok`] /
//! [`ns_write_window_ok`] and then AND the result with the ARMv8-M
//! `TT`/SAU hardware check (which has no host model and is `true`
//! off-target); `ns_ptr.rs`'s `ReadPtr`/`WritePtr` deref helpers call
//! [`ns_read_volatile_into`] / [`ns_write_volatile_from`] /
//! [`ns_as_slice`]. So the host build verifies exactly the bytes the
//! firmware runs.
//!
//! ## Scope / honest limit
//!
//! This module owns ONLY the pure arithmetic + raw-copy mechanics:
//! null reject, `usize → u32` truncation reject, `ptr + len` 32-bit
//! address-wrap reject, constant-window containment, shared-mailbox
//! disjointness, and the per-byte volatile copy. The hardware memory
//! map is injected via [`NsRegions`] (not hard-coded) so the Kani proof
//! is over the actual compiled constants AND, in a second harness, over
//! fully symbolic well-formed maps. The `TT`/SAU re-classification — the
//! TOCTOU half that catches a stale linker map — is the hardware check
//! and is *out of scope here* (host-stubbed `true`).

/// The non-secure memory map the validator checks a pointer range
/// against. In firmware these fields come from `pqsigner-proto`'s
/// cfg-gated linker constants (re-exported at this crate's root); the
/// Kani harnesses instantiate it from those same constants and, for
/// generality, from symbolic bounds.
#[derive(Copy, Clone, Debug)]
pub struct NsRegions {
    /// Inclusive base of the non-secure SRAM window.
    pub ns_sram_base: u32,
    /// Exclusive end of the non-secure SRAM window.
    pub ns_sram_end: u32,
    /// Inclusive base of the non-secure flash window (read-only).
    pub ns_flash_base: u32,
    /// Exclusive end of the non-secure flash window.
    pub ns_flash_end: u32,
    /// Inclusive base of the shared gateway mailbox (carved out of NS SRAM).
    pub mailbox_base: u32,
    /// Exclusive end of the shared gateway mailbox.
    pub mailbox_end: u32,
}

/// Pure arithmetic core of `validate_ns_write_ptr`: `true` iff
/// `[ptr, ptr + len)` lies wholly inside the NS SRAM window, does not
/// overlap the shared mailbox, does not overflow the 32-bit address
/// space, and the `len` did not silently truncate in the `usize → u32`
/// cast.
///
/// Does **not** include the ARMv8-M `TT`/SAU hardware re-classification
/// (that has no host model); the firmware ANDs that in separately.
#[inline]
#[must_use]
pub fn ns_write_window_ok(r: &NsRegions, ptr: u32, len: usize) -> bool {
    if ptr == 0 {
        return false;
    }
    // The validator reasons in 32-bit address space; an oversized
    // `usize` would silently truncate in the `len as u32` cast below
    // and approve a range orders of magnitude larger than measured.
    // No-op on 32-bit ARM (`usize == u32`); defensive on hosts/tests.
    if len > u32::MAX as usize {
        return false;
    }
    let end = match ptr.checked_add(len as u32) {
        Some(e) => e,
        None => return false,
    };
    if !(ptr >= r.ns_sram_base && end <= r.ns_sram_end) {
        return false;
    }
    // Reject any overlap with the shared mailbox region.
    if ptr < r.mailbox_end && end > r.mailbox_base {
        return false;
    }
    true
}

/// Pure arithmetic core of `validate_ns_read_ptr`: `true` iff
/// `[ptr, ptr + len)` lies wholly inside the NS SRAM window **or** the
/// NS flash window (flash is read-only but NS-readable, e.g. a static
/// unsigned-tx blob), does not overlap the shared mailbox when in SRAM,
/// does not overflow the 32-bit address space, and the `len` did not
/// truncate.
///
/// Does **not** include the ARMv8-M `TT`/SAU hardware check.
#[inline]
#[must_use]
pub fn ns_read_window_ok(r: &NsRegions, ptr: u32, len: usize) -> bool {
    if ptr == 0 {
        return false;
    }
    if len > u32::MAX as usize {
        return false;
    }
    let end = match ptr.checked_add(len as u32) {
        Some(e) => e,
        None => return false,
    };
    let in_sram = ptr >= r.ns_sram_base && end <= r.ns_sram_end;
    let in_flash = ptr >= r.ns_flash_base && end <= r.ns_flash_end;
    if !(in_sram || in_flash) {
        return false;
    }
    if in_sram && ptr < r.mailbox_end && end > r.mailbox_base {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Volatile copy primitives — the genuine NS-pointer-deref `unsafe`.
//
// Extracted so Miri can vet the per-byte `read_volatile`/`write_volatile`
// loop + the `from_raw_parts` slice construction for OOB / provenance /
// aliasing UB over a real host allocation. The firmware's `ReadPtr` /
// `WritePtr` call these after the typestate validation gate has fired.
// The per-byte volatile ordering is load-bearing: it realises the TOCTOU
// snapshot the compiler is forbidden to elide or batch.
// ---------------------------------------------------------------------------

/// Volatile, byte-by-byte read of `[src, src + dst.len())` into `dst`.
///
/// # Safety
/// `src` must be valid for reads of `dst.len()` bytes for the duration
/// of the call, and must not be mutated by another agent mid-copy (the
/// secure-world gateway holds the non-reentrant dispatcher lock, so NS
/// cannot race it). Each byte is a separate `read_volatile`, so the
/// compiler may not coalesce or reorder the loads.
#[inline]
pub unsafe fn ns_read_volatile_into(src: *const u8, dst: &mut [u8]) {
    for (i, slot) in dst.iter_mut().enumerate() {
        // SAFETY: caller guarantees `[src, src + dst.len())` is valid for
        // reads; `i < dst.len()` so `src.add(i)` is in-bounds.
        *slot = unsafe { core::ptr::read_volatile(src.add(i)) };
    }
}

/// Volatile, byte-by-byte write of `src` into `[dst, dst + src.len())`.
///
/// # Safety
/// `dst` must be valid for writes of `src.len()` bytes for the duration
/// of the call. Each byte is a separate `write_volatile`, so NS
/// observers cannot see torn / partial words mid-copy.
#[inline]
pub unsafe fn ns_write_volatile_from(dst: *mut u8, src: &[u8]) {
    for (i, &b) in src.iter().enumerate() {
        // SAFETY: caller guarantees `[dst, dst + src.len())` is valid for
        // writes; `i < src.len()` so `dst.add(i)` is in-bounds.
        unsafe { core::ptr::write_volatile(dst.add(i), b) };
    }
}

/// Construct a `&[u8]` view of `[ptr, ptr + len)`.
///
/// # Safety
/// `[ptr, ptr + len)` must be valid for reads and immutable for the
/// returned reference's lifetime. The caller carries the
/// no-concurrent-mutation contract (single-threaded gateway makes this
/// trivially true for one handler).
#[inline]
#[must_use]
pub unsafe fn ns_as_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    // SAFETY: forwarded to the caller's contract above.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

// ---------------------------------------------------------------------------
// Bounded verification (Kani) — soundness of the window check.
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod verification {
    use super::*;

    /// The NS map as actually compiled into this crate (the cfg-gated
    /// `pqsigner-proto` linker constants). `cargo kani -p
    /// sphincs-tz-shared` with default features compiles the mps2/QEMU
    /// layout; `--features stm32u585` compiles the shipping layout. Both
    /// are well-formed maps whose NS windows lie entirely outside secure
    /// SRAM/flash, so "range ⊆ NS window" ⟹ "range disjoint from secure
    /// memory" for either. The arithmetic itself is layout-independent —
    /// `ns_write_sound_symbolic_regions` proves that for ALL maps.
    const NS_MAP: NsRegions = NsRegions {
        ns_sram_base: crate::NS_SRAM_BASE,
        ns_sram_end: crate::NS_SRAM_END,
        ns_flash_base: crate::NS_FLASH_BASE,
        ns_flash_end: crate::NS_FLASH_END,
        mailbox_base: crate::SHARED_MAILBOX_BASE,
        mailbox_end: crate::SHARED_MAILBOX_END,
    };

    /// Soundness (write). **Unbounded** — loop-free body, fully symbolic
    /// `ptr: u32` and `len: usize`, no `kani::unwind` needed; exhaustive
    /// over the entire input domain.
    ///
    /// `ns_write_window_ok(&NS_MAP, ptr, len)` ⟹ the following, each
    /// stated in *independent* `u128` over the ORIGINAL `ptr`/`len` (never
    /// the function's truncated internal `end`, so this is a real proof,
    /// not a re-check of the function against itself):
    ///
    ///   D  `len ≤ u32::MAX`                       — the `usize → u32` truncation
    ///        residual cannot let an oversized length through.
    ///   A  `ptr + len ≤ 2^32`                     — no 32-bit address-space wrap.
    ///   B  `ns_sram_base ≤ ptr ∧ ptr + len ≤ ns_sram_end` — the FULL range is
    ///        inside NS SRAM ⟹ disjoint from secure memory (it lies outside
    ///        these windows).
    ///   C  `ptr + len ≤ mailbox_base ∨ ptr ≥ mailbox_end` — disjoint from the
    ///        shared mailbox (no TOCTOU on the command word being dispatched).
    ///
    /// B/C in u128 are non-vacuous precisely because they hold for the
    /// untruncated `len`: that is what makes the `len > u32::MAX` guard
    /// load-bearing.
    #[kani::proof]
    fn ns_write_sound() {
        let ptr: u32 = kani::any();
        let len: usize = kani::any();
        if ns_write_window_ok(&NS_MAP, ptr, len) {
            let p = ptr as u128;
            let end = p + len as u128; // u128: p < 2^32, len < 2^64 ⟹ no overflow
            assert!(len <= u32::MAX as usize); // D
            assert!(end <= (1u128 << 32)); // A
            assert!(p >= NS_MAP.ns_sram_base as u128); // B lo
            assert!(end <= NS_MAP.ns_sram_end as u128); // B hi
            assert!(
                end <= NS_MAP.mailbox_base as u128 || p >= NS_MAP.mailbox_end as u128
            ); // C
        }
    }

    /// Soundness (read). Same shape, but containment is NS SRAM **or** NS
    /// flash, and mailbox-disjointness is required only for the SRAM case
    /// (the mailbox is carved out of SRAM, so a flash-resident range
    /// cannot alias it). **Unbounded**, loop-free, fully symbolic.
    #[kani::proof]
    fn ns_read_sound() {
        let ptr: u32 = kani::any();
        let len: usize = kani::any();
        if ns_read_window_ok(&NS_MAP, ptr, len) {
            let p = ptr as u128;
            let end = p + len as u128;
            assert!(len <= u32::MAX as usize); // D
            assert!(end <= (1u128 << 32)); // A
            let in_sram =
                p >= NS_MAP.ns_sram_base as u128 && end <= NS_MAP.ns_sram_end as u128;
            let in_flash =
                p >= NS_MAP.ns_flash_base as u128 && end <= NS_MAP.ns_flash_end as u128;
            assert!(in_sram || in_flash); // B
            if in_sram {
                assert!(
                    end <= NS_MAP.mailbox_base as u128 || p >= NS_MAP.mailbox_end as u128
                ); // C
            }
        }
    }

    /// Generalization — **arithmetic robustness across memory maps**, NOT
    /// a secure-disjointness claim (no secure region is modeled here). For
    /// ANY map of symbolic bounds, `accept ⟹` the same window facts hold
    /// in independent u128. Forecloses, in spirit, the "constants drifted
    /// vs the linker script" failure mode for the pure-arithmetic half.
    /// **Unbounded**, loop-free, fully symbolic (regions + ptr + len).
    #[kani::proof]
    fn ns_write_sound_symbolic_regions() {
        let r = NsRegions {
            ns_sram_base: kani::any(),
            ns_sram_end: kani::any(),
            ns_flash_base: kani::any(),
            ns_flash_end: kani::any(),
            mailbox_base: kani::any(),
            mailbox_end: kani::any(),
        };
        let ptr: u32 = kani::any();
        let len: usize = kani::any();
        if ns_write_window_ok(&r, ptr, len) {
            let p = ptr as u128;
            let end = p + len as u128;
            assert!(len <= u32::MAX as usize);
            assert!(end <= (1u128 << 32));
            assert!(p >= r.ns_sram_base as u128);
            assert!(end <= r.ns_sram_end as u128);
            assert!(end <= r.mailbox_base as u128 || p >= r.mailbox_end as u128);
        }
    }

    /// Non-vacuity (positive control): a concrete in-window NS-SRAM range
    /// is ACCEPTED. Without this, the `accept ⟹ P` soundness harnesses
    /// could pass vacuously — a validator that rejected everything would
    /// satisfy them trivially. Proves the `if accept {…}` block is
    /// reachable.
    #[kani::proof]
    fn ns_accepts_inwindow_control() {
        // 64 bytes at base + 0x1000: well inside NS SRAM and below the
        // mailbox carve-out for both compiled layouts.
        assert!(ns_write_window_ok(&NS_MAP, NS_MAP.ns_sram_base + 0x1000, 64));
        assert!(ns_read_window_ok(&NS_MAP, NS_MAP.ns_sram_base + 0x1000, 64));
    }

    /// Non-vacuity (negative control — secure-boundary straddle): a range
    /// starting one byte below `ns_sram_base` crosses out of the NS window
    /// toward secure/unmapped memory and MUST be rejected.
    #[kani::proof]
    fn ns_rejects_below_base_control() {
        assert!(!ns_write_window_ok(&NS_MAP, NS_MAP.ns_sram_base - 1, 64));
        assert!(!ns_read_window_ok(&NS_MAP, NS_MAP.ns_sram_base - 1, 64));
    }

    /// Non-vacuity (negative control — address-space wrap): a pointer near
    /// the top of the 32-bit space with a length that wraps past `2^32`
    /// MUST be rejected (the `checked_add` returns `None`). Without it, the
    /// wrapped range would alias low memory.
    #[kani::proof]
    fn ns_rejects_wrap_control() {
        assert!(!ns_write_window_ok(&NS_MAP, 0xFFFF_FFF0, 0x20));
        assert!(!ns_read_window_ok(&NS_MAP, 0xFFFF_FFF0, 0x20));
    }

    /// Non-vacuity (negative control — the documented `usize → u32`
    /// truncation residual): `len = u32::MAX + 1` truncates to `0`; without
    /// the `len > u32::MAX` guard the range would masquerade as a
    /// zero-length NS-SRAM range and be accepted. MUST be rejected. Only
    /// reachable on 64-bit `usize` — the host build Kani runs on.
    #[cfg(target_pointer_width = "64")]
    #[kani::proof]
    fn ns_rejects_truncating_len_control() {
        let huge: usize = (u32::MAX as usize) + 1;
        assert!(!ns_write_window_ok(&NS_MAP, NS_MAP.ns_sram_base, huge));
        assert!(!ns_read_window_ok(&NS_MAP, NS_MAP.ns_sram_base, huge));
    }

    /// Non-vacuity (negative control — mailbox straddle): a range starting
    /// 4 bytes before the shared mailbox and running into it MUST be
    /// rejected (TOCTOU on the very command word being dispatched).
    #[kani::proof]
    fn ns_rejects_mailbox_straddle_control() {
        assert!(!ns_write_window_ok(&NS_MAP, NS_MAP.mailbox_base - 4, 8));
        assert!(!ns_read_window_ok(&NS_MAP, NS_MAP.mailbox_base - 4, 8));
    }
}

// ---------------------------------------------------------------------------
// Host tests — Miri tree-borrows coverage of the deref `unsafe` + a few
// plain unit checks of the window arithmetic.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn host_map() -> NsRegions {
        NsRegions {
            ns_sram_base: crate::NS_SRAM_BASE,
            ns_sram_end: crate::NS_SRAM_END,
            ns_flash_base: crate::NS_FLASH_BASE,
            ns_flash_end: crate::NS_FLASH_END,
            mailbox_base: crate::SHARED_MAILBOX_BASE,
            mailbox_end: crate::SHARED_MAILBOX_END,
        }
    }

    // -- Miri tree-borrows: the genuine NS-pointer-deref `unsafe` over a
    //    REAL stack allocation (clean provenance for tree-borrows to vet).

    #[test]
    fn miri_read_volatile_into_copies_exact_bytes() {
        let src: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut dst = [0u8; 8];
        // SAFETY: `src` is a live 8-byte allocation, not mutated here.
        unsafe { ns_read_volatile_into(src.as_ptr(), &mut dst) };
        assert_eq!(dst, src);
    }

    #[test]
    fn miri_write_volatile_from_copies_exact_bytes() {
        let src: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];
        let mut dst = [0u8; 8];
        // SAFETY: `dst` is a live 8-byte allocation.
        unsafe { ns_write_volatile_from(dst.as_mut_ptr(), &src) };
        assert_eq!(dst, src);
    }

    #[test]
    fn miri_read_then_write_roundtrip_offset() {
        // Copy a sub-range with a non-zero offset to exercise `.add(i)`
        // provenance arithmetic, not just base-pointer reads.
        let src: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let mut mid = [0u8; 4];
        // SAFETY: reading 4 bytes starting at offset 4 stays in-bounds of
        // the 16-byte source.
        unsafe { ns_read_volatile_into(src.as_ptr().add(4), &mut mid) };
        assert_eq!(mid, [0x14, 0x15, 0x16, 0x17]);

        let mut out = [0u8; 16];
        // SAFETY: writing 4 bytes starting at offset 8 stays in-bounds of
        // the 16-byte dst.
        unsafe { ns_write_volatile_from(out.as_mut_ptr().add(8), &mid) };
        assert_eq!(&out[8..12], &[0x14, 0x15, 0x16, 0x17]);
    }

    #[test]
    fn miri_as_slice_aliases_source_bytes() {
        let buf: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        // SAFETY: `buf` is live for 4 bytes and is not mutated while `s`
        // is borrowed.
        let s = unsafe { ns_as_slice(buf.as_ptr(), buf.len()) };
        assert_eq!(s, &buf[..]);
    }

    // -- Plain unit checks of the extracted window arithmetic against the
    //    crate's compiled NS constants (regression oracle for the firmware
    //    re-export).

    #[test]
    fn window_accepts_inwindow_sram() {
        let r = host_map();
        assert!(ns_write_window_ok(&r, r.ns_sram_base, 64));
        assert!(ns_read_window_ok(&r, r.ns_sram_base, 64));
    }

    #[test]
    fn window_read_accepts_flash_write_rejects_flash() {
        let r = host_map();
        assert!(ns_read_window_ok(&r, r.ns_flash_base, 8));
        assert!(!ns_write_window_ok(&r, r.ns_flash_base, 8));
    }

    #[test]
    fn window_rejects_null_wrap_and_boundary() {
        let r = host_map();
        assert!(!ns_write_window_ok(&r, 0, 0));
        assert!(!ns_read_window_ok(&r, 0, 0));
        assert!(!ns_write_window_ok(&r, 0xFFFF_FFF0, 0x20));
        assert!(!ns_write_window_ok(&r, r.ns_sram_base - 1, 64));
        assert!(!ns_write_window_ok(&r, r.mailbox_base, 4));
        assert!(!ns_read_window_ok(&r, r.mailbox_base - 4, 8));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn window_rejects_truncating_len() {
        let r = host_map();
        let huge: usize = (u32::MAX as usize) + 1;
        assert!(!ns_write_window_ok(&r, r.ns_sram_base, huge));
        assert!(!ns_read_window_ok(&r, r.ns_sram_base, huge));
    }
}
