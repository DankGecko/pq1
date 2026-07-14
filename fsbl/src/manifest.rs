//! Manifest I/O for the FSBL.
//!
//! Reads the 8 KB manifest page directly from flash and wraps it in
//! a [`fw_manifest::ManifestRef`]. Does NOT copy the bytes; the
//! returned reference borrows the memory-mapped flash region. This is
//! safe because:
//!
//! 1. Flash is read-only during FSBL execution (we never program flash
//!    from FSBL in the normal path — the only write is the boot-state
//!    page update, which is a separate address).
//! 2. The FSBL never hands the `ManifestRef` out to untrusted code.
//!
//! The manifest's SHA-256 fields point at 464 KB + 512 KB images, so
//! verifying them dominates runtime. We stream-hash those images
//! directly from flash in `verify.rs` — no RAM copy needed.

use fw_manifest::{ManifestRef, MANIFEST_SIZE};

use crate::slot::{manifest_addr, Slot};

/// Borrow a manifest **directly from its memory-mapped flash page** — no RAM
/// copy. The returned [`ManifestRef`] reads its fields straight from flash.
///
/// This removes the known pair of live 8 KB stack copies; it does not prove
/// Draft 1.1's still-open static-RAM plus worst-case-stack envelope. It is the
/// no-copy design this module's doc-comment has always described. The prior
/// `read()` copied each 8 KB manifest into a stack `[u8; MANIFEST_SIZE]`; with
/// BOTH slots' buffers live simultaneously across the multi-KB-stack
/// SPHINCS+C10 verify, `main`'s boot frame reserved ~24.7 KB and overran the
/// 16 KB stack (`_stack_start = 0x3000_4000`, no MSPLIM) — a silent stack
/// overflow / HardFault on the immutable, WRP1A-locked bootloader (it was never
/// caught because QEMU/e2e load the secure world directly and the only
/// HW-exercised FSBL path short-circuits before this verify body). Borrowing
/// flash removes both 8 KB copies.
///
/// SAFETY / correctness: flash is read-only during FSBL execution (the only
/// FSBL flash write is the separate boot-state page), so the bytes are stable
/// and a non-volatile borrow is sound; `manifest_addr(slot)` is a fixed,
/// always-mapped, 8 KB-aligned address in secure bank 1; `[u8; N]` has
/// alignment 1; and the reference never escapes the FSBL to untrusted code.
pub fn at(slot: Slot) -> ManifestRef<'static> {
    let ptr = manifest_addr(slot) as *const [u8; MANIFEST_SIZE];
    // SAFETY: see the doc above — `ptr` addresses the always-mapped, read-only,
    // MANIFEST_SIZE-byte manifest page (alignment 1); the `'static` borrow is of
    // immutable memory-mapped flash that outlives every FSBL use.
    let bytes: &'static [u8; MANIFEST_SIZE] = unsafe { &*ptr };
    ManifestRef::new(bytes)
}
