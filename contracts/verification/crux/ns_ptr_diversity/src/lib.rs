//! crux-mir IMPLEMENTATION-DIVERSITY check for the NS-pointer window validator.
//!
//! Runs `shared/src/ns_ptr_validate.rs`'s `ns_{read,write}_window_ok` through a SECOND
//! symbolic engine (crux-mir / crucible, independent of the existing Kani `#[cfg(kani)]`
//! harnesses) and against an INDEPENDENTLY-written u64 oracle. The functions below are
//! copied VERBATIM / behaviour-identical from `shared/src/ns_ptr_validate.rs` (KEEP IN
//! SYNC); the oracle re-formulates "range ⊆ NS window" in wide (u64) arithmetic with NO
//! `checked_add` and NO `usize→u32` cast — a genuinely different implementation.
//!
//! WHAT THIS ADDS over Kani: the Kani harnesses prove only the SOUNDNESS direction
//! (`accept ⟹ range ⊆ NS window`). This asserts full EQUIVALENCE `real == oracle`, which
//! ALSO covers COMPLETENESS (the validator does not spuriously REJECT an in-window range)
//! — a direction the soundness harness doesn't reach — and does it on a different engine.
//! Value is only real if it CONFIRMS across engines or FINDS a divergence (roadmap caveat).

// ── copied verbatim from shared/src/ns_ptr_validate.rs (behaviour-identical) ──
#[derive(Copy, Clone)]
pub struct NsRegions {
    pub ns_sram_base: u32,
    pub ns_sram_end: u32,
    pub ns_flash_base: u32,
    pub ns_flash_end: u32,
    pub mailbox_base: u32,
    pub mailbox_end: u32,
}

pub fn ns_write_window_ok(r: &NsRegions, ptr: u32, len: usize) -> bool {
    if ptr == 0 { return false; }
    if len > u32::MAX as usize { return false; }
    let end = match ptr.checked_add(len as u32) { Some(e) => e, None => return false };
    if !(ptr >= r.ns_sram_base && end <= r.ns_sram_end) { return false; }
    if ptr < r.mailbox_end && end > r.mailbox_base { return false; }
    true
}

pub fn ns_read_window_ok(r: &NsRegions, ptr: u32, len: usize) -> bool {
    if ptr == 0 { return false; }
    if len > u32::MAX as usize { return false; }
    let end = match ptr.checked_add(len as u32) { Some(e) => e, None => return false };
    let in_sram = ptr >= r.ns_sram_base && end <= r.ns_sram_end;
    let in_flash = ptr >= r.ns_flash_base && end <= r.ns_flash_end;
    if !(in_sram || in_flash) { return false; }
    if in_sram && ptr < r.mailbox_end && end > r.mailbox_base { return false; }
    true
}

// ── INDEPENDENT oracle: same predicate, re-expressed in u64 (no checked_add, no u32 cast) ──
fn oracle_write_ok(r: &NsRegions, ptr: u32, len: usize) -> bool {
    if ptr == 0 { return false; }
    let p = ptr as u64;
    let e = p.saturating_add(len as u64);  // independent overflow-safety (real uses checked_add + len-guard)
    if !(p >= r.ns_sram_base as u64 && e <= r.ns_sram_end as u64) { return false; }
    if p < r.mailbox_end as u64 && e > r.mailbox_base as u64 { return false; }
    true
}

fn oracle_read_ok(r: &NsRegions, ptr: u32, len: usize) -> bool {
    if ptr == 0 { return false; }
    let p = ptr as u64;
    let e = p.saturating_add(len as u64);  // independent overflow-safety (real uses checked_add + len-guard)
    let in_sram = p >= r.ns_sram_base as u64 && e <= r.ns_sram_end as u64;
    let in_flash = p >= r.ns_flash_base as u64 && e <= r.ns_flash_end as u64;
    if !(in_sram || in_flash) { return false; }
    if in_sram && p < r.mailbox_end as u64 && e > r.mailbox_base as u64 { return false; }
    true
}

// stm32u585 NS map (matches proto/src/lib.rs stm32u585 + the P1.9 Lean MemoryMap).
const NS_MAP: NsRegions = NsRegions {
    ns_sram_base: 0x2003_0000, ns_sram_end: 0x2004_0000,
    ns_flash_base: 0x0810_0000, ns_flash_end: 0x0820_0000,
    mailbox_base: 0x2003_FF00, mailbox_end: 0x2003_FF18,
};

#[cfg(crux)]
extern crate crucible;

#[cfg(crux)]
use crucible::Symbolic;

/// ∀ ptr, len: the real read validator EQUALS the independent u64 oracle.
#[cfg(crux)]
#[crux::test]
pub fn read_window_matches_u64_oracle() {
    let ptr = u32::symbolic("ptr");
    let len = usize::symbolic("len");
    crucible::crucible_assert!(ns_read_window_ok(&NS_MAP, ptr, len) == oracle_read_ok(&NS_MAP, ptr, len));
}

/// ∀ ptr, len: the real write validator EQUALS the independent u64 oracle.
#[cfg(crux)]
#[crux::test]
pub fn write_window_matches_u64_oracle() {
    let ptr = u32::symbolic("ptr");
    let len = usize::symbolic("len");
    crucible::crucible_assert!(ns_write_window_ok(&NS_MAP, ptr, len) == oracle_write_ok(&NS_MAP, ptr, len));
}

/// **Anti-vacuity (concrete).** The equivalence above is not over constant functions: a
/// valid in-SRAM range is ACCEPTED and a secure-flash range is REJECTED, by both the real
/// validator and the oracle. (The stronger non-vacuity evidence is that crux-mir DISPROVED
/// the earlier *naive* u64 oracle — `p + len as u64` without overflow-safety — showing the
/// validator's `len`-guard + `checked_add` are load-bearing and that crux genuinely bites.)
#[cfg(crux)]
#[crux::test]
pub fn non_vacuous_concrete() {
    // in NS-SRAM, below the mailbox: accepted
    crucible::crucible_assert!(ns_read_window_ok(&NS_MAP, 0x2003_1000, 256));
    crucible::crucible_assert!(oracle_read_ok(&NS_MAP, 0x2003_1000, 256));
    // a SECURE-flash range (0x0C00_0000): rejected
    crucible::crucible_assert!(!ns_read_window_ok(&NS_MAP, 0x0C00_0000, 16));
    crucible::crucible_assert!(!oracle_read_ok(&NS_MAP, 0x0C00_0000, 16));
    // a range straddling the shared mailbox: rejected (write path)
    crucible::crucible_assert!(!ns_write_window_ok(&NS_MAP, 0x2003_FEF0, 64));
}
