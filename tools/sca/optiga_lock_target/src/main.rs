//! thumbv8m FI target for the OPTIGA **LcsO-ratchet read-back gate** —
//! `verify_and_lock` (`secure/src/optiga/mod.rs:731-768`), the verify-before-
//! lock gate the S-1/S-2/S-3 provisioning hardening relies on. work-todo
//! §18b RANK 3 (lowest priority).
//!
//! `verify_and_lock` is the single chokepoint before every **irreversible**
//! `LcsO=Operational` ratchet (F1D0 AuthRef lock, the S-2 trust-anchor pool
//! lockdown, the E120 counter lock). The OPTIGA silently accepts SetMetadata
//! APDUs carrying access-condition constructs it won't honour (returns OK,
//! stores nothing / a truncated form), so the firmware MUST read the metadata
//! back and confirm the exact AC bytes landed before freezing them forever:
//!
//! ```text
//! n = get_metadata(oid, &mut stored)?;                  // I2C round-trip
//! if is_metadata_operational(stored, n) { return Ok }   // idempotent skip
//! if !metadata_matches_expected(stored, n, expected) {  // <-- THE GATE
//!     return Err(Status(0xEB));                         // fail closed, no lock
//! }
//! lock_oid(oid)                                         // irreversible ratchet
//! ```
//!
//! **FI question:** can a single skip / stuck-at fault make `verify_and_lock`
//! reach `lock_oid` (fire the irreversible ratchet) when the readback did NOT
//! match the intended AC — i.e. freeze a chip whose Change/Read/Execute AC
//! silently didn't land (bricking it with the wrong, possibly all-deny or
//! attacker-favourable, permissions)?
//!
//! `optiga/{mod,apdu}.rs` can't be `#[path]`-included (entangled with the
//! IFX-I2C + Shielded-Connection driver), so the I2C round-trips
//! (`get_metadata` / `lock_oid`) are stubbed and the gate flow is a structural
//! mirror — but the pure metadata parser/comparator is copied VERBATIM.
//!
//! **Scope (honest).** Emulation tests the software readback-verify-then-lock
//! logic. The OPTIGA's own LcsO sequencing, the I2C transport, and the
//! SetMetadata silent-accept quirk are stubbed — silicon behaviour is out of
//! scope. Single-fault FI completeness for the provisioning-hardening gate.

#![no_std]
#![no_main]

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use cortex_m_rt::entry;
use panic_halt as _;

// ===========================================================================
// VERBATIM COPY — keep in sync with secure/src/optiga/apdu.rs
//   metadata tag constants : apdu.rs:211-252
//   find_metadata_tag       : apdu.rs:1231-1252
//   is_metadata_operational : apdu.rs:1255-1260
//   metadata_matches_expected : apdu.rs:1277-1292
// ===========================================================================
const META_ROOT: u8 = 0x20;
const META_LCSO: u8 = 0xC0;
const META_CHANGE: u8 = 0xD0;
const META_READ: u8 = 0xD1;
const META_EXECUTE: u8 = 0xD3;
const META_DATA_TYPE: u8 = 0xE8;
const LCS_OPERATIONAL: u8 = 0x07;

fn find_metadata_tag(metadata: &[u8], len: usize, tag: u8) -> Option<&[u8]> {
    if len < 2 || metadata[0] != META_ROOT {
        return None;
    }
    let root_len = metadata[1] as usize;
    if 2 + root_len > len {
        return None;
    }
    let mut pos = 2;
    while pos + 2 <= 2 + root_len {
        let t = metadata[pos];
        let tlen = metadata[pos + 1] as usize;
        if pos + 2 + tlen > 2 + root_len {
            return None;
        }
        if t == tag {
            return Some(&metadata[pos + 2..pos + 2 + tlen]);
        }
        pos += 2 + tlen;
    }
    None
}

fn is_metadata_operational(metadata: &[u8], len: usize) -> bool {
    match find_metadata_tag(metadata, len, META_LCSO) {
        Some(v) if v.len() == 1 => v[0] == LCS_OPERATIONAL,
        _ => false,
    }
}

fn metadata_matches_expected(
    stored: &[u8],
    stored_len: usize,
    expected: &[u8],
    expected_len: usize,
) -> bool {
    for &tag in &[META_CHANGE, META_READ, META_EXECUTE, META_DATA_TYPE] {
        if let Some(exp) = find_metadata_tag(expected, expected_len, tag) {
            match find_metadata_tag(stored, stored_len, tag) {
                Some(got) if got == exp => {}
                _ => return false,
            }
        }
    }
    true
}

// ===========================================================================
// Harness surface — fixed metadata scenarios + stubbed I2C round-trips.
// ===========================================================================

/// The intended AC for the OID being locked: `Change = Auto(F1D0)` — the S-1
/// hardening (`d0 03 23 f1 d0`), wrapped in a META_ROOT TLV.
const EXPECTED: &[u8] = &[META_ROOT, 0x05, META_CHANGE, 0x03, 0x23, 0xF1, 0xD0];

/// Stored readback variants the stubbed `get_metadata` can return:
///  0 = MISMATCH — chip silently kept the default `Change = ALW` (`d0 01 00`):
///      the AC did NOT land → `verify_and_lock` MUST refuse to lock.
///  1 = MATCH    — chip stored `Change = Auto(F1D0)` as intended → lock.
///  2 = OPERATIONAL — already LcsO=Operational → idempotent skip (no lock).
const STORED_MISMATCH: &[u8] = &[META_ROOT, 0x03, META_CHANGE, 0x01, 0x00];
const STORED_MATCH: &[u8] = &[META_ROOT, 0x05, META_CHANGE, 0x03, 0x23, 0xF1, 0xD0];
const STORED_OPERATIONAL: &[u8] = &[META_ROOT, 0x03, META_LCSO, 0x01, LCS_OPERATIONAL];

/// Harness selects the stored-metadata scenario (0/1/2 as above).
#[no_mangle]
pub static mut OPTIGA_STORED_SEL: u32 = 0;
/// Set to 1 by the stubbed `lock_oid` — the irreversible LcsO ratchet fired.
/// `.bss` → re-zeroed on every `e.reset()`.
#[no_mangle]
pub static mut OPTIGA_LOCK_FIRED: u32 = 0;

/// Stub for `apdu::get_metadata` — returns the harness-selected stored buffer.
fn stub_get_metadata(out: &mut [u8]) -> usize {
    let sel = unsafe { read_volatile(addr_of!(OPTIGA_STORED_SEL)) };
    let src: &[u8] = match sel {
        1 => STORED_MATCH,
        2 => STORED_OPERATIONAL,
        _ => STORED_MISMATCH,
    };
    out[..src.len()].copy_from_slice(src);
    src.len()
}

/// Stub for `OptigaTrustM::lock_oid` — records the irreversible ratchet firing.
fn stub_lock_oid() -> Result<(), ()> {
    // SAFETY: single-threaded; marks the irreversible lock for the harness.
    unsafe { write_volatile(addr_of_mut!(OPTIGA_LOCK_FIRED), 1) };
    Ok(())
}

/// **FI target.** Structural mirror of `verify_and_lock`'s
/// `optiga-lock-operational` branch (mod.rs:741-767). Returns:
///   0 = REFUSED (`Status(0xEB)` — readback didn't match, fail-closed)
///   1 = LOCKED  (verified against intent, irreversible ratchet fired)
///   2 = SKIPPED (already Operational — idempotent, no lock)
///   3 = LOCK ERROR
/// The harness's bypass signal in the MISMATCH scenario is `OPTIGA_LOCK_FIRED
/// == 1` (a chip with unconfirmed AC got frozen) and/or a return of 1.
#[no_mangle]
pub extern "C" fn sca_optiga_verify_and_lock() -> u32 {
    let mut stored = [0u8; 128];
    let n = stub_get_metadata(&mut stored);
    if is_metadata_operational(&stored, n) {
        return 2; // idempotent skip — no lock
    }
    if !metadata_matches_expected(&stored, n, EXPECTED, EXPECTED.len()) {
        return 0; // 0xEB — refuse to lock (fail closed)
    }
    match stub_lock_oid() {
        Ok(()) => 1,
        Err(()) => 3,
    }
}

// ===========================================================================
// Keep-alive roots.
// ===========================================================================
#[used]
static _KEEP_GATE: extern "C" fn() -> u32 = sca_optiga_verify_and_lock;

#[entry]
fn main() -> ! {
    core::hint::black_box(&_KEEP_GATE);
    // SAFETY: single-threaded address-of for keep-alive.
    unsafe {
        core::hint::black_box(addr_of!(OPTIGA_STORED_SEL));
        core::hint::black_box(addr_of!(OPTIGA_LOCK_FIRED));
    }
    loop {
        cortex_m::asm::nop();
    }
}
