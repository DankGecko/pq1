//! thumbv8m SCA target for the SE050 **SCP03 response-unwrap** path —
//! the S-5 ship-blocker fix (`P1=0x33`, 2026-05-28) that made SE050
//! responses (incl. `half_E`, invariant #1) come back **R-ENC encrypted +
//! R-MAC authenticated** instead of plaintext-on-I2C (closes invariant #3
//! on the response leg). work-todo §18b RANK 1.
//!
//! Two attack surfaces, two harness flavours (mirroring existing patterns):
//!
//!  * **FI gate-bypass** (`fault_sweep_scp03.py`, pattern `fault_sweep_pin.py`)
//!    — `sca_scp03_unwrap_gate`: feed a **forged** response (valid R-ENC
//!    ciphertext of the *complement* of an attacker-chosen `half_E`, plus a
//!    WRONG R-MAC). Can a single fault make the R-MAC authentication-receipt
//!    gate (`scp03_logic::verify_rmac_into` + its dual volatile checks)
//!    pass → host accepts and releases the attacker's `half_E`? The
//!    complemented payload is the case the legacy infective `0xFF` mask
//!    would have turned into the exact attacker-selected bytes — the mask
//!    is gone, so ANY acceptance that releases `half_E` is a genuine bypass.
//!  * **Leakage / constant-time** (`leakage_scp03.py`, pattern
//!    `leakage_saes_kdf.py`) — `sca_scp03_cbc_decrypt` / `sca_scp03_cmac`:
//!    does the R-ENC decrypt or the R-MAC CMAC do data-dependent
//!    `mem_address` accesses that leak the session key or `half_E`?
//!
//! **Scope (honest).** Emulation tests the *software* unwrap logic + the
//! MAC-verify gate, NOT the SE050 silicon or the I2C bus physics. This is
//! defense-in-depth completeness — a new gate-shaped secret path shouldn't
//! ship un-swept when every comparable path (C10 sign, KDF, PIN gate,
//! FW-verify) has a harness — not a known-bug fire drill.
//!
//! The secret-touching primitives (`aes128_cbc_decrypt`, `cmac_aes128`,
//! `aes128_ecb_encrypt`) are the REAL firmware code, `#[path]`-included from
//! `secure/src/scp03_logic.rs`. The thin `unwrap_response` wrapper is a
//! kept-in-sync copy of `secure/src/se050/scp03.rs` (that file can't be
//! `#[path]`-included — it's entangled with the SE050 I2C driver module).

#![no_std]
#![no_main]

use cortex_m_rt::entry;
use panic_halt as _;

/// Real firmware crypto primitives, byte-for-byte (`aes` 0.8 / `cmac` 0.7
/// soft backends, same as production). The `#[cfg(test)] mod tests` inside
/// is excluded from this non-test release build.
#[path = "../../../../secure/src/scp03_logic.rs"]
mod scp03_logic;

use scp03_logic::{aes128_cbc_decrypt, aes128_cbc_encrypt, aes128_ecb_encrypt, cmac_aes128};

/// RNG stub for `fi::wait_random` (production calls `crate::rng::byte()`); the
/// value only sets the random-delay loop length, irrelevant to what the sweep
/// probes. Mirrors `fi_target`.
pub mod rng {
    #[inline(never)]
    pub fn byte() -> u8 {
        5
    }

    /// Non-secret TRNG hook the production `fi.rs` uses for its delay loop
    /// (degrades to `fallback` on transient TRNG errors). Constant here for the
    /// same reason as `byte()`.
    #[inline(never)]
    pub fn byte_nonsecret(fallback: u8) -> u8 {
        fallback
    }
}

/// The REAL production FI-countermeasure source, included verbatim — so the
/// kept-in-sync `unwrap_response` copy below exercises the same
/// `check_true_into_sentinel` + Hamming-distant `OK_SENTINEL` hardening the
/// firmware uses (F-28).
#[path = "../../../../secure/src/fi.rs"]
mod fi;

/// The REAL receipt-bound exact copy used at the firmware's hardware-RNG
/// boundaries — the kept-in-sync `unwrap_response` copy releases through it
/// exactly like production (`copy_exact` wipes the destination on failure).
#[path = "../../../../secure/src/rng_exact.rs"]
mod rng_exact;

// ===========================================================================
// VERBATIM COPY — keep in sync with secure/src/se050/scp03.rs
//   Scp03Session (struct + inc_counter)  : scp03.rs:107-165
//   UnwrapError                          : scp03.rs:497-515   (From impl dropped)
//   ct_eq_8                              : scp03.rs:532-537
//   response_icv                         : scp03.rs:388-392
//   unwrap_response                      : scp03.rs:596-..    (debug-log line dropped)
// The only edits are: drop `#[cfg(feature="debug-log")] secure_log!(...)`,
// drop `impl From<UnwrapError> for Se050Error`, and make the items local.
// The release path carries the reworked F-28 hardening (fail-initialized
// R-MAC receipt via `scp03_logic::verify_rmac_into`, the wave-18 R-ENC
// decrypt-fidelity receipt via `verify_renc_relation_into`, dual volatile
// checks, and the receipt-bound `rng_exact::copy_exact` release) in
// lock-step with the firmware — that is what `make scp03-fi` re-validates.
// ===========================================================================

pub struct Scp03Session {
    pub s_enc: [u8; 16],
    pub s_mac: [u8; 16],
    pub s_rmac: [u8; 16],
    pub mcv: [u8; 16],
    pub counter: [u8; 16],
    pub active: bool,
}

impl Scp03Session {
    fn inc_counter(&mut self) {
        for i in (0..16).rev() {
            self.counter[i] = self.counter[i].wrapping_add(1);
            if self.counter[i] != 0 {
                break;
            }
        }
    }
}

#[derive(Debug)]
pub enum UnwrapError {
    Truncated,
    Inactive,
    MalformedLength,
    RMacMismatch,
    RelationMismatch,
    BadCiphertextLen,
    BadPadding,
    Overflow,
}

/// Constant-time equality on two 8-byte slices (`subtle::ConstantTimeEq`).
/// Unused by the reworked F-28 gate below (which delegates to
/// `scp03_logic::verify_rmac_into`) but part of the kept-in-sync copy —
/// the real `scp03.rs` still uses it in `establish`.
#[allow(dead_code)]
fn ct_eq_8(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    debug_assert_eq!(a.len(), 8);
    debug_assert_eq!(b.len(), 8);
    a.ct_eq(b).into()
}

/// Response ICV: `AES-ECB(S-ENC, 0x80 || counter[1..16])` (GP Amd D §6.2.7).
fn response_icv(session: &Scp03Session) -> [u8; 16] {
    let mut block = session.counter;
    block[0] = 0x80;
    aes128_ecb_encrypt(&session.s_enc, &block)
}

/// Unwrap an SCP03-protected response (R-MAC verify + R-ENC decrypt).
pub fn unwrap_response(
    session: &mut Scp03Session,
    wrapped: &[u8],
    out: &mut [u8],
) -> Result<usize, UnwrapError> {
    if !session.active {
        return Err(UnwrapError::Inactive);
    }
    let n = wrapped.len();
    if n < 2 {
        return Err(UnwrapError::Truncated);
    }

    if n == 2 {
        if out.len() < 2 {
            return Err(UnwrapError::Overflow);
        }
        out[0] = wrapped[0];
        out[1] = wrapped[1];
        session.inc_counter();
        return Ok(2);
    }

    if n < 10 {
        return Err(UnwrapError::MalformedLength);
    }

    let body_end = n - 10;
    let body = &wrapped[..body_end];
    let rmac_recv = &wrapped[body_end..body_end + 8];
    let sw = &wrapped[n - 2..];

    // R-MAC = CMAC(S-RMAC, MCV || ciphered_body || SW)[..8]
    //
    // F-28 rework (kept in sync with scp03.rs): the authoritative gate is a
    // fail-initialized authentication receipt — `verify_rmac_into` publishes
    // `OK_SENTINEL` only after two independent full R-MAC recomputations, and
    // two independent volatile checks (separated by `wait_random`) must pass
    // before any copy, counter advance, or `Ok`. There is deliberately NO
    // complementing infective mask: XOR-0xFF is a public bijection, so the
    // forged frame in this harness carries the *complement* of
    // `ATTACKER_HALF_E` — the old mask would have turned it into the exact
    // attacker-selected bytes after one fault.
    crate::fi::wait_random();
    let mut rmac_auth_receipt: u32 = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique stack receipt, fail-initialized.
    unsafe {
        core::ptr::write_volatile(&mut rmac_auth_receipt, crate::fi::FAIL_SENTINEL);
    }
    scp03_logic::verify_rmac_into(
        &session.s_rmac,
        &session.mcv,
        body,
        sw,
        rmac_recv,
        &mut rmac_auth_receipt,
    );
    if unsafe { core::ptr::read_volatile(&rmac_auth_receipt) } != crate::fi::OK_SENTINEL {
        return Err(UnwrapError::RMacMismatch);
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&rmac_auth_receipt) } != crate::fi::OK_SENTINEL {
        return Err(UnwrapError::RMacMismatch);
    }

    if body_end == 0 {
        if out.len() < 2 {
            return Err(UnwrapError::Overflow);
        }
        out[0] = sw[0];
        out[1] = sw[1];
        session.inc_counter();
        return Ok(2);
    }

    if body_end % 16 != 0 {
        return Err(UnwrapError::BadCiphertextLen);
    }

    let mut plain = zeroize::Zeroizing::new([0u8; 1024]);
    if body_end > plain.len() {
        return Err(UnwrapError::Overflow);
    }
    plain[..body_end].copy_from_slice(body);

    let icv = response_icv(session);
    aes128_cbc_decrypt(&session.s_enc, &icv, &mut plain[..body_end]);

    // Decrypt-fidelity receipt (kept in sync with scp03.rs): bind the
    // decrypted padded buffer back to the authenticated ciphertext — a
    // skipped/corrupted decrypt writeback otherwise releases bus-visible
    // ciphertext behind an Ok (wave-18 GPT-5.6 blocker).
    let mut renc_receipt: u32 = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique stack receipt, fail-initialized.
    unsafe {
        core::ptr::write_volatile(&mut renc_receipt, crate::fi::FAIL_SENTINEL);
    }
    scp03_logic::verify_renc_relation_into(
        &session.s_enc,
        &session.counter,
        &plain[..body_end],
        body,
        &mut renc_receipt,
    );
    if unsafe { core::ptr::read_volatile(&renc_receipt) } != crate::fi::OK_SENTINEL {
        return Err(UnwrapError::RelationMismatch);
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&renc_receipt) } != crate::fi::OK_SENTINEL {
        return Err(UnwrapError::RelationMismatch);
    }

    // ISO 7816-4 depad.
    let mut pad_pos = body_end;
    while pad_pos > 0 {
        pad_pos -= 1;
        if plain[pad_pos] == 0x80 {
            break;
        }
        if plain[pad_pos] != 0x00 {
            return Err(UnwrapError::BadPadding);
        }
        if pad_pos + 16 <= body_end {
            return Err(UnwrapError::BadPadding);
        }
    }
    if plain[pad_pos] != 0x80 {
        return Err(UnwrapError::BadPadding);
    }
    let plaintext_len = pad_pos;

    if out.len() < plaintext_len + 2 {
        return Err(UnwrapError::Overflow);
    }

    // Both receipts passed — release through the receipt-bound exact copy
    // (kept in sync with scp03.rs). No infective mask.
    if rng_exact::copy_exact(&plain[..plaintext_len], &mut out[..plaintext_len]).is_err() {
        return Err(UnwrapError::RelationMismatch);
    }
    out[plaintext_len] = sw[0];
    out[plaintext_len + 1] = sw[1];

    session.inc_counter();

    Ok(plaintext_len + 2)
}

// ===========================================================================
// SCA harness surface
// ===========================================================================

// Fixed (arbitrary) SCP03 session state. Real per-device keys are
// BHK/SAES-derived; the SCA logic is key-value-independent, so a hard fixed
// session suffices and keeps the emulation deterministic.
const S_ENC: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
const S_RMAC: [u8; 16] = [
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
];
const MCV: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const COUNTER: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const SW: [u8; 2] = [0x90, 0x00];
/// The `half_E` an attacker would try to inject via a forged response.
/// 15 data bytes so a single `0x80` ISO-7816-4 pad fills the 16-byte block.
const ATTACKER_HALF_E: [u8; 15] = *b"FORGED::half_E!";

/// Out-of-band output buffer for the FI harness. Lives in `.bss` (mapped +
/// re-zeroed on every `e.reset()`), so the harness reads the released
/// plaintext by symbol address rather than relying on a hand-mapped scratch.
/// `#[used]` keeps it (and its symbol) past LTO/`--gc-sections` even though
/// the firmware writes it only through the `out_ptr` the harness supplies.
/// 96 bytes: the valid3 witness publishes 32 plaintext + 48 ciphertext bytes.
#[no_mangle]
#[used]
pub static mut SCA_SCP03_OUT: [u8; 96] = [0u8; 96];

fn fixed_session() -> Scp03Session {
    Scp03Session {
        s_enc: S_ENC,
        s_mac: [0u8; 16],
        s_rmac: S_RMAC,
        mcv: MCV,
        counter: COUNTER,
        active: true,
    }
}

/// Build a 26-byte wrapped response (`ciphertext(16) || R-MAC(8) || SW(2)`).
/// A valid frame carries `ATTACKER_HALF_E`. A forged frame carries its bitwise
/// complement so the legacy `0xff` infective mask turns it back into the exact
/// attacker-selected bytes if one fault skips the early R-MAC rejection.
/// `valid_rmac=false` also plants a deliberately-wrong (all-zero) R-MAC — the
/// attacker can know R-ENC while still being unable to compute `S-RMAC`.
fn build_forged_wrapped(valid_rmac: bool) -> [u8; 26] {
    let sess = fixed_session();
    let mut block = [0u8; 16];
    for (slot, selected) in block[..15].iter_mut().zip(ATTACKER_HALF_E.iter()) {
        *slot = if valid_rmac { *selected } else { !*selected };
    }
    block[15] = 0x80; // ISO 7816-4 pad
    let icv = response_icv(&sess);
    aes128_cbc_encrypt(&sess.s_enc, &icv, &mut block); // block := R-ENC ciphertext

    let mut wrapped = [0u8; 26];
    wrapped[..16].copy_from_slice(&block);
    if valid_rmac {
        let mac = cmac_aes128(&sess.s_rmac, &[&sess.mcv, &block, &SW]);
        wrapped[16..24].copy_from_slice(&mac[..8]);
    } else {
        wrapped[16..24].copy_from_slice(&[0u8; 8]); // attacker can't forge the R-MAC
    }
    wrapped[24] = SW[0];
    wrapped[25] = SW[1];
    wrapped
}

/// **FI gate-bypass target.** Unwrap a FORGED response (wrong R-MAC). The
/// R-MAC gate MUST reject it. Returns `0` on rejection (correct), `1` if the
/// gate was bypassed and the attacker's `half_E` was released into `out_ptr`
/// (the harness confirms `out[..15] == ATTACKER_HALF_E`).
#[no_mangle]
pub extern "C" fn sca_scp03_unwrap_gate(out_ptr: *mut u8) -> u32 {
    let wrapped = build_forged_wrapped(false);
    let mut sess = fixed_session();
    let mut out = [0u8; 64];
    match unwrap_response(&mut sess, &wrapped, &mut out) {
        Ok(n) => {
            // GATE BYPASSED — forged response accepted, plaintext released.
            let m = if n > 64 { 64 } else { n };
            for i in 0..m {
                // SAFETY: harness provides a ≥64-byte out buffer.
                unsafe { core::ptr::write_volatile(out_ptr.add(i), out[i]) };
            }
            1
        }
        Err(_) => 0,
    }
}

/// **Valid-frame output-equality target (wave-18 follow-up).** Unwrap a
/// CORRECTLY-MAC'd 58-byte response (3-block R-ENC body of a 32-byte
/// TLV-shaped plaintext + ISO pad, valid R-MAC). The gate must release the
/// expected plaintext. The FI sweep faults every instruction and requires
/// that no single fault yields `Ok` with output ≠ the expected plaintext
/// (the decrypt-writeback skip class that released bus-visible ciphertext
/// before the R-ENC relation receipt).
#[no_mangle]
pub extern "C" fn sca_scp03_unwrap_valid3_gate(out_ptr: *mut u8) -> u32 {
    let (wrapped, _expected) = build_valid3_wrapped();
    let mut sess = fixed_session();
    let mut out = [0u8; 64];
    match unwrap_response(&mut sess, &wrapped, &mut out) {
        Ok(n) => {
            let m = if n > 64 { 64 } else { n };
            for i in 0..m {
                // SAFETY: harness provides a ≥64-byte out buffer.
                unsafe { core::ptr::write_volatile(out_ptr.add(i), out[i]) };
            }
            1
        }
        Err(_) => 0,
    }
}

/// The valid3 frame's expected released plaintext (`TLV || 30 bytes`).
fn valid3_expected() -> [u8; 32] {
    let mut expected = [0u8; 32];
    expected[0] = 0x41; // TAG_1
    expected[1] = 0x1e; // len 30
    for (i, b) in expected[2..].iter_mut().enumerate() {
        *b = 0xA0 + i as u8;
    }
    expected
}

/// Build a VALID 58-byte wrapped response: 48-byte R-ENC body (32-byte
/// plaintext || 0x80 || 0-padding) || correct R-MAC(8) || SW(2).
fn build_valid3_wrapped() -> ([u8; 58], [u8; 32]) {
    let sess = fixed_session();
    let expected = valid3_expected();
    let mut plain = [0u8; 48];
    plain[..32].copy_from_slice(&expected);
    plain[32] = 0x80; // ISO 7816-4 pad
    let icv = response_icv(&sess);
    aes128_cbc_encrypt(&sess.s_enc, &icv, &mut plain); // plain := R-ENC ciphertext
    let mac = cmac_aes128(&sess.s_rmac, &[&sess.mcv, &plain, &SW]);
    let mut wrapped = [0u8; 58];
    wrapped[..48].copy_from_slice(&plain);
    wrapped[48..56].copy_from_slice(&mac[..8]);
    wrapped[56] = SW[0];
    wrapped[57] = SW[1];
    (wrapped, expected)
}

/// Witness for the harness script: expected plaintext at [0..32], R-ENC
/// ciphertext body at [32..80].
#[no_mangle]
pub extern "C" fn sca_scp03_valid3_witness(out_ptr: *mut u8) -> u32 {
    let (wrapped, expected) = build_valid3_wrapped();
    for i in 0..32 {
        // SAFETY: harness provides a ≥80-byte buffer.
        unsafe { core::ptr::write_volatile(out_ptr.add(i), expected[i]) };
    }
    for i in 0..48 {
        // SAFETY: harness provides a ≥80-byte buffer.
        unsafe { core::ptr::write_volatile(out_ptr.add(32 + i), wrapped[i]) };
    }
    1
}

/// Sanity self-test (no fault): a CORRECTLY-MAC'd response of the same shape
/// must unwrap to `ATTACKER_HALF_E || SW` (17 bytes). Returns `1` on the
/// expected result, `2` on wrong plaintext, `0` on rejection. Proves the
/// target isn't trivially always-reject (which would make the FI sweep
/// vacuous).
#[no_mangle]
pub extern "C" fn sca_scp03_unwrap_valid_selftest() -> u32 {
    let wrapped = build_forged_wrapped(true);
    let mut sess = fixed_session();
    let mut out = [0u8; 64];
    match unwrap_response(&mut sess, &wrapped, &mut out) {
        Ok(n) => {
            if n == 17 && out[..15] == ATTACKER_HALF_E {
                1
            } else {
                2
            }
        }
        Err(_) => 0,
    }
}

/// **Leakage target (a).** R-ENC AES-128-CBC decrypt under a per-trace
/// session key. Input `key(16) || iv(16) || ct(32)`; output `pt(32)`. TVLA
/// varying the key: the `aes` soft backend is bitsliced (no T-tables), so
/// `mem_address` is expected FLAT (the key/`half_E` doesn't index memory).
#[no_mangle]
#[inline(never)]
pub extern "C" fn sca_scp03_cbc_decrypt(in_ptr: *const u8, out_ptr: *mut u8) {
    // SAFETY: harness plants a 64-byte input and a ≥32-byte output buffer.
    let input = unsafe { core::slice::from_raw_parts(in_ptr, 64) };
    let mut key = [0u8; 16];
    key.copy_from_slice(&input[..16]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&input[16..32]);
    let mut data = [0u8; 32];
    data.copy_from_slice(&input[32..64]);
    aes128_cbc_decrypt(&key, &iv, &mut data);
    for i in 0..32 {
        // SAFETY: out_ptr valid for 32 bytes.
        unsafe { core::ptr::write_volatile(out_ptr.add(i), data[i]) };
    }
}

/// **Leakage target (b).** R-MAC CMAC-AES-128 under a per-trace session key.
/// Input `key(16) || msg(32)`; output `tag(16)`. Same flat-on-`mem_address`
/// expectation as (a).
#[no_mangle]
#[inline(never)]
pub extern "C" fn sca_scp03_cmac(in_ptr: *const u8, out_ptr: *mut u8) {
    // SAFETY: harness plants a 48-byte input and a ≥16-byte output buffer.
    let input = unsafe { core::slice::from_raw_parts(in_ptr, 48) };
    let mut key = [0u8; 16];
    key.copy_from_slice(&input[..16]);
    let msg = &input[16..48];
    let tag = cmac_aes128(&key, &[msg]);
    for i in 0..16 {
        // SAFETY: out_ptr valid for 16 bytes.
        unsafe { core::ptr::write_volatile(out_ptr.add(i), tag[i]) };
    }
}

// ===========================================================================
// Keep-alive roots — defeat `--gc-sections` / LTO stripping of the exports.
// ===========================================================================
#[used]
static _KEEP_GATE: extern "C" fn(*mut u8) -> u32 = sca_scp03_unwrap_gate;
#[used]
static _KEEP_SELFTEST: extern "C" fn() -> u32 = sca_scp03_unwrap_valid_selftest;
#[used]
static _KEEP_VALID3: extern "C" fn(*mut u8) -> u32 = sca_scp03_unwrap_valid3_gate;
#[used]
static _KEEP_WIT3: extern "C" fn(*mut u8) -> u32 = sca_scp03_valid3_witness;
#[used]
static _KEEP_CBC: extern "C" fn(*const u8, *mut u8) = sca_scp03_cbc_decrypt;
#[used]
static _KEEP_CMAC: extern "C" fn(*const u8, *mut u8) = sca_scp03_cmac;

#[entry]
fn main() -> ! {
    // The harness jumps straight to the `sca_*` symbols; main never runs the
    // real work. Touch the keep-statics belt-and-braces against DCE.
    core::hint::black_box(&_KEEP_GATE);
    core::hint::black_box(&_KEEP_SELFTEST);
    core::hint::black_box(&_KEEP_VALID3);
    core::hint::black_box(&_KEEP_WIT3);
    core::hint::black_box(&_KEEP_CBC);
    core::hint::black_box(&_KEEP_CMAC);
    loop {
        cortex_m::asm::nop();
    }
}
