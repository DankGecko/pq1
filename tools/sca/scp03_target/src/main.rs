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
//!    ciphertext of an attacker-chosen `half_E`, but a WRONG R-MAC). Can a
//!    single fault make the R-MAC verify gate
//!    (`if !ct_eq_8(mac_full[..8], rmac_recv)`) pass → host accepts and
//!    releases the attacker's `half_E`?
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
}

/// The REAL production FI-countermeasure source, included verbatim — so the
/// kept-in-sync `unwrap_response` copy below exercises the same
/// `check_true_into_sentinel` + Hamming-distant `OK_SENTINEL` hardening the
/// firmware uses (F-28).
#[path = "../../../../secure/src/fi.rs"]
mod fi;

// ===========================================================================
// VERBATIM COPY — keep in sync with secure/src/se050/scp03.rs
//   Scp03Session (struct + inc_counter)  : scp03.rs:92-125
//   UnwrapError                          : scp03.rs:417-435   (From impl dropped)
//   ct_eq_8                              : scp03.rs:452-457
//   response_icv                         : scp03.rs:310-314
//   unwrap_response                      : scp03.rs:491-601   (debug-log line dropped)
// The only edits are: drop `#[cfg(feature="debug-log")] secure_log!(...)`,
// drop `impl From<UnwrapError> for Se050Error`, and make the items local.
// The R-MAC gate carries the F-28 FI-hardening (sentinel + recomputed CMAC)
// in lock-step with the firmware — that is what `make scp03-fi` re-validates.
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
    BadCiphertextLen,
    BadPadding,
    Overflow,
}

/// Constant-time equality on two 8-byte slices (`subtle::ConstantTimeEq`).
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
    // F-28 FI-hardening (kept in sync with scp03.rs): recompute the CMAC inside
    // the double-evaluated closure (a fault corrupting one computation makes
    // the two disagree) and route the verdict through the Hamming-distant
    // sentinel; `black_box` stops LLVM collapsing the two evaluations.
    crate::fi::wait_random();
    let rmac_ok = crate::fi::check_true_into_sentinel(|| {
        let mac = cmac_aes128(&session.s_rmac, &[&session.mcv, body, sw]);
        core::hint::black_box(ct_eq_8(&mac[..8], rmac_recv))
    });
    if rmac_ok != crate::fi::OK_SENTINEL {
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

    let mut plain = [0u8; 1024];
    if body_end > plain.len() {
        return Err(UnwrapError::Overflow);
    }
    plain[..body_end].copy_from_slice(body);

    let icv = response_icv(session);
    aes128_cbc_decrypt(&session.s_enc, &icv, &mut plain[..body_end]);

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

    // F-28 infective release gate (kept in sync with scp03.rs): fold a fresh,
    // INDEPENDENT R-MAC recompute branchlessly into the released bytes, so a
    // forged response that slips past the early sentinel gate (which is itself
    // single-skip-defeatable via check_true_into_sentinel's verdict branch) is
    // XOR-garbled rather than releasing the attacker's half_E. No branch on the
    // verdict here.
    let mac_chk = cmac_aes128(&session.s_rmac, &[&session.mcv, body, sw]);
    let mac_matches = ct_eq_8(&mac_chk[..8], rmac_recv);
    let release_mask = (mac_matches as u8).wrapping_sub(1);
    for (o, p) in out[..plaintext_len]
        .iter_mut()
        .zip(plain[..plaintext_len].iter())
    {
        *o = p ^ release_mask;
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
#[no_mangle]
#[used]
pub static mut SCA_SCP03_OUT: [u8; 64] = [0u8; 64];

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

/// Build a 26-byte wrapped response (`ciphertext(16) || R-MAC(8) || SW(2)`)
/// carrying `ATTACKER_HALF_E` under R-ENC. `valid_rmac=false` plants a
/// deliberately-wrong (all-zero) R-MAC — the response a forging attacker can
/// actually produce (they cannot compute the R-MAC without `S-RMAC`).
fn build_forged_wrapped(valid_rmac: bool) -> [u8; 26] {
    let sess = fixed_session();
    let mut block = [0u8; 16];
    block[..15].copy_from_slice(&ATTACKER_HALF_E);
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
static _KEEP_CBC: extern "C" fn(*const u8, *mut u8) = sca_scp03_cbc_decrypt;
#[used]
static _KEEP_CMAC: extern "C" fn(*const u8, *mut u8) = sca_scp03_cmac;

#[entry]
fn main() -> ! {
    // The harness jumps straight to the `sca_*` symbols; main never runs the
    // real work. Touch the keep-statics belt-and-braces against DCE.
    core::hint::black_box(&_KEEP_GATE);
    core::hint::black_box(&_KEEP_SELFTEST);
    core::hint::black_box(&_KEEP_CBC);
    core::hint::black_box(&_KEEP_CMAC);
    loop {
        cortex_m::asm::nop();
    }
}
