use crate::rng::{PrivateRng, PublicRng, RngCore};
use checkct_macros::checkct;
use subtle::ConstantTimeEq;

// CT proof of the `subtle::ConstantTimeEq::ct_eq` secret-vs-secret COMPARE
// mechanism — the primitive behind every constant-time equality the firmware
// performs on secret operands:
//   * the C10 double-compute signature check  (secure/src/crypto.rs:188
//        `sig_a[..].ct_eq(&sig_b[..])` — the FI-hardened verify-before-release),
//   * the dual-SE master-secret reconstruction check (dual_se.rs:283/443
//        `derived_master.ct_eq(&stored_master)`),
//   * the SE050 SCP03 host-cryptogram / MAC verify (se050/scp03.rs),
//   * the FW-update secure/nonsecure hash verify (fw_update/verify.rs).
//
// `subtle` is constant-time BY CONSTRUCTION, so this driver is a REGRESSION
// GUARD, not a discovery: it certifies the compare stays branch-free and
// address-oblivious under the SHIPPED `opt-level="s"` + `overflow-checks=true`
// profile — the exact profile that, 2026-07-02, compiled `cmac.rs::double_l`'s
// GF(2^128) reduction to a secret-MSB branch (checkct `driver_saes`). The
// `subtle` byte-fold loop is length-independent (it folds `x ^ y` OR-accumulated
// across the bytes), so a 32-byte operand certifies the mechanism for all the
// call sites above regardless of their operand lengths (16/32/4008 B).
//
// SECURE   => the ct_eq compare is constant-time w.r.t. BOTH secret operands.
// INSECURE => the compiler lowered a subtle byte-fold to a data-dependent branch
//             or a secret-address memory access — a real CT regression to fix.
#[checkct]
pub fn checkct() {
    // Two SECRET operands: the firmware compares a freshly-derived secret against
    // a stored secret, and neither the equal/unequal RESULT nor the operand bytes
    // may leak through control flow or a secret-dependent access.
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    PrivateRng.fill_bytes(&mut a);
    PrivateRng.fill_bytes(&mut b);

    // The relational CT model needs a PUBLIC input source present (both traces
    // share public inputs, differ on secret). This compare has no public operand,
    // so touch `__checkct_public_rand` to keep the symbol live — it never enters
    // the compare, so it does not weaken the CT property.
    core::hint::black_box(PublicRng.next_u32());

    // Match the production slice form exactly (crypto.rs:188).
    let eq: bool = a[..].ct_eq(&b[..]).into();
    core::hint::black_box(eq);
}
