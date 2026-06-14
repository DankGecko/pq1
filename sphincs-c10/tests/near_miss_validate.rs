//! Validate the +C-gate near-miss generator (feature `near-miss-gen`).
//!
//! Asserts the two structural properties the KAT relies on:
//!   * the unmodified verifier REJECTS each near-miss vector;
//!   * the rejection is caused ONLY by the targeted +C gate — verified by
//!     re-running an "ungated" reconstruction that reproduces the verifier
//!     minus the one gate and confirming it ACCEPTS (root matches).
//!
//! Run: cargo test -p sphincs-c10 --test near_miss_validate \
//!        --features near-miss-gen --release -- --nocapture
#![cfg(feature = "near-miss-gen")]

use sphincs_c10::near_miss::{sign_near_miss, verify_with_gate_removed, Kind};
use sphincs_c10::{verify, SigningKey};

fn keypair() -> SigningKey {
    let sk_seed: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0, 0x01,
    ];
    let pk_seed: [u8; 16] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];
    SigningKey::keygen(sk_seed, pk_seed)
}

#[test]
fn nm1_wots_digit_sum_is_a_clean_near_miss() {
    let sk = keypair();
    let msg: [u8; 32] = *b"PQSigner C10 near-miss NM1 vec 1";

    // A genuine signature verifies.
    let real = sk.sign(&msg, None);
    assert!(verify(sk.pk_seed(), sk.pk_root(), &msg, &real));

    // The near-miss is REJECTED by the unmodified verifier.
    let nm = sign_near_miss(sk.sk_seed(), sk.pk_seed(), sk.pk_root(), &msg, Kind::WotsDigitSum);
    assert!(
        !verify(sk.pk_seed(), sk.pk_root(), &msg, &nm),
        "NM1 must be rejected by the production verifier"
    );

    // ... and the rejection is ONLY the digit-sum gate: with that one gate
    // removed, the verifier ACCEPTS (root reconstructs correctly).
    assert!(
        verify_with_gate_removed(sk.pk_seed(), sk.pk_root(), &msg, &nm, Kind::WotsDigitSum),
        "NM1 must verify once the digit-sum gate is removed (clean near-miss)"
    );
    // Sanity: removing the OTHER gate must NOT rescue it (the WOTS gate is
    // still there) — confirms NM1 targets exactly the digit-sum gate.
    assert!(
        !verify_with_gate_removed(sk.pk_seed(), sk.pk_root(), &msg, &nm, Kind::ForsForcedZero),
        "removing the forced-zero gate must not accept an NM1 vector"
    );
    println!("NM1: production REJECT, digit-sum-gate-removed ACCEPT — clean near-miss.");
}

#[test]
fn nm2_fors_forced_zero_is_a_clean_near_miss() {
    let sk = keypair();
    let msg: [u8; 32] = *b"PQSigner C10 near-miss NM2 vec 2";

    let real = sk.sign(&msg, None);
    assert!(verify(sk.pk_seed(), sk.pk_root(), &msg, &real));

    let nm = sign_near_miss(sk.sk_seed(), sk.pk_seed(), sk.pk_root(), &msg, Kind::ForsForcedZero);
    assert!(
        !verify(sk.pk_seed(), sk.pk_root(), &msg, &nm),
        "NM2 must be rejected by the production verifier"
    );
    assert!(
        verify_with_gate_removed(sk.pk_seed(), sk.pk_root(), &msg, &nm, Kind::ForsForcedZero),
        "NM2 must verify once the forced-zero gate is removed (clean near-miss)"
    );
    assert!(
        !verify_with_gate_removed(sk.pk_seed(), sk.pk_root(), &msg, &nm, Kind::WotsDigitSum),
        "removing the digit-sum gate must not accept an NM2 vector"
    );
    println!("NM2: production REJECT, forced-zero-gate-removed ACCEPT — clean near-miss.");
}
