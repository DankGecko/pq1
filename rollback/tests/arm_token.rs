//! Arm-token tests: golden PQFW_A3 binding, layout pins, Hamming
//! properties, decode negatives (§6.2 L2028–2062, L2064–2091).

mod common;

use common::*;
use pqsigner_rollback::arm_token::*;
use fw_manifest::v6::PhysicalSlot;

fn golden_binding() -> ArmBinding {
    ArmBinding {
        slot: PhysicalSlot::B,
        r: GOLDEN_R,
        e: GOLDEN_E,
        t: GOLDEN_T,
        install_id: INSTALL_ID,
        manifest_digest: seq(0x00), // placeholder; replaced below
        secure_hash: seq(0x00),
        nonsecure_hash: seq(0x20),
    }
}

#[test]
fn golden_arm_token_binding_digest() {
    // §6.2 L2076–2080: for the §6.1 golden fixture, exact install
    // identity, and T=0x05060707, the binding digest is b8efdef8…ba2f.
    let mut b = golden_binding();
    b.manifest_digest = [
        0xfb, 0x0f, 0x51, 0xff, 0x0a, 0xd2, 0x1b, 0xf0, 0x2a, 0x15, 0x04, 0x1d, 0xba, 0xa2, 0x72,
        0x8e, 0xa1, 0x0b, 0x6a, 0x76, 0x01, 0x75, 0x3b, 0x15, 0xcb, 0x08, 0x3a, 0xd2, 0x12, 0xd6,
        0x16, 0x62,
    ];
    let want: [u8; 32] = [
        0xb8, 0xef, 0xde, 0xf8, 0x28, 0x95, 0x7f, 0x09, 0x68, 0x9c, 0x6a, 0xf0, 0xb7, 0x4b, 0x73,
        0x02, 0x8a, 0x0a, 0x00, 0x21, 0x4d, 0xb4, 0xf2, 0xa0, 0x0a, 0xc1, 0x79, 0x21, 0x36, 0xc9,
        0xba, 0x2f,
    ];
    let preimage = b.preimage();
    assert_eq!(preimage.len(), ARM_TOKEN_PREIMAGE_LEN);
    assert_eq!(&preimage[0..7], b"PQFW_A3");
    assert_eq!(preimage[7], 0x01);
    assert_eq!(&preimage[8..12], &GOLDEN_R.to_be_bytes());
    assert_eq!(&preimage[12..16], &GOLDEN_E.to_be_bytes());
    assert_eq!(&preimage[16..20], &GOLDEN_T.to_be_bytes());
    assert_eq!(&preimage[20..36], &INSTALL_ID);
    assert_eq!(&preimage[132..139], b"CLEAN10");
    assert_eq!(b.binding_hash(), want);

    // Word encoding: eight big-endian u32 words at BKP18..25.
    let words = ArmToken::encode(ArmState::ArmReady, &b);
    assert_eq!(words[WORD_BINDING], 0xB8EF_DEF8);
    assert_eq!(words[WORD_BINDING + 1], 0x2895_7F09);
    assert_eq!(words[WORD_BINDING + 7], 0x36C9_BA2F);
}

#[test]
fn token_layout_and_state_hamming() {
    // State pairs: distance 32 over the 64-bit pair (also const-pinned).
    let hd = |a: (u32, u32), b: (u32, u32)| (a.0 ^ b.0).count_ones() + (a.1 ^ b.1).count_ones();
    assert_eq!(hd(STATE_ARM_READY, STATE_ATTEMPTED), 32);
    assert_eq!(hd(STATE_ARM_READY, STATE_INVALID), 32);
    assert_eq!(hd(STATE_ATTEMPTED, STATE_INVALID), 32);
    // Slot codes are exact complements, distinct between slots.
    assert_eq!(SLOT_CODE_A.1, !SLOT_CODE_A.0);
    assert_eq!(SLOT_CODE_B.1, !SLOT_CODE_B.0);
    assert_ne!(SLOT_CODE_A.0, SLOT_CODE_B.0);
}

#[test]
fn token_encode_decode_round_trip() {
    let b = golden_binding();
    let words = ArmToken::encode(ArmState::ArmReady, &b);
    let s = ArmToken::decode_structure(&words).expect("structure");
    assert_eq!(s.state, ArmState::ArmReady);
    assert_eq!(s.slot, PhysicalSlot::B);
    assert_eq!((s.r, s.e, s.t), (GOLDEN_R, GOLDEN_E, GOLDEN_T));
    let t = ArmToken::decode_and_bind(
        &words,
        PhysicalSlot::B,
        &INSTALL_ID,
        &b.manifest_digest,
        &b.secure_hash,
        &b.nonsecure_hash,
    )
    .expect("bind");
    assert_eq!(t.state, ArmState::ArmReady);
    assert_eq!(t.binding.install_id, INSTALL_ID);
}

#[test]
fn token_decode_negatives() {
    let b = golden_binding();
    let good = ArmToken::encode(ArmState::ArmReady, &b);
    let bind = |w: &[u32; TOKEN_WORDS]| {
        ArmToken::decode_and_bind(
            w,
            PhysicalSlot::B,
            &INSTALL_ID,
            &b.manifest_digest,
            &b.secure_hash,
            &b.nonsecure_hash,
        )
    };

    // Bad magic.
    let mut w = good;
    w[WORD_MAGIC] ^= 1;
    assert_eq!(bind(&w), Err(TokenError::BadMagic));

    // Bad slot code (A-code words but not B's; actually a garbage pair).
    let mut w = good;
    w[WORD_SLOT_CODE + 1] ^= 0xFF; // complement broken AND not A's pair
    assert!(matches!(
        bind(&w),
        Err(TokenError::BadSlotCode) | Err(TokenError::BadComplement)
    ));

    // Bad R complement.
    let mut w = good;
    w[WORD_R + 1] ^= 1;
    assert_eq!(bind(&w), Err(TokenError::BadComplement));

    // Bad seal.
    let mut w = good;
    w[WORD_SEAL_0] ^= 1;
    assert_eq!(bind(&w), Err(TokenError::BadSeal));

    // Reset (0,0) and INVALID state are not valid states.
    let mut w = good;
    w[WORD_STATE] = 0;
    w[WORD_STATE + 1] = 0;
    assert_eq!(bind(&w), Err(TokenError::BadState));
    let mut w = good;
    w[WORD_STATE] = STATE_INVALID.0;
    w[WORD_STATE + 1] = STATE_INVALID.1;
    assert_eq!(bind(&w), Err(TokenError::BadState));

    // Out-of-range R (0) and E (0xFFFF_FFFF): encode manually since
    // encode() takes a valid binding.
    let mut w = good;
    w[WORD_R] = 0;
    w[WORD_R + 1] = !0u32;
    // Recompute nothing else — structural range check fires first.
    assert_eq!(bind(&w), Err(TokenError::OutOfRangeVersion));
    let mut w = good;
    w[WORD_E] = 0xFFFF_FFFF;
    w[WORD_E + 1] = !0xFFFF_FFFFu32;
    assert_eq!(bind(&w), Err(TokenError::OutOfRangeVersion));

    // T != E - 1.
    let mut w = good;
    w[WORD_T] = GOLDEN_T + 1;
    w[WORD_T + 1] = !(GOLDEN_T + 1);
    assert_eq!(bind(&w), Err(TokenError::InconsistentTarget));

    // Slot mismatch (token says B, we expect A).
    assert_eq!(
        ArmToken::decode_and_bind(
            &good,
            PhysicalSlot::A,
            &INSTALL_ID,
            &b.manifest_digest,
            &b.secure_hash,
            &b.nonsecure_hash,
        ),
        Err(TokenError::SlotMismatch)
    );

    // Binding mismatch: same structure, different install id.
    assert_eq!(
        ArmToken::decode_and_bind(
            &good,
            PhysicalSlot::B,
            &[0x11; 16],
            &b.manifest_digest,
            &b.secure_hash,
            &b.nonsecure_hash,
        ),
        Err(TokenError::BindingMismatch)
    );
}
