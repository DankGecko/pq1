//! Evidence-layer fail-closed tests: out-of-range fields in a
//! struct-literal `ManifestV6` must never panic the decoder.

mod common;

use common::*;
use fw_manifest::v6::{ManifestV6, PhysicalSlot};
use fw_manifest::SIGNATURE_LEN;

fn struct_literal_manifest(r: u32, e: u32) -> ManifestV6 {
    // Bypasses the v6 builder/parser (which rejects these values) to
    // model a mutated or struct-literal ManifestV6.
    ManifestV6 {
        slot: PhysicalSlot::A,
        release_version: r,
        security_epoch: e,
        secure_len: 0x1000,
        nonsecure_len: 0x2000,
        secure_hash: seq(0x00),
        nonsecure_hash: seq(0x20),
        vendor_fpr: seq(0x40),
        build_id: seq(0x60),
        stored_digest: seq(0x80),
        signature: [0xAA; SIGNATURE_LEN],
        stored_crc32: 0,
    }
}

#[test]
fn zero_epoch_yields_none_not_panic() {
    let p = pass();
    let (pk_seed, pk_root) = test_key_material();
    let m = struct_literal_manifest(GOLDEN_R, 0);
    assert!(p.verify_artifact(&m, INSTALL_ID, &pk_seed, &pk_root).is_none());
}

#[test]
fn max_epoch_sentinel_yields_none() {
    let p = pass();
    let (pk_seed, pk_root) = test_key_material();
    let m = struct_literal_manifest(GOLDEN_R, 0xFFFF_FFFF);
    assert!(p.verify_artifact(&m, INSTALL_ID, &pk_seed, &pk_root).is_none());
}

#[test]
fn zero_release_version_yields_none() {
    let p = pass();
    let (pk_seed, pk_root) = test_key_material();
    let m = struct_literal_manifest(0, GOLDEN_E);
    assert!(p.verify_artifact(&m, INSTALL_ID, &pk_seed, &pk_root).is_none());
}

#[test]
fn in_range_signed_manifest_derives_checked_t() {
    // R5-1: a genuinely signed manifest verifies through the real
    // authority path and derives checked T = E - 1.
    let p = pass();
    let (pk_seed, pk_root) = test_key_material();
    let m = manifest(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let art = p
        .verify_artifact(&m, INSTALL_ID, &pk_seed, &pk_root)
        .expect("signed manifest verifies");
    assert_eq!(art.t(), GOLDEN_E - 1);
    assert_eq!(art.e(), GOLDEN_E);
}

#[test]
fn unsigned_struct_literal_is_rejected() {
    // R5-1: a struct-literal manifest with a dummy digest/signature
    // yields None at the digest/signature leg (it previously yielded
    // Some — the mint ran no verification).
    let p = pass();
    let (pk_seed, pk_root) = test_key_material();
    let m = struct_literal_manifest(GOLDEN_R, GOLDEN_E);
    assert!(p.verify_artifact(&m, INSTALL_ID, &pk_seed, &pk_root).is_none());
}

#[test]
fn verify_artifact_runs_real_verification() {
    let p = pass();
    let (pk_seed, pk_root) = test_key_material();

    // A genuinely signed page verifies.
    let m = manifest(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    assert!(p.verify_artifact(&m, INSTALL_ID, &pk_seed, &pk_root).is_some());

    // Wrong key → None (previously Some).
    let wrong = sphincs_c10::SigningKey::keygen(*b"RB-TEST-SK-SEED-NONPROD-00000002", *b"RB-TEST-PK-00002");
    let wvk = wrong.verifying_key();
    assert!(p.verify_artifact(&m, INSTALL_ID, &wvk.pk_seed, &wvk.pk_root).is_none());

    // One-bit signature corruption → None (re-seal CRC so only the
    // signature leg can catch it).
    let mut page = signed_page(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    page[fw_manifest::v6::OFF_SIGNATURE + 2000] ^= 0x01;
    fw_manifest::v6::rewrite_normalized_crc(&mut page);
    let corrupted = fw_manifest::v6::parse_and_validate(&page, PhysicalSlot::A).unwrap();
    assert!(p.verify_artifact(&corrupted, INSTALL_ID, &pk_seed, &pk_root).is_none());

    // Tampered stored digest → None at the digest leg.
    let mut page = signed_page(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    page[fw_manifest::v6::OFF_DIGEST] ^= 0x01;
    fw_manifest::v6::rewrite_normalized_crc(&mut page);
    let tampered = fw_manifest::v6::parse_and_validate(&page, PhysicalSlot::A).unwrap();
    assert!(p.verify_artifact(&tampered, INSTALL_ID, &pk_seed, &pk_root).is_none());
}
