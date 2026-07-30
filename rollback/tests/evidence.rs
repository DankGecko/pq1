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
    let m = struct_literal_manifest(GOLDEN_R, 0);
    assert!(p.verify_artifact(&m, INSTALL_ID).is_none());
}

#[test]
fn max_epoch_sentinel_yields_none() {
    let p = pass();
    let m = struct_literal_manifest(GOLDEN_R, 0xFFFF_FFFF);
    assert!(p.verify_artifact(&m, INSTALL_ID).is_none());
}

#[test]
fn zero_release_version_yields_none() {
    let p = pass();
    let m = struct_literal_manifest(0, GOLDEN_E);
    assert!(p.verify_artifact(&m, INSTALL_ID).is_none());
}

#[test]
fn in_range_struct_literal_derives_checked_t() {
    let p = pass();
    let m = struct_literal_manifest(GOLDEN_R, GOLDEN_E);
    let art = p.verify_artifact(&m, INSTALL_ID).expect("in range");
    assert_eq!(art.t(), GOLDEN_E - 1);
    assert_eq!(art.e(), GOLDEN_E);
}
