//! Shared helpers for the manifest-v6 signature-fixture generator and its
//! consumer test (`gen_v6_signature_fixture.rs` /
//! `v6_signature_fixtures.rs`). Test-side only; not part of the crate.
//!
//! The fixture key material below is a DEDICATED NONPRODUCTION C10 fixture
//! keypair. It is NOT the firmware-vendor key, NOT a wallet bootstrap/slot
//! key, NOT a health-only key, and MUST NEVER be compiled into or
//! referenced by any production image, signer, or provisioning path. Its
//! only purpose is to make the §6.1 key-matched fixture byte-reproducible
//! on any host.

// Each test binary compiles its own copy of this module and uses a
// different subset of the helpers.
#![allow(dead_code)]

use fw_manifest::v6::{self, PhysicalSlot, ReleasePackageFields};
use fw_manifest::{MANIFEST_SIZE, SIGNATURE_LEN};
use sha2::{Digest, Sha256};
use sphincs_c10::SigningKey;

// ---------------------------------------------------------------------------
// Fixture key material — TEST ONLY (see the module banner).
// ---------------------------------------------------------------------------

/// Fixture signing-key seed (32 bytes). TEST ONLY.
pub const V6_FIXTURE_SK_SEED: [u8; 32] = *b"V6-FIXTURE-NONPROD-SK-SEED-00001";
/// Fixture public seed (16 bytes). TEST ONLY.
pub const V6_FIXTURE_PK_SEED: [u8; 16] = *b"V6-FIXTURE-PK-01";
/// Second, unrelated fixture keypair for the wrong-key negative fixture.
/// TEST ONLY.
pub const V6_WRONGKEY_SK_SEED: [u8; 32] = *b"V6-FIXTURE-NONPROD-SK-SEED-00002";
/// Wrong-key public seed. TEST ONLY.
pub const V6_WRONGKEY_PK_SEED: [u8; 16] = *b"V6-FIXTURE-PK-02";

// ---------------------------------------------------------------------------
// Pinned fixture receipts (§6.1 L1924–1933). The generator asserts its
// freshly computed values against these constants; the consumer test
// asserts the checked-in artifact against the same constants — the two
// sides can only drift if someone changes the seeds or the shared code, in
// which case one of the two assertions fails loudly.
// ---------------------------------------------------------------------------

/// Deterministic keygen output for the fixture seeds (pinned receipt).
pub const FIXTURE_PK_ROOT: &str = "9eb0ff9813adf4c71b21d6bed0d2d383";
/// `vendor_fingerprint(pk_seed, pk_root)` for the fixture key (pinned).
pub const FIXTURE_FPR: &str =
    "4005485c1354e4953b02b28a786ea6683d81f95784f579459d42f1644e00a61c";
/// §6.1 receipt row: SHA-256 over the 4,008 fixture signature bytes.
pub const FIXTURE_SIG_SHA256: &str =
    "7bf48b0c8e908a76a96828ce01345f05206024051c97bf363f01f8d9daadb13d";
/// SHA-256 over the complete signed fixture page (CRC sealed).
pub const FIXTURE_PAGE_SHA256: &str =
    "d3a95154fd02fdcc4a8cafe379b568846fef218fbb91874aff2f69d7ff653851";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn hexs(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn hex_bytes(s: &str, out: &mut [u8]) {
    let s = s.as_bytes();
    assert_eq!(s.len(), out.len() * 2, "hex length mismatch");
    let nib = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex"),
        }
    };
    for (i, b) in out.iter_mut().enumerate() {
        *b = (nib(s[2 * i]) << 4) | nib(s[2 * i + 1]);
    }
}

pub fn hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex_bytes(s, &mut out);
    out
}

pub fn hex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    hex_bytes(s, &mut out);
    out
}

pub fn seq(start: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn fixture_key() -> SigningKey {
    SigningKey::keygen(V6_FIXTURE_SK_SEED, V6_FIXTURE_PK_SEED)
}

pub fn wrong_key() -> SigningKey {
    SigningKey::keygen(V6_WRONGKEY_SK_SEED, V6_WRONGKEY_PK_SEED)
}

const SECURE_HASH: [u8; 32] = {
    let mut o = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        o[i] = i as u8;
        i += 1;
    }
    o
};
const NONSECURE_HASH: [u8; 32] = {
    let mut o = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        o[i] = 0x20 + i as u8;
        i += 1;
    }
    o
};
const BUILD_ID: [u8; 32] = {
    let mut o = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        o[i] = 0x60 + i as u8;
        i += 1;
    }
    o
};
const PLACEHOLDER_SIG: [u8; SIGNATURE_LEN] = [0xFF; SIGNATURE_LEN];

/// The golden field set with the FIXTURE key's fingerprint in the
/// vendor-fpr slot (unsigned placeholder signature — the caller signs).
pub fn fixture_fields(fpr: &[u8; 32]) -> ReleasePackageFields<'_> {
    ReleasePackageFields {
        slot: PhysicalSlot::B,
        release_version: 0x0102_0304,
        security_epoch: 0x0506_0708,
        secure_len: 0x1000,
        nonsecure_len: 0x2000,
        secure_hash: &SECURE_HASH,
        nonsecure_hash: &NONSECURE_HASH,
        vendor_fpr: fpr,
        build_id: &BUILD_ID,
        signature: &PLACEHOLDER_SIG,
    }
}

/// Build the canonical package page for `fields`, then sign its recomputed
/// manifest digest with `key` (deterministic path, `opt_rand = None`) and
/// seal the page (signature written, normalized CRC recomputed).
pub fn sign_page(fields: &ReleasePackageFields<'_>, key: &SigningKey) -> [u8; MANIFEST_SIZE] {
    let mut page = v6::build_release_package(fields).expect("fixture fields are valid");
    let digest = v6::parse_and_validate(&page, fields.slot)
        .unwrap()
        .manifest_digest();
    let sig = key.sign(&digest, None);
    page[v6::OFF_SIGNATURE..v6::OFF_SIGNATURE + SIGNATURE_LEN].copy_from_slice(&sig);
    v6::rewrite_normalized_crc(&mut page);
    page
}

/// Overwrite the signature area of an otherwise-valid page with a signature
/// over an attacker-chosen 32-byte digest, then re-seal the CRC.
pub fn resign_page_with_digest(
    page: &mut [u8; MANIFEST_SIZE],
    key: &SigningKey,
    digest: &[u8; 32],
) {
    let sig = key.sign(digest, None);
    page[v6::OFF_SIGNATURE..v6::OFF_SIGNATURE + SIGNATURE_LEN].copy_from_slice(&sig);
    v6::rewrite_normalized_crc(page);
}

/// The freshly-computed fixture page (runtime regeneration). Used by the
/// generator to write the checked-in artifact and by the consumer test as
/// the determinism CROSS-CHECK — the canonical fixture source is the
/// checked-in artifact, never this function.
pub fn regenerate_fixture_page() -> [u8; MANIFEST_SIZE] {
    let key = fixture_key();
    let vk = key.verifying_key();
    let fpr = v6::vendor_fingerprint(&vk.pk_seed, &vk.pk_root);
    sign_page(&fixture_fields(&fpr), &key)
}
