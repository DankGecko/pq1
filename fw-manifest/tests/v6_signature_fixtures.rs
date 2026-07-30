//! Key-matched manifest-v6 signature fixtures — FA-1.2b, Draft 1.1 §6.1
//! L1924–1933.
//!
//! The positive fixture uses a DEDICATED NONPRODUCTION C10 fixture keypair
//! (fixed, documented seeds below), its exact public-key fingerprint, a
//! canonical release-package page built through `v6::build_release_package`,
//! and a real C10 signature over the recomputed manifest digest. The
//! regeneration-identity test plus the pinned SHA-256 of the signature
//! bytes are the §6.1 "receipt binds the fixture-file hashes" row.
//!
//! The negative fixtures cover: wrong key, one-bit signature corruption,
//! domain substitution, schema substitution (the page-level schema gate
//! fires first), slot substitution, tuple change, length change, image-hash
//! change, and legacy-format retry (a genuine legacy v2 page built through
//! the legacy `ManifestBuilder` must fail at the v6 schema gate).
//!
//! The `i mod 256` patterned signature used by `v6_golden_fixtures.rs`
//! remains a serialization/normalization fixture only. It is NOT a valid
//! C10 signature KAT — `patterned_signature_is_not_a_c10_kat` proves it
//! does not verify.

use fw_manifest::v6::{self, PhysicalSlot, ReleasePackageFields, ValidationError};
use fw_manifest::{ManifestBuilder, ManifestRef, MANIFEST_SIZE, SIGNATURE_LEN};
use sha2::{Digest, Sha256};
use sphincs_c10::SigningKey;

// ---------------------------------------------------------------------------
// Fixture key material — TEST ONLY.
//
// These seeds are a DEDICATED NONPRODUCTION fixture keypair for the
// manifest-v6 host test fixtures. They are NOT the firmware-vendor key,
// NOT a wallet bootstrap/slot key, NOT a health-only key, and MUST NEVER
// be compiled into or referenced by any production image, signer, or
// provisioning path. Their only purpose is to make the §6.1 key-matched
// fixture byte-reproducible on any host.
// ---------------------------------------------------------------------------

/// Fixture signing-key seed (32 bytes). TEST ONLY — see warning above.
const V6_FIXTURE_SK_SEED: [u8; 32] = *b"V6-FIXTURE-NONPROD-SK-SEED-00001";
/// Fixture public seed (16 bytes). TEST ONLY — see warning above.
const V6_FIXTURE_PK_SEED: [u8; 16] = *b"V6-FIXTURE-PK-01";
/// Second, unrelated fixture keypair for the wrong-key negative fixture.
/// TEST ONLY — same warning applies.
const V6_WRONGKEY_SK_SEED: [u8; 32] = *b"V6-FIXTURE-NONPROD-SK-SEED-00002";
/// Wrong-key public seed. TEST ONLY.
const V6_WRONGKEY_PK_SEED: [u8; 16] = *b"V6-FIXTURE-PK-02";

/// Deterministic keygen output for the fixture seeds (pinned receipt).
const FIXTURE_PK_ROOT: &str = "9eb0ff9813adf4c71b21d6bed0d2d383";
/// `vendor_fingerprint(pk_seed, pk_root)` for the fixture key (pinned).
const FIXTURE_FPR: &str = "4005485c1354e4953b02b28a786ea6683d81f95784f579459d42f1644e00a61c";
/// §6.1 receipt row: SHA-256 over the 4,008 fixture signature bytes.
const FIXTURE_SIG_SHA256: &str =
    "7bf48b0c8e908a76a96828ce01345f05206024051c97bf363f01f8d9daadb13d";
/// SHA-256 over the complete signed fixture page (CRC sealed).
const FIXTURE_PAGE_SHA256: &str =
    "d3a95154fd02fdcc4a8cafe379b568846fef218fbb91874aff2f69d7ff653851";

// ---------------------------------------------------------------------------
// Helpers (same shape as v6_golden_fixtures.rs)
// ---------------------------------------------------------------------------

fn hex_bytes(s: &str, out: &mut [u8]) {
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

fn hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex_bytes(s, &mut out);
    out
}

fn hex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    hex_bytes(s, &mut out);
    out
}

fn seq(start: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    out
}

fn fixture_key() -> SigningKey {
    SigningKey::keygen(V6_FIXTURE_SK_SEED, V6_FIXTURE_PK_SEED)
}

fn wrong_key() -> SigningKey {
    SigningKey::keygen(V6_WRONGKEY_SK_SEED, V6_WRONGKEY_PK_SEED)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The golden field set with the FIXTURE key's fingerprint in the
/// vendor-fpr slot (unsigned placeholder signature — the caller signs).
fn fixture_fields(fpr: &[u8; 32]) -> ReleasePackageFields<'_> {
    // Leak-free: these are 'static test constants.
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
fn sign_page(fields: &ReleasePackageFields<'_>, key: &SigningKey) -> [u8; MANIFEST_SIZE] {
    let mut page = v6::build_release_package(fields).expect("fixture fields are valid");
    let digest = v6::parse_and_validate(&page, fields.slot)
        .unwrap()
        .manifest_digest();
    let sig = key.sign(&digest, None);
    page[v6::OFF_SIGNATURE..v6::OFF_SIGNATURE + SIGNATURE_LEN].copy_from_slice(&sig);
    v6::rewrite_normalized_crc(&mut page);
    page
}

/// The checked-in positive fixture page: golden fields + fixture fpr,
/// signed by the fixture key.
fn signed_fixture_page() -> [u8; MANIFEST_SIZE] {
    let key = fixture_key();
    let vk = key.verifying_key();
    let fpr = v6::vendor_fingerprint(&vk.pk_seed, &vk.pk_root);
    sign_page(&fixture_fields(&fpr), &key)
}

/// Overwrite the signature area of an otherwise-valid page with a signature
/// over an attacker-chosen 32-byte digest, then re-seal the CRC.
fn resign_page_with_digest(page: &mut [u8; MANIFEST_SIZE], key: &SigningKey, digest: &[u8; 32]) {
    let sig = key.sign(digest, None);
    page[v6::OFF_SIGNATURE..v6::OFF_SIGNATURE + SIGNATURE_LEN].copy_from_slice(&sig);
    v6::rewrite_normalized_crc(page);
}

// ---------------------------------------------------------------------------
// Positive fixtures (§6.1 L1924–1933)
// ---------------------------------------------------------------------------

#[test]
fn fixture_keypair_is_deterministic_and_fingerprint_pinned() {
    let vk1 = fixture_key().verifying_key();
    let vk2 = fixture_key().verifying_key();
    assert_eq!(vk1, vk2, "fixture keygen must be seed-deterministic");
    assert_eq!(vk1.pk_seed, V6_FIXTURE_PK_SEED);
    assert_eq!(vk1.pk_root, hex16(FIXTURE_PK_ROOT));
    assert_eq!(
        v6::vendor_fingerprint(&vk1.pk_seed, &vk1.pk_root),
        hex(FIXTURE_FPR),
        "exact public-key fingerprint of the fixture key"
    );
}

#[test]
fn signed_fixture_regeneration_identity_and_receipt() {
    let key = fixture_key();
    let page = signed_fixture_page();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();

    // (i) Regeneration identity: re-signing the same recomputed digest with
    // the same seeds and opt_rand=None reproduces the page's signature
    // bytes exactly. This binds the checked-in fixture.
    let re_sig = key.sign(&m.manifest_digest(), None);
    assert_eq!(re_sig, m.signature);

    // §6.1 receipt row: SHA-256 of the fixture signature bytes is pinned.
    assert_eq!(sha256(&re_sig), hex(FIXTURE_SIG_SHA256));
    // The complete sealed page is pinned too.
    assert_eq!(sha256(&page), hex(FIXTURE_PAGE_SHA256));
}

#[test]
fn verify_signature_and_embedded_key_succeed_on_signed_page() {
    let vk = fixture_key().verifying_key();
    let page = signed_fixture_page();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(m.stored_digest_matches());
    // (ii) both verification entry points succeed.
    assert!(m.verify_signature(&vk.pk_seed, &vk.pk_root));
    assert!(m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));
}

#[test]
fn patterned_signature_is_not_a_c10_kat() {
    // (iii) The `i mod 256` patterned signature (v6_golden_fixtures.rs) is
    // a serialization/normalization fixture ONLY: it must not verify.
    let vk = fixture_key().verifying_key();
    let fpr = v6::vendor_fingerprint(&vk.pk_seed, &vk.pk_root);
    let mut patterned = [0u8; SIGNATURE_LEN];
    for (i, b) in patterned.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
    let fields = ReleasePackageFields {
        signature: &patterned,
        ..fixture_fields(&fpr)
    };
    let page = v6::build_release_package(&fields).unwrap();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(!m.verify_signature(&vk.pk_seed, &vk.pk_root));
    assert!(!m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));
}

// ---------------------------------------------------------------------------
// Negative fixtures — each must FAIL verification (or the schema gate)
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_fails() {
    let page = signed_fixture_page();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    let wk = wrong_key().verifying_key();
    assert!(!m.verify_signature(&wk.pk_seed, &wk.pk_root));
    assert!(!m.verify_with_embedded_key(&wk.pk_seed, &wk.pk_root));
    // The fingerprint leg alone already refuses the foreign key.
    assert!(!m.vendor_fpr_matches(&wk.pk_seed, &wk.pk_root));
}

#[test]
fn one_bit_signature_corruption_fails() {
    let vk = fixture_key().verifying_key();
    let mut page = signed_fixture_page();
    page[v6::OFF_SIGNATURE + 2000] ^= 0x01; // one bit, mid-signature
    v6::rewrite_normalized_crc(&mut page);
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(!m.verify_signature(&vk.pk_seed, &vk.pk_root));
    assert!(!m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));
}

#[test]
fn domain_substitution_fails() {
    let key = fixture_key();
    let vk = key.verifying_key();
    let mut page = signed_fixture_page();
    // Attacker re-signs over a preimage built with a WRONG domain tag.
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    let mut evil_preimage = m.signed_preimage();
    evil_preimage[0..7].copy_from_slice(b"PQFW_V7");
    let evil_digest = sha256(&evil_preimage);
    resign_page_with_digest(&mut page, &key, &evil_digest);
    // The verifier recomputes with the frozen PQFW_V6 domain → mismatch.
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(!m.verify_signature(&vk.pk_seed, &vk.pk_root));
    assert!(!m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));
}

#[test]
fn schema_substitution_fails() {
    let key = fixture_key();
    let vk = key.verifying_key();

    // (a) Signature over a preimage with a wrong schema byte: the verifier
    // recomputes with schema 0x06 → mismatch.
    let mut page = signed_fixture_page();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    let mut evil_preimage = m.signed_preimage();
    evil_preimage[7] = 0x07;
    let evil_digest = sha256(&evil_preimage);
    resign_page_with_digest(&mut page, &key, &evil_digest);
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(!m.verify_signature(&vk.pk_seed, &vk.pk_root));

    // (b) The page-level schema gate fires FIRST: a page whose schema byte
    // is not exactly 0x06 is rejected before any signature path runs.
    let mut page = signed_fixture_page();
    page[v6::OFF_SCHEMA] = 0x07;
    v6::rewrite_normalized_crc(&mut page);
    assert_eq!(
        v6::parse_and_validate(&page, PhysicalSlot::B),
        Err(ValidationError::BadSchema(0x07))
    );
}

#[test]
fn slot_substitution_fails() {
    let key = fixture_key();
    let vk = key.verifying_key();
    let mut page = signed_fixture_page(); // page is slot B (0x01)
    // Signature produced over a slot-A preimage must not authorize slot B.
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    let mut evil_preimage = m.signed_preimage();
    evil_preimage[8] = PhysicalSlot::A.to_u8();
    let evil_digest = sha256(&evil_preimage);
    resign_page_with_digest(&mut page, &key, &evil_digest);
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(!m.verify_signature(&vk.pk_seed, &vk.pk_root));
    assert!(!m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));
}

#[test]
fn tuple_change_fails() {
    let vk = fixture_key().verifying_key();
    for (off, bumped) in [
        (v6::OFF_RELEASE_VERSION, 0x0102_0305u32),
        (v6::OFF_SECURITY_EPOCH, 0x0506_0709u32),
    ] {
        let mut page = signed_fixture_page();
        page[off..off + 4].copy_from_slice(&bumped.to_be_bytes());
        v6::rewrite_normalized_crc(&mut page);
        let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
        assert!(!m.verify_signature(&vk.pk_seed, &vk.pk_root));
        assert!(!m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));
    }
}

#[test]
fn length_change_fails() {
    let vk = fixture_key().verifying_key();
    let mut page = signed_fixture_page();
    page[v6::OFF_SECURE_LEN..v6::OFF_SECURE_LEN + 4].copy_from_slice(&0x1008u32.to_be_bytes());
    v6::rewrite_normalized_crc(&mut page);
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(!m.verify_signature(&vk.pk_seed, &vk.pk_root));
    assert!(!m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));
}

#[test]
fn image_hash_change_fails() {
    let vk = fixture_key().verifying_key();
    let mut page = signed_fixture_page();
    page[v6::OFF_SECURE_HASH] ^= 0x01; // one bit of the signed secure hash
    v6::rewrite_normalized_crc(&mut page);
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(!m.verify_signature(&vk.pk_seed, &vk.pk_root));
    assert!(!m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));
}

#[test]
fn legacy_format_retry_fails_at_schema_gate() {
    // A GENUINE legacy v0x02 page, built through the legacy builder and
    // valid under the legacy CRC — never translated, never retried (§6.1
    // L1976–1981 flag day).
    let mut legacy = ManifestBuilder::new();
    legacy
        .init(1)
        .fw_version(7)
        .secure_image(&seq(0x00), 0x1000)
        .nonsecure_image(&seq(0x20), 0x2000)
        .vendor_pubkey_fpr(&seq(0x40))
        .build_id(&seq(0x60));
    let page = legacy.finalize();

    // Sanity: it really is a well-formed legacy page…
    let legacy_ref = ManifestRef::new(&page);
    assert_eq!(legacy_ref.manifest_version(), 0x02);
    legacy_ref.verify_crc().expect("legacy page is legacy-valid");
    // …and the v6 schema gate rejects it outright.
    assert_eq!(
        v6::parse_and_validate(&page, PhysicalSlot::B),
        Err(ValidationError::BadSchema(0x02))
    );
    assert_eq!(
        v6::validate_release_package(&page, PhysicalSlot::B),
        Err(ValidationError::BadSchema(0x02))
    );
}
