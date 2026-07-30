//! Key-matched manifest-v6 signature fixtures — FA-1.2b, Draft 1.1 §6.1
//! L1924–1933.
//!
//! The canonical positive fixture is the CHECKED-IN artifact
//! `fixtures/manifest_v6_positive.bin` (8,192 bytes, exact signed
//! manifest-v6 page) plus its receipt `fixtures/manifest_v6_positive.
//! receipt.txt`, which binds the fixture-file hashes. Both are produced by
//! the dev-time generator `gen_v6_signature_fixture.rs` (ignored test; run
//! with `-- --ignored --nocapture`) and are the shared reference for
//! firmware, fwsign, inspector, factory/updater, extraction, formal models,
//! and host tests (§6.1 flag-day paragraph). Runtime re-signing appears
//! here ONLY as a labeled determinism cross-check — it is never the
//! fixture source.
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

mod common;

use common::{
    fixture_fields, fixture_key, hex, hex16, hexs, regenerate_fixture_page,
    resign_page_with_digest, seq, sha256, wrong_key, FIXTURE_FPR, FIXTURE_PAGE_SHA256,
    FIXTURE_PK_ROOT, FIXTURE_SIG_SHA256, V6_FIXTURE_PK_SEED,
};
use fw_manifest::v6::{self, PhysicalSlot, ReleasePackageFields, ValidationError};
use fw_manifest::{ManifestBuilder, ManifestRef, MANIFEST_SIZE, SIGNATURE_LEN};

// ---------------------------------------------------------------------------
// The checked-in fixture artifacts (see the module banner).
// ---------------------------------------------------------------------------

/// The canonical key-matched positive fixture page. NEVER regenerate at
/// test time — the artifact is the source of truth.
const ARTIFACT: &[u8; MANIFEST_SIZE] = include_bytes!("fixtures/manifest_v6_positive.bin");

/// The receipt binding the fixture-file hashes (§6.1 L1924–1933).
const RECEIPT: &str = include_str!("fixtures/manifest_v6_positive.receipt.txt");

fn artifact_page() -> [u8; MANIFEST_SIZE] {
    *ARTIFACT
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
fn artifact_parses_and_passes_both_verify_paths() {
    // (a) The checked-in artifact parses and passes the authority path.
    let page = artifact_page();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).expect("artifact parses");
    assert!(m.stored_digest_matches());
    let vk = fixture_key().verifying_key();
    assert!(m.verify_signature(&vk.pk_seed, &vk.pk_root));
    assert!(m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));
}

#[test]
fn artifact_hashes_match_pins_and_receipt() {
    // (b) The artifact's signature-region SHA-256 and full-page SHA-256
    // equal BOTH the pinned constants AND the receipt file's values.
    let page = artifact_page();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    let sig_sha = hexs(&sha256(&m.signature));
    let page_sha = hexs(&sha256(&page));
    assert_eq!(sig_sha, FIXTURE_SIG_SHA256, "signature-bytes receipt row");
    assert_eq!(page_sha, FIXTURE_PAGE_SHA256, "full-page receipt row");
    assert!(
        RECEIPT.contains(&format!("signature_sha256: {sig_sha}")),
        "receipt must bind the signature-bytes hash"
    );
    assert!(
        RECEIPT.contains(&format!("page_sha256: {page_sha}")),
        "receipt must bind the full-page hash"
    );
}

#[test]
fn receipt_fields_match_artifact() {
    // (d) The receipt file's fields match the artifact's parsed fields.
    let page = artifact_page();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    let vk = fixture_key().verifying_key();
    let expected_lines = [
        "schema: 0x06".to_string(),
        "domain: PQFW_V6".to_string(),
        format!("physical_slot: 0x{:02x}", m.slot.to_u8()),
        format!("release_version: 0x{:08x}", m.release_version),
        format!("security_epoch: 0x{:08x}", m.security_epoch),
        format!("secure_len: 0x{:08x}", m.secure_len),
        format!("nonsecure_len: 0x{:08x}", m.nonsecure_len),
        format!("secure_hash: {}", hexs(&m.secure_hash)),
        format!("nonsecure_hash: {}", hexs(&m.nonsecure_hash)),
        format!("build_id: {}", hexs(&m.build_id)),
        format!("pk_root: {}", hexs(&vk.pk_root)),
        format!("vendor_fpr: {}", hexs(&m.vendor_fpr)),
        format!("manifest_digest: {}", hexs(&m.manifest_digest())),
    ];
    for line in expected_lines {
        assert!(RECEIPT.contains(&line), "receipt missing line: {line}");
    }
    // The loud NONPRODUCTION key banner must be in the receipt.
    assert!(RECEIPT.contains("NONPRODUCTION"), "receipt key banner");
}

#[test]
fn regeneration_identity_is_a_determinism_cross_check() {
    // (c) CROSS-CHECK ONLY, not the fixture source: a fresh re-sign with
    // the same seeds + opt_rand=None reproduces the artifact bytes exactly
    // (sphincs-c10's deterministic path is byte-stable). The canonical
    // fixture is the checked-in artifact above.
    let regenerated = regenerate_fixture_page();
    assert_eq!(
        hexs(&sha256(&regenerated)),
        FIXTURE_PAGE_SHA256,
        "regenerated page hash"
    );
    assert_eq!(
        regenerated, *ARTIFACT,
        "deterministic regeneration must reproduce the checked-in artifact byte-for-byte"
    );
}

#[test]
fn patterned_signature_is_not_a_c10_kat() {
    // The `i mod 256` patterned signature (v6_golden_fixtures.rs) is a
    // serialization/normalization fixture ONLY: it must not verify.
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
// Negative fixtures — each must FAIL verification (or the schema gate).
// Every mutation starts from a copy of the checked-in artifact.
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_fails() {
    let page = artifact_page();
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
    let mut page = artifact_page();
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
    let mut page = artifact_page();
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
    let mut page = artifact_page();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    let mut evil_preimage = m.signed_preimage();
    evil_preimage[7] = 0x07;
    let evil_digest = sha256(&evil_preimage);
    resign_page_with_digest(&mut page, &key, &evil_digest);
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(!m.verify_signature(&vk.pk_seed, &vk.pk_root));

    // (b) The page-level schema gate fires FIRST: a page whose schema byte
    // is not exactly 0x06 is rejected before any signature path runs.
    let mut page = artifact_page();
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
    let mut page = artifact_page(); // artifact is slot B (0x01)
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
        let mut page = artifact_page();
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
    let mut page = artifact_page();
    page[v6::OFF_SECURE_LEN..v6::OFF_SECURE_LEN + 4].copy_from_slice(&0x1008u32.to_be_bytes());
    v6::rewrite_normalized_crc(&mut page);
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(!m.verify_signature(&vk.pk_seed, &vk.pk_root));
    assert!(!m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));
}

#[test]
fn image_hash_change_fails() {
    let vk = fixture_key().verifying_key();
    let mut page = artifact_page();
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
