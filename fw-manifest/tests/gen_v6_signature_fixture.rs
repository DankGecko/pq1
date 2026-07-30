//! Dev-time generator for the key-matched manifest-v6 positive fixture
//! (FA-1.2b, Draft 1.1 §6.1 L1924–1933).
//!
//! Writes the two CHECKED-IN artifacts consumed by
//! `v6_signature_fixtures.rs` (and, per §6.1's flag-day paragraph, the
//! shared reference for every other consumer — fwsign, inspector,
//! factory/updater, extraction, formal models):
//!
//!   * `fw-manifest/tests/fixtures/manifest_v6_positive.bin` — the exact
//!     8,192-byte signed manifest-v6 page.
//!   * `fw-manifest/tests/fixtures/manifest_v6_positive.receipt.txt` —
//!     the receipt binding the fixture-file hashes (see below).
//!
//! Run:
//!   cargo test -p fw-manifest --test gen_v6_signature_fixture -- --ignored --nocapture
//!
//! Determinism: the fixture key is `SigningKey::keygen(V6_FIXTURE_SK_SEED,
//! V6_FIXTURE_PK_SEED)` and the signature is `sign(digest, opt_rand=None)`,
//! the byte-stable deterministic path — regeneration on any host must
//! reproduce the checked-in bytes exactly. The generator asserts its
//! freshly computed values against the pinned constants in
//! `tests/common/mod.rs` BEFORE writing, so a seed/code drift fails here
//! instead of silently rewriting the artifact.

mod common;

use common::{
    fixture_key, hexs, regenerate_fixture_page, sha256, FIXTURE_FPR, FIXTURE_PAGE_SHA256,
    FIXTURE_PK_ROOT, FIXTURE_SIG_SHA256, V6_FIXTURE_PK_SEED, V6_FIXTURE_SK_SEED,
};
use fw_manifest::v6::{self, PhysicalSlot};
use std::fs;

#[test]
#[ignore = "dev-time fixture generator"]
fn gen_v6_signature_fixture() {
    let key = fixture_key();
    let vk = key.verifying_key();
    let page = regenerate_fixture_page();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).expect("fixture page parses");

    // Guard: the fresh computation must match the pinned receipts before
    // anything is written.
    assert_eq!(vk.pk_seed, V6_FIXTURE_PK_SEED);
    assert_eq!(hexs(&vk.pk_root), FIXTURE_PK_ROOT);
    let fpr = v6::vendor_fingerprint(&vk.pk_seed, &vk.pk_root);
    assert_eq!(hexs(&fpr), FIXTURE_FPR);
    let sig_sha = sha256(&m.signature);
    assert_eq!(hexs(&sig_sha), FIXTURE_SIG_SHA256);
    let page_sha = sha256(&page);
    assert_eq!(hexs(&page_sha), FIXTURE_PAGE_SHA256);
    // The artifact must pass the authority path it fixtures.
    assert!(m.verify_signature(&vk.pk_seed, &vk.pk_root));
    assert!(m.verify_with_embedded_key(&vk.pk_seed, &vk.pk_root));

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    fs::create_dir_all(dir).expect("create fixtures dir");
    fs::write(format!("{dir}/manifest_v6_positive.bin"), page).expect("write fixture page");

    let receipt = format!(
        "# Manifest-v6 key-matched POSITIVE fixture receipt (FA-1.2b; Draft 1.1 §6.1 L1924–1933)\n\
         #\n\
         # This receipt binds the fixture-FILE hashes of\n\
         #   fw-manifest/tests/fixtures/manifest_v6_positive.bin\n\
         # (8,192 bytes, exact signed manifest-v6 page). It is the shared reference for\n\
         # firmware, fwsign, inspector, factory/updater, extraction, formal models, and\n\
         # host tests (§6.1 flag-day paragraph).\n\
         #\n\
         # KEY MATERIAL WARNING: the fixture keypair is a DEDICATED NONPRODUCTION C10\n\
         # fixture key (TEST ONLY). It is NOT the firmware-vendor key, NOT a wallet\n\
         # bootstrap/slot key, NOT a health-only key, and MUST NEVER be compiled into or\n\
         # referenced by any production image, signer, or provisioning path.\n\
         #\n\
         # Generation: deterministic — SigningKey::keygen(V6_FIXTURE_SK_SEED,\n\
         # V6_FIXTURE_PK_SEED) then sign(manifest_digest, opt_rand=None) (byte-stable\n\
         # deterministic path). Regenerate:\n\
         #   cargo test -p fw-manifest --test gen_v6_signature_fixture -- --ignored --nocapture\n\
         schema: 0x06\n\
         domain: PQFW_V6\n\
         physical_slot: 0x01\n\
         release_version: 0x01020304\n\
         security_epoch: 0x05060708\n\
         secure_len: 0x00001000\n\
         nonsecure_len: 0x00002000\n\
         secure_hash: {secure_hash}\n\
         nonsecure_hash: {nonsecure_hash}\n\
         build_id: {build_id}\n\
         pk_seed: {pk_seed}  # NONPRODUCTION FIXTURE — TEST ONLY (see warning above)\n\
         pk_root: {pk_root}\n\
         vendor_fpr: {vendor_fpr}\n\
         manifest_digest: {digest}\n\
         signature_sha256: {sig_sha}\n\
         page_sha256: {page_sha}\n",
        secure_hash = hexs(&m.secure_hash),
        nonsecure_hash = hexs(&m.nonsecure_hash),
        build_id = hexs(&m.build_id),
        pk_seed = hexs(&V6_FIXTURE_PK_SEED),
        pk_root = hexs(&vk.pk_root),
        vendor_fpr = hexs(&fpr),
        digest = hexs(&m.manifest_digest()),
        sig_sha = hexs(&sig_sha),
        page_sha = hexs(&page_sha),
    );
    // sk_seed never leaves the generator process; assert it is the
    // documented constant without printing it into the receipt.
    assert_eq!(V6_FIXTURE_SK_SEED, *b"V6-FIXTURE-NONPROD-SK-SEED-00001");
    fs::write(
        format!("{dir}/manifest_v6_positive.receipt.txt"),
        receipt,
    )
    .expect("write fixture receipt");
    eprintln!(
        "gen_v6_signature_fixture: wrote manifest_v6_positive.bin (8192 bytes, sig sha256 {}) + receipt",
        hexs(&sig_sha)
    );
}
