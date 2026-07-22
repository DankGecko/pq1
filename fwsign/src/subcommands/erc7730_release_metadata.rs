//! Authenticate the firmware-release half of ERC-7730 compatibility.
//!
//! This command deliberately stops before inspecting a companion catalogue.
//! It authenticates the legacy bundle's C10 manifest and exact image bytes,
//! binds the unique P73S receipt inside the authenticated secure image to the
//! bundle sidecar, enforces the caller's exact/minimum version policy, and
//! emits a compact machine-readable receipt.  The companion catalogue helper
//! consumes the exact extracted P73S bytes and performs the remaining full
//! P730/Bloom/Merkle preflight.

use anyhow::{bail, Context, Result};
use pqsigner_erc7730::catalogue_status::{
    CatalogueProvenance, CatalogueStatusV1, CATALOGUE_STATUS_SCHEMA_V1, CATALOGUE_STATUS_V1_LEN,
};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::Path;

use super::verify::{authenticate_bundle, AuthenticatedBundle};

pub fn run(
    bundle_path: &Path,
    pubkey_path: &Path,
    expected_version: u32,
    minimum_version: u32,
    status_out: Option<&Path>,
) -> Result<()> {
    validate_policy_configuration(expected_version, minimum_version)?;
    let authenticated = authenticate_bundle(bundle_path, pubkey_path)?;
    let (report, status) = build_report(&authenticated, expected_version, minimum_version)?;

    if let Some(path) = status_out {
        std::fs::write(path, status)
            .with_context(|| format!("writing authenticated ERC-7730 status {}", path.display()))?;
    }
    println!("{report}");
    Ok(())
}

fn validate_policy_configuration(expected_version: u32, minimum_version: u32) -> Result<()> {
    if expected_version < minimum_version {
        bail!(
            "invalid firmware-version policy: expected version {expected_version} is below minimum {minimum_version}"
        );
    }
    Ok(())
}

fn enforce_authenticated_version(
    actual_version: u32,
    expected_version: u32,
    minimum_version: u32,
) -> Result<()> {
    validate_policy_configuration(expected_version, minimum_version)?;
    if actual_version < minimum_version {
        bail!(
            "authenticated firmware version {actual_version} is below required minimum {minimum_version}"
        );
    }
    if actual_version != expected_version {
        bail!(
            "authenticated firmware version skew: got {actual_version}, expected exactly {expected_version}"
        );
    }
    Ok(())
}

fn build_report(
    authenticated: &AuthenticatedBundle,
    expected_version: u32,
    minimum_version: u32,
) -> Result<(String, [u8; CATALOGUE_STATUS_V1_LEN])> {
    enforce_authenticated_version(authenticated.fw_version, expected_version, minimum_version)?;
    let status_bytes = authenticated.erc7730_status.ok_or_else(|| {
        anyhow::anyhow!(
            "authenticated bundle has no ERC-7730 status; clear-signing release identity is unknown"
        )
    })?;
    let status = CatalogueStatusV1::from_bytes(&status_bytes)
        .map_err(|error| anyhow::anyhow!("authenticated ERC-7730 status is invalid: {error:?}"))?;

    let status_sha256: [u8; 32] = Sha256::digest(status_bytes).into();
    let slot = if authenticated.slot == fw_manifest::SLOT_A {
        "A"
    } else {
        "B"
    };
    let provenance = match status.provenance {
        CatalogueProvenance::DevUnattested => "dev-unattested",
        CatalogueProvenance::Erc8176Verified => "erc8176-verified",
    };
    let secure_words = measurement_words_json(&authenticated.secure_hash);
    let nonsecure_words = measurement_words_json(&authenticated.nonsecure_hash);
    let tool_version = json_ascii_string(status.tool_version());

    // All strings except `tool_version` are fixed literals or lowercase hex.
    // `tool_version` is strictly printable ASCII and is escaped above. Keeping
    // this renderer local avoids adding serde dependencies to the release
    // graph (the curation receipt hash-pins Cargo.lock).
    let mut out = String::with_capacity(2_800);
    write!(
        out,
        concat!(
            "{{",
            "\"report_kind\":\"authenticated-release-metadata\",",
            "\"erc8176_attestation\":false,",
            "\"production_authority\":false,",
            "\"device_rollback_verified\":false,",
            "\"version_policy\":{{\"expected\":{},\"minimum\":{}}},",
            "\"firmware\":{{",
            "\"manifest_version\":{},",
            "\"firmware_version\":{},",
            "\"slot\":\"{}\",",
            "\"slot_authenticated_by_legacy_signature\":false,",
            "\"secure_hash\":\"{}\",",
            "\"secure_len\":{},",
            "\"secure_measurement_words\":{},",
            "\"nonsecure_hash\":\"{}\",",
            "\"nonsecure_len\":{},",
            "\"nonsecure_measurement_words\":{},",
            "\"build_id\":\"{}\",",
            "\"build_id_authenticated_by_legacy_signature\":false,",
            "\"vendor_pubkey_fingerprint\":\"{}\",",
            "\"manifest_digest\":\"{}\",",
            "\"manifest_sha256\":\"{}\",",
            "\"manifest_sha256_authenticated_by_legacy_signature\":false",
            "}},",
            "\"catalogue_status\":{{",
            "\"status_schema\":{},",
            "\"encoded_length\":{},",
            "\"status_sha256\":\"{}\",",
            "\"catalogue_format_version\":{},",
            "\"ir_schema_version\":{},",
            "\"provenance\":\"{}\",",
            "\"provenance_code\":{},",
            "\"leaf_count\":{},",
            "\"catalogue_blob_size\":{},",
            "\"known_call_count\":{},",
            "\"bloom_size\":{},",
            "\"descriptor_root\":\"{}\",",
            "\"catalogue_sha256\":\"{}\",",
            "\"known_call_set_sha256\":\"{}\",",
            "\"bloom_sha256\":\"{}\",",
            "\"policy_sha256\":\"{}\",",
            "\"curation_input_sha256\":\"{}\",",
            "\"tool_version\":{}",
            "}}",
            "}}"
        ),
        expected_version,
        minimum_version,
        authenticated.manifest_version,
        authenticated.fw_version,
        slot,
        hex::encode(authenticated.secure_hash),
        authenticated.secure_len,
        secure_words,
        hex::encode(authenticated.nonsecure_hash),
        authenticated.nonsecure_len,
        nonsecure_words,
        hex::encode(authenticated.build_id),
        hex::encode(authenticated.vendor_pubkey_fingerprint),
        hex::encode(authenticated.manifest_digest),
        hex::encode(authenticated.manifest_sha256),
        CATALOGUE_STATUS_SCHEMA_V1,
        CATALOGUE_STATUS_V1_LEN,
        hex::encode(status_sha256),
        status.catalogue_format_version,
        status.ir_schema_version,
        provenance,
        status.provenance as u8,
        status.leaf_count,
        status.catalogue_blob_size,
        status.known_call_count,
        status.bloom_size,
        hex::encode(status.descriptor_root),
        hex::encode(status.catalogue_sha256),
        hex::encode(status.known_call_set_sha256),
        hex::encode(status.bloom_sha256),
        hex::encode(status.policy_sha256),
        hex::encode(status.curation_input_sha256),
        tool_version,
    )
    .expect("writing JSON to String cannot fail");

    Ok((out, status_bytes))
}

fn measurement_words_json(hash: &[u8; 32]) -> String {
    use sphincs_tz_bip39::{hash_to_word_indices, WORDLIST};

    let mut out = String::from("[");
    for (index, word_index) in hash_to_word_indices(hash).iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(WORDLIST[*word_index as usize]);
        out.push('"');
    }
    out.push(']');
    out
}

fn json_ascii_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for byte in bytes {
        match *byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(*byte as char),
            other => write!(out, "\\u00{other:02x}").expect("writing JSON escape cannot fail"),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{self, BundleInputs};
    use fw_manifest::{ManifestBuilder, TRY_ONCE_COMMITTED};
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use tempfile::TempDir;

    const VERSION_A: u32 = 17;
    const VERSION_B: u32 = 18;

    struct SignedFixture {
        manifest: [u8; fw_manifest::MANIFEST_SIZE],
        signature: [u8; sphincs_c10::params::SIGNATURE_LEN],
        secure: Vec<u8>,
        nonsecure: Vec<u8>,
        pubkey: [u8; fw_manifest::VERIFYING_KEY_LEN],
        status: [u8; CATALOGUE_STATUS_V1_LEN],
    }

    struct PackedFixture {
        _dir: TempDir,
        bundle: PathBuf,
        pubkey: PathBuf,
    }

    fn status_fixture() -> [u8; CATALOGUE_STATUS_V1_LEN] {
        CatalogueStatusV1::new(
            1,
            pqsigner_erc7730::ir::SCHEMA_VER,
            CatalogueProvenance::DevUnattested,
            4,
            1_024,
            8,
            16_384,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            b"dbgen/test-1",
        )
        .expect("fixture status is canonical")
        .to_bytes()
    }

    fn signed_fixture() -> &'static SignedFixture {
        static FIXTURE: OnceLock<SignedFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let status = status_fixture();
            let mut secure = vec![0xa5; 64];
            secure.extend_from_slice(&status);
            secure.extend_from_slice(&[0x5a; 64]);
            let nonsecure = vec![0x3c; 512];
            let secure_hash: [u8; 32] = Sha256::digest(&secure).into();
            let nonsecure_hash: [u8; 32] = Sha256::digest(&nonsecure).into();

            let signing_key = super::super::dev_pubkey::signing_key();
            let vendor_fingerprint = fw_manifest::vendor_pubkey_fingerprint(
                signing_key.pk_seed(),
                signing_key.pk_root(),
            );
            let mut builder = ManifestBuilder::new();
            builder
                .init(fw_manifest::SLOT_A)
                .fw_version(VERSION_A)
                .secure_image(&secure_hash, secure.len() as u32)
                .nonsecure_image(&nonsecure_hash, nonsecure.len() as u32)
                .vendor_pubkey_fpr(&vendor_fingerprint)
                .build_id(&[0x77; 32])
                .boot_counter_snap(VERSION_A - 1)
                .try_once(TRY_ONCE_COMMITTED);
            let digest = builder.finalize_preimage();
            let signature = signing_key.sign(&digest, None);
            builder.set_signature(&signature);

            let mut pubkey = [0u8; fw_manifest::VERIFYING_KEY_LEN];
            pubkey[..sphincs_c10::params::N].copy_from_slice(signing_key.pk_seed());
            pubkey[sphincs_c10::params::N..].copy_from_slice(signing_key.pk_root());
            SignedFixture {
                manifest: builder.finalize(),
                signature,
                secure,
                nonsecure,
                pubkey,
                status,
            }
        })
    }

    fn pack_fixture(
        secure: &[u8],
        status: Option<[u8; CATALOGUE_STATUS_V1_LEN]>,
        measurement: &str,
        release: &str,
    ) -> PackedFixture {
        let fixture = signed_fixture();
        pack_fixture_with_manifest(fixture.manifest, secure, status, measurement, release)
    }

    fn pack_fixture_with_manifest(
        manifest: [u8; fw_manifest::MANIFEST_SIZE],
        secure: &[u8],
        status: Option<[u8; CATALOGUE_STATUS_V1_LEN]>,
        measurement: &str,
        release: &str,
    ) -> PackedFixture {
        let fixture = signed_fixture();
        let dir = tempfile::tempdir().expect("temp fixture directory");
        let bundle_path = dir.path().join("release.pqfw");
        let pubkey_path = dir.path().join("vendor.pub");
        let inputs = BundleInputs {
            manifest_bytes: manifest,
            secure_bytes: secure.to_vec(),
            nonsecure_bytes: fixture.nonsecure.clone(),
            measurement_txt: measurement.to_owned(),
            pubkey_bytes: fixture.pubkey,
            release_json: release.to_owned(),
            erc7730_status_bytes: status,
        };
        bundle::pack(&inputs, &bundle_path).expect("pack signed fixture");
        std::fs::write(&pubkey_path, fixture.pubkey).expect("write fixture pubkey");
        PackedFixture {
            _dir: dir,
            bundle: bundle_path,
            pubkey: pubkey_path,
        }
    }

    #[test]
    fn version_transition_matrix_fails_closed() {
        // A/A and B/B are the two accepted exact-version pairings.
        assert!(enforce_authenticated_version(VERSION_A, VERSION_A, VERSION_A - 1).is_ok());
        assert!(enforce_authenticated_version(VERSION_B, VERSION_B, VERSION_A).is_ok());

        // A/B and B/A are both version skew, even though both versions may be
        // individually above the configured minimum.
        assert!(enforce_authenticated_version(VERSION_A, VERSION_B, VERSION_A).is_err());
        assert!(enforce_authenticated_version(VERSION_B, VERSION_A, VERSION_A).is_err());

        let stale = enforce_authenticated_version(VERSION_A - 1, VERSION_B, VERSION_A)
            .unwrap_err()
            .to_string();
        assert!(stale.contains("below required minimum"), "got: {stale}");
        assert!(validate_policy_configuration(VERSION_A, VERSION_B).is_err());
    }

    #[test]
    fn authenticated_report_requires_status_and_exact_version() {
        let fixture = signed_fixture();
        let packed = pack_fixture(
            &fixture.secure,
            None,
            "unsigned measurement",
            "{\"unsigned\":true}",
        );
        let authenticated = authenticate_bundle(&packed.bundle, &packed.pubkey).unwrap();
        assert!(build_report(&authenticated, VERSION_A, VERSION_A - 1)
            .unwrap_err()
            .to_string()
            .contains("identity is unknown"));
        assert!(build_report(&authenticated, VERSION_B, VERSION_A).is_err());
    }

    #[test]
    fn unsigned_outer_metadata_cannot_change_report_authority() {
        let fixture = signed_fixture();
        let first = pack_fixture(
            &fixture.secure,
            Some(fixture.status),
            "attacker measurement A",
            "{\"version\":999,\"root\":\"attacker-A\"}",
        );
        let second = pack_fixture(
            &fixture.secure,
            Some(fixture.status),
            "attacker measurement B",
            "{\"version\":1,\"root\":\"attacker-B\"}",
        );
        let first = authenticate_bundle(&first.bundle, &first.pubkey).unwrap();
        let second = authenticate_bundle(&second.bundle, &second.pubkey).unwrap();
        let (first_report, _) = build_report(&first, VERSION_A, VERSION_A - 1).unwrap();
        let (second_report, _) = build_report(&second, VERSION_A, VERSION_A - 1).unwrap();
        assert_eq!(first_report, second_report);
        assert!(!first_report.contains("attacker"));
        assert!(first_report.contains("\"report_kind\":\"authenticated-release-metadata\""));
        assert!(first_report.contains("\"secure_measurement_words\":["));
    }

    #[test]
    fn valid_unsigned_manifest_metadata_is_reported_only_as_non_authority() {
        let fixture = signed_fixture();
        let original_manifest = fw_manifest::ManifestRef::new(&fixture.manifest);
        let mut variant = ManifestBuilder::new();
        variant
            .init(fw_manifest::SLOT_B)
            .fw_version(VERSION_A)
            .secure_image(
                original_manifest.secure_hash(),
                original_manifest.secure_len(),
            )
            .nonsecure_image(
                original_manifest.nonsecure_hash(),
                original_manifest.nonsecure_len(),
            )
            .vendor_pubkey_fpr(original_manifest.vendor_pubkey_fpr())
            .build_id(&[0x88; 32])
            .boot_counter_snap(3)
            .try_once(TRY_ONCE_COMMITTED);
        let digest = variant.finalize_preimage();
        assert_eq!(&digest, original_manifest.manifest_digest());
        variant.set_signature(&fixture.signature);
        let variant_manifest = variant.finalize();

        let original = pack_fixture(&fixture.secure, Some(fixture.status), "ignored", "{}");
        let variant = pack_fixture_with_manifest(
            variant_manifest,
            &fixture.secure,
            Some(fixture.status),
            "ignored",
            "{}",
        );
        let original = authenticate_bundle(&original.bundle, &original.pubkey).unwrap();
        let variant = authenticate_bundle(&variant.bundle, &variant.pubkey).unwrap();

        // The exact readiness inputs remain identical.
        assert_eq!(original.fw_version, variant.fw_version);
        assert_eq!(original.secure_hash, variant.secure_hash);
        assert_eq!(original.nonsecure_hash, variant.nonsecure_hash);
        assert_eq!(original.manifest_digest, variant.manifest_digest);
        assert_eq!(original.erc7730_status, variant.erc7730_status);

        // Legacy-unsigned presentation/file-identity fields change and are
        // labelled non-authoritative in both reports.
        assert_ne!(original.slot, variant.slot);
        assert_ne!(original.build_id, variant.build_id);
        assert_ne!(original.manifest_sha256, variant.manifest_sha256);
        for authenticated in [&original, &variant] {
            let (report, _) = build_report(authenticated, VERSION_A, VERSION_A - 1).unwrap();
            assert!(report.contains("\"slot_authenticated_by_legacy_signature\":false"));
            assert!(report.contains("\"build_id_authenticated_by_legacy_signature\":false"));
            assert!(report.contains("\"manifest_sha256_authenticated_by_legacy_signature\":false"));
        }
    }

    #[test]
    fn changing_embedded_status_and_sidecar_without_resigning_fails_image_hash() {
        let fixture = signed_fixture();
        let mut changed_status = fixture.status;
        changed_status[32] ^= 1; // Still structurally valid; changes the root.
        let mut changed_secure = fixture.secure.clone();
        changed_secure[64..64 + CATALOGUE_STATUS_V1_LEN].copy_from_slice(&changed_status);
        let packed = pack_fixture(&changed_secure, Some(changed_status), "ignored", "{}");
        let error = authenticate_bundle(&packed.bundle, &packed.pubkey)
            .unwrap_err()
            .to_string();
        assert!(error.contains("secure.bin SHA-256"), "got: {error}");
    }

    #[test]
    fn authenticated_image_rejects_mismatched_status_sidecar() {
        let fixture = signed_fixture();
        let mut changed_status = fixture.status;
        changed_status[32] ^= 1; // Structurally valid, but not the embedded P73S.
        let packed = pack_fixture(&fixture.secure, Some(changed_status), "ignored", "{}");
        let error = authenticate_bundle(&packed.bundle, &packed.pubkey)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("differs from the unique valid status"),
            "got: {error}"
        );
    }

    #[test]
    fn report_returns_exact_authenticated_status_for_private_extraction() {
        let fixture = signed_fixture();
        let packed = pack_fixture(&fixture.secure, Some(fixture.status), "ignored", "{}");
        let authenticated = authenticate_bundle(&packed.bundle, &packed.pubkey).unwrap();
        let (report, status) = build_report(&authenticated, VERSION_A, VERSION_A - 1).unwrap();
        assert_eq!(status, fixture.status);
        assert!(report.contains(&hex::encode(Sha256::digest(fixture.status))));
        assert!(report.contains("\"erc8176_attestation\":false"));
        assert!(report.contains("\"production_authority\":false"));
        assert!(report.contains("\"device_rollback_verified\":false"));

        let parsed = std::process::Command::new("python3")
            .arg("-c")
            .arg("import json,sys; r=json.loads(sys.argv[1]); assert r['report_kind']=='authenticated-release-metadata'")
            .arg(&report)
            .status()
            .expect("python3 must parse compact report JSON");
        assert!(
            parsed.success(),
            "compact release report must be valid JSON"
        );
    }

    #[test]
    fn command_writes_exact_status_only_after_authentication() {
        let fixture = signed_fixture();
        let packed = pack_fixture(&fixture.secure, Some(fixture.status), "ignored", "{}");
        let output_dir = tempfile::tempdir().unwrap();
        let status_path = output_dir.path().join("authenticated.bin");
        run(
            &packed.bundle,
            &packed.pubkey,
            VERSION_A,
            VERSION_A - 1,
            Some(&status_path),
        )
        .unwrap();
        assert_eq!(std::fs::read(status_path).unwrap(), fixture.status);
    }

    #[test]
    fn json_tool_version_escaping_is_valid_and_deterministic() {
        assert_eq!(
            json_ascii_string(b"dbgen/\\\"test"),
            "\"dbgen/\\\\\\\"test\""
        );
    }
}
