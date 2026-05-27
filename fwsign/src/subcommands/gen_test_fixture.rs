//! `fwsign gen-test-fixture` — emit a self-consistent dev-signed bundle
//! (manifest + raw image bytes) for the over-USB FW-update transport e2e
//! test (`make fwup-transport-hw`).
//!
//! The test needs:
//!   * A manifest signed with the **dev** vendor key (matches the
//!     `FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY)` the test build embeds).
//!   * Raw image bytes whose SHA-256 matches the manifest's signed
//!     `secure_hash` / `nonsecure_hash` (so `verify_images` at COMMIT
//!     passes on the actually-streamed bytes).
//!
//! The bytes are deterministic (`[0xAA; secure_len]`, `[0xBB; nonsecure_len]`)
//! and small (default 240 B each — QW-aligned, fits in a single FW_CHUNK
//! APDU under the 255-byte LC limit). Output goes to `<out_dir>/`:
//!   * `manifest.bin`   — 8192 bytes, ready to send as FW_BEGIN.
//!   * `secure.bin`     — raw secure-image bytes (kind=0).
//!   * `nonsecure.bin`  — raw nonsecure-image bytes (kind=1).
//!
//! **NEVER** use for production releases. The key is a public fixed seed.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use sphincs_c10::SigningKey;
use std::path::Path;

use fw_manifest::{ManifestBuilder, SLOT_A, TRY_ONCE_COMMITTED};

/// Dev signing seed — MUST stay byte-identical to the other copies
/// (`fsbl/build.rs`, `fwsign/src/subcommands/dev_pubkey.rs`,
/// `fwsign/tests/sign_verify_roundtrip.rs`,
/// `secure/src/fw_rollback_e2e.rs`).
const DEV_SK: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
const DEV_PS: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

pub fn run(version: u32, secure_len: u32, nonsecure_len: u32, out_dir: &Path) -> Result<()> {
    if secure_len & 0xF != 0 || nonsecure_len & 0xF != 0 {
        anyhow::bail!(
            "image lengths must be QW-aligned (multiple of 16); got secure={secure_len} nonsecure={nonsecure_len}"
        );
    }

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating {}", out_dir.display()))?;

    // Deterministic raw images.
    let secure_bytes: Vec<u8> = vec![0xAA; secure_len as usize];
    let nonsecure_bytes: Vec<u8> = vec![0xBB; nonsecure_len as usize];

    let secure_hash: [u8; 32] = Sha256::digest(&secure_bytes).into();
    let nonsecure_hash: [u8; 32] = Sha256::digest(&nonsecure_bytes).into();

    // Dev vendor fingerprint = SHA-256(pk_seed || pk_root). This is the
    // value the device's `verify_vendor_fpr` will recompute from the
    // build-baked VENDOR_PK_{SEED,ROOT} and compare; if our seeds match
    // (which they do, by construction), the fingerprint matches.
    let sk = SigningKey::keygen(DEV_SK, DEV_PS);
    let vendor_fpr = fw_manifest::vendor_pubkey_fingerprint(sk.pk_seed(), sk.pk_root());

    // Build manifest. The fields we care about for verify_images are
    // `(fw_version, secure_hash, secure_len, nonsecure_hash, nonsecure_len)`
    // — the rest are informational or zero.
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A)
        .fw_version(version)
        .secure_image(&secure_hash, secure_len)
        .nonsecure_image(&nonsecure_hash, nonsecure_len)
        .vendor_pubkey_fpr(&vendor_fpr)
        .build_id(&[0xCDu8; 32]) // sentinel "test fixture" build_id
        .boot_counter_snap(0)
        .try_once(TRY_ONCE_COMMITTED);

    let digest = b.finalize_preimage();
    let sig = sk.sign(&digest, None);
    b.set_signature(&sig);
    let manifest = b.finalize();

    // Sanity: re-verify via the public API before we hand it to anyone.
    {
        let m = fw_manifest::ManifestRef::new(&manifest);
        m.verify_structural()
            .map_err(|e| anyhow::anyhow!("fixture failed verify_structural: {e:?}"))?;
        m.verify_crc()
            .map_err(|e| anyhow::anyhow!("fixture failed verify_crc: {e:?}"))?;
        m.verify_digest()
            .map_err(|e| anyhow::anyhow!("fixture failed verify_digest: {e:?}"))?;
        m.verify_vendor_fpr(sk.pk_seed(), sk.pk_root())
            .map_err(|e| anyhow::anyhow!("fixture failed verify_vendor_fpr: {e:?}"))?;
        m.verify_signature(sk.pk_seed(), sk.pk_root())
            .map_err(|e| anyhow::anyhow!("fixture failed verify_signature: {e:?}"))?;
    }

    let manifest_path = out_dir.join("manifest.bin");
    let secure_path = out_dir.join("secure.bin");
    let nonsecure_path = out_dir.join("nonsecure.bin");

    std::fs::write(&manifest_path, manifest)
        .with_context(|| format!("writing {}", manifest_path.display()))?;
    std::fs::write(&secure_path, &secure_bytes)
        .with_context(|| format!("writing {}", secure_path.display()))?;
    std::fs::write(&nonsecure_path, &nonsecure_bytes)
        .with_context(|| format!("writing {}", nonsecure_path.display()))?;

    eprintln!("==> Wrote dev-signed test fixture:");
    eprintln!("      {} ({} bytes)", manifest_path.display(), manifest.len());
    eprintln!(
        "      {} ({} bytes, SHA-256 {})",
        secure_path.display(),
        secure_bytes.len(),
        hex::encode(secure_hash)
    );
    eprintln!(
        "      {} ({} bytes, SHA-256 {})",
        nonsecure_path.display(),
        nonsecure_bytes.len(),
        hex::encode(nonsecure_hash)
    );
    eprintln!("      version: {version}");
    eprintln!("      vendor_fpr: {}", hex::encode(vendor_fpr));
    Ok(())
}
