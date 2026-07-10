//! Final-artifact firmware trust-root verification.
//!
//! Both firmware worlds retain the raw public key they actually consume in a
//! dedicated allocated/loadable ELF section. Release packaging and signing
//! hash those bytes to prove `FSBL == secure == reviewed policy` from the
//! linked artifacts. This deliberately does not inspect Cargo OUT_DIR files or
//! trust that two builds happened to receive the same mutable pathname.

use anyhow::{bail, Context, Result};
use object::{
    Architecture, BinaryFormat, Object, ObjectKind, ObjectSection, ObjectSegment, SectionFlags,
    SegmentFlags,
};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const VENDOR_KEY_SECTION: &str = ".pqsigner.vendor_pubkey";
const DEVELOPMENT_VENDOR_KEY_HEX: &str =
    include_str!("../../config/development-firmware-vendor-pubkey.hex");

#[derive(Clone, Copy)]
struct ArtifactVendorKey {
    raw: [u8; 32],
    address: u64,
}

pub struct VerifiedArtifactKeys {
    fingerprint: [u8; 32],
    secure: ArtifactVendorKey,
}

impl VerifiedArtifactKeys {
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Prove that the key checked above is inside the exact flat secure image
    /// bytes that will be hashed into and signed by the update manifest.
    pub fn verify_secure_flat_image(&self, image: &crate::elf::FlatImage) -> Result<()> {
        let offset = self.secure.address.checked_sub(image.base).ok_or_else(|| {
            anyhow::anyhow!(
                "secure runtime vendor key at {:#x} precedes signed image base {:#x}",
                self.secure.address,
                image.base
            )
        })?;
        let offset =
            usize::try_from(offset).context("vendor-key image offset does not fit usize")?;
        let end = offset
            .checked_add(self.secure.raw.len())
            .context("vendor-key image range overflow")?;
        if image.bytes.get(offset..end) != Some(self.secure.raw.as_slice()) {
            bail!(
                "secure runtime vendor key is outside or differs in the exact flat image being signed"
            );
        }
        Ok(())
    }
}

pub fn verify_artifacts(
    fsbl_path: &Path,
    secure_path: &Path,
    policy_path: &Path,
    signer_fingerprint: Option<&[u8; 32]>,
) -> Result<VerifiedArtifactKeys> {
    let fsbl_bytes =
        std::fs::read(fsbl_path).with_context(|| format!("reading ELF {}", fsbl_path.display()))?;
    let secure_bytes = std::fs::read(secure_path)
        .with_context(|| format!("reading ELF {}", secure_path.display()))?;
    verify_artifact_bytes(
        fsbl_path,
        &fsbl_bytes,
        secure_path,
        &secure_bytes,
        policy_path,
        signer_fingerprint,
    )
}

pub fn verify_artifact_bytes(
    fsbl_path: &Path,
    fsbl_bytes: &[u8],
    secure_path: &Path,
    secure_bytes: &[u8],
    policy_path: &Path,
    signer_fingerprint: Option<&[u8; 32]>,
) -> Result<VerifiedArtifactKeys> {
    let fsbl = read_vendor_key_section(fsbl_path, fsbl_bytes)?;
    let secure = read_vendor_key_section(secure_path, secure_bytes)?;
    let policy = read_policy_fingerprint(policy_path)?;
    verify_values(&fsbl, &secure, &policy, signer_fingerprint)?;
    Ok(VerifiedArtifactKeys {
        fingerprint: policy,
        secure,
    })
}

fn read_vendor_key_section(path: &Path, bytes: &[u8]) -> Result<ArtifactVendorKey> {
    let file =
        object::File::parse(bytes).with_context(|| format!("parsing ELF {}", path.display()))?;

    if file.format() != BinaryFormat::Elf
        || file.architecture() != Architecture::Arm
        || file.is_64()
        || !file.is_little_endian()
        || file.kind() != ObjectKind::Executable
    {
        bail!(
            "{}: expected a little-endian ARM ELF32 executable",
            path.display()
        );
    }

    let mut matches = file.sections().filter(|section| {
        section
            .name()
            .map(|name| name == VENDOR_KEY_SECTION)
            .unwrap_or(false)
    });
    let section = matches.next().ok_or_else(|| {
        anyhow::anyhow!(
            "{}: missing retained {} section",
            path.display(),
            VENDOR_KEY_SECTION
        )
    })?;
    if matches.next().is_some() {
        bail!(
            "{}: more than one {} section",
            path.display(),
            VENDOR_KEY_SECTION
        );
    }
    match section.flags() {
        SectionFlags::Elf { sh_flags } if sh_flags & u64::from(object::elf::SHF_ALLOC) != 0 => {}
        _ => bail!(
            "{}: {} must be an allocated ELF section",
            path.display(),
            VENDOR_KEY_SECTION
        ),
    }
    let data = section
        .data()
        .with_context(|| format!("reading {} from {}", VENDOR_KEY_SECTION, path.display()))?;
    if data.len() != 32 {
        bail!(
            "{}: {} must contain exactly 32 bytes, got {}",
            path.display(),
            VENDOR_KEY_SECTION,
            data.len()
        );
    }
    let Some((_, file_size)) = section.file_range() else {
        bail!(
            "{}: {} has no file-backed range",
            path.display(),
            VENDOR_KEY_SECTION
        );
    };
    if file_size != 32 {
        bail!(
            "{}: {} file-backed range must be exactly 32 bytes",
            path.display(),
            VENDOR_KEY_SECTION
        );
    }

    let address = section.address();
    let in_readonly_load = file.segments().any(|segment| {
        let flags_ok = matches!(
            segment.flags(),
            SegmentFlags::Elf { p_flags }
                if p_flags & object::elf::PF_R != 0 && p_flags & object::elf::PF_W == 0
        );
        flags_ok
            && segment
                .data_range(address, 32)
                .ok()
                .flatten()
                .is_some_and(|loaded| loaded == data)
    });
    if !in_readonly_load {
        bail!(
            "{}: {} is not contained byte-for-byte in a read-only PT_LOAD segment",
            path.display(),
            VENDOR_KEY_SECTION
        );
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(data);
    Ok(ArtifactVendorKey { raw: out, address })
}

pub fn read_policy_fingerprint(path: &Path) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading firmware-key policy {}", path.display()))?;
    parse_policy_fingerprint(&text)
        .with_context(|| format!("invalid firmware-key policy {}", path.display()))
}

fn parse_policy_fingerprint(text: &str) -> Result<[u8; 32]> {
    let hex = text.trim();
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!(
            "expected exactly one lowercase 64-character SHA-256 fingerprint; \
             policy is not provisioned"
        );
    }
    let raw = hex::decode(hex).context("decoding SHA-256 fingerprint")?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn verify_values(
    fsbl: &ArtifactVendorKey,
    secure: &ArtifactVendorKey,
    policy: &[u8; 32],
    signer: Option<&[u8; 32]>,
) -> Result<()> {
    let dev = parse_policy_fingerprint(DEVELOPMENT_VENDOR_KEY_HEX)
        .expect("committed development public key is valid hex");
    let artifact_fingerprint: [u8; 32] = Sha256::digest(fsbl.raw).into();
    let dev_fingerprint: [u8; 32] = Sha256::digest(dev).into();
    if fsbl.raw == dev
        || secure.raw == dev
        || policy == &dev_fingerprint
        || signer == Some(&dev_fingerprint)
    {
        bail!("public in-tree development firmware key is forbidden in a release");
    }
    if fsbl.raw != secure.raw {
        bail!(
            "firmware trust-root mismatch: FSBL={}, secure={}",
            hex::encode(fsbl.raw),
            hex::encode(secure.raw)
        );
    }
    if &artifact_fingerprint != policy {
        bail!(
            "firmware trust root does not match reviewed policy: artifact={}, policy={}",
            hex::encode(artifact_fingerprint),
            hex::encode(policy)
        );
    }
    if let Some(signer) = signer {
        if signer != policy {
            bail!(
                "signing key does not match firmware artifacts/policy: signer={}, policy={}",
                hex::encode(signer),
                hex::encode(policy)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_parser_is_strict_and_fail_closed() {
        assert!(parse_policy_fingerprint("UNPROVISIONED").is_err());
        assert!(parse_policy_fingerprint(&"AA".repeat(32)).is_err());
        assert!(parse_policy_fingerprint(&"aa".repeat(31)).is_err());
        assert_eq!(
            parse_policy_fingerprint(&"12".repeat(32)).unwrap(),
            [0x12; 32]
        );
    }

    #[test]
    fn all_release_participants_must_match() {
        let a = ArtifactVendorKey {
            raw: [0x12; 32],
            address: 0,
        };
        let b = ArtifactVendorKey {
            raw: [0x34; 32],
            address: 0,
        };
        let policy: [u8; 32] = Sha256::digest(a.raw).into();
        let wrong: [u8; 32] = Sha256::digest(b.raw).into();
        assert!(verify_values(&a, &a, &policy, Some(&policy)).is_ok());
        assert!(verify_values(&a, &b, &policy, Some(&policy)).is_err());
        assert!(verify_values(&a, &a, &wrong, Some(&policy)).is_err());
        assert!(verify_values(&a, &a, &policy, Some(&wrong)).is_err());
    }

    #[test]
    fn development_key_is_always_rejected() {
        let raw = parse_policy_fingerprint(DEVELOPMENT_VENDOR_KEY_HEX).unwrap();
        let dev = ArtifactVendorKey { raw, address: 0 };
        let fpr: [u8; 32] = Sha256::digest(raw).into();
        assert!(verify_values(&dev, &dev, &fpr, Some(&fpr)).is_err());
    }

    #[test]
    fn secure_runtime_key_must_be_inside_exact_signed_flat_image() {
        let raw = [0x5a; 32];
        let mut bytes = vec![0xff; 80];
        bytes[16..48].copy_from_slice(&raw);
        let verified = VerifiedArtifactKeys {
            fingerprint: Sha256::digest(raw).into(),
            secure: ArtifactVendorKey {
                raw,
                address: 0x1010,
            },
        };
        let image = crate::elf::FlatImage {
            hash: Sha256::digest(&bytes).into(),
            bytes,
            base: 0x1000,
        };
        assert!(verified.verify_secure_flat_image(&image).is_ok());

        let mut changed = image.bytes.clone();
        changed[16] ^= 1;
        let changed = crate::elf::FlatImage {
            hash: Sha256::digest(&changed).into(),
            bytes: changed,
            base: image.base,
        };
        assert!(verified.verify_secure_flat_image(&changed).is_err());
    }
}
