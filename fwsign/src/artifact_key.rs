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
pub const ERC7730_STATUS_SECTION: &str = ".pqsigner.erc7730_status";
const DEVELOPMENT_VENDOR_KEY_HEX: &str =
    include_str!("../../config/development-firmware-vendor-pubkey.hex");

#[derive(Clone, Copy)]
pub(crate) struct ArtifactSection<const N: usize> {
    raw: [u8; N],
    address: u64,
}

type ArtifactVendorKey = ArtifactSection<32>;

impl<const N: usize> ArtifactSection<N> {
    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8; N] {
        &self.raw
    }

    /// Prove that this retained section is inside the exact flat secure image
    /// bytes whose hash is bound by the signed firmware manifest.
    pub(crate) fn verify_flat_image(
        &self,
        image: &crate::elf::FlatImage,
        label: &str,
    ) -> Result<()> {
        let offset = self.address.checked_sub(image.base).ok_or_else(|| {
            anyhow::anyhow!(
                "secure runtime {label} at {:#x} precedes signed image base {:#x}",
                self.address,
                image.base
            )
        })?;
        let offset = usize::try_from(offset)
            .with_context(|| format!("{label} image offset does not fit usize"))?;
        let end = offset
            .checked_add(self.raw.len())
            .with_context(|| format!("{label} image range overflow"))?;
        if image.bytes.get(offset..end) != Some(self.raw.as_slice()) {
            bail!(
                "secure runtime {label} is outside or differs in the exact flat image being signed"
            );
        }
        Ok(())
    }
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
        self.secure.verify_flat_image(image, "vendor key")
    }
}

/// Read and validate the fixed ERC-7730 catalogue-status receipt retained by
/// the final secure ELF. The section is accepted only when it is allocated,
/// read-only, file-backed, and contained byte-for-byte in a read-only load
/// segment.
pub(crate) fn read_erc7730_status_section(
    path: &Path,
    bytes: &[u8],
) -> Result<ArtifactSection<{ pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN }>> {
    let section = read_fixed_section::<
        { pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN },
    >(path, bytes, ERC7730_STATUS_SECTION)?;
    pqsigner_erc7730::catalogue_status::CatalogueStatusV1::from_bytes(section.bytes()).map_err(
        |error| {
            anyhow::anyhow!(
                "{}: invalid {ERC7730_STATUS_SECTION}: {error:?}",
                path.display()
            )
        },
    )?;
    Ok(section)
}

/// Verify a bundle sidecar against authenticated flat secure-image bytes.
///
/// A `.pqfw` carries flat images rather than ELF section tables. New signing
/// proves the receipt came from the named retained ELF section before hashing
/// the image. Independent bundle verification therefore re-parses the fixed
/// record and requires the exact sidecar bytes to occur exactly once in the
/// already-authenticated secure image. Zero or multiple matches fail closed.
pub(crate) fn verify_unique_erc7730_status_in_flat_image(
    status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    secure_image: &[u8],
) -> Result<()> {
    pqsigner_erc7730::catalogue_status::CatalogueStatusV1::from_bytes(status)
        .map_err(|error| anyhow::anyhow!("invalid erc7730-status.bin: {error:?}"))?;

    let mut embedded: Option<&[u8]> = None;
    for (offset, magic) in secure_image.windows(4).enumerate() {
        if magic != pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_MAGIC {
            continue;
        }
        let Some(end) = offset.checked_add(status.len()) else {
            continue;
        };
        let Some(candidate) = secure_image.get(offset..end) else {
            continue;
        };
        if pqsigner_erc7730::catalogue_status::CatalogueStatusV1::from_bytes(candidate).is_err() {
            continue;
        }
        if embedded.replace(candidate).is_some() {
            bail!(
                "authenticated secure.bin contains more than one valid ERC-7730 catalogue status; binding is ambiguous"
            );
        }
    }

    match embedded {
        Some(candidate) if candidate == status.as_slice() => Ok(()),
        Some(_) => bail!(
            "erc7730-status.bin differs from the unique valid status in authenticated secure.bin"
        ),
        None => bail!("authenticated secure.bin contains no valid ERC-7730 catalogue status"),
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
    read_fixed_section::<32>(path, bytes, VENDOR_KEY_SECTION)
}

fn read_fixed_section<const N: usize>(
    path: &Path,
    bytes: &[u8],
    section_name: &str,
) -> Result<ArtifactSection<N>> {
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
            .map(|name| name == section_name)
            .unwrap_or(false)
    });
    let section = matches.next().ok_or_else(|| {
        anyhow::anyhow!(
            "{}: missing retained {} section",
            path.display(),
            section_name
        )
    })?;
    if matches.next().is_some() {
        bail!("{}: more than one {} section", path.display(), section_name);
    }
    match section.flags() {
        SectionFlags::Elf { sh_flags }
            if sh_flags & u64::from(object::elf::SHF_ALLOC) != 0
                && sh_flags & u64::from(object::elf::SHF_WRITE) == 0 => {}
        _ => bail!(
            "{}: {} must be an allocated, read-only ELF section",
            path.display(),
            section_name
        ),
    }
    let data = section
        .data()
        .with_context(|| format!("reading {} from {}", section_name, path.display()))?;
    if data.len() != N {
        bail!(
            "{}: {} must contain exactly {} bytes, got {}",
            path.display(),
            section_name,
            N,
            data.len()
        );
    }
    let Some((_, file_size)) = section.file_range() else {
        bail!(
            "{}: {} has no file-backed range",
            path.display(),
            section_name
        );
    };
    if file_size != N as u64 {
        bail!(
            "{}: {} file-backed range must be exactly {} bytes",
            path.display(),
            section_name,
            N
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
                .data_range(address, N as u64)
                .ok()
                .flatten()
                .is_some_and(|loaded| loaded == data)
    });
    if !in_readonly_load {
        bail!(
            "{}: {} is not contained byte-for-byte in a read-only PT_LOAD segment",
            path.display(),
            section_name
        );
    }

    let mut out = [0u8; N];
    out.copy_from_slice(data);
    Ok(ArtifactSection { raw: out, address })
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

    fn empty_arm_elf32_executable() -> [u8; 52] {
        let mut elf = [0u8; 52];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 1; // ELFCLASS32
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        elf[18..20].copy_from_slice(&object::elf::EM_ARM.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        elf[40..42].copy_from_slice(&52u16.to_le_bytes());
        elf[42..44].copy_from_slice(&32u16.to_le_bytes());
        elf[46..48].copy_from_slice(&40u16.to_le_bytes());
        elf
    }

    fn fixture_erc7730_status() -> [u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN]
    {
        pqsigner_erc7730::catalogue_status::CatalogueStatusV1::new(
            1,
            pqsigner_erc7730::ir::SCHEMA_VER,
            pqsigner_erc7730::catalogue_status::CatalogueProvenance::DevUnattested,
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
            b"dbgen/0.1.0",
        )
        .expect("fixture status is canonical")
        .to_bytes()
    }

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
    fn missing_erc7730_status_section_is_rejected() {
        let elf = empty_arm_elf32_executable();
        let error = read_erc7730_status_section(Path::new("secure.elf"), &elf)
            .err()
            .expect("missing retained status must fail")
            .to_string();
        assert!(error.contains("missing retained"), "got: {error}");
        assert!(error.contains(ERC7730_STATUS_SECTION), "got: {error}");
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

    #[test]
    fn erc7730_status_must_occur_exactly_once_in_authenticated_image() {
        let status = fixture_erc7730_status();
        let mut one = vec![0xa5; 32];
        one.extend_from_slice(&status);
        one.extend_from_slice(&[0x5a; 32]);
        assert!(verify_unique_erc7730_status_in_flat_image(&status, &one).is_ok());

        let absent = vec![0u8; status.len() + 64];
        assert!(verify_unique_erc7730_status_in_flat_image(&status, &absent).is_err());

        let mut duplicate = one.clone();
        duplicate.extend_from_slice(&status);
        assert!(verify_unique_erc7730_status_in_flat_image(&status, &duplicate).is_err());

        let mut alternate = status;
        alternate[64] ^= 1;
        let mut two_distinct = one;
        two_distinct.extend_from_slice(&alternate);
        assert!(verify_unique_erc7730_status_in_flat_image(&status, &two_distinct).is_err());
    }

    #[test]
    fn erc7730_status_mutations_fail_closed() {
        let status = fixture_erc7730_status();
        let mut image = status.to_vec();

        image[64] ^= 1;
        assert!(verify_unique_erc7730_status_in_flat_image(&status, &image).is_err());

        let mut malformed_sidecar = status;
        malformed_sidecar[0] ^= 1;
        assert!(verify_unique_erc7730_status_in_flat_image(&malformed_sidecar, &image).is_err());
    }
}
