//! Verify that final FSBL and secure ELFs contain the same reviewed update key.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn run(fsbl: &Path, secure: &Path, trusted_fingerprint: &Path) -> Result<()> {
    let verified = crate::artifact_key::verify_artifacts(fsbl, secure, trusted_fingerprint, None)?;
    let secure_elf = std::fs::read(secure)
        .with_context(|| format!("reading final secure ELF {}", secure.display()))?;
    let status = crate::artifact_key::read_erc7730_status_section(secure, &secure_elf)?;
    let forced_eligible =
        crate::artifact_key::read_optional_erc7730_forced_eligible_section(secure, &secure_elf)?;
    let flat = crate::elf::flatten_elf_bytes(secure, &secure_elf)?;
    status.verify_flat_image(&flat, "ERC-7730 catalogue status")?;
    crate::artifact_key::verify_unique_erc7730_status_in_flat_image(status.bytes(), &flat.bytes)?;
    let forced_summary = if let Some(forced_eligible) = &forced_eligible {
        crate::artifact_key::verify_erc7730_elf_sections_disjoint(&status, forced_eligible)?;
        forced_eligible.verify_flat_image(&flat, "ERC-7730 forced-eligible set")?;
        let summary = crate::artifact_key::verify_unique_erc7730_forced_eligible_in_flat_image(
            forced_eligible.bytes(),
            &flat.bytes,
        )?;
        crate::artifact_key::verify_erc7730_sidecars_disjoint_in_flat_image(
            status.bytes(),
            forced_eligible.bytes(),
            &flat.bytes,
        )?;
        Some(summary)
    } else {
        crate::artifact_key::verify_erc7730_forced_eligible_absent_from_flat_image(&flat.bytes)?;
        None
    };
    println!(
        "firmware vendor key: {}",
        hex::encode(verified.fingerprint())
    );
    println!("artifact key agreement: PASS");
    println!(
        "ERC-7730 catalogue status: {} bytes, SHA-256 {}, allocated/read-only/flat-image bound: PASS",
        status.bytes().len(),
        hex::encode(Sha256::digest(status.bytes()))
    );
    if let (Some(section), Some(summary)) = (&forced_eligible, forced_summary) {
        println!(
            "ERC-7730 forced eligible: {} bytes, {} groups, {} tuples, SHA-256 {}, allocated/read-only/flat-image bound: PASS",
            section.bytes().len(),
            summary.group_count,
            summary.tuple_count,
            hex::encode(Sha256::digest(section.bytes()))
        );
    } else {
        println!("ERC-7730 forced eligible: ABSENT (legacy/feature-off image)");
    }
    Ok(())
}
