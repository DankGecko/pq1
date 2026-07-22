//! Verify that final FSBL and secure ELFs contain the same reviewed update key.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn run(fsbl: &Path, secure: &Path, trusted_fingerprint: &Path) -> Result<()> {
    let verified = crate::artifact_key::verify_artifacts(fsbl, secure, trusted_fingerprint, None)?;
    let secure_elf = std::fs::read(secure)
        .with_context(|| format!("reading final secure ELF {}", secure.display()))?;
    let status = crate::artifact_key::read_erc7730_status_section(secure, &secure_elf)?;
    let flat = crate::elf::flatten_elf_bytes(secure, &secure_elf)?;
    status.verify_flat_image(&flat, "ERC-7730 catalogue status")?;
    crate::artifact_key::verify_unique_erc7730_status_in_flat_image(status.bytes(), &flat.bytes)?;
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
    Ok(())
}
