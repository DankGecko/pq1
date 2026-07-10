//! Verify that final FSBL and secure ELFs contain the same reviewed update key.

use anyhow::Result;
use std::path::Path;

pub fn run(fsbl: &Path, secure: &Path, trusted_fingerprint: &Path) -> Result<()> {
    let verified = crate::artifact_key::verify_artifacts(fsbl, secure, trusted_fingerprint, None)?;
    println!(
        "firmware vendor key: {}",
        hex::encode(verified.fingerprint())
    );
    println!("artifact key agreement: PASS");
    Ok(())
}
