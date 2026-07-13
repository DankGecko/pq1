//! Strict ELF-to-flat-image adapter shared with `fwmeasure`.
//!
//! Release signing and user-visible measured-boot words must consume the
//! exact same bytes.  The implementation lives in the `fwmeasure` library;
//! this module only preserves the signer's existing interface.

use anyhow::{bail, Result};
use std::path::Path;

pub use fwmeasure::FlatImage;

pub fn flatten_elf(path: &Path) -> Result<FlatImage> {
    fwmeasure::flatten_elf(path).map_err(Into::into)
}

pub fn flatten_elf_bytes(path: &Path, bytes: &[u8]) -> Result<FlatImage> {
    fwmeasure::flatten_elf_bytes(path, bytes).map_err(Into::into)
}

pub fn ensure_image_capacity(label: &str, len: usize, capacity: u32) -> Result<()> {
    if len > capacity as usize {
        bail!("{label} image is {len} bytes, above the fixed {capacity}-byte slot capacity");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_slot_capacity_is_accepted() {
        assert!(ensure_image_capacity("secure", 475_136, 475_136).is_ok());
    }

    #[test]
    fn one_byte_over_slot_capacity_is_rejected() {
        let error = ensure_image_capacity("secure", 475_137, 475_136)
            .expect_err("capacity + 1 must fail")
            .to_string();
        assert!(error.contains("475137"));
        assert!(error.contains("475136"));
    }
}
