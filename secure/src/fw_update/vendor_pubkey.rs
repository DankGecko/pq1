//! Vendor SPHINCS+C10 public key, baked into the secure image at build time.
//!
//! `secure/build.rs` reads `FSBL_VENDOR_PUBKEY` (a 32-byte file holding
//! `pk_seed[16] || pk_root[16]`) and emits this module's contents into
//! OUT_DIR. The FSBL crate runs the same logic — both binaries must
//! produce byte-identical constants so a manifest accepted at BEGIN by
//! the secure firmware is *also* accepted at boot by FSBL.
//!
//! Without this, the secure firmware would have to defer signature
//! verification to FSBL after reset, leaving the OTP rollback-floor
//! bump in `cmd_fw_commit` running on unverified bytes (C-1 in the
//! security review).
//!
//! Bench builds may intentionally embed the all-zero reject-all placeholder;
//! production builds require an absolute immutable key snapshot whose hash
//! matches `config/production-firmware-vendor-key.sha256`.

mod bytes {
    include!(concat!(env!("OUT_DIR"), "/vendor_pubkey_bytes.rs"));
}

/// The exact update root used at BEGIN.
///
/// This is deliberately the sole runtime copy of the raw key. `key_parts`
/// returns references into this allocation, while the release gate extracts
/// the same allocated/loadable section from the final ELF and hashes it against
/// the FSBL key and reviewed production policy.
#[used]
#[no_mangle]
#[link_section = ".pqsigner.vendor_pubkey"]
pub static PQSIGNER_SECURE_VENDOR_PUBKEY: [u8; 32] = bytes::VENDOR_PUBKEY;

/// Split the allocated runtime key without maintaining duplicate seed/root
/// constants that could drift from the final-artifact statement.
#[inline(never)]
pub fn key_parts() -> (&'static [u8; 16], &'static [u8; 16]) {
    let raw = core::hint::black_box(&PQSIGNER_SECURE_VENDOR_PUBKEY);
    let seed = raw[..16].try_into().expect("fixed 16-byte pk_seed");
    let root = raw[16..].try_into().expect("fixed 16-byte pk_root");
    (seed, root)
}
