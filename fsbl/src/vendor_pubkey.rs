//! Compiled-in vendor SPHINCS+C10 public key.
//!
//! The contents come from `OUT_DIR/vendor_pubkey_bytes.rs`, generated
//! by `build.rs` from either `FSBL_VENDOR_PUBKEY` (production) or the
//! built-in dev fixture (non-production). Changing this pubkey is
//! equivalent to provisioning a new vendor identity — the device will
//! no longer accept any previously-signed releases.

#[allow(dead_code)]
mod bytes {
    include!(concat!(env!("OUT_DIR"), "/vendor_pubkey_bytes.rs"));
}

/// The exact update root used by the FSBL verifier.
///
/// This is deliberately the sole runtime copy of the raw key. `key_parts`
/// returns references into this allocation, while the release gate extracts
/// the same allocated/loadable section from the final ELF and hashes it against
/// the secure-world key and reviewed production policy.
#[used]
#[no_mangle]
#[link_section = ".pqsigner.vendor_pubkey"]
pub static PQSIGNER_FSBL_VENDOR_PUBKEY: [u8; 32] = bytes::VENDOR_PUBKEY;

/// Split the allocated runtime key without maintaining duplicate seed/root
/// constants that could drift from the final-artifact statement.
#[inline(never)]
pub fn key_parts() -> (&'static [u8; 16], &'static [u8; 16]) {
    let raw = core::hint::black_box(&PQSIGNER_FSBL_VENDOR_PUBKEY);
    let seed = raw[..16].try_into().expect("fixed 16-byte pk_seed");
    let root = raw[16..].try_into().expect("fixed 16-byte pk_root");
    (seed, root)
}
