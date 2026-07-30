//! Manifest-v6 pure format core — Draft 1.1 §6.1/§6.2 (Foundation A slice
//! FA-1.2 v0, issue #540).
//!
//! This module is the single no_std implementation of the frozen flag-day
//! 8,192-byte manifest-v6 page: offsets, 121-byte signed preimage, manifest
//! digest, domain-separated vendor-key fingerprint, normalized CRC-32,
//! validation (including flag-day legacy rejection), the journal-QW codec,
//! and the canonical release-package page builder.
//!
//! FROZEN-MAN-4 (architecture doc lines 666–675): no temporary literals, no
//! default epochs, no translated legacy offsets, no dual parsers. Every
//! consumer (FSBL, fwsign, inspector, factory/updater, extraction, formal
//! models, host tests) MUST share these exact bytes.
//!
//! ## Explicitly out of scope for v0 — deferred to FA-1.2b
//!
//! * C10 signature verification (`sphincs-c10` verify over the recomputed
//!   manifest digest against the immutable embedded firmware-vendor key).
//! * The key-matched signed positive/negative fixture set (dedicated
//!   nonproduction C10 key, exact fingerprint, signed images, expected
//!   shared-verifier result; §6.1 L1924–1933). The `i mod 256` patterned
//!   signature in the golden page fixture is a serialization/normalization
//!   fixture only — it is NOT a valid C10 signature KAT and must never be
//!   reported as one.
//!
//! ## Durability/ECC attribution (owner-adopted review amendment)
//!
//! Journal reads enter this codec ONLY through explicit [`Attribution`]
//! parameters carried by [`JournalRead`]. Nothing here hardcodes a scripted
//! durability assumption: `OPEN-JRN-DUR-1` will later define the real
//! discriminator, and the caller (FSBL journal backend) is responsible for
//! attributing each raw 16-byte read as ECC-clean and durably clean. A torn,
//! ECCC, ECCD, may-have-launched, or otherwise ambiguous observation is not a
//! valid marker and contributes no authority anywhere in this module.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{read_array, MAGIC, MANIFEST_SIZE, SIGNATURE_LEN};

// ---------------------------------------------------------------------------
// Frozen format constants (§6.1)
// ---------------------------------------------------------------------------

/// Manifest-v6 schema byte. Flag day: any other value (including legacy
/// `0x02..=0x05`) is rejected — never translated, retried, or defaulted.
pub const SCHEMA_V6: u8 = 0x06;

/// Exact 7-byte signing domain.
pub const DOMAIN_TAG: &[u8; 7] = b"PQFW_V6";

/// Exact 10-byte vendor-key-fingerprint domain.
pub const VENDOR_FPR_DOMAIN: &[u8; 10] = b"PQFW_VK_V6";

/// Signed preimage length: 7 + 1 + 1 + 4 + 4 + 4 + 4 + 32 + 32 + 32.
pub const SIGNED_PREIMAGE_LEN: usize = 121;

/// Inclusive range for `release_version` and `security_epoch`. Both `0` and
/// `0xFFFF_FFFF` are forbidden (no default epoch, no sentinel).
pub const VERSION_MIN: u32 = 1;
/// See [`VERSION_MIN`].
pub const VERSION_MAX: u32 = 0xFFFF_FFFE;

/// Minimum image length for either world.
pub const IMAGE_LEN_MIN: u32 = 8;

pub const OFF_MAGIC: usize = 0;
pub const OFF_SCHEMA: usize = 4;
pub const OFF_SLOT: usize = 5;
pub const OFF_HEADER_RESERVED: usize = 6;
pub const OFF_RELEASE_VERSION: usize = 8;
pub const OFF_SECURITY_EPOCH: usize = 12;
pub const OFF_SECURE_LEN: usize = 16;
pub const OFF_NONSECURE_LEN: usize = 20;
pub const OFF_SECURE_HASH: usize = 24;
pub const OFF_NONSECURE_HASH: usize = 56;
pub const OFF_VENDOR_FPR: usize = 88;
pub const OFF_BUILD_ID: usize = 120;
pub const OFF_DIGEST: usize = 152;
pub const OFF_SIGNATURE: usize = 184;
/// `QW_PENDING` — journal QW index 262.
pub const OFF_QW_PENDING: usize = 4192;
/// `QW_CONFIRMED_0` — journal QW index 263, first terminal replica.
pub const OFF_QW_CONFIRMED_0: usize = 4208;
/// `QW_INSTALL_ID` — journal QW index 264.
pub const OFF_QW_INSTALL_ID: usize = 4224;
/// `QW_INSTALL_ID_INV` — journal QW index 265, exact bitwise complement.
pub const OFF_QW_INSTALL_ID_INV: usize = 4240;
/// `QW_CONFIRMED_1` — journal QW index 266, second terminal replica.
pub const OFF_QW_CONFIRMED_1: usize = 4256;
pub const OFF_TRAILING_RESERVED: usize = 4272;
pub const OFF_CRC32: usize = 8188;

/// The five journal QW offsets, in page order. These are the only
/// CRC-normalized bytes on the page.
pub const JOURNAL_QW_OFFSETS: [usize; 5] = [
    OFF_QW_PENDING,
    OFF_QW_CONFIRMED_0,
    OFF_QW_INSTALL_ID,
    OFF_QW_INSTALL_ID_INV,
    OFF_QW_CONFIRMED_1,
];

/// Byte length of the CRC-normalized journal window (5 × 16).
pub const JOURNAL_WINDOW_LEN: usize = OFF_TRAILING_RESERVED - OFF_QW_PENDING;

// ---------------------------------------------------------------------------
// §6.1 compile-time pins (the build proves them)
// ---------------------------------------------------------------------------

const _: () = assert!(OFF_MAGIC == 0);
const _: () = assert!(OFF_SCHEMA == 4);
const _: () = assert!(OFF_SLOT == 5);
const _: () = assert!(OFF_HEADER_RESERVED == 6);
const _: () = assert!(OFF_RELEASE_VERSION == 8);
const _: () = assert!(OFF_SECURITY_EPOCH == 12);
const _: () = assert!(OFF_SECURE_LEN == 16);
const _: () = assert!(OFF_NONSECURE_LEN == 20);
const _: () = assert!(OFF_SECURE_HASH == 24);
const _: () = assert!(OFF_NONSECURE_HASH == 56);
const _: () = assert!(OFF_VENDOR_FPR == 88);
const _: () = assert!(OFF_BUILD_ID == 120);
const _: () = assert!(OFF_DIGEST == 152);
const _: () = assert!(OFF_SIGNATURE == 184);
const _: () = assert!(OFF_QW_PENDING == 4192);
const _: () = assert!(OFF_QW_CONFIRMED_0 == 4208);
const _: () = assert!(OFF_QW_INSTALL_ID == 4224);
const _: () = assert!(OFF_QW_INSTALL_ID_INV == 4240);
const _: () = assert!(OFF_QW_CONFIRMED_1 == 4256);
const _: () = assert!(OFF_TRAILING_RESERVED == 4272);
const _: () = assert!(OFF_CRC32 == 8188);
const _: () = assert!(SIGNATURE_LEN == 4008);
const _: () = assert!(SIGNED_PREIMAGE_LEN == 121);
const _: () = assert!(JOURNAL_WINDOW_LEN == 80);
const _: () = assert!(
    OFF_QW_PENDING % 16 == 0
        && OFF_QW_CONFIRMED_0 % 16 == 0
        && OFF_QW_INSTALL_ID % 16 == 0
        && OFF_QW_INSTALL_ID_INV % 16 == 0
        && OFF_QW_CONFIRMED_1 % 16 == 0
);
const _: () = assert!(OFF_SIGNATURE + SIGNATURE_LEN == OFF_QW_PENDING);
const _: () = assert!(OFF_CRC32 == MANIFEST_SIZE - 4);

// ---------------------------------------------------------------------------
// Journal codewords (§6.2) — each has 64 programmed zero bits, its second
// half is the bitwise complement of its first, pairwise Hamming distance is
// at least 64, and each is distance 64 from erased. Property-tested in the
// host fixture suite.
// ---------------------------------------------------------------------------

/// Pending activation marker (`QW_PENDING`).
pub const QW_PENDING: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, //
    0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21, 0x0F,
];

/// Terminal marker, replica 0 (`QW_CONFIRMED_0`).
pub const QW_CONFIRMED_0: [u8; 16] = [
    0xAA, 0x55, 0x99, 0x66, 0xF0, 0x0F, 0xC3, 0x3C, //
    0x55, 0xAA, 0x66, 0x99, 0x0F, 0xF0, 0x3C, 0xC3,
];

/// Terminal marker, replica 1 (`QW_CONFIRMED_1`).
pub const QW_CONFIRMED_1: [u8; 16] = [
    0x5A, 0xA5, 0x96, 0x69, 0x3C, 0xC3, 0xF0, 0x0F, //
    0xA5, 0x5A, 0x69, 0x96, 0xC3, 0x3C, 0x0F, 0xF0,
];

// ---------------------------------------------------------------------------
// Physical slot
// ---------------------------------------------------------------------------

/// The physical slot a manifest page belongs to. The slot byte must match
/// the containing page; it is never inferred from the manifest alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PhysicalSlot {
    A,
    B,
}

impl PhysicalSlot {
    /// On-page slot byte (`0x00=A`, `0x01=B`).
    pub const fn to_u8(self) -> u8 {
        match self {
            PhysicalSlot::A => 0x00,
            PhysicalSlot::B => 0x01,
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(PhysicalSlot::A),
            0x01 => Some(PhysicalSlot::B),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Durability/ECC attribution — the ONLY way journal evidence enters the codec
// ---------------------------------------------------------------------------

/// Caller-supplied attribution for one raw journal-QW read. The codec never
/// assumes durability; `OPEN-JRN-DUR-1` will later define the real
/// discriminator behind these two booleans.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attribution {
    /// The read returned without ECC correction or double-bit error.
    pub ecc_clean: bool,
    /// The read is durably clean (no torn/interrupted program, no
    /// may-have-launched ambiguity).
    pub durably_clean: bool,
}

impl Attribution {
    /// Fully clean attribution.
    pub const CLEAN: Self = Attribution {
        ecc_clean: true,
        durably_clean: true,
    };

    /// An exact full-QW observation requires BOTH legs. Torn, ECCC, ECCD,
    /// may-have-launched, or any other ambiguous observation is not exact.
    pub const fn is_exact(self) -> bool {
        self.ecc_clean && self.durably_clean
    }
}

/// One raw 16-byte journal-QW read plus its explicit attribution.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct JournalRead {
    pub raw: [u8; 16],
    pub attribution: Attribution,
}

impl JournalRead {
    /// Convenience constructor.
    pub const fn new(raw: [u8; 16], attribution: Attribution) -> Self {
        JournalRead { raw, attribution }
    }

    /// True iff this read is an exact, durably-clean full-QW observation.
    pub const fn is_exact(&self) -> bool {
        self.attribution.is_exact()
    }
}

/// A codeword marker is valid only on an exact full-QW read whose bytes equal
/// the codeword exactly. Anything else — wrong bytes, torn, ECCC/ECCD,
/// may-have-launched — is not a valid marker.
pub fn is_exact_marker(read: &JournalRead, codeword: &[u8; 16]) -> bool {
    read.is_exact() && read.raw == *codeword
}

// ---------------------------------------------------------------------------
// Install-identity generation (§6.2)
// ---------------------------------------------------------------------------

/// Later-lifecycle evidence that the activation writer reached the step
/// after the install-identity program. Supplied explicitly by the caller,
/// which must itself have observed the marker through [`is_exact_marker`]
/// (durably clean, ECC-clean). The codec cannot and does not verify the
/// evidence — it only refuses to reconstruct anything without it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LaterLifecycleEvidence {
    /// An exact durably-clean `QW_PENDING` was observed.
    Pending,
    /// Exact durably-clean terminal evidence (a CONFIRMED replica) was
    /// observed.
    Terminal,
}

const fn is_all(byte: u8, raw: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < 16 {
        if raw[i] != byte {
            return false;
        }
        i += 1;
    }
    true
}

/// All-zero and all-one install identities are forbidden (the writer rejects
/// and resamples them so both QWs require a real program operation). All-one
/// is also the erased pattern, so an erased half is trivially nontrivial-
/// rejected too.
fn is_forbidden_install_id(raw: &[u8; 16]) -> bool {
    is_all(0x00, raw) || is_all(0xFF, raw)
}

fn complement(raw: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = !raw[i];
        i += 1;
    }
    out
}

/// `FullInstallGeneration`: two durably-clean exact reads, exact
/// complementarity, and neither forbidden value. Anything less is `None`.
pub fn full_install_generation(id: &JournalRead, inv: &JournalRead) -> Option<[u8; 16]> {
    if !id.is_exact() || !inv.is_exact() {
        return None;
    }
    if is_forbidden_install_id(&id.raw) {
        return None;
    }
    if complement(&id.raw) != inv.raw {
        return None;
    }
    Some(id.raw)
}

/// `SurvivingInstallGeneration` (owner-decided 2026-07-26, implemented as
/// frozen): reconstruct the identity from exactly ONE independently durable,
/// clean, nontrivial half, and ONLY because the caller supplies
/// later-lifecycle evidence (`evidence`) proving the activation writer
/// reached the later step. The missing half contributes no authority. If
/// both halves are exact this degenerates to [`full_install_generation`]
/// semantics — a conflicting exact value rejects the generation. A lone
/// identity half without evidence is incomplete, never an installed
/// artifact (callers must not call this without evidence; the parameter
/// makes that obligation explicit at every call site).
pub fn surviving_install_generation(
    id: &JournalRead,
    inv: &JournalRead,
    evidence: LaterLifecycleEvidence,
) -> Option<[u8; 16]> {
    // Both evidence kinds carry the same weight here; the parameter exists
    // so no call site can reconstruct silently.
    let _ = evidence;
    match (id.is_exact(), inv.is_exact()) {
        (true, true) => full_install_generation(id, inv),
        (true, false) => {
            if is_forbidden_install_id(&id.raw) {
                None
            } else {
                Some(id.raw)
            }
        }
        (false, true) => {
            let reconstructed = complement(&inv.raw);
            if is_forbidden_install_id(&reconstructed) {
                None
            } else {
                Some(reconstructed)
            }
        }
        (false, false) => None,
    }
}

// ---------------------------------------------------------------------------
// Normalized CRC-32 (§6.1) — the ONLY CRC path for v6 pages. No raw-CRC call
// sites: this goes through the crate's single shared IEEE implementation.
// ---------------------------------------------------------------------------

/// The 80 erased bytes that replace the journal window for CRC purposes.
const ERASED_JOURNAL_WINDOW: [u8; JOURNAL_WINDOW_LEN] = [0xFF; JOURNAL_WINDOW_LEN];

/// Normalized CRC-32 over bytes `0..8188` with the journal window
/// `4192..4272` replaced by 80 bytes of `0xFF` — i.e. over page bytes
/// `0..4192`, then the erased window, then `4272..8188`. Reflected poly
/// `0xEDB88320`, init/final-XOR `0xFFFFFFFF`; stored big-endian at 8188.
pub fn normalized_crc32(page: &[u8; MANIFEST_SIZE]) -> u32 {
    crate::crc32_ieee_multi(&[
        &page[..OFF_QW_PENDING],
        &ERASED_JOURNAL_WINDOW,
        &page[OFF_TRAILING_RESERVED..OFF_CRC32],
    ])
}

/// Recompute the normalized CRC and store it big-endian at `OFF_CRC32`.
pub fn rewrite_normalized_crc(page: &mut [u8; MANIFEST_SIZE]) {
    let crc = normalized_crc32(page);
    page[OFF_CRC32..OFF_CRC32 + 4].copy_from_slice(&crc.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Vendor-key fingerprint (§6.1) — equality check, never a key selector
// ---------------------------------------------------------------------------

/// `SHA-256("PQFW_VK_V6" || pk_seed[16] || pk_root[16])` of the immutable
/// embedded firmware-vendor verifying key.
pub fn vendor_fingerprint(pk_seed: &[u8; 16], pk_root: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(VENDOR_FPR_DOMAIN);
    h.update(pk_seed);
    h.update(pk_root);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Parsed manifest
// ---------------------------------------------------------------------------

/// A manifest-v6 page that passed [`parse_and_validate`]. The C10 signature
/// is carried but NOT verified here (FA-1.2b); `stored_digest` is a redundant
/// comparison value, never a signing authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestV6 {
    pub slot: PhysicalSlot,
    pub release_version: u32,
    pub security_epoch: u32,
    pub secure_len: u32,
    pub nonsecure_len: u32,
    pub secure_hash: [u8; 32],
    pub nonsecure_hash: [u8; 32],
    pub vendor_fpr: [u8; 32],
    /// Unsigned, non-authoritative correlation metadata.
    pub build_id: [u8; 32],
    /// Redundant comparison value — see [`ManifestV6::stored_digest_matches`].
    pub stored_digest: [u8; 32],
    /// C10 signature over the 32-byte manifest digest (verified in FA-1.2b).
    pub signature: [u8; SIGNATURE_LEN],
    pub stored_crc32: u32,
}

impl ManifestV6 {
    /// The exact 121-byte signed preimage:
    /// `DOMAIN_TAG || schema || slot || R || E || secure_len ||
    /// nonsecure_len || secure_hash || nonsecure_hash || vendor_fpr`
    /// (all integers big-endian).
    pub fn signed_preimage(&self) -> [u8; SIGNED_PREIMAGE_LEN] {
        let mut p = [0u8; SIGNED_PREIMAGE_LEN];
        p[0..7].copy_from_slice(DOMAIN_TAG);
        p[7] = SCHEMA_V6;
        p[8] = self.slot.to_u8();
        p[9..13].copy_from_slice(&self.release_version.to_be_bytes());
        p[13..17].copy_from_slice(&self.security_epoch.to_be_bytes());
        p[17..21].copy_from_slice(&self.secure_len.to_be_bytes());
        p[21..25].copy_from_slice(&self.nonsecure_len.to_be_bytes());
        p[25..57].copy_from_slice(&self.secure_hash);
        p[57..89].copy_from_slice(&self.nonsecure_hash);
        p[89..121].copy_from_slice(&self.vendor_fpr);
        p
    }

    /// `SHA256(signed_preimage)`. This recomputation — followed by C10
    /// verification in FA-1.2b — is the ONLY signing-authority path.
    pub fn manifest_digest(&self) -> [u8; 32] {
        Sha256::digest(self.signed_preimage()).into()
    }

    /// Redundant comparison between the stored digest field and a fresh
    /// recomputation. Parse does NOT fail on a mismatch: the stored digest
    /// is a comparison value, never an independent signing authority.
    pub fn stored_digest_matches(&self) -> bool {
        bool::from(self.stored_digest.ct_eq(&self.manifest_digest()))
    }

    /// Equality check of the signed vendor-key fingerprint against a fresh
    /// recomputation from the immutable embedded key bytes. Never a key
    /// selector, locator, rollover instruction, or authority to load key
    /// bytes from the manifest.
    pub fn vendor_fpr_matches(&self, pk_seed: &[u8; 16], pk_root: &[u8; 16]) -> bool {
        bool::from(
            self.vendor_fpr
                .ct_eq(&vendor_fingerprint(pk_seed, pk_root)),
        )
    }
}

/// Two manifests belong to one logical release-set when they carry identical
/// `(release_version, security_epoch)` and policy identity (the vendor-key
/// fingerprint). Slot, slot-specific image hashes, signature, and digest
/// differ: each artifact is independently signed for its physical slot.
/// `build_id` is unsigned/non-authoritative and plays no identity role.
pub fn same_release_set(a: &ManifestV6, b: &ManifestV6) -> bool {
    a.release_version == b.release_version
        && a.security_epoch == b.security_epoch
        && bool::from(a.vendor_fpr.ct_eq(&b.vendor_fpr))
}

// ---------------------------------------------------------------------------
// Validation (flag day)
// ---------------------------------------------------------------------------

/// Everything that can be wrong with a candidate manifest-v6 page. Legacy
/// schemas are reported as [`ValidationError::BadSchema`] and never
/// translated, retried, or defaulted (FROZEN-MAN-4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValidationError {
    BadMagic,
    /// Schema byte other than `0x06` (including legacy `0x02..=0x05`).
    BadSchema(u8),
    NonZeroHeaderReserved,
    BadSlotByte(u8),
    SlotMismatch {
        found: PhysicalSlot,
        expected: PhysicalSlot,
    },
    BadReleaseVersion(u32),
    BadSecurityEpoch(u32),
    BadSecureLen(u32),
    BadNonsecureLen(u32),
    NonErasedTrailingReserved,
    CrcMismatch {
        stored: u32,
        computed: u32,
    },
    /// A release-package page carried a non-erased journal QW (§6.1
    /// L1935–1944): PENDING/CONFIRMED/install-id/any other value in a
    /// package is rejected even though the normalized CRC ignores it.
    NonErasedJournalQw { offset: usize },
    /// A release-package page whose stored digest field is not the exact
    /// freshly recomputed digest (§6.1 offset-152 frozen rule). Package
    /// canonicality only — the signing-authority path remains
    /// recompute-then-verify; on-device parse does not fail on this.
    StoredDigestMismatch,
}

/// Parse and fully validate a candidate manifest-v6 page (any lifecycle
/// state). Checks: magic, exact schema `0x06` (flag day), zero header
/// reserved, slot byte ∈ {0,1} and equal to `expected_slot`, R/E ranges,
/// image lengths within the frozen §5 geometry spans, erased trailing
/// reserved, and stored CRC equal to the recomputed normalized CRC. The
/// stored digest is NOT checked here (redundant comparison value — see
/// [`ManifestV6::stored_digest_matches`]); the journal window is NOT
/// constrained here (device-mutated bytes).
pub fn parse_and_validate(
    page: &[u8; MANIFEST_SIZE],
    expected_slot: PhysicalSlot,
) -> Result<ManifestV6, ValidationError> {
    if *read_array::<4>(page, OFF_MAGIC) != MAGIC {
        return Err(ValidationError::BadMagic);
    }
    let schema = page[OFF_SCHEMA];
    if schema != SCHEMA_V6 {
        return Err(ValidationError::BadSchema(schema));
    }
    if page[OFF_HEADER_RESERVED..OFF_HEADER_RESERVED + 2] != [0x00, 0x00] {
        return Err(ValidationError::NonZeroHeaderReserved);
    }
    let slot_byte = page[OFF_SLOT];
    let slot = PhysicalSlot::from_byte(slot_byte).ok_or(ValidationError::BadSlotByte(slot_byte))?;
    if slot != expected_slot {
        return Err(ValidationError::SlotMismatch {
            found: slot,
            expected: expected_slot,
        });
    }
    let release_version = u32::from_be_bytes(*read_array(page, OFF_RELEASE_VERSION));
    if !(VERSION_MIN..=VERSION_MAX).contains(&release_version) {
        return Err(ValidationError::BadReleaseVersion(release_version));
    }
    let security_epoch = u32::from_be_bytes(*read_array(page, OFF_SECURITY_EPOCH));
    if !(VERSION_MIN..=VERSION_MAX).contains(&security_epoch) {
        return Err(ValidationError::BadSecurityEpoch(security_epoch));
    }
    let secure_len = u32::from_be_bytes(*read_array(page, OFF_SECURE_LEN));
    if secure_len < IMAGE_LEN_MIN || secure_len > pqsigner_geometry::SECURE_SLOT_SPAN {
        return Err(ValidationError::BadSecureLen(secure_len));
    }
    let nonsecure_len = u32::from_be_bytes(*read_array(page, OFF_NONSECURE_LEN));
    if nonsecure_len < IMAGE_LEN_MIN || nonsecure_len > pqsigner_geometry::NS_SLOT_SPAN {
        return Err(ValidationError::BadNonsecureLen(nonsecure_len));
    }
    if page[OFF_TRAILING_RESERVED..OFF_CRC32].iter().any(|&b| b != 0xFF) {
        return Err(ValidationError::NonErasedTrailingReserved);
    }
    let stored_crc32 = u32::from_be_bytes(*read_array(page, OFF_CRC32));
    let computed_crc32 = normalized_crc32(page);
    if stored_crc32 != computed_crc32 {
        return Err(ValidationError::CrcMismatch {
            stored: stored_crc32,
            computed: computed_crc32,
        });
    }
    Ok(ManifestV6 {
        slot,
        release_version,
        security_epoch,
        secure_len,
        nonsecure_len,
        secure_hash: *read_array(page, OFF_SECURE_HASH),
        nonsecure_hash: *read_array(page, OFF_NONSECURE_HASH),
        vendor_fpr: *read_array(page, OFF_VENDOR_FPR),
        build_id: *read_array(page, OFF_BUILD_ID),
        stored_digest: *read_array(page, OFF_DIGEST),
        signature: *read_array(page, OFF_SIGNATURE),
        stored_crc32,
    })
}

/// The incoming release-package rule (§6.1 L1935–1944): a package page MUST
/// carry raw `0xFF × 16` in all five journal QWs. Any PENDING, CONFIRMED,
/// install-identity, or other value is rejected even though the normalized
/// CRC ignores the window.
pub fn validate_release_package(
    page: &[u8; MANIFEST_SIZE],
    expected_slot: PhysicalSlot,
) -> Result<ManifestV6, ValidationError> {
    let manifest = parse_and_validate(page, expected_slot)?;
    for offset in JOURNAL_QW_OFFSETS {
        if page[offset..offset + 16] != [0xFF; 16] {
            return Err(ValidationError::NonErasedJournalQw { offset });
        }
    }
    // §6.1 offset-152 frozen rule: a canonical package's stored digest is
    // the exact freshly recomputed digest. Package canonicality only —
    // the signing-authority path is recompute-then-verify (FA-1.2b), and
    // on-device parse keeps the stored digest a redundant comparison.
    if !manifest.stored_digest_matches() {
        return Err(ValidationError::StoredDigestMismatch);
    }
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Canonical release-package builder
// ---------------------------------------------------------------------------

/// Everything the offline signer needs to serialize one canonical
/// release-package page. The digest and normalized CRC are computed, never
/// accepted from the caller.
pub struct ReleasePackageFields<'a> {
    pub slot: PhysicalSlot,
    pub release_version: u32,
    pub security_epoch: u32,
    pub secure_len: u32,
    pub nonsecure_len: u32,
    pub secure_hash: &'a [u8; 32],
    pub nonsecure_hash: &'a [u8; 32],
    pub vendor_fpr: &'a [u8; 32],
    pub build_id: &'a [u8; 32],
    /// C10 signature over the manifest digest (produced by the signer;
    /// verification lives in FA-1.2b).
    pub signature: &'a [u8; SIGNATURE_LEN],
}

/// Build the canonical unstamped release-package serialization: all fields
/// in place, freshly computed manifest digest, all five journal QWs erased,
/// trailing reserved erased, normalized CRC stored big-endian at 8188. The
/// result is self-checked through [`validate_release_package`] before it is
/// returned, so an out-of-range field is an error, not a malformed page.
pub fn build_release_package(
    fields: &ReleasePackageFields<'_>,
) -> Result<[u8; MANIFEST_SIZE], ValidationError> {
    let manifest = ManifestV6 {
        slot: fields.slot,
        release_version: fields.release_version,
        security_epoch: fields.security_epoch,
        secure_len: fields.secure_len,
        nonsecure_len: fields.nonsecure_len,
        secure_hash: *fields.secure_hash,
        nonsecure_hash: *fields.nonsecure_hash,
        vendor_fpr: *fields.vendor_fpr,
        build_id: *fields.build_id,
        stored_digest: [0u8; 32], // computed below
        signature: *fields.signature,
        stored_crc32: 0, // computed below
    };
    let mut page = [0xFFu8; MANIFEST_SIZE];
    page[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
    page[OFF_SCHEMA] = SCHEMA_V6;
    page[OFF_SLOT] = fields.slot.to_u8();
    page[OFF_HEADER_RESERVED..OFF_HEADER_RESERVED + 2].copy_from_slice(&[0x00, 0x00]);
    page[OFF_RELEASE_VERSION..OFF_RELEASE_VERSION + 4]
        .copy_from_slice(&fields.release_version.to_be_bytes());
    page[OFF_SECURITY_EPOCH..OFF_SECURITY_EPOCH + 4]
        .copy_from_slice(&fields.security_epoch.to_be_bytes());
    page[OFF_SECURE_LEN..OFF_SECURE_LEN + 4]
        .copy_from_slice(&fields.secure_len.to_be_bytes());
    page[OFF_NONSECURE_LEN..OFF_NONSECURE_LEN + 4]
        .copy_from_slice(&fields.nonsecure_len.to_be_bytes());
    page[OFF_SECURE_HASH..OFF_SECURE_HASH + 32].copy_from_slice(fields.secure_hash);
    page[OFF_NONSECURE_HASH..OFF_NONSECURE_HASH + 32].copy_from_slice(fields.nonsecure_hash);
    page[OFF_VENDOR_FPR..OFF_VENDOR_FPR + 32].copy_from_slice(fields.vendor_fpr);
    page[OFF_BUILD_ID..OFF_BUILD_ID + 32].copy_from_slice(fields.build_id);
    let digest = manifest.manifest_digest();
    page[OFF_DIGEST..OFF_DIGEST + 32].copy_from_slice(&digest);
    page[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_LEN].copy_from_slice(fields.signature);
    // Journal QWs stay erased (unstamped package); trailing reserved stays
    // erased; CRC covers the normalized page.
    rewrite_normalized_crc(&mut page);
    validate_release_package(&page, fields.slot)?;
    Ok(page)
}
