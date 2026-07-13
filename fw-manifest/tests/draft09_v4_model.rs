//! Test-only executable model of the frozen Draft 0.9 manifest-v4 bytes.
//!
//! This deliberately does not use or change the production manifest API.  The
//! production crate still exposes the quarantined legacy format; these vectors
//! pin the reviewed replacement contract before that implementation is shared
//! by the signer, updater, inspector, and FSBL.

use sha2::{Digest, Sha256};
use std::process::Command;

const MANIFEST_SIZE: usize = 8_192;
const SIGNATURE_LEN: usize = 4_008;
const SIGNED_PREIMAGE_LEN: usize = 80;
const ARM_TOKEN_PREIMAGE_LEN: usize = 116;

const MAGIC: [u8; 4] = *b"PQSF";
const SCHEMA_V4: u8 = 0x04;
const SLOT_A: u8 = 0x00;
const SLOT_B: u8 = 0x01;
const DOMAIN_V4: &[u8; 7] = b"PQFW_V4";
const ARM_DOMAIN: &[u8; 7] = b"PQFW_A1";

const OFF_MAGIC: usize = 0;
const OFF_SCHEMA: usize = 4;
const OFF_SLOT: usize = 5;
const OFF_HEADER_RESERVED: usize = 6;
const OFF_RELEASE_VERSION: usize = 8;
const OFF_SECURITY_EPOCH: usize = 12;
const OFF_SECURE_LEN: usize = 16;
const OFF_NONSECURE_LEN: usize = 20;
const OFF_SECURE_HASH: usize = 24;
const OFF_NONSECURE_HASH: usize = 56;
const OFF_VENDOR_FPR: usize = 88;
const OFF_BUILD_ID: usize = 120;
const OFF_MANIFEST_DIGEST: usize = 152;
const OFF_SIGNATURE: usize = 184;
const OFF_PENDING: usize = 4_192;
const OFF_CONFIRMED: usize = 4_208;
const OFF_TRAILING_RESERVED: usize = 4_224;
const OFF_CRC32: usize = 8_188;

const QW_PENDING: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21, 0x0F,
];
const QW_CONFIRMED: [u8; 16] = [
    0xAA, 0x55, 0x99, 0x66, 0xF0, 0x0F, 0xC3, 0x3C, 0x55, 0xAA, 0x66, 0x99, 0x0F, 0xF0, 0x3C, 0xC3,
];

const RELEASE_VERSION: u32 = 0x0102_0304;
const SECURITY_EPOCH: u32 = 0x0506_0708;
const FLOOR_TARGET: u32 = 0x0506_0707;
const MIN_IMAGE_LEN: u32 = 8;
const MAX_SECURE_IMAGE_LEN: u32 = 0x0007_4000;
const MAX_NONSECURE_IMAGE_LEN: u32 = 0x0007_A000;

const SECURE_HASH: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];
const NONSECURE_HASH: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];
const VENDOR_FINGERPRINT: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
];

const MANIFEST_DIGEST: [u8; 32] = [
    0xB2, 0x64, 0x91, 0xE8, 0x6C, 0x8B, 0x97, 0xFE, 0x7E, 0x6B, 0xC3, 0xB6, 0x7B, 0xE7, 0x3D, 0x1A,
    0x69, 0x63, 0xEE, 0x42, 0x90, 0xC9, 0xFC, 0xAE, 0xF5, 0xF2, 0xDA, 0xD0, 0x1F, 0x86, 0x46, 0x1F,
];
const ARM_BINDING_DIGEST: [u8; 32] = [
    0x16, 0x72, 0x70, 0x42, 0x3F, 0x35, 0xF1, 0x6B, 0xCD, 0xEC, 0xAD, 0x4E, 0x9E, 0x19, 0x81, 0x7A,
    0xC8, 0x7B, 0x06, 0xBB, 0x88, 0x38, 0x48, 0x3B, 0xE8, 0xB9, 0x76, 0x36, 0x47, 0x6C, 0x7B, 0x7A,
];

const PAGE_HASH_ERASED: [u8; 32] = [
    0x8E, 0x80, 0xB3, 0x17, 0xA7, 0xA5, 0x7A, 0x80, 0x13, 0x66, 0x44, 0x33, 0x9C, 0x6A, 0x10, 0xE3,
    0x40, 0xAB, 0xF6, 0xC5, 0x84, 0xFD, 0x73, 0xD5, 0x8A, 0xFE, 0xDF, 0x33, 0x18, 0x87, 0x57, 0x10,
];
const PAGE_HASH_PENDING: [u8; 32] = [
    0x0B, 0x2B, 0x7E, 0x22, 0xE2, 0x3F, 0xA9, 0xC1, 0x7A, 0x7A, 0x76, 0x9A, 0x21, 0x03, 0x54, 0xF7,
    0x11, 0x20, 0x22, 0x73, 0x71, 0x9E, 0x54, 0x16, 0x95, 0xFF, 0x1C, 0x1C, 0x5F, 0xBD, 0x78, 0x47,
];
const PAGE_HASH_CONFIRMED: [u8; 32] = [
    0xDA, 0x4E, 0xEC, 0x46, 0xBA, 0xED, 0x28, 0x12, 0xBE, 0x2A, 0xF7, 0x31, 0xBF, 0x76, 0xE3, 0x19,
    0xE1, 0xCA, 0x23, 0x13, 0x7F, 0x4A, 0x11, 0x7D, 0x7B, 0xA3, 0xEC, 0xED, 0xEC, 0x09, 0x18, 0xF3,
];

const _: () = assert!(SIGNATURE_LEN == 4_008);
const _: () = assert!(SIGNED_PREIMAGE_LEN == 7 + 1 + 4 + 4 + 32 + 32);
const _: () = assert!(ARM_TOKEN_PREIMAGE_LEN == 7 + 1 + 4 + 4 + 4 + 32 + 32 + 32);
const _: () = assert!(OFF_PENDING.is_multiple_of(16));
const _: () = assert!(OFF_CONFIRMED.is_multiple_of(16));
const _: () = assert!(OFF_SIGNATURE + SIGNATURE_LEN == OFF_PENDING);
const _: () = assert!(OFF_CRC32 == MANIFEST_SIZE - 4);

#[derive(Clone, Copy)]
enum JournalFixture {
    Erased,
    Pending,
    Confirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelError {
    Domain,
    Magic,
    Schema,
    Slot,
    Reserved,
    ReleaseVersion,
    SecurityEpoch,
    SecureLength,
    NonsecureLength,
    VendorFingerprint,
    Digest,
    Crc,
}

fn signed_preimage(
    domain: &[u8; 7],
    slot: u8,
    release_version: u32,
    security_epoch: u32,
    secure_hash: &[u8; 32],
    nonsecure_hash: &[u8; 32],
) -> [u8; SIGNED_PREIMAGE_LEN] {
    let mut out = [0u8; SIGNED_PREIMAGE_LEN];
    out[..7].copy_from_slice(domain);
    out[7] = slot;
    out[8..12].copy_from_slice(&release_version.to_be_bytes());
    out[12..16].copy_from_slice(&security_epoch.to_be_bytes());
    out[16..48].copy_from_slice(secure_hash);
    out[48..80].copy_from_slice(nonsecure_hash);
    out
}

fn digest_preimage(preimage: &[u8]) -> [u8; 32] {
    Sha256::digest(preimage).into()
}

fn arm_token_preimage(
    slot: u8,
    release_version: u32,
    security_epoch: u32,
    floor_target: u32,
    signed_manifest_digest: &[u8; 32],
    secure_hash: &[u8; 32],
    nonsecure_hash: &[u8; 32],
) -> [u8; ARM_TOKEN_PREIMAGE_LEN] {
    let mut out = [0u8; ARM_TOKEN_PREIMAGE_LEN];
    out[..7].copy_from_slice(ARM_DOMAIN);
    out[7] = slot;
    out[8..12].copy_from_slice(&release_version.to_be_bytes());
    out[12..16].copy_from_slice(&security_epoch.to_be_bytes());
    out[16..20].copy_from_slice(&floor_target.to_be_bytes());
    out[20..52].copy_from_slice(signed_manifest_digest);
    out[52..84].copy_from_slice(secure_hash);
    out[84..116].copy_from_slice(nonsecure_hash);
    out
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn normalized_crc(page: &[u8; MANIFEST_SIZE]) -> u32 {
    let mut crc = u32::MAX;
    for (offset, &stored) in page[..OFF_CRC32].iter().enumerate() {
        let byte = if (OFF_PENDING..OFF_TRAILING_RESERVED).contains(&offset) {
            0xFF
        } else {
            stored
        };
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn read_u32(page: &[u8; MANIFEST_SIZE], offset: usize) -> u32 {
    u32::from_be_bytes(page[offset..offset + 4].try_into().unwrap())
}

fn write_normalized_crc(page: &mut [u8; MANIFEST_SIZE]) {
    let crc = normalized_crc(page);
    page[OFF_CRC32..].copy_from_slice(&crc.to_be_bytes());
}

fn golden_page(journal: JournalFixture) -> [u8; MANIFEST_SIZE] {
    let mut page = [0xFF; MANIFEST_SIZE];
    page[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
    page[OFF_SCHEMA] = SCHEMA_V4;
    page[OFF_SLOT] = SLOT_B;
    page[OFF_HEADER_RESERVED..OFF_RELEASE_VERSION].fill(0);
    page[OFF_RELEASE_VERSION..OFF_SECURITY_EPOCH].copy_from_slice(&RELEASE_VERSION.to_be_bytes());
    page[OFF_SECURITY_EPOCH..OFF_SECURE_LEN].copy_from_slice(&SECURITY_EPOCH.to_be_bytes());
    page[OFF_SECURE_LEN..OFF_NONSECURE_LEN].copy_from_slice(&0x1000u32.to_be_bytes());
    page[OFF_NONSECURE_LEN..OFF_SECURE_HASH].copy_from_slice(&0x2000u32.to_be_bytes());
    page[OFF_SECURE_HASH..OFF_NONSECURE_HASH].copy_from_slice(&SECURE_HASH);
    page[OFF_NONSECURE_HASH..OFF_VENDOR_FPR].copy_from_slice(&NONSECURE_HASH);
    for (i, byte) in page[OFF_VENDOR_FPR..OFF_BUILD_ID].iter_mut().enumerate() {
        *byte = 0x40 + u8::try_from(i).unwrap();
    }
    for (i, byte) in page[OFF_BUILD_ID..OFF_MANIFEST_DIGEST]
        .iter_mut()
        .enumerate()
    {
        *byte = 0x60 + u8::try_from(i).unwrap();
    }
    page[OFF_MANIFEST_DIGEST..OFF_SIGNATURE].copy_from_slice(&MANIFEST_DIGEST);
    for (i, byte) in page[OFF_SIGNATURE..OFF_PENDING].iter_mut().enumerate() {
        *byte = u8::try_from(i % 256).unwrap();
    }
    match journal {
        JournalFixture::Erased => {}
        JournalFixture::Pending => {
            page[OFF_PENDING..OFF_CONFIRMED].copy_from_slice(&QW_PENDING);
        }
        JournalFixture::Confirmed => {
            page[OFF_PENDING..OFF_CONFIRMED].copy_from_slice(&QW_PENDING);
            page[OFF_CONFIRMED..OFF_TRAILING_RESERVED].copy_from_slice(&QW_CONFIRMED);
        }
    }
    write_normalized_crc(&mut page);
    page
}

/// Model only the frozen unsigned/structural, digest, and normalized-CRC
/// boundary.  This is deliberately not full `Verified` admission: it does
/// not validate the fixture's arbitrary C10 signature, re-hash either image,
/// or validate vectors/reset targets.  Production code must perform all of
/// those checks in addition to this modeled surface.
fn model_structural_digest_crc_admit(
    page: &[u8; MANIFEST_SIZE],
    containing_slot: u8,
    signing_domain: &[u8; 7],
    expected_vendor_fingerprint: &[u8; 32],
) -> Result<(), ModelError> {
    if signing_domain != DOMAIN_V4 {
        return Err(ModelError::Domain);
    }
    if page[OFF_MAGIC..OFF_SCHEMA] != MAGIC {
        return Err(ModelError::Magic);
    }
    if page[OFF_SCHEMA] != SCHEMA_V4 {
        return Err(ModelError::Schema);
    }
    if page[OFF_SLOT] != containing_slot || !matches!(containing_slot, SLOT_A | SLOT_B) {
        return Err(ModelError::Slot);
    }
    if page[OFF_HEADER_RESERVED..OFF_RELEASE_VERSION] != [0, 0]
        || page[OFF_TRAILING_RESERVED..OFF_CRC32]
            .iter()
            .any(|&byte| byte != 0xFF)
    {
        return Err(ModelError::Reserved);
    }
    let release_version = read_u32(page, OFF_RELEASE_VERSION);
    if !(1..=0xFFFF_FFFE).contains(&release_version) {
        return Err(ModelError::ReleaseVersion);
    }
    let security_epoch = read_u32(page, OFF_SECURITY_EPOCH);
    if !(1..=0xFFFF_FFFE).contains(&security_epoch) {
        return Err(ModelError::SecurityEpoch);
    }
    let secure_len = read_u32(page, OFF_SECURE_LEN);
    if !(MIN_IMAGE_LEN..=MAX_SECURE_IMAGE_LEN).contains(&secure_len) {
        return Err(ModelError::SecureLength);
    }
    let nonsecure_len = read_u32(page, OFF_NONSECURE_LEN);
    if !(MIN_IMAGE_LEN..=MAX_NONSECURE_IMAGE_LEN).contains(&nonsecure_len) {
        return Err(ModelError::NonsecureLength);
    }
    if page[OFF_VENDOR_FPR..OFF_BUILD_ID] != *expected_vendor_fingerprint {
        return Err(ModelError::VendorFingerprint);
    }
    let secure_hash = &page[OFF_SECURE_HASH..OFF_NONSECURE_HASH];
    let nonsecure_hash = &page[OFF_NONSECURE_HASH..OFF_VENDOR_FPR];
    let preimage = signed_preimage(
        signing_domain,
        containing_slot,
        release_version,
        security_epoch,
        secure_hash.try_into().unwrap(),
        nonsecure_hash.try_into().unwrap(),
    );
    if page[OFF_MANIFEST_DIGEST..OFF_SIGNATURE] != digest_preimage(&preimage) {
        return Err(ModelError::Digest);
    }
    if read_u32(page, OFF_CRC32) != normalized_crc(page) {
        return Err(ModelError::Crc);
    }
    Ok(())
}

fn hamming_bytes(left: &[u8], right: &[u8]) -> u32 {
    left.iter()
        .zip(right)
        .map(|(&a, &b)| (a ^ b).count_ones())
        .sum()
}

fn hamming_pair(left: (u32, u32), right: (u32, u32)) -> u32 {
    (left.0 ^ right.0).count_ones() + (left.1 ^ right.1).count_ones()
}

#[test]
fn exact_layout_constants_and_offsets_are_frozen() {
    assert_eq!(MANIFEST_SIZE, 8_192);
    assert_eq!(SIGNATURE_LEN, 4_008);
    assert_eq!(SIGNED_PREIMAGE_LEN, 80);
    assert_eq!(ARM_TOKEN_PREIMAGE_LEN, 116);
    assert_eq!(MAGIC, *b"PQSF");
    assert_eq!(SCHEMA_V4, 0x04);
    assert_eq!(DOMAIN_V4, b"PQFW_V4");
    assert_eq!(ARM_DOMAIN, b"PQFW_A1");
    assert_eq!(SLOT_A, 0);
    assert_eq!(SLOT_B, 1);
    assert_eq!(
        [
            OFF_MAGIC,
            OFF_SCHEMA,
            OFF_SLOT,
            OFF_HEADER_RESERVED,
            OFF_RELEASE_VERSION,
            OFF_SECURITY_EPOCH,
            OFF_SECURE_LEN,
            OFF_NONSECURE_LEN,
            OFF_SECURE_HASH,
            OFF_NONSECURE_HASH,
            OFF_VENDOR_FPR,
            OFF_BUILD_ID,
            OFF_MANIFEST_DIGEST,
            OFF_SIGNATURE,
            OFF_PENDING,
            OFF_CONFIRMED,
            OFF_TRAILING_RESERVED,
            OFF_CRC32,
        ],
        [0, 4, 5, 6, 8, 12, 16, 20, 24, 56, 88, 120, 152, 184, 4_192, 4_208, 4_224, 8_188]
    );
}

#[test]
fn frozen_v4_preimage_and_digest_match() {
    let expected_preimage: [u8; SIGNED_PREIMAGE_LEN] = [
        0x50, 0x51, 0x46, 0x57, 0x5F, 0x56, 0x34, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    ];
    let actual = signed_preimage(
        DOMAIN_V4,
        SLOT_B,
        RELEASE_VERSION,
        SECURITY_EPOCH,
        &SECURE_HASH,
        &NONSECURE_HASH,
    );
    assert_eq!(actual, expected_preimage);
    assert_eq!(digest_preimage(&actual), MANIFEST_DIGEST);
}

#[test]
fn normalized_crc_and_all_full_page_hashes_match() {
    assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    let fixtures = [
        (JournalFixture::Erased, PAGE_HASH_ERASED),
        (JournalFixture::Pending, PAGE_HASH_PENDING),
        (JournalFixture::Confirmed, PAGE_HASH_CONFIRMED),
    ];
    for (journal, expected_page_hash) in fixtures {
        let page = golden_page(journal);
        assert_eq!(normalized_crc(&page), 0x9936_15CD);
        assert_eq!(read_u32(&page, OFF_CRC32), 0x9936_15CD);
        assert_eq!(digest_preimage(&page), expected_page_hash);
        assert_eq!(
            model_structural_digest_crc_admit(&page, SLOT_B, DOMAIN_V4, &VENDOR_FINGERPRINT),
            Ok(())
        );
    }

    let mut body_mutation = golden_page(JournalFixture::Erased);
    body_mutation[OFF_SIGNATURE] ^= 1;
    assert_ne!(normalized_crc(&body_mutation), 0x9936_15CD);
    assert_eq!(
        model_structural_digest_crc_admit(&body_mutation, SLOT_B, DOMAIN_V4, &VENDOR_FINGERPRINT),
        Err(ModelError::Crc)
    );
}

#[test]
fn structural_model_pins_image_length_bounds_and_vendor_fingerprint() {
    for (offset, accepted, rejected, error) in [
        (
            OFF_SECURE_LEN,
            MAX_SECURE_IMAGE_LEN,
            MAX_SECURE_IMAGE_LEN + 1,
            ModelError::SecureLength,
        ),
        (
            OFF_NONSECURE_LEN,
            MAX_NONSECURE_IMAGE_LEN,
            MAX_NONSECURE_IMAGE_LEN + 1,
            ModelError::NonsecureLength,
        ),
    ] {
        for accepted_len in [MIN_IMAGE_LEN, accepted] {
            let mut page = golden_page(JournalFixture::Erased);
            page[offset..offset + 4].copy_from_slice(&accepted_len.to_be_bytes());
            write_normalized_crc(&mut page);
            assert_eq!(
                model_structural_digest_crc_admit(&page, SLOT_B, DOMAIN_V4, &VENDOR_FINGERPRINT),
                Ok(())
            );
        }
        for rejected_len in [0, MIN_IMAGE_LEN - 1, rejected] {
            let mut page = golden_page(JournalFixture::Erased);
            page[offset..offset + 4].copy_from_slice(&rejected_len.to_be_bytes());
            write_normalized_crc(&mut page);
            assert_eq!(
                model_structural_digest_crc_admit(&page, SLOT_B, DOMAIN_V4, &VENDOR_FINGERPRINT),
                Err(error)
            );
        }
    }

    let mut wrong_vendor = golden_page(JournalFixture::Erased);
    wrong_vendor[OFF_VENDOR_FPR] ^= 1;
    write_normalized_crc(&mut wrong_vendor);
    assert_eq!(
        model_structural_digest_crc_admit(&wrong_vendor, SLOT_B, DOMAIN_V4, &VENDOR_FINGERPRINT),
        Err(ModelError::VendorFingerprint)
    );
}

#[test]
fn structural_model_is_not_a_signature_or_image_verifier() {
    // The frozen fixture intentionally contains signature byte `i mod 256`,
    // not a real C10 signature, and no image bytes are supplied to this test.
    // Acceptance here means only that the modeled structural/digest/CRC
    // boundary passed; it must never be promoted to a `Verified` slot.
    let page = golden_page(JournalFixture::Erased);
    assert_eq!(
        model_structural_digest_crc_admit(&page, SLOT_B, DOMAIN_V4, &VENDOR_FINGERPRINT),
        Ok(())
    );
}

#[test]
fn marker_and_token_codewords_have_frozen_distance_and_complements() {
    for marker in [QW_PENDING, QW_CONFIRMED] {
        for i in 0..8 {
            assert_eq!(marker[i + 8], !marker[i]);
        }
        assert_eq!(hamming_bytes(&marker, &[0xFF; 16]), 64);
        assert_eq!(
            marker.iter().map(|byte| byte.count_zeros()).sum::<u32>(),
            64
        );
    }
    assert_eq!(hamming_bytes(&QW_PENDING, &QW_CONFIRMED), 68);

    let slots = [(0x3C3C_A5A5u32, 0xC3C3_5A5A), (0x9696_6969, 0x6969_9696)];
    for &(code, complement) in &slots {
        assert_eq!(complement, !code);
    }
    let states = [
        (0xA5A5_A5A5u32, 0x5A5A_5A5A),
        (0x3C3C_3C3C, 0xC3C3_C3C3),
        (0x9696_9696, 0x6969_6969),
    ];
    for &(state, complement) in &states {
        assert_eq!(complement, !state);
    }
    for i in 0..states.len() {
        for j in i + 1..states.len() {
            assert_eq!(hamming_pair(states[i], states[j]), 32);
        }
    }
    assert_eq!(!0x4152_4D31u32, 0xBEAD_B2CE);
    assert_eq!(!0x1357_9BDFu32, 0xECA8_6420);
    assert_eq!(!0x2468_ACE0u32, 0xDB97_531F);
    assert!(!states.contains(&(0, 0)));
}

#[test]
fn frozen_arm_token_preimage_and_binding_digest_match() {
    let expected_preimage: [u8; ARM_TOKEN_PREIMAGE_LEN] = [
        0x50, 0x51, 0x46, 0x57, 0x5F, 0x41, 0x31, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x05, 0x06, 0x07, 0x07, 0xB2, 0x64, 0x91, 0xE8, 0x6C, 0x8B, 0x97, 0xFE, 0x7E, 0x6B,
        0xC3, 0xB6, 0x7B, 0xE7, 0x3D, 0x1A, 0x69, 0x63, 0xEE, 0x42, 0x90, 0xC9, 0xFC, 0xAE, 0xF5,
        0xF2, 0xDA, 0xD0, 0x1F, 0x86, 0x46, 0x1F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    ];
    let actual = arm_token_preimage(
        SLOT_B,
        RELEASE_VERSION,
        SECURITY_EPOCH,
        FLOOR_TARGET,
        &MANIFEST_DIGEST,
        &SECURE_HASH,
        &NONSECURE_HASH,
    );
    assert_eq!(actual, expected_preimage);
    assert_eq!(digest_preimage(&actual), ARM_BINDING_DIGEST);
    let words: [u32; 8] = core::array::from_fn(|i| {
        u32::from_be_bytes(ARM_BINDING_DIGEST[i * 4..i * 4 + 4].try_into().unwrap())
    });
    assert_eq!(
        words,
        [
            0x1672_7042,
            0x3F35_F16B,
            0xCDEC_AD4E,
            0x9E19_817A,
            0xC87B_06BB,
            0x8838_483B,
            0xE8B9_7636,
            0x476C_7B7A,
        ]
    );
}

#[test]
fn slot_release_epoch_and_hash_mutations_break_both_bindings() {
    let manifest_base = signed_preimage(
        DOMAIN_V4,
        SLOT_B,
        RELEASE_VERSION,
        SECURITY_EPOCH,
        &SECURE_HASH,
        &NONSECURE_HASH,
    );
    let manifest_digest = digest_preimage(&manifest_base);
    let mut changed_secure = SECURE_HASH;
    changed_secure[0] ^= 1;
    let mut changed_nonsecure = NONSECURE_HASH;
    changed_nonsecure[31] ^= 1;
    for changed in [
        signed_preimage(
            DOMAIN_V4,
            SLOT_A,
            RELEASE_VERSION,
            SECURITY_EPOCH,
            &SECURE_HASH,
            &NONSECURE_HASH,
        ),
        signed_preimage(
            DOMAIN_V4,
            SLOT_B,
            RELEASE_VERSION + 1,
            SECURITY_EPOCH,
            &SECURE_HASH,
            &NONSECURE_HASH,
        ),
        signed_preimage(
            DOMAIN_V4,
            SLOT_B,
            RELEASE_VERSION,
            SECURITY_EPOCH + 1,
            &SECURE_HASH,
            &NONSECURE_HASH,
        ),
        signed_preimage(
            DOMAIN_V4,
            SLOT_B,
            RELEASE_VERSION,
            SECURITY_EPOCH,
            &changed_secure,
            &NONSECURE_HASH,
        ),
        signed_preimage(
            DOMAIN_V4,
            SLOT_B,
            RELEASE_VERSION,
            SECURITY_EPOCH,
            &SECURE_HASH,
            &changed_nonsecure,
        ),
    ] {
        assert_ne!(digest_preimage(&changed), manifest_digest);
    }

    let token_base = arm_token_preimage(
        SLOT_B,
        RELEASE_VERSION,
        SECURITY_EPOCH,
        FLOOR_TARGET,
        &MANIFEST_DIGEST,
        &SECURE_HASH,
        &NONSECURE_HASH,
    );
    let token_digest = digest_preimage(&token_base);
    let mut changed_manifest_digest = MANIFEST_DIGEST;
    changed_manifest_digest[15] ^= 1;
    for changed in [
        arm_token_preimage(
            SLOT_A,
            RELEASE_VERSION,
            SECURITY_EPOCH,
            FLOOR_TARGET,
            &MANIFEST_DIGEST,
            &SECURE_HASH,
            &NONSECURE_HASH,
        ),
        arm_token_preimage(
            SLOT_B,
            RELEASE_VERSION + 1,
            SECURITY_EPOCH,
            FLOOR_TARGET,
            &MANIFEST_DIGEST,
            &SECURE_HASH,
            &NONSECURE_HASH,
        ),
        arm_token_preimage(
            SLOT_B,
            RELEASE_VERSION,
            SECURITY_EPOCH + 1,
            FLOOR_TARGET,
            &MANIFEST_DIGEST,
            &SECURE_HASH,
            &NONSECURE_HASH,
        ),
        arm_token_preimage(
            SLOT_B,
            RELEASE_VERSION,
            SECURITY_EPOCH,
            FLOOR_TARGET - 1,
            &MANIFEST_DIGEST,
            &SECURE_HASH,
            &NONSECURE_HASH,
        ),
        arm_token_preimage(
            SLOT_B,
            RELEASE_VERSION,
            SECURITY_EPOCH,
            FLOOR_TARGET,
            &changed_manifest_digest,
            &SECURE_HASH,
            &NONSECURE_HASH,
        ),
        arm_token_preimage(
            SLOT_B,
            RELEASE_VERSION,
            SECURITY_EPOCH,
            FLOOR_TARGET,
            &MANIFEST_DIGEST,
            &changed_secure,
            &NONSECURE_HASH,
        ),
        arm_token_preimage(
            SLOT_B,
            RELEASE_VERSION,
            SECURITY_EPOCH,
            FLOOR_TARGET,
            &MANIFEST_DIGEST,
            &SECURE_HASH,
            &changed_nonsecure,
        ),
    ] {
        assert_ne!(digest_preimage(&changed), token_digest);
    }

    for offset in [
        OFF_SLOT,
        OFF_RELEASE_VERSION,
        OFF_SECURITY_EPOCH,
        OFF_SECURE_HASH,
        OFF_NONSECURE_HASH,
    ] {
        let mut page = golden_page(JournalFixture::Erased);
        page[offset] ^= 1;
        write_normalized_crc(&mut page);
        let containing_slot = page[OFF_SLOT];
        assert_eq!(
            model_structural_digest_crc_admit(
                &page,
                containing_slot,
                DOMAIN_V4,
                &VENDOR_FINGERPRINT
            ),
            Err(ModelError::Digest)
        );
    }
}

#[test]
fn legacy_schema_and_domain_are_rejected_without_translation() {
    let page = golden_page(JournalFixture::Erased);
    assert_eq!(
        model_structural_digest_crc_admit(&page, SLOT_B, DOMAIN_V4, &VENDOR_FINGERPRINT),
        Ok(())
    );
    assert_eq!(
        model_structural_digest_crc_admit(&page, SLOT_B, b"PQFW_V1", &VENDOR_FINGERPRINT),
        Err(ModelError::Domain)
    );

    for schema in [0x01, 0x02, 0x03] {
        let mut legacy_schema = page;
        legacy_schema[OFF_SCHEMA] = schema;
        write_normalized_crc(&mut legacy_schema);
        assert_eq!(
            model_structural_digest_crc_admit(
                &legacy_schema,
                SLOT_B,
                DOMAIN_V4,
                &VENDOR_FINGERPRINT
            ),
            Err(ModelError::Schema)
        );
    }
    assert_eq!(
        model_structural_digest_crc_admit(&page, SLOT_A, DOMAIN_V4, &VENDOR_FINGERPRINT),
        Err(ModelError::Slot)
    );
}

#[test]
fn independent_python_stdlib_reproduces_the_frozen_vectors() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/check_draft09_v4_vectors.py");
    let output = Command::new("python3")
        .arg(&script)
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", script.display()));
    assert!(
        output.status.success(),
        "independent Draft 0.9 vector oracle failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("oracle emits UTF-8 JSON");
    assert!(stdout.contains("b26491e86c8b97fe7e6bc3b67be73d1a6963ee4290c9fcaef5f2dad01f86461f"));
    assert!(stdout.contains("993615cd"));
}
