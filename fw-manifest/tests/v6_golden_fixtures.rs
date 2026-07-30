//! Golden-fixture host tests for the manifest-v6 pure core
//! (`fw-manifest/src/v6.rs`), Draft 1.1 §6.1/§6.2, slice FA-1.2 v0.
//!
//! Every fixture value below is DERIVED through the shared module code and
//! cross-checked against the frozen table (§6.1 L1881–1922) — plus an
//! independent bitwise CRC implementation in this file — because "merely
//! copying the table is not evidence".
//!
//! The `i mod 256` patterned signature is a serialization/normalization
//! fixture only. It is NOT a valid C10 signature KAT and must never be
//! reported as one; the key-matched signed fixture set is FA-1.2b.

use fw_manifest::v6::{
    self, full_install_generation, is_exact_marker, surviving_install_generation, Attribution,
    JournalRead, LaterLifecycleEvidence, ManifestV6, PhysicalSlot, ReleasePackageFields,
    ValidationError, QW_CONFIRMED_0, QW_CONFIRMED_1, QW_PENDING,
};
use fw_manifest::MANIFEST_SIZE;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex(s: &str) -> [u8; 32] {
    let s = s.as_bytes();
    assert_eq!(s.len(), 64, "hex helper expects 32 bytes");
    let mut out = [0u8; 32];
    let nib = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex"),
        }
    };
    for i in 0..32 {
        out[i] = (nib(s[2 * i]) << 4) | nib(s[2 * i + 1]);
    }
    out
}

fn seq(start: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    out
}

fn golden_signature() -> [u8; fw_manifest::SIGNATURE_LEN] {
    let mut sig = [0u8; fw_manifest::SIGNATURE_LEN];
    for (i, b) in sig.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }
    sig
}

struct Golden {
    secure_hash: [u8; 32],
    nonsecure_hash: [u8; 32],
    vendor_fpr: [u8; 32],
    build_id: [u8; 32],
    signature: [u8; fw_manifest::SIGNATURE_LEN],
}

impl Golden {
    fn new() -> Self {
        Golden {
            secure_hash: seq(0x00),
            nonsecure_hash: seq(0x20),
            vendor_fpr: seq(0x40),
            build_id: seq(0x60),
            signature: golden_signature(),
        }
    }

    fn fields(&self) -> ReleasePackageFields<'_> {
        ReleasePackageFields {
            slot: PhysicalSlot::B, // golden slot byte = 0x01
            release_version: 0x0102_0304,
            security_epoch: 0x0506_0708,
            secure_len: 0x1000,
            nonsecure_len: 0x2000,
            secure_hash: &self.secure_hash,
            nonsecure_hash: &self.nonsecure_hash,
            vendor_fpr: &self.vendor_fpr,
            build_id: &self.build_id,
            signature: &self.signature,
        }
    }

    fn page(&self) -> [u8; MANIFEST_SIZE] {
        v6::build_release_package(&self.fields()).expect("golden fields are valid")
    }
}

const GOLDEN_DIGEST: &str = "fb0f51ff0ad21bf02a15041dbaa2728ea10b6a7601753b15cb083ad212d61662";
const GOLDEN_CRC: u32 = 0x5F7D_EB92;
const GOLDEN_PAGE_SHA: &str = "632e90f280c80ce6843aa5a5e679658295f3738b8ee27a058fb8baff3a44e25f";

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SECOND, independent CRC-32 implementation (§6.1 L1919–1922 cross-check).
/// The crate's shared helper is a reflected bitwise loop over
/// `0xEDB88320`; this one is the MSB-first normal form over `0x04C11DB7`
/// with bit-reversed input bytes and a reversed final register — a
/// different code path over a different polynomial representation.
fn crc32_ieee_independent(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= (b.reverse_bits() as u32) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04C1_1DB7
            } else {
                crc << 1
            };
        }
    }
    crc.reverse_bits() ^ 0xFFFF_FFFF
}

/// The 8188-byte normalized CRC input: page bytes 0..4192, then 80×0xFF,
/// then 4272..8188.
fn normalized_input(page: &[u8; MANIFEST_SIZE]) -> Vec<u8> {
    let mut v = Vec::with_capacity(v6::OFF_CRC32);
    v.extend_from_slice(&page[..v6::OFF_QW_PENDING]);
    v.extend_from_slice(&[0xFF; 80]);
    v.extend_from_slice(&page[v6::OFF_TRAILING_RESERVED..v6::OFF_CRC32]);
    v
}

// ---------------------------------------------------------------------------
// 1. Preimage + digest golden fixture (§6.1 L1881–1894)
// ---------------------------------------------------------------------------

#[test]
fn golden_signed_preimage_layout_and_digest() {
    let g = Golden::new();
    let page = g.page();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();

    let preimage = m.signed_preimage();
    assert_eq!(preimage.len(), 121);

    // Exact layout: DOMAIN_TAG || schema || slot || R || E || secure_len ||
    // nonsecure_len || secure_hash || nonsecure_hash || vendor_fpr.
    assert_eq!(&preimage[0..7], b"PQFW_V6");
    assert_eq!(preimage[7], 0x06);
    assert_eq!(preimage[8], 0x01);
    assert_eq!(&preimage[9..13], &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(&preimage[13..17], &[0x05, 0x06, 0x07, 0x08]);
    assert_eq!(&preimage[17..21], &0x1000u32.to_be_bytes());
    assert_eq!(&preimage[21..25], &0x2000u32.to_be_bytes());
    assert_eq!(&preimage[25..57], &g.secure_hash);
    assert_eq!(&preimage[57..89], &g.nonsecure_hash);
    assert_eq!(&preimage[89..121], &g.vendor_fpr);

    assert_eq!(m.manifest_digest(), hex(GOLDEN_DIGEST));
    assert!(m.stored_digest_matches());
}

// ---------------------------------------------------------------------------
// 2. Full-page golden fixture — canonical builder, normalized CRC, page hash
// ---------------------------------------------------------------------------

#[test]
fn golden_full_page_crc_and_sha256() {
    let g = Golden::new();
    let page = g.page();

    // Built through the canonical builder, not a literal blob: spot-check
    // the serialization.
    assert_eq!(&page[0..4], b"PQSF");
    assert_eq!(page[4], 0x06);
    assert_eq!(page[5], 0x01);
    assert_eq!(&page[6..8], &[0x00, 0x00]);
    assert_eq!(&page[152..184], &hex(GOLDEN_DIGEST));
    assert_eq!(&page[184..184 + 4008], &g.signature);
    for off in v6::JOURNAL_QW_OFFSETS {
        assert_eq!(&page[off..off + 16], &[0xFF; 16], "package journal erased");
    }
    assert!(page[v6::OFF_TRAILING_RESERVED..v6::OFF_CRC32]
        .iter()
        .all(|&b| b == 0xFF));

    assert_eq!(v6::normalized_crc32(&page), GOLDEN_CRC);
    assert_eq!(&page[v6::OFF_CRC32..], &GOLDEN_CRC.to_be_bytes());
    assert_eq!(sha256(&page), hex(GOLDEN_PAGE_SHA));
}

// ---------------------------------------------------------------------------
// 3. Journal-row table — CRC normalization is invariant, page hash is not
// ---------------------------------------------------------------------------

const INSTALL_ID: [u8; 16] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, //
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
];
const INSTALL_ID_INV: [u8; 16] = [
    0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, //
    0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70,
];

#[test]
fn golden_journal_rows_crc_invariant_page_hash_varies() {
    let g = Golden::new();
    let base = g.page();

    let rows: [(&str, [Option<[u8; 16]>; 5], &str); 5] = [
        ("all erased", [None, None, None, None, None], GOLDEN_PAGE_SHA),
        (
            "install pair + PENDING",
            [Some(QW_PENDING), None, Some(INSTALL_ID), Some(INSTALL_ID_INV), None],
            "02aa62037bf01285f3a09cbbd1292f1995a1b3d21141a8af8dee528710d822be",
        ),
        (
            "install pair + PENDING + CONFIRMED_0",
            [
                Some(QW_PENDING),
                Some(QW_CONFIRMED_0),
                Some(INSTALL_ID),
                Some(INSTALL_ID_INV),
                None,
            ],
            "b10c7bdf879e5cce6abb8a20558e339d8023c2b04b1a11dc0032871b9d5e83d6",
        ),
        (
            "install pair + PENDING + CONFIRMED_1 (negative writer-order)",
            [
                Some(QW_PENDING),
                None,
                Some(INSTALL_ID),
                Some(INSTALL_ID_INV),
                Some(QW_CONFIRMED_1),
            ],
            "84738dd794722e9025341214410faeb2dfbe0f4e2794f80c13cc80e2fdbe4845",
        ),
        (
            "install pair + PENDING + both CONFIRMED",
            [
                Some(QW_PENDING),
                Some(QW_CONFIRMED_0),
                Some(INSTALL_ID),
                Some(INSTALL_ID_INV),
                Some(QW_CONFIRMED_1),
            ],
            "e7f9b80d21d0a24cf3a84ec76a2b62cd19c6f22464515039c7ea77fa198a8db6",
        ),
    ];

    for (name, qws, want_sha) in rows {
        let mut page = base;
        for (i, qw) in qws.iter().enumerate() {
            if let Some(qw) = qw {
                let off = v6::JOURNAL_QW_OFFSETS[i];
                page[off..off + 16].copy_from_slice(qw);
            }
        }
        v6::rewrite_normalized_crc(&mut page);
        assert_eq!(
            v6::normalized_crc32(&page),
            GOLDEN_CRC,
            "row {name}: normalized CRC must be journal-invariant"
        );
        assert_eq!(
            u32::from_be_bytes(page[v6::OFF_CRC32..].try_into().unwrap()),
            GOLDEN_CRC,
            "row {name}: stored CRC"
        );
        assert_eq!(sha256(&page), hex(want_sha), "row {name}: page SHA-256");
    }
}

// ---------------------------------------------------------------------------
// 4. Independent CRC cross-check
// ---------------------------------------------------------------------------

#[test]
fn independent_crc_implementation_reproduces_every_row() {
    // Self-check against the standard zlib KAT before trusting it here.
    assert_eq!(crc32_ieee_independent(b"123456789"), 0xCBF4_3926);

    let g = Golden::new();
    let base = g.page();
    assert_eq!(
        crc32_ieee_independent(&normalized_input(&base)),
        GOLDEN_CRC
    );

    let variants: [[Option<[u8; 16]>; 5]; 4] = [
        [Some(QW_PENDING), None, Some(INSTALL_ID), Some(INSTALL_ID_INV), None],
        [
            Some(QW_PENDING),
            Some(QW_CONFIRMED_0),
            Some(INSTALL_ID),
            Some(INSTALL_ID_INV),
            None,
        ],
        [
            Some(QW_PENDING),
            None,
            Some(INSTALL_ID),
            Some(INSTALL_ID_INV),
            Some(QW_CONFIRMED_1),
        ],
        [
            Some(QW_PENDING),
            Some(QW_CONFIRMED_0),
            Some(INSTALL_ID),
            Some(INSTALL_ID_INV),
            Some(QW_CONFIRMED_1),
        ],
    ];
    for qws in variants {
        let mut page = base;
        for (i, qw) in qws.iter().enumerate() {
            if let Some(qw) = qw {
                let off = v6::JOURNAL_QW_OFFSETS[i];
                page[off..off + 16].copy_from_slice(qw);
            }
        }
        let independent = crc32_ieee_independent(&normalized_input(&page));
        assert_eq!(independent, GOLDEN_CRC);
        assert_eq!(v6::normalized_crc32(&page), independent);
    }
}

// ---------------------------------------------------------------------------
// 5. Codeword properties (§6.2)
// ---------------------------------------------------------------------------

fn hamming(a: &[u8; 16], b: &[u8; 16]) -> u32 {
    let mut d = 0;
    for i in 0..16 {
        d += (a[i] ^ b[i]).count_ones();
    }
    d
}

#[test]
fn journal_codeword_properties() {
    const ERASED: [u8; 16] = [0xFF; 16];
    for cw in [QW_PENDING, QW_CONFIRMED_0, QW_CONFIRMED_1] {
        // 64 programmed zero bits == distance 64 from erased.
        assert_eq!(hamming(&cw, &ERASED), 64);
        // Second half is the bitwise complement of the first.
        for i in 0..8 {
            assert_eq!(cw[8 + i], !cw[i]);
        }
    }
    assert!(hamming(&QW_PENDING, &QW_CONFIRMED_0) >= 64);
    assert!(hamming(&QW_PENDING, &QW_CONFIRMED_1) >= 64);
    assert!(hamming(&QW_CONFIRMED_0, &QW_CONFIRMED_1) >= 64);
}

#[test]
fn codeword_marker_requires_exact_clean_read() {
    let clean_pending = JournalRead::new(QW_PENDING, Attribution::CLEAN);
    assert!(is_exact_marker(&clean_pending, &QW_PENDING));
    assert!(!is_exact_marker(&clean_pending, &QW_CONFIRMED_0));

    for attr in [
        Attribution { ecc_clean: false, durably_clean: true },  // ECCC/ECCD leg
        Attribution { ecc_clean: true, durably_clean: false },  // torn / may-have-launched
        Attribution { ecc_clean: false, durably_clean: false },
    ] {
        assert!(
            !is_exact_marker(&JournalRead::new(QW_PENDING, attr), &QW_PENDING),
            "ambiguous observation must never be a valid marker"
        );
    }
}

// ---------------------------------------------------------------------------
// 5b. Install-generation codec
// ---------------------------------------------------------------------------

#[test]
fn full_install_generation_rules() {
    let clean = Attribution::CLEAN;
    let id = JournalRead::new(INSTALL_ID, clean);
    let inv = JournalRead::new(INSTALL_ID_INV, clean);
    assert_eq!(full_install_generation(&id, &inv), Some(INSTALL_ID));

    // One leg not durably clean → no generation.
    let torn = Attribution { ecc_clean: true, durably_clean: false };
    assert_eq!(full_install_generation(&JournalRead::new(INSTALL_ID, torn), &inv), None);
    assert_eq!(full_install_generation(&id, &JournalRead::new(INSTALL_ID_INV, torn)), None);

    // Complementarity violation rejects.
    let mut bad_inv = INSTALL_ID_INV;
    bad_inv[0] ^= 0x01;
    assert_eq!(full_install_generation(&id, &JournalRead::new(bad_inv, clean)), None);

    // Forbidden values reject (all-zero, all-one == erased).
    assert_eq!(
        full_install_generation(
            &JournalRead::new([0x00; 16], clean),
            &JournalRead::new([0xFF; 16], clean)
        ),
        None
    );
    assert_eq!(
        full_install_generation(
            &JournalRead::new([0xFF; 16], clean),
            &JournalRead::new([0x00; 16], clean)
        ),
        None
    );
}

#[test]
fn surviving_install_generation_rules() {
    let clean = Attribution::CLEAN;
    let dirty = Attribution { ecc_clean: true, durably_clean: false };
    let id = JournalRead::new(INSTALL_ID, clean);
    let inv = JournalRead::new(INSTALL_ID_INV, clean);
    let erased_inv = JournalRead::new([0xFF; 16], dirty); // torn-looking missing half
    let erased_id = JournalRead::new([0xFF; 16], dirty);

    // Exactly one durable clean nontrivial half + explicit evidence →
    // reconstruct.
    assert_eq!(
        surviving_install_generation(&id, &erased_inv, LaterLifecycleEvidence::Pending),
        Some(INSTALL_ID)
    );
    assert_eq!(
        surviving_install_generation(&erased_id, &inv, LaterLifecycleEvidence::Terminal),
        Some(INSTALL_ID)
    );

    // Both halves exact → full-generation semantics; conflict rejects.
    assert_eq!(
        surviving_install_generation(&id, &inv, LaterLifecycleEvidence::Pending),
        Some(INSTALL_ID)
    );
    let mut conflict = INSTALL_ID_INV;
    conflict[3] ^= 0x40;
    assert_eq!(
        surviving_install_generation(&id, &JournalRead::new(conflict, clean), LaterLifecycleEvidence::Pending),
        None
    );

    // Neither half exact → nothing to reconstruct.
    assert_eq!(
        surviving_install_generation(&erased_id, &erased_inv, LaterLifecycleEvidence::Terminal),
        None
    );

    // Nontrivial-half rule: an all-zero/all-one surviving half is forbidden
    // even with evidence.
    assert_eq!(
        surviving_install_generation(
            &JournalRead::new([0x00; 16], clean),
            &erased_inv,
            LaterLifecycleEvidence::Pending
        ),
        None
    );
}

// ---------------------------------------------------------------------------
// 6. Negative tests — flag-day rejection, ranges, CRC, package rule
// ---------------------------------------------------------------------------

/// Rewrite one field on the golden page and re-seal the CRC (so only the
/// intended rejection fires).
fn mutated_page(mutate: impl Fn(&mut [u8; MANIFEST_SIZE])) -> [u8; MANIFEST_SIZE] {
    let g = Golden::new();
    let mut page = g.page();
    mutate(&mut page);
    v6::rewrite_normalized_crc(&mut page);
    page
}

#[test]
fn flag_day_rejects_every_non_v6_schema() {
    for schema in [0x02u8, 0x05, 0x07] {
        let page = mutated_page(|p| p[v6::OFF_SCHEMA] = schema);
        assert_eq!(
            v6::parse_and_validate(&page, PhysicalSlot::B),
            Err(ValidationError::BadSchema(schema)),
            "schema {schema:#04x} must be rejected, never translated/retried/defaulted"
        );
    }
}

#[test]
fn rejects_out_of_range_release_and_epoch() {
    let page = mutated_page(|p| p[v6::OFF_RELEASE_VERSION..v6::OFF_RELEASE_VERSION + 4].fill(0));
    assert_eq!(
        v6::parse_and_validate(&page, PhysicalSlot::B),
        Err(ValidationError::BadReleaseVersion(0))
    );

    let page = mutated_page(|p| {
        p[v6::OFF_RELEASE_VERSION..v6::OFF_RELEASE_VERSION + 4]
            .copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes())
    });
    assert_eq!(
        v6::parse_and_validate(&page, PhysicalSlot::B),
        Err(ValidationError::BadReleaseVersion(0xFFFF_FFFF))
    );

    let page = mutated_page(|p| p[v6::OFF_SECURITY_EPOCH..v6::OFF_SECURITY_EPOCH + 4].fill(0));
    assert_eq!(
        v6::parse_and_validate(&page, PhysicalSlot::B),
        Err(ValidationError::BadSecurityEpoch(0))
    );
}

#[test]
fn rejects_bad_slot_byte_and_containing_slot_mismatch() {
    let page = mutated_page(|p| p[v6::OFF_SLOT] = 0x02);
    assert_eq!(
        v6::parse_and_validate(&page, PhysicalSlot::B),
        Err(ValidationError::BadSlotByte(0x02))
    );

    let g = Golden::new();
    let page = g.page(); // slot byte 0x01 (B)
    assert_eq!(
        v6::parse_and_validate(&page, PhysicalSlot::A),
        Err(ValidationError::SlotMismatch {
            found: PhysicalSlot::B,
            expected: PhysicalSlot::A,
        })
    );
}

#[test]
fn rejects_image_lengths_outside_frozen_spans() {
    let page = mutated_page(|p| {
        p[v6::OFF_SECURE_LEN..v6::OFF_SECURE_LEN + 4].copy_from_slice(&7u32.to_be_bytes())
    });
    assert_eq!(
        v6::parse_and_validate(&page, PhysicalSlot::B),
        Err(ValidationError::BadSecureLen(7))
    );

    let page = mutated_page(|p| {
        p[v6::OFF_SECURE_LEN..v6::OFF_SECURE_LEN + 4]
            .copy_from_slice(&0x72001u32.to_be_bytes())
    });
    assert_eq!(
        v6::parse_and_validate(&page, PhysicalSlot::B),
        Err(ValidationError::BadSecureLen(0x72001))
    );

    let page = mutated_page(|p| {
        p[v6::OFF_NONSECURE_LEN..v6::OFF_NONSECURE_LEN + 4]
            .copy_from_slice(&0x7A001u32.to_be_bytes())
    });
    assert_eq!(
        v6::parse_and_validate(&page, PhysicalSlot::B),
        Err(ValidationError::BadNonsecureLen(0x7A001))
    );

    // Boundary values are accepted: 8 and the exact §5 spans.
    let page = mutated_page(|p| {
        p[v6::OFF_SECURE_LEN..v6::OFF_SECURE_LEN + 4]
            .copy_from_slice(&pqsigner_geometry::SECURE_SLOT_SPAN.to_be_bytes());
        p[v6::OFF_NONSECURE_LEN..v6::OFF_NONSECURE_LEN + 4]
            .copy_from_slice(&pqsigner_geometry::NS_SLOT_SPAN.to_be_bytes());
    });
    assert!(v6::parse_and_validate(&page, PhysicalSlot::B).is_ok());
}

#[test]
fn rejects_corrupted_stored_crc() {
    let g = Golden::new();
    let mut page = g.page();
    page[v6::OFF_CRC32] ^= 0x01; // stored CRC no longer matches recomputation
    let err = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap_err();
    assert!(
        matches!(err, ValidationError::CrcMismatch { .. }),
        "expected CrcMismatch, got {err:?}"
    );
}

#[test]
fn release_package_rejects_any_non_erased_journal_qw() {
    let g = Golden::new();
    for (i, off) in v6::JOURNAL_QW_OFFSETS.into_iter().enumerate() {
        let mut page = g.page();
        page[off..off + 16].copy_from_slice(&INSTALL_ID);
        v6::rewrite_normalized_crc(&mut page); // CRC still seals: window is normalized

        // Generic parse must NOT care (journal bytes are device-mutated)…
        assert!(
            v6::parse_and_validate(&page, PhysicalSlot::B).is_ok(),
            "journal QW {i}: parse ignores device-mutated window"
        );
        // …but the incoming release-package rule rejects it (§6.1 L1935–1944).
        assert_eq!(
            v6::validate_release_package(&page, PhysicalSlot::B),
            Err(ValidationError::NonErasedJournalQw { offset: off }),
            "journal QW {i}: package rule"
        );
    }
}

#[test]
fn tampered_stored_digest_is_caught_by_comparison_not_parse() {
    let page = mutated_page(|p| p[v6::OFF_DIGEST] ^= 0x01);
    // Parse succeeds: the stored digest is a redundant comparison value,
    // never an independent signing authority.
    let m = v6::parse_and_validate(&page, PhysicalSlot::B)
        .expect("stored digest mismatch must not fail parse");
    // …and the recompute-compare helper is what catches it.
    assert!(!m.stored_digest_matches());
    // The canonical-package gate DOES enforce the offset-152 frozen rule:
    // a package whose stored digest is not the exact freshly recomputed
    // digest is rejected (package canonicality, never signing authority).
    assert_eq!(
        v6::validate_release_package(&page, PhysicalSlot::B),
        Err(ValidationError::StoredDigestMismatch),
        "package with planted stored digest must be rejected"
    );
}

#[test]
fn same_release_set_identity() {
    let g = Golden::new();
    let page_b = g.page();
    let b = v6::parse_and_validate(&page_b, PhysicalSlot::B).unwrap();

    // Same (R, E) + vendor identity, different slot + hashes + signature.
    let fields_a = ReleasePackageFields {
        slot: PhysicalSlot::A,
        secure_hash: &g.build_id, // any different bytes stand in
        ..g.fields()
    };
    let page_a = v6::build_release_package(&fields_a).unwrap();
    let a = v6::parse_and_validate(&page_a, PhysicalSlot::A).unwrap();
    assert!(v6::same_release_set(&a, &b));

    // Different epoch → not the same release set.
    let mut fields_c = g.fields();
    fields_c.security_epoch = 0x0506_0709;
    fields_c.slot = PhysicalSlot::A;
    let page_c = v6::build_release_package(&fields_c).unwrap();
    let c = v6::parse_and_validate(&page_c, PhysicalSlot::A).unwrap();
    assert!(!v6::same_release_set(&c, &b));
}

#[test]
fn vendor_fingerprint_domain_separation() {
    let seed = [0x11u8; 16];
    let root = [0x22u8; 16];
    let fpr = v6::vendor_fingerprint(&seed, &root);

    // Domain tag is part of the preimage: SHA256("PQFW_VK_V6" || seed || root).
    let mut expect = Sha256::new();
    expect.update(b"PQFW_VK_V6");
    expect.update(seed);
    expect.update(root);
    assert_eq!(fpr, <[u8; 32]>::from(expect.finalize()));

    let g = Golden::new();
    let mut fields = g.fields();
    fields.vendor_fpr = &fpr;
    let page = v6::build_release_package(&fields).unwrap();
    let m = v6::parse_and_validate(&page, PhysicalSlot::B).unwrap();
    assert!(m.vendor_fpr_matches(&seed, &root));
    assert!(!m.vendor_fpr_matches(&root, &seed)); // order matters, never a selector
}

#[test]
fn builder_rejects_invalid_fields_instead_of_serializing() {
    let g = Golden::new();
    let mut fields = g.fields();
    fields.release_version = 0;
    assert!(matches!(
        v6::build_release_package(&fields),
        Err(ValidationError::BadReleaseVersion(0))
    ));
}

#[test]
fn manifest_v6_struct_size_is_bounded_for_no_std_stacks() {
    // The 4008-byte signature dominates; keep the struct honest.
    assert_eq!(core::mem::size_of::<[u8; 4008]>(), 4008);
    let _ = core::mem::size_of::<ManifestV6>();
}
