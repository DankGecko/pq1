//! Canonical authenticated release receipt for an ERC-7730 catalogue.
//!
//! The receipt is embedded in the secure firmware image.  The firmware image
//! hash is authenticated by the existing update manifest, so companion tools
//! can bind a P730 catalogue and its lookup accelerator to one exact signed
//! release without adding another signature scheme or a mutable device query.
//!
//! All integers are big-endian.  Version 1 is exactly 256 bytes:
//!
//! ```text
//!   0..4     magic = "P73S"
//!   4..6     status schema = 1
//!   6..8     total length = 256
//!   8..12    P730 catalogue format version
//!   12       ERC-7730 IR schema version
//!   13       provenance (0 = dev-unattested, 1 = ERC-8176-verified)
//!   14..16   reserved = 0
//!   16..20   descriptor leaf count
//!   20..24   catalogue blob size
//!   24..28   exact known-call tuple count
//!   28..32   known-call Bloom size
//!   32..224  six SHA-256 receipts (see [`CatalogueStatusV1`])
//!   224..256 printable-ASCII tool version followed by canonical NUL padding
//! ```

use core::convert::TryFrom;

/// Magic prefix for the catalogue-status receipt.
pub const CATALOGUE_STATUS_MAGIC: [u8; 4] = *b"P73S";
/// First catalogue-status receipt schema.
pub const CATALOGUE_STATUS_SCHEMA_V1: u16 = 1;
/// Exact encoded length of a version-1 receipt.
pub const CATALOGUE_STATUS_V1_LEN: usize = 256;
/// Width of the canonical NUL-padded tool-version field.
pub const CATALOGUE_STATUS_TOOL_VERSION_LEN: usize = 32;
/// Maximum printable tool-version length, leaving one required NUL byte.
pub const CATALOGUE_STATUS_TOOL_VERSION_MAX_LEN: usize = CATALOGUE_STATUS_TOOL_VERSION_LEN - 1;

const HASH_LEN: usize = 32;
const DESCRIPTOR_ROOT_OFFSET: usize = 32;
const CATALOGUE_SHA256_OFFSET: usize = DESCRIPTOR_ROOT_OFFSET + HASH_LEN;
const KNOWN_CALL_SET_SHA256_OFFSET: usize = CATALOGUE_SHA256_OFFSET + HASH_LEN;
const BLOOM_SHA256_OFFSET: usize = KNOWN_CALL_SET_SHA256_OFFSET + HASH_LEN;
const POLICY_SHA256_OFFSET: usize = BLOOM_SHA256_OFFSET + HASH_LEN;
const CURATION_INPUT_SHA256_OFFSET: usize = POLICY_SHA256_OFFSET + HASH_LEN;
const TOOL_VERSION_OFFSET: usize = CURATION_INPUT_SHA256_OFFSET + HASH_LEN;

/// Provenance class of every descriptor admitted to the catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CatalogueProvenance {
    /// Development catalogue whose ERC-8176 provenance was not verified.
    DevUnattested = 0,
    /// Every admitted descriptor passed the release's ERC-8176 policy.
    Erc8176Verified = 1,
}

impl TryFrom<u8> for CatalogueProvenance {
    type Error = CatalogueStatusError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::DevUnattested),
            1 => Ok(Self::Erc8176Verified),
            _ => Err(CatalogueStatusError::Provenance),
        }
    }
}

/// Structural or canonical-encoding failure in a catalogue-status receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogueStatusError {
    /// The supplied slice is not exactly [`CATALOGUE_STATUS_V1_LEN`] bytes.
    Length,
    /// The `P73S` magic is absent.
    Magic,
    /// The status schema is not version 1.
    StatusSchema,
    /// The encoded total-length field is not 256.
    EncodedLength,
    /// A reserved byte is non-zero.
    Reserved,
    /// The provenance discriminator is unknown.
    Provenance,
    /// A caller tried to encode more than 31 tool-version bytes.
    ToolVersionTooLong,
    /// The tool version is not printable ASCII plus one all-zero suffix.
    ToolVersionEncoding,
}

/// Parsed version-1 catalogue identity embedded in an authenticated release.
///
/// The wire-level schema, length, reserved bytes, provenance discriminator,
/// and tool-version encoding are validated by [`Self::from_bytes`] and fixed
/// by [`Self::new`].  Catalogue and IR version compatibility is deliberately a
/// companion-policy decision, so those identity fields are preserved rather
/// than interpreted here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogueStatusV1 {
    /// P730 catalogue container format version.
    pub catalogue_format_version: u32,
    /// Compiled ERC-7730 IR schema version.
    pub ir_schema_version: u8,
    /// Descriptor provenance class admitted to this exact catalogue.
    pub provenance: CatalogueProvenance,
    /// Number of real descriptor leaves (before Merkle padding).
    pub leaf_count: u32,
    /// Exact P730 catalogue blob size in bytes.
    pub catalogue_blob_size: u32,
    /// Number of exact `(chain, contract, selector)` known-call tuples.
    pub known_call_count: u32,
    /// Exact known-call Bloom-filter size in bytes.
    pub bloom_size: u32,
    /// Merkle root of the ordered descriptor IR leaves.
    pub descriptor_root: [u8; HASH_LEN],
    /// SHA-256 of the exact P730 catalogue blob.
    pub catalogue_sha256: [u8; HASH_LEN],
    /// SHA-256 identity of the exact canonical known-call tuple set.
    pub known_call_set_sha256: [u8; HASH_LEN],
    /// SHA-256 of the exact known-call Bloom-filter bytes.
    pub bloom_sha256: [u8; HASH_LEN],
    /// SHA-256 of the catalogue-admission policy input.
    pub policy_sha256: [u8; HASH_LEN],
    /// SHA-256 of the canonical curation/input receipt.
    pub curation_input_sha256: [u8; HASH_LEN],
    tool_version: [u8; CATALOGUE_STATUS_TOOL_VERSION_LEN],
    tool_version_len: u8,
}

impl CatalogueStatusV1 {
    /// Construct a canonical receipt, refusing an unrepresentable tool name.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        catalogue_format_version: u32,
        ir_schema_version: u8,
        provenance: CatalogueProvenance,
        leaf_count: u32,
        catalogue_blob_size: u32,
        known_call_count: u32,
        bloom_size: u32,
        descriptor_root: [u8; HASH_LEN],
        catalogue_sha256: [u8; HASH_LEN],
        known_call_set_sha256: [u8; HASH_LEN],
        bloom_sha256: [u8; HASH_LEN],
        policy_sha256: [u8; HASH_LEN],
        curation_input_sha256: [u8; HASH_LEN],
        tool_version: &[u8],
    ) -> Result<Self, CatalogueStatusError> {
        let (tool_version, tool_version_len) = encode_tool_version(tool_version)?;
        Ok(Self {
            catalogue_format_version,
            ir_schema_version,
            provenance,
            leaf_count,
            catalogue_blob_size,
            known_call_count,
            bloom_size,
            descriptor_root,
            catalogue_sha256,
            known_call_set_sha256,
            bloom_sha256,
            policy_sha256,
            curation_input_sha256,
            tool_version,
            tool_version_len,
        })
    }

    /// Parse and strictly validate one exact version-1 receipt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CatalogueStatusError> {
        if bytes.len() != CATALOGUE_STATUS_V1_LEN {
            return Err(CatalogueStatusError::Length);
        }
        if bytes[..4] != CATALOGUE_STATUS_MAGIC {
            return Err(CatalogueStatusError::Magic);
        }
        if read_u16(bytes, 4) != CATALOGUE_STATUS_SCHEMA_V1 {
            return Err(CatalogueStatusError::StatusSchema);
        }
        if usize::from(read_u16(bytes, 6)) != CATALOGUE_STATUS_V1_LEN {
            return Err(CatalogueStatusError::EncodedLength);
        }
        if bytes[14] != 0 || bytes[15] != 0 {
            return Err(CatalogueStatusError::Reserved);
        }

        let provenance = CatalogueProvenance::try_from(bytes[13])?;
        let mut tool_version = [0u8; CATALOGUE_STATUS_TOOL_VERSION_LEN];
        tool_version.copy_from_slice(&bytes[TOOL_VERSION_OFFSET..CATALOGUE_STATUS_V1_LEN]);
        let tool_version_len = validate_tool_version(&tool_version)?;

        Ok(Self {
            catalogue_format_version: read_u32(bytes, 8),
            ir_schema_version: bytes[12],
            provenance,
            leaf_count: read_u32(bytes, 16),
            catalogue_blob_size: read_u32(bytes, 20),
            known_call_count: read_u32(bytes, 24),
            bloom_size: read_u32(bytes, 28),
            descriptor_root: read_hash(bytes, DESCRIPTOR_ROOT_OFFSET),
            catalogue_sha256: read_hash(bytes, CATALOGUE_SHA256_OFFSET),
            known_call_set_sha256: read_hash(bytes, KNOWN_CALL_SET_SHA256_OFFSET),
            bloom_sha256: read_hash(bytes, BLOOM_SHA256_OFFSET),
            policy_sha256: read_hash(bytes, POLICY_SHA256_OFFSET),
            curation_input_sha256: read_hash(bytes, CURATION_INPUT_SHA256_OFFSET),
            tool_version,
            tool_version_len,
        })
    }

    /// Encode the unique canonical 256-byte representation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CATALOGUE_STATUS_V1_LEN] {
        let mut bytes = [0u8; CATALOGUE_STATUS_V1_LEN];
        bytes[..4].copy_from_slice(&CATALOGUE_STATUS_MAGIC);
        bytes[4..6].copy_from_slice(&CATALOGUE_STATUS_SCHEMA_V1.to_be_bytes());
        bytes[6..8].copy_from_slice(&(CATALOGUE_STATUS_V1_LEN as u16).to_be_bytes());
        bytes[8..12].copy_from_slice(&self.catalogue_format_version.to_be_bytes());
        bytes[12] = self.ir_schema_version;
        bytes[13] = self.provenance as u8;
        bytes[16..20].copy_from_slice(&self.leaf_count.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.catalogue_blob_size.to_be_bytes());
        bytes[24..28].copy_from_slice(&self.known_call_count.to_be_bytes());
        bytes[28..32].copy_from_slice(&self.bloom_size.to_be_bytes());
        bytes[DESCRIPTOR_ROOT_OFFSET..CATALOGUE_SHA256_OFFSET]
            .copy_from_slice(&self.descriptor_root);
        bytes[CATALOGUE_SHA256_OFFSET..KNOWN_CALL_SET_SHA256_OFFSET]
            .copy_from_slice(&self.catalogue_sha256);
        bytes[KNOWN_CALL_SET_SHA256_OFFSET..BLOOM_SHA256_OFFSET]
            .copy_from_slice(&self.known_call_set_sha256);
        bytes[BLOOM_SHA256_OFFSET..POLICY_SHA256_OFFSET].copy_from_slice(&self.bloom_sha256);
        bytes[POLICY_SHA256_OFFSET..CURATION_INPUT_SHA256_OFFSET]
            .copy_from_slice(&self.policy_sha256);
        bytes[CURATION_INPUT_SHA256_OFFSET..TOOL_VERSION_OFFSET]
            .copy_from_slice(&self.curation_input_sha256);
        bytes[TOOL_VERSION_OFFSET..].copy_from_slice(&self.tool_version);
        bytes
    }

    /// Printable tool-version bytes without the canonical NUL padding.
    #[must_use]
    pub fn tool_version(&self) -> &[u8] {
        &self.tool_version[..usize::from(self.tool_version_len)]
    }
}

fn encode_tool_version(
    tool_version: &[u8],
) -> Result<([u8; CATALOGUE_STATUS_TOOL_VERSION_LEN], u8), CatalogueStatusError> {
    if tool_version.len() > CATALOGUE_STATUS_TOOL_VERSION_MAX_LEN {
        return Err(CatalogueStatusError::ToolVersionTooLong);
    }
    if tool_version.is_empty() || !tool_version.iter().all(|byte| (0x20..0x7f).contains(byte)) {
        return Err(CatalogueStatusError::ToolVersionEncoding);
    }
    let mut encoded = [0u8; CATALOGUE_STATUS_TOOL_VERSION_LEN];
    encoded[..tool_version.len()].copy_from_slice(tool_version);
    Ok((encoded, tool_version.len() as u8))
}

fn validate_tool_version(
    encoded: &[u8; CATALOGUE_STATUS_TOOL_VERSION_LEN],
) -> Result<u8, CatalogueStatusError> {
    let Some(end) = encoded.iter().position(|byte| *byte == 0) else {
        return Err(CatalogueStatusError::ToolVersionEncoding);
    };
    if end == 0
        || !encoded[..end]
            .iter()
            .all(|byte| (0x20..0x7f).contains(byte))
        || encoded[end..].iter().any(|byte| *byte != 0)
    {
        return Err(CatalogueStatusError::ToolVersionEncoding);
    }
    Ok(end as u8)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_hash(bytes: &[u8], offset: usize) -> [u8; HASH_LEN] {
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(&bytes[offset..offset + HASH_LEN]);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_HEX: &str = concat!(
        "5037335300010100000000010601000001020304112233445566778899aabbcc",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "5555555555555555555555555555555555555555555555555555555555555555",
        "6666666666666666666666666666666666666666666666666666666666666666",
        "646267656e2f302e312e30000000000000000000000000000000000000000000",
    );

    fn golden_status() -> CatalogueStatusV1 {
        CatalogueStatusV1::new(
            1,
            6,
            CatalogueProvenance::Erc8176Verified,
            0x0102_0304,
            0x1122_3344,
            0x5566_7788,
            0x99aa_bbcc,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            b"dbgen/0.1.0",
        )
        .expect("golden status must be representable")
    }

    fn golden_bytes() -> [u8; CATALOGUE_STATUS_V1_LEN] {
        let decoded = hex::decode(GOLDEN_HEX).expect("valid golden hex");
        decoded.try_into().expect("golden is exactly 256 bytes")
    }

    #[test]
    fn golden_encoding_and_round_trip() {
        let status = golden_status();
        let golden = golden_bytes();
        assert_eq!(status.to_bytes(), golden);

        let parsed = CatalogueStatusV1::from_bytes(&golden).expect("golden status parses");
        assert_eq!(parsed, status);
        assert_eq!(parsed.tool_version(), b"dbgen/0.1.0");
        assert_eq!(parsed.to_bytes(), golden);
    }

    #[test]
    fn malformed_fixed_fields_fail_closed() {
        let golden = golden_bytes();
        assert_eq!(
            CatalogueStatusV1::from_bytes(&golden[..255]),
            Err(CatalogueStatusError::Length)
        );

        let cases = [
            (0usize, 0u8, CatalogueStatusError::Magic),
            (5, 2, CatalogueStatusError::StatusSchema),
            (7, 0xff, CatalogueStatusError::EncodedLength),
            (14, 1, CatalogueStatusError::Reserved),
            (13, 2, CatalogueStatusError::Provenance),
        ];
        for (offset, value, expected) in cases {
            let mut bytes = golden;
            bytes[offset] = value;
            assert_eq!(CatalogueStatusV1::from_bytes(&bytes), Err(expected));
        }
    }

    #[test]
    fn malformed_tool_versions_fail_closed() {
        let golden = golden_bytes();

        let mut control = golden;
        control[TOOL_VERSION_OFFSET] = 0x1f;
        assert_eq!(
            CatalogueStatusV1::from_bytes(&control),
            Err(CatalogueStatusError::ToolVersionEncoding)
        );

        let mut hidden_suffix = golden;
        hidden_suffix[TOOL_VERSION_OFFSET + 12] = b'X';
        assert_eq!(
            CatalogueStatusV1::from_bytes(&hidden_suffix),
            Err(CatalogueStatusError::ToolVersionEncoding)
        );

        let mut no_nul = golden;
        no_nul[TOOL_VERSION_OFFSET..].fill(b'A');
        assert_eq!(
            CatalogueStatusV1::from_bytes(&no_nul),
            Err(CatalogueStatusError::ToolVersionEncoding)
        );

        let mut empty = golden;
        empty[TOOL_VERSION_OFFSET..].fill(0);
        assert_eq!(
            CatalogueStatusV1::from_bytes(&empty),
            Err(CatalogueStatusError::ToolVersionEncoding)
        );

        assert_eq!(
            CatalogueStatusV1::new(
                1,
                6,
                CatalogueProvenance::DevUnattested,
                1,
                1,
                1,
                1,
                [0; 32],
                [0; 32],
                [0; 32],
                [0; 32],
                [0; 32],
                [0; 32],
                b"",
            ),
            Err(CatalogueStatusError::ToolVersionEncoding)
        );

        assert_eq!(
            CatalogueStatusV1::new(
                1,
                6,
                CatalogueProvenance::DevUnattested,
                1,
                1,
                1,
                1,
                [0; 32],
                [0; 32],
                [0; 32],
                [0; 32],
                [0; 32],
                [0; 32],
                &[b'A'; CATALOGUE_STATUS_TOOL_VERSION_LEN],
            ),
            Err(CatalogueStatusError::ToolVersionTooLong)
        );
    }

    #[test]
    fn maximum_tool_version_is_canonical() {
        let max = [b'X'; CATALOGUE_STATUS_TOOL_VERSION_MAX_LEN];
        let status = CatalogueStatusV1::new(
            1,
            6,
            CatalogueProvenance::DevUnattested,
            0,
            0,
            0,
            0,
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            &max,
        )
        .expect("31 printable bytes fit");
        assert_eq!(status.tool_version(), &max);
        assert_eq!(status.to_bytes()[CATALOGUE_STATUS_V1_LEN - 1], 0);
    }
}
