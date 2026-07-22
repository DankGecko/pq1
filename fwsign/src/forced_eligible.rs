//! Strict host-side validation for the canonical P73K v1 refused-known set.
//!
//! This module is deliberately isolated behind a small API because the base
//! branch does not yet contain the shared `pqsigner-erc7730` runtime parser.
//! The release boundary must nevertheless compile and fail closed on its own;
//! integration can replace this implementation with the shared parser without
//! changing the ELF/bundle binding code.

use anyhow::{bail, Context, Result};

pub(crate) const MAGIC: &[u8; 4] = b"P73K";
pub(crate) const SCHEMA_V1: u16 = 1;
pub(crate) const HEADER_LEN: usize = 16;
pub(crate) const GROUP_RECORD_LEN: usize = 36;
pub(crate) const SELECTOR_LEN: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Summary {
    pub(crate) schema: u16,
    pub(crate) group_count: u32,
    pub(crate) tuple_count: u32,
    pub(crate) encoded_len: usize,
}

/// Return the exact encoded length declared by a P73K header.
///
/// This validates only the fixed header and checked size arithmetic. Callers
/// must pass the resulting exact slice to [`validate`] before treating it as
/// an artifact.
pub(crate) fn encoded_len_from_header(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < HEADER_LEN {
        bail!(
            "P73K header truncated: got {} bytes, need {HEADER_LEN}",
            bytes.len()
        );
    }
    if &bytes[..4] != MAGIC {
        bail!("P73K magic mismatch");
    }
    let schema = read_u16(bytes, 4)?;
    if schema != SCHEMA_V1 {
        bail!("unsupported P73K schema {schema}, expected {SCHEMA_V1}");
    }
    let header_len = usize::from(read_u16(bytes, 6)?);
    if header_len != HEADER_LEN {
        bail!("invalid P73K header length {header_len}, expected {HEADER_LEN}");
    }
    let group_count =
        usize::try_from(read_u32(bytes, 8)?).context("P73K group count does not fit usize")?;
    let tuple_count =
        usize::try_from(read_u32(bytes, 12)?).context("P73K tuple count does not fit usize")?;

    HEADER_LEN
        .checked_add(
            GROUP_RECORD_LEN
                .checked_mul(group_count)
                .context("P73K group-table length overflow")?,
        )
        .and_then(|len| {
            SELECTOR_LEN
                .checked_mul(tuple_count)
                .and_then(|pool_len| len.checked_add(pool_len))
        })
        .context("P73K total length overflow")
}

/// Strictly validate one complete canonical P73K v1 artifact.
pub(crate) fn validate(bytes: &[u8]) -> Result<Summary> {
    let expected_len = encoded_len_from_header(bytes)?;
    if bytes.len() != expected_len {
        bail!(
            "P73K length mismatch: got {} bytes, header requires {expected_len}",
            bytes.len()
        );
    }

    let group_count = read_u32(bytes, 8)?;
    let tuple_count = read_u32(bytes, 12)?;
    let group_count_usize =
        usize::try_from(group_count).context("P73K group count does not fit usize")?;
    let tuple_count_usize =
        usize::try_from(tuple_count).context("P73K tuple count does not fit usize")?;
    let group_table_end = HEADER_LEN
        .checked_add(
            GROUP_RECORD_LEN
                .checked_mul(group_count_usize)
                .context("P73K group-table length overflow")?,
        )
        .context("P73K group-table end overflow")?;
    let selector_pool = bytes
        .get(group_table_end..)
        .context("P73K selector pool is outside the artifact")?;

    let mut previous_key: Option<[u8; 28]> = None;
    let mut next_selector = 0usize;
    for group_index in 0..group_count_usize {
        let start = HEADER_LEN
            .checked_add(
                GROUP_RECORD_LEN
                    .checked_mul(group_index)
                    .context("P73K group offset overflow")?,
            )
            .context("P73K group offset overflow")?;
        let record = bytes
            .get(start..start + GROUP_RECORD_LEN)
            .context("P73K group record truncated")?;

        let mut key = [0u8; 28];
        key.copy_from_slice(&record[..28]);
        if previous_key.is_some_and(|previous| previous >= key) {
            bail!("P73K group {group_index} is not strictly sorted and unique by (chain,target)");
        }
        previous_key = Some(key);

        let selector_start = usize::try_from(read_u32(record, 28)?)
            .context("P73K selector start does not fit usize")?;
        let selector_count = usize::from(read_u16(record, 32)?);
        let reserved = read_u16(record, 34)?;
        if reserved != 0 {
            bail!("P73K group {group_index} has non-zero reserved field");
        }
        if selector_count == 0 {
            bail!("P73K group {group_index} has an empty selector range");
        }
        if selector_start != next_selector {
            bail!(
                "P73K group {group_index} selector range is non-contiguous: starts at {selector_start}, expected {next_selector}"
            );
        }
        let selector_end = selector_start
            .checked_add(selector_count)
            .context("P73K selector range overflow")?;
        if selector_end > tuple_count_usize {
            bail!(
                "P73K group {group_index} selector range ends at {selector_end}, beyond tuple count {tuple_count_usize}"
            );
        }

        let byte_start = SELECTOR_LEN
            .checked_mul(selector_start)
            .context("P73K selector byte offset overflow")?;
        let byte_end = SELECTOR_LEN
            .checked_mul(selector_end)
            .context("P73K selector byte end overflow")?;
        let selectors = selector_pool
            .get(byte_start..byte_end)
            .context("P73K selector range is outside the selector pool")?;
        let mut chunks = selectors.chunks_exact(SELECTOR_LEN);
        let mut previous_selector: Option<[u8; SELECTOR_LEN]> = None;
        for selector in chunks.by_ref() {
            let mut current = [0u8; SELECTOR_LEN];
            current.copy_from_slice(selector);
            if previous_selector.is_some_and(|previous| previous >= current) {
                bail!("P73K group {group_index} selectors are not strictly sorted and unique");
            }
            previous_selector = Some(current);
        }
        if !chunks.remainder().is_empty() {
            bail!("P73K group {group_index} has a partial selector");
        }
        next_selector = selector_end;
    }

    if next_selector != tuple_count_usize {
        bail!("P73K group ranges cover {next_selector} selectors, expected {tuple_count_usize}");
    }
    if group_count == 0 && tuple_count != 0 {
        bail!("P73K has selectors but no groups");
    }

    Ok(Summary {
        schema: SCHEMA_V1,
        group_count,
        tuple_count,
        encoded_len: expected_len,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .context("P73K u16 field truncated")?
        .try_into()
        .expect("checked two-byte slice");
    Ok(u16::from_be_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .context("P73K u32 field truncated")?
        .try_into()
        .expect("checked four-byte slice");
    Ok(u32::from_be_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&SCHEMA_V1.to_be_bytes());
        out.extend_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&3u32.to_be_bytes());

        out.extend_from_slice(&1u64.to_be_bytes());
        out.extend_from_slice(&[0x11; 20]);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());

        out.extend_from_slice(&2u64.to_be_bytes());
        out.extend_from_slice(&[0x22; 20]);
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());

        out.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        out.extend_from_slice(&[0x01, 0x02, 0x03, 0x05]);
        out.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        out
    }

    #[test]
    fn canonical_fixture_validates() {
        let bytes = fixture();
        assert_eq!(
            validate(&bytes).unwrap(),
            Summary {
                schema: 1,
                group_count: 2,
                tuple_count: 3,
                encoded_len: bytes.len(),
            }
        );
    }

    #[test]
    fn malformed_headers_and_lengths_fail_closed() {
        for mutation in [0usize, 4, 6, 8, 12] {
            let mut bytes = fixture();
            bytes[mutation] ^= 1;
            assert!(validate(&bytes).is_err(), "mutation at {mutation} escaped");
        }
        let mut trailing = fixture();
        trailing.push(0);
        assert!(validate(&trailing).is_err());
        let mut truncated = fixture();
        truncated.pop();
        assert!(validate(&truncated).is_err());
    }

    #[test]
    fn malformed_groups_and_selectors_fail_closed() {
        let cases: &[(usize, u8)] = &[
            (HEADER_LEN + 34, 1),                        // reserved
            (HEADER_LEN + 32, 0x02),                     // empty/wrong count
            (HEADER_LEN + GROUP_RECORD_LEN + 28 + 3, 1), // non-contiguous start
            (HEADER_LEN + GROUP_RECORD_LEN + 7, 2),      // unsorted group key
            (HEADER_LEN + 2 * GROUP_RECORD_LEN + 7, 1),  // duplicate selector
        ];
        for (offset, xor) in cases {
            let mut bytes = fixture();
            bytes[*offset] ^= xor;
            assert!(validate(&bytes).is_err(), "mutation at {offset} escaped");
        }
    }

    #[test]
    fn empty_set_is_canonical_but_inconsistent_empty_shapes_are_not() {
        let mut empty = Vec::new();
        empty.extend_from_slice(MAGIC);
        empty.extend_from_slice(&SCHEMA_V1.to_be_bytes());
        empty.extend_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        empty.extend_from_slice(&0u32.to_be_bytes());
        empty.extend_from_slice(&0u32.to_be_bytes());
        assert!(validate(&empty).is_ok());

        let mut selectors_without_groups = empty;
        selectors_without_groups[12..16].copy_from_slice(&1u32.to_be_bytes());
        selectors_without_groups.extend_from_slice(&[0u8; 4]);
        assert!(validate(&selectors_without_groups).is_err());
    }
}
