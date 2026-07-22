//! Canonical exact-set format for ERC-7730 forced-blind eligibility.
//!
//! `P73K` contains the exact refused-known set `F = K ∖ C`. It is embedded
//! in the same authenticated secure-firmware image as the clear-signing
//! catalogue. This module is deliberately only a strict format reader and an
//! exact-membership primitive: it does not grant signing authority or infer
//! eligibility from parse failures.
//!
//! All integers are big-endian. Version 1 is encoded as:
//!
//! ```text
//!  0..4    magic = "P73K"
//!  4..6    schema = 1
//!  6..8    header length = 16
//!  8..12   group count
//! 12..16   tuple/selector count
//!
//! group_count records, each 36 bytes:
//!  0..8    chain id
//!  8..28   target address
//! 28..32   selector-pool start index
//! 32..34   selector count
//! 34..36   reserved = 0
//!
//! one contiguous pool of tuple_count four-byte selectors
//! ```
//!
//! Groups are strictly ordered by `(chain_id, target)`. Every group is
//! non-empty, its selector range begins exactly where the preceding range
//! ended, and its selectors are strictly ordered. Consequently each accepted
//! byte string has one canonical set interpretation.

use core::convert::TryFrom;

/// Magic prefix for a forced-eligible exact set.
pub const FORCED_ELIGIBLE_MAGIC: [u8; 4] = *b"P73K";
/// First forced-eligible set schema.
pub const FORCED_ELIGIBLE_SCHEMA_V1: u16 = 1;
/// Exact header width for schema version 1.
pub const FORCED_ELIGIBLE_HEADER_LEN: usize = 16;
/// Exact `(chain_id, target, selector range)` record width.
pub const FORCED_ELIGIBLE_GROUP_LEN: usize = 36;
/// Width of one selector in the shared selector pool.
pub const FORCED_ELIGIBLE_SELECTOR_LEN: usize = 4;

const GROUP_CHAIN_OFFSET: usize = 0;
const GROUP_TARGET_OFFSET: usize = 8;
const GROUP_SELECTOR_START_OFFSET: usize = 28;
const GROUP_SELECTOR_COUNT_OFFSET: usize = 32;
const GROUP_RESERVED_OFFSET: usize = 34;

/// Structural or non-canonical `P73K` encoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForcedEligibleError {
    /// The artifact is shorter than the fixed header or not exactly the length
    /// derived from its canonical counts.
    Length,
    /// The `P73K` magic is absent.
    Magic,
    /// The schema field is not version 1.
    Schema,
    /// The encoded fixed-header width is not 16 bytes.
    HeaderLength,
    /// Count-derived length or selector-range arithmetic overflowed.
    ArithmeticOverflow,
    /// A group record's reserved field is non-zero.
    Reserved,
    /// Groups are duplicated or not strictly ordered by `(chain_id, target)`.
    GroupOrder,
    /// A canonical group has no selectors.
    EmptyGroup,
    /// A group's selector range exceeds the declared selector pool.
    SelectorRange,
    /// Selector ranges overlap or leave a gap.
    SelectorRangeContinuity,
    /// The group ranges do not cover the selector pool exactly.
    SelectorCoverage,
    /// Selectors within a group are duplicated or not strictly ordered.
    SelectorOrder,
}

/// Strictly validated borrowed view of one canonical `P73K` exact set.
///
/// Construction validates the complete artifact before publishing this view.
/// Membership can therefore use bounded binary searches without reparsing or
/// allocating.
#[derive(Clone, Copy, Debug)]
pub struct ForcedEligibleSet<'a> {
    bytes: &'a [u8],
    group_count: u32,
    tuple_count: u32,
    selector_pool_offset: usize,
}

impl<'a> ForcedEligibleSet<'a> {
    /// Parse and strictly validate an entire canonical version-1 artifact.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ForcedEligibleError> {
        if bytes.len() < FORCED_ELIGIBLE_HEADER_LEN {
            return Err(ForcedEligibleError::Length);
        }
        if bytes[..4] != FORCED_ELIGIBLE_MAGIC {
            return Err(ForcedEligibleError::Magic);
        }
        if read_u16(bytes, 4) != FORCED_ELIGIBLE_SCHEMA_V1 {
            return Err(ForcedEligibleError::Schema);
        }
        if usize::from(read_u16(bytes, 6)) != FORCED_ELIGIBLE_HEADER_LEN {
            return Err(ForcedEligibleError::HeaderLength);
        }

        let group_count = read_u32(bytes, 8);
        let tuple_count = read_u32(bytes, 12);
        let (expected_len, selector_pool_offset) = encoded_layout(group_count, tuple_count)?;
        if bytes.len() != expected_len {
            return Err(ForcedEligibleError::Length);
        }

        let set = Self {
            bytes,
            group_count,
            tuple_count,
            selector_pool_offset,
        };
        set.validate_groups()?;
        Ok(set)
    }

    /// Number of canonical `(chain_id, target)` groups.
    #[must_use]
    pub const fn group_count(&self) -> u32 {
        self.group_count
    }

    /// Number of exact `(chain_id, target, selector)` tuples.
    #[must_use]
    pub const fn tuple_count(&self) -> u32 {
        self.tuple_count
    }

    /// Iterate over every tuple in canonical wire order without allocation.
    #[must_use]
    pub fn iter(&self) -> ForcedEligibleIter<'a> {
        ForcedEligibleIter {
            set: *self,
            group_index: 0,
            selector_in_group: 0,
            remaining: self.tuple_count,
        }
    }

    /// Return whether the validated exact set contains one full call tuple.
    ///
    /// This uses one bounded binary search over the group records and one over
    /// the matching group's selector slice. Failure is exact non-membership;
    /// callers must not reinterpret it as signing authority.
    #[must_use]
    pub fn contains(&self, chain_id: u64, target: &[u8; 20], selector: &[u8; 4]) -> bool {
        let mut low = 0u32;
        let mut high = self.group_count;
        while low < high {
            let middle = low + (high - low) / 2;
            let group = self.group(middle);
            match compare_group(group.chain_id, &group.target, chain_id, target) {
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
                core::cmp::Ordering::Equal => return self.group_contains(group, selector),
            }
        }
        false
    }

    fn validate_groups(&self) -> Result<(), ForcedEligibleError> {
        let mut previous_chain = 0u64;
        let mut previous_target = [0u8; 20];
        let mut selector_cursor = 0u32;

        for group_index in 0..self.group_count {
            let group = self.group(group_index);
            if group_index != 0
                && compare_group(
                    previous_chain,
                    &previous_target,
                    group.chain_id,
                    &group.target,
                ) != core::cmp::Ordering::Less
            {
                return Err(ForcedEligibleError::GroupOrder);
            }
            previous_chain = group.chain_id;
            previous_target = group.target;

            if group.reserved != 0 {
                return Err(ForcedEligibleError::Reserved);
            }
            if group.selector_count == 0 {
                return Err(ForcedEligibleError::EmptyGroup);
            }

            let selector_end = group
                .selector_start
                .checked_add(u32::from(group.selector_count))
                .ok_or(ForcedEligibleError::ArithmeticOverflow)?;
            if group.selector_start > self.tuple_count || selector_end > self.tuple_count {
                return Err(ForcedEligibleError::SelectorRange);
            }
            if group.selector_start != selector_cursor {
                return Err(ForcedEligibleError::SelectorRangeContinuity);
            }

            let mut previous_selector = [0u8; 4];
            for selector_index in group.selector_start..selector_end {
                let selector = self.selector(selector_index);
                if selector_index != group.selector_start && selector <= previous_selector {
                    return Err(ForcedEligibleError::SelectorOrder);
                }
                previous_selector = selector;
            }
            selector_cursor = selector_end;
        }

        if selector_cursor != self.tuple_count {
            return Err(ForcedEligibleError::SelectorCoverage);
        }
        Ok(())
    }

    fn group_contains(&self, group: Group, selector: &[u8; 4]) -> bool {
        let mut low = group.selector_start;
        let mut high = group.selector_start + u32::from(group.selector_count);
        while low < high {
            let middle = low + (high - low) / 2;
            match self.selector(middle).cmp(selector) {
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
                core::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    fn group(&self, index: u32) -> Group {
        let offset = FORCED_ELIGIBLE_HEADER_LEN + index as usize * FORCED_ELIGIBLE_GROUP_LEN;
        let mut target = [0u8; 20];
        target.copy_from_slice(
            &self.bytes[offset + GROUP_TARGET_OFFSET..offset + GROUP_SELECTOR_START_OFFSET],
        );
        Group {
            chain_id: read_u64(self.bytes, offset + GROUP_CHAIN_OFFSET),
            target,
            selector_start: read_u32(self.bytes, offset + GROUP_SELECTOR_START_OFFSET),
            selector_count: read_u16(self.bytes, offset + GROUP_SELECTOR_COUNT_OFFSET),
            reserved: read_u16(self.bytes, offset + GROUP_RESERVED_OFFSET),
        }
    }

    fn selector(&self, index: u32) -> [u8; 4] {
        let offset = self.selector_pool_offset + index as usize * FORCED_ELIGIBLE_SELECTOR_LEN;
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&self.bytes[offset..offset + FORCED_ELIGIBLE_SELECTOR_LEN]);
        selector
    }
}

/// Canonical, allocation-free iterator returned by [`ForcedEligibleSet::iter`].
#[derive(Clone, Debug)]
pub struct ForcedEligibleIter<'a> {
    set: ForcedEligibleSet<'a>,
    group_index: u32,
    selector_in_group: u16,
    remaining: u32,
}

impl Iterator for ForcedEligibleIter<'_> {
    type Item = (u64, [u8; 20], [u8; 4]);

    fn next(&mut self) -> Option<Self::Item> {
        while self.group_index < self.set.group_count {
            let group = self.set.group(self.group_index);
            if self.selector_in_group < group.selector_count {
                let selector_index = group.selector_start + u32::from(self.selector_in_group);
                self.selector_in_group += 1;
                self.remaining -= 1;
                return Some((
                    group.chain_id,
                    group.target,
                    self.set.selector(selector_index),
                ));
            }
            self.group_index += 1;
            self.selector_in_group = 0;
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ForcedEligibleIter<'_> {}

#[derive(Clone, Copy)]
struct Group {
    chain_id: u64,
    target: [u8; 20],
    selector_start: u32,
    selector_count: u16,
    reserved: u16,
}

fn encoded_layout(
    group_count: u32,
    tuple_count: u32,
) -> Result<(usize, usize), ForcedEligibleError> {
    let groups_len = group_count
        .checked_mul(FORCED_ELIGIBLE_GROUP_LEN as u32)
        .ok_or(ForcedEligibleError::ArithmeticOverflow)?;
    let selectors_len = tuple_count
        .checked_mul(FORCED_ELIGIBLE_SELECTOR_LEN as u32)
        .ok_or(ForcedEligibleError::ArithmeticOverflow)?;
    let pool_offset = (FORCED_ELIGIBLE_HEADER_LEN as u32)
        .checked_add(groups_len)
        .ok_or(ForcedEligibleError::ArithmeticOverflow)?;
    let total_len = pool_offset
        .checked_add(selectors_len)
        .ok_or(ForcedEligibleError::ArithmeticOverflow)?;
    Ok((
        usize::try_from(total_len).map_err(|_| ForcedEligibleError::ArithmeticOverflow)?,
        usize::try_from(pool_offset).map_err(|_| ForcedEligibleError::ArithmeticOverflow)?,
    ))
}

fn compare_group(
    left_chain: u64,
    left_target: &[u8; 20],
    right_chain: u64,
    right_target: &[u8; 20],
) -> core::cmp::Ordering {
    left_chain
        .cmp(&right_chain)
        .then_with(|| left_target.cmp(right_target))
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

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    const TARGET_A: [u8; 20] = [0x11; 20];
    const TARGET_B: [u8; 20] = [0x22; 20];
    const SELECTOR_A: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
    const SELECTOR_B: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
    const SELECTOR_C: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

    fn header(group_count: u32, tuple_count: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FORCED_ELIGIBLE_MAGIC);
        bytes.extend_from_slice(&FORCED_ELIGIBLE_SCHEMA_V1.to_be_bytes());
        bytes.extend_from_slice(&(FORCED_ELIGIBLE_HEADER_LEN as u16).to_be_bytes());
        bytes.extend_from_slice(&group_count.to_be_bytes());
        bytes.extend_from_slice(&tuple_count.to_be_bytes());
        bytes
    }

    fn group(
        bytes: &mut Vec<u8>,
        chain_id: u64,
        target: [u8; 20],
        start: u32,
        count: u16,
        reserved: u16,
    ) {
        bytes.extend_from_slice(&chain_id.to_be_bytes());
        bytes.extend_from_slice(&target);
        bytes.extend_from_slice(&start.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&reserved.to_be_bytes());
    }

    fn golden() -> Vec<u8> {
        let mut bytes = header(2, 3);
        group(&mut bytes, 1, TARGET_A, 0, 2, 0);
        group(&mut bytes, 10, TARGET_B, 2, 1, 0);
        bytes.extend_from_slice(&SELECTOR_A);
        bytes.extend_from_slice(&SELECTOR_B);
        bytes.extend_from_slice(&SELECTOR_C);
        bytes
    }

    fn rejects(mutator: impl FnOnce(&mut Vec<u8>), expected: ForcedEligibleError) {
        let mut bytes = golden();
        mutator(&mut bytes);
        assert_eq!(ForcedEligibleSet::from_bytes(&bytes).unwrap_err(), expected);
    }

    #[test]
    fn independent_golden_vector_parses_iterates_and_searches_exactly() {
        // Literal expected bytes freeze magic, field widths, big-endian order,
        // record layout, shared-pool layout, and canonical tuple order.
        let bytes = golden();
        assert_eq!(
            bytes,
            std::vec![
                0x50, 0x37, 0x33, 0x4b, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
                0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x0a, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x00, 0x00, 0x02,
                0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x12, 0x34, 0x56, 0x78, 0xa9, 0x05,
                0x9c, 0xbb,
            ]
        );

        let set = ForcedEligibleSet::from_bytes(&bytes).unwrap();
        assert_eq!(set.group_count(), 2);
        assert_eq!(set.tuple_count(), 3);
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            std::vec![
                (1, TARGET_A, SELECTOR_A),
                (1, TARGET_A, SELECTOR_B),
                (10, TARGET_B, SELECTOR_C),
            ]
        );
        for tuple in set.iter() {
            assert!(set.contains(tuple.0, &tuple.1, &tuple.2));
        }
        assert!(!set.contains(0, &TARGET_A, &SELECTOR_A));
        assert!(!set.contains(1, &TARGET_B, &SELECTOR_A));
        assert!(!set.contains(1, &TARGET_A, &SELECTOR_C));
        assert!(!set.contains(11, &TARGET_B, &SELECTOR_C));
    }

    #[test]
    fn canonical_empty_set_is_accepted() {
        let bytes = header(0, 0);
        let set = ForcedEligibleSet::from_bytes(&bytes).unwrap();
        assert_eq!(set.group_count(), 0);
        assert_eq!(set.tuple_count(), 0);
        assert_eq!(set.iter().len(), 0);
        assert!(!set.contains(1, &TARGET_A, &SELECTOR_A));
    }

    #[test]
    fn header_and_exact_length_mutations_are_rejected() {
        rejects(|bytes| bytes[0] ^= 1, ForcedEligibleError::Magic);
        rejects(|bytes| bytes[5] = 2, ForcedEligibleError::Schema);
        rejects(|bytes| bytes[7] = 15, ForcedEligibleError::HeaderLength);
        rejects(
            |bytes| {
                bytes.pop().unwrap();
            },
            ForcedEligibleError::Length,
        );
        rejects(|bytes| bytes.push(0), ForcedEligibleError::Length);
        assert_eq!(
            ForcedEligibleSet::from_bytes(&golden()[..15]).unwrap_err(),
            ForcedEligibleError::Length
        );
    }

    #[test]
    fn count_arithmetic_overflow_is_rejected_before_length_use() {
        let bytes = header(u32::MAX, 0);
        assert_eq!(
            ForcedEligibleSet::from_bytes(&bytes).unwrap_err(),
            ForcedEligibleError::ArithmeticOverflow
        );
        let bytes = header(0, u32::MAX);
        assert_eq!(
            ForcedEligibleSet::from_bytes(&bytes).unwrap_err(),
            ForcedEligibleError::ArithmeticOverflow
        );
    }

    #[test]
    fn reserved_and_empty_groups_are_rejected() {
        rejects(|bytes| bytes[51] = 1, ForcedEligibleError::Reserved);

        let mut bytes = header(1, 0);
        group(&mut bytes, 1, TARGET_A, 0, 0, 0);
        assert_eq!(
            ForcedEligibleSet::from_bytes(&bytes).unwrap_err(),
            ForcedEligibleError::EmptyGroup
        );
    }

    #[test]
    fn group_order_and_duplicates_are_rejected() {
        rejects(
            |bytes| bytes[52..60].copy_from_slice(&0u64.to_be_bytes()),
            ForcedEligibleError::GroupOrder,
        );
        rejects(
            |bytes| {
                bytes[52..60].copy_from_slice(&1u64.to_be_bytes());
                bytes[60..80].copy_from_slice(&TARGET_A);
            },
            ForcedEligibleError::GroupOrder,
        );
    }

    #[test]
    fn range_overflow_out_of_bounds_gaps_and_coverage_are_rejected() {
        rejects(
            |bytes| {
                bytes[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
                bytes[48..50].copy_from_slice(&1u16.to_be_bytes());
            },
            ForcedEligibleError::ArithmeticOverflow,
        );
        rejects(
            |bytes| bytes[44..48].copy_from_slice(&3u32.to_be_bytes()),
            ForcedEligibleError::SelectorRange,
        );
        rejects(
            |bytes| bytes[44..48].copy_from_slice(&1u32.to_be_bytes()),
            ForcedEligibleError::SelectorRangeContinuity,
        );
        rejects(
            |bytes| bytes[80..84].copy_from_slice(&1u32.to_be_bytes()),
            ForcedEligibleError::SelectorRangeContinuity,
        );

        let mut bytes = header(0, 1);
        bytes.extend_from_slice(&SELECTOR_A);
        assert_eq!(
            ForcedEligibleSet::from_bytes(&bytes).unwrap_err(),
            ForcedEligibleError::SelectorCoverage
        );
    }

    #[test]
    fn selector_order_and_duplicates_are_rejected_within_each_group() {
        rejects(
            |bytes| bytes[92..96].copy_from_slice(&SELECTOR_A),
            ForcedEligibleError::SelectorOrder,
        );
        rejects(
            |bytes| bytes[88..92].copy_from_slice(&SELECTOR_C),
            ForcedEligibleError::SelectorOrder,
        );
    }
}
