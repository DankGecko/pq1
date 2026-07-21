//! Exact admission policy for nested ERC-7730 `calldata` fields.
//!
//! A rooted descriptor is not enough to establish how a parent contract
//! executes embedded bytes.  Every admitted parent therefore needs one exact
//! firmware policy row binding its descriptor/deployment/selector, the sole
//! dynamic field, the address-typed callee path, and the execution semantics.
//! Dbgen and the device consume these same rows.  The production table is
//! intentionally empty until a real deployment earns source evidence.

use crate::{abi::container_field, ir::PathOp};

/// Execution meaning established by source/deployment evidence, not inferred
/// from calldata.  The first slice has exactly one ordinary zero-value call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NestedCalldataExecution {
    CallZeroValue,
}

/// Exact identity of the evidence behind one execution-policy row.
///
/// These strings are audit receipts only; the device never displays or
/// interprets them.  Keeping them on the row prevents a future production
/// admission from losing the source revision that justified `CALL` semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NestedCalldataEvidence {
    pub repository: &'static str,
    pub revision: &'static str,
    pub deployment: &'static str,
    pub code_identity: &'static str,
}

/// One exact parent-format admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NestedCalldataEnrollment {
    pub descriptor_hash: [u8; 32],
    pub chain_id: u64,
    pub parent_contract: [u8; 20],
    /// Compiler-only source belt.  The device binds the independently derived
    /// selector because the canonical signature text is not present in IR.
    pub canonical_signature: &'static str,
    pub parent_selector: [u8; 4],
    pub field_ordinal: u8,
    /// Exact `RootStructured / FieldIdx(slot) / FollowOffset` bytecode.
    pub field_path: [u8; 5],
    /// Exact address-typed `calleePath` bytecode (`@.to` or a static word).
    pub callee_path: [u8; 4],
    pub execution: NestedCalldataExecution,
    pub evidence: NestedCalldataEvidence,
}

/// Parent identity available on both compiler and device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NestedCalldataParentKey<'a> {
    pub descriptor_hash: &'a [u8; 32],
    pub chain_id: u64,
    pub parent_contract: &'a [u8; 20],
    pub parent_selector: &'a [u8; 4],
}

/// Complete field identity used by device deep validation and nested binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NestedCalldataFieldKey<'a> {
    pub parent: NestedCalldataParentKey<'a>,
    pub field_ordinal: u8,
    pub field_path: &'a [u8; 5],
    pub callee_path: &'a [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NestedCalldataPolicyError {
    AmbiguousEnrollment,
}

/// The meaning of one canonical callee path after structural validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NestedCalleeLocation {
    ContainerTo,
    /// One direct word slot in the parent's static ABI head.
    StaticWord(u16),
}

/// Production nested-calldata signing authority.
///
/// Deliberately empty: Phase C proves the mechanism with a synthetic fixture
/// but admits no real descriptor or deployment.
pub const PRODUCTION_NESTED_CALLDATA_ENROLLMENTS: &[NestedCalldataEnrollment] = &[];

pub const TEST_NESTED_CALLDATA_DESCRIPTOR_HASH: [u8; 32] = [
    0x04, 0x83, 0x00, 0x07, 0xcb, 0xd4, 0xf6, 0x3e, 0xeb, 0xa1, 0x0a, 0xf5, 0x4d, 0xd7, 0xfa, 0x33,
    0x99, 0xcf, 0xb0, 0xdf, 0x49, 0xab, 0x5f, 0x34, 0x3e, 0xe2, 0x91, 0xc6, 0xae, 0x14, 0x74, 0xe4,
];
pub const TEST_NESTED_CALLDATA_PARENT_CONTRACT: [u8; 20] = [0x34; 20];
pub const TEST_NESTED_CALLDATA_PARENT_SELECTOR: [u8; 4] = [0x6f, 0xad, 0xcf, 0x72];
pub const TEST_NESTED_CALLDATA_FIELD_PATH: [u8; 5] = [
    PathOp::RootStructured as u8,
    PathOp::FieldIdx as u8,
    0,
    1,
    PathOp::FollowOffset as u8,
];
pub const TEST_NESTED_CALLDATA_CALLEE_PATH: [u8; 4] =
    [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0];

/// Exact synthetic row used only through explicitly injected test tables.
/// It is not a member of [`PRODUCTION_NESTED_CALLDATA_ENROLLMENTS`].
pub const TEST_NESTED_CALLDATA_ENROLLMENT: NestedCalldataEnrollment = NestedCalldataEnrollment {
    descriptor_hash: TEST_NESTED_CALLDATA_DESCRIPTOR_HASH,
    chain_id: 31_337,
    parent_contract: TEST_NESTED_CALLDATA_PARENT_CONTRACT,
    canonical_signature: "forward(address,bytes)",
    parent_selector: TEST_NESTED_CALLDATA_PARENT_SELECTOR,
    field_ordinal: 1,
    field_path: TEST_NESTED_CALLDATA_FIELD_PATH,
    callee_path: TEST_NESTED_CALLDATA_CALLEE_PATH,
    execution: NestedCalldataExecution::CallZeroValue,
    evidence: NestedCalldataEvidence {
        repository: "EthereumPhone/PQ1 synthetic test fixture",
        revision: "nested-calldata-forward-v1",
        deployment: "chain 31337 / 0x3434343434343434343434343434343434343434",
        code_identity: "forward(address,bytes): target.call(data), no value",
    },
};

pub const TEST_NESTED_CALLDATA_ENROLLMENTS: &[NestedCalldataEnrollment] =
    &[TEST_NESTED_CALLDATA_ENROLLMENT];

/// Build-selected device policy. The test row can enter only through the
/// explicit fixture feature; ordinary and production builds resolve this to
/// the empty production table.
#[cfg(feature = "nested-calldata-test-fixture")]
pub const ACTIVE_NESTED_CALLDATA_ENROLLMENTS: &[NestedCalldataEnrollment] =
    TEST_NESTED_CALLDATA_ENROLLMENTS;
#[cfg(not(feature = "nested-calldata-test-fixture"))]
pub const ACTIVE_NESTED_CALLDATA_ENROLLMENTS: &[NestedCalldataEnrollment] =
    PRODUCTION_NESTED_CALLDATA_ENROLLMENTS;

fn parent_matches(row: &NestedCalldataEnrollment, key: NestedCalldataParentKey<'_>) -> bool {
    row.descriptor_hash == *key.descriptor_hash
        && row.chain_id == key.chain_id
        && row.parent_contract == *key.parent_contract
        && row.parent_selector == *key.parent_selector
}

/// Select one exact parent policy row. Duplicate matching rows fail closed.
pub fn lookup_parent<'a>(
    rows: &'a [NestedCalldataEnrollment],
    key: NestedCalldataParentKey<'_>,
) -> Result<Option<&'a NestedCalldataEnrollment>, NestedCalldataPolicyError> {
    let mut found = None;
    for row in rows {
        if parent_matches(row, key) {
            if found.is_some() {
                return Err(NestedCalldataPolicyError::AmbiguousEnrollment);
            }
            found = Some(row);
        }
    }
    Ok(found)
}

/// Select one exact parent field policy row. Every IR-controlled path byte is
/// part of the key; a near match is an ordinary `None`, never partial authority.
pub fn lookup_field<'a>(
    rows: &'a [NestedCalldataEnrollment],
    key: NestedCalldataFieldKey<'_>,
) -> Result<Option<&'a NestedCalldataEnrollment>, NestedCalldataPolicyError> {
    let mut found = None;
    for row in rows {
        if parent_matches(row, key.parent)
            && row.field_ordinal == key.field_ordinal
            && row.field_path == *key.field_path
            && row.callee_path == *key.callee_path
        {
            if found.is_some() {
                return Err(NestedCalldataPolicyError::AmbiguousEnrollment);
            }
            found = Some(row);
        }
    }
    Ok(found)
}

/// Return the sole-C1 field's static-head slot when its program is exactly
/// `RootStructured / FieldIdx(slot) / FollowOffset`.
#[must_use]
pub fn calldata_field_slot(path: &[u8]) -> Option<u16> {
    if path.len() != 5
        || path[0] != PathOp::RootStructured as u8
        || path[1] != PathOp::FieldIdx as u8
        || path[4] != PathOp::FollowOffset as u8
    {
        return None;
    }
    Some(u16::from_be_bytes([path[2], path[3]]))
}

/// Validate a callee program as either exact `@.to` or one static structured
/// word. The first slice deliberately admits only a direct static word; tuple
/// descent remains outside the fixed four-byte enrollment shape.
#[must_use]
pub fn callee_location(path: &[u8]) -> Option<NestedCalleeLocation> {
    const TO_PATH: [u8; 4] = [
        PathOp::RootContainer as u8,
        PathOp::FieldIdx as u8,
        (container_field::TO >> 8) as u8,
        container_field::TO as u8,
    ];
    if path == TO_PATH {
        return Some(NestedCalleeLocation::ContainerTo);
    }
    if path.len() == 4
        && path[0] == PathOp::RootStructured as u8
        && path[1] == PathOp::FieldIdx as u8
    {
        return Some(NestedCalleeLocation::StaticWord(u16::from_be_bytes([
            path[2], path[3],
        ])));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent_key() -> NestedCalldataParentKey<'static> {
        NestedCalldataParentKey {
            descriptor_hash: &TEST_NESTED_CALLDATA_DESCRIPTOR_HASH,
            chain_id: TEST_NESTED_CALLDATA_ENROLLMENT.chain_id,
            parent_contract: &TEST_NESTED_CALLDATA_PARENT_CONTRACT,
            parent_selector: &TEST_NESTED_CALLDATA_PARENT_SELECTOR,
        }
    }

    #[test]
    fn production_table_is_dormant_and_test_row_is_exact() {
        assert!(PRODUCTION_NESTED_CALLDATA_ENROLLMENTS.is_empty());
        assert!(
            lookup_parent(PRODUCTION_NESTED_CALLDATA_ENROLLMENTS, parent_key())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            lookup_field(
                TEST_NESTED_CALLDATA_ENROLLMENTS,
                NestedCalldataFieldKey {
                    parent: parent_key(),
                    field_ordinal: 1,
                    field_path: &TEST_NESTED_CALLDATA_FIELD_PATH,
                    callee_path: &TEST_NESTED_CALLDATA_CALLEE_PATH,
                },
            )
            .unwrap(),
            Some(&TEST_NESTED_CALLDATA_ENROLLMENT)
        );
    }

    #[test]
    fn lookup_rejects_ambiguity_and_near_matches() {
        let duplicates = [
            TEST_NESTED_CALLDATA_ENROLLMENT,
            TEST_NESTED_CALLDATA_ENROLLMENT,
        ];
        assert_eq!(
            lookup_parent(&duplicates, parent_key()),
            Err(NestedCalldataPolicyError::AmbiguousEnrollment)
        );

        let mut wrong_path = TEST_NESTED_CALLDATA_FIELD_PATH;
        wrong_path[3] ^= 1;
        assert!(lookup_field(
            TEST_NESTED_CALLDATA_ENROLLMENTS,
            NestedCalldataFieldKey {
                parent: parent_key(),
                field_ordinal: 1,
                field_path: &wrong_path,
                callee_path: &TEST_NESTED_CALLDATA_CALLEE_PATH,
            },
        )
        .unwrap()
        .is_none());

        let mut wrong_callee = TEST_NESTED_CALLDATA_CALLEE_PATH;
        wrong_callee[3] ^= 1;
        assert!(lookup_field(
            TEST_NESTED_CALLDATA_ENROLLMENTS,
            NestedCalldataFieldKey {
                parent: parent_key(),
                field_ordinal: 1,
                field_path: &TEST_NESTED_CALLDATA_FIELD_PATH,
                callee_path: &wrong_callee,
            },
        )
        .unwrap()
        .is_none());

        let wrong_hash = [0x72; 32];
        let wrong_contract = [0x35; 20];
        let wrong_selector = [0x6e, 0xad, 0xcf, 0x72];
        for key in [
            NestedCalldataParentKey {
                descriptor_hash: &wrong_hash,
                ..parent_key()
            },
            NestedCalldataParentKey {
                chain_id: 31_338,
                ..parent_key()
            },
            NestedCalldataParentKey {
                parent_contract: &wrong_contract,
                ..parent_key()
            },
            NestedCalldataParentKey {
                parent_selector: &wrong_selector,
                ..parent_key()
            },
        ] {
            assert!(lookup_parent(TEST_NESTED_CALLDATA_ENROLLMENTS, key)
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn path_predicates_accept_only_the_fixed_topologies() {
        assert_eq!(
            calldata_field_slot(&TEST_NESTED_CALLDATA_FIELD_PATH),
            Some(1)
        );
        assert_eq!(
            callee_location(&TEST_NESTED_CALLDATA_CALLEE_PATH),
            Some(NestedCalleeLocation::StaticWord(0))
        );
        assert_eq!(
            callee_location(&[
                PathOp::RootContainer as u8,
                PathOp::FieldIdx as u8,
                (container_field::TO >> 8) as u8,
                container_field::TO as u8,
            ]),
            Some(NestedCalleeLocation::ContainerTo)
        );
        assert!(callee_location(&[
            PathOp::RootContainer as u8,
            PathOp::FieldIdx as u8,
            (container_field::FROM >> 8) as u8,
            container_field::FROM as u8,
        ])
        .is_none());
        assert!(callee_location(&[
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
            PathOp::FollowOffset as u8,
        ])
        .is_none());
    }
}
