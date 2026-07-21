//! Backward-compatible ERC-7730 descriptor proof-set envelope.
//!
//! Existing callers send one exact legacy bundle. Contract-call signing may
//! additionally send an ordered pair of independently rooted legacy bundles:
//!
//! ```text
//! magic:u16 BE = 0xe773 || version:u8 = 1 || count:u8 = 2 ||
//! outer_len:u16 BE || outer_legacy_bundle ||
//! child_len:u16 BE || child_legacy_bundle
//! ```
//!
//! The returned handles borrow the exact legacy sub-slices from the caller's
//! TOCTOU snapshot. Secure-world FI checks can therefore re-verify either
//! bundle without copying bytes to the stack or trusting host-derived offsets.

use crate::bundle::{
    leaf_hash, verify_erc7730_bundle, verify_erc7730_bundle_with_leaf_count, BundleError,
    VerifiedDescriptor, MAX_ERC7730_BUNDLE_LEN,
};

/// Magic prefix for the versioned proof-set envelope.
pub const ERC7730_PROOF_SET_MAGIC: u16 = 0xe773;
/// First proof-set envelope syntax version.
pub const ERC7730_PROOF_SET_VERSION: u8 = 1;
/// Version 1 always carries exactly the outer and one distinct child bundle.
pub const ERC7730_PROOF_SET_COUNT: usize = 2;
/// Header bytes: magic(2), version(1), count(1).
pub const ERC7730_PROOF_SET_HEADER_LEN: usize = 4;
/// Maximum proof-set payload size: 4 + 2 * (u16 length + 5130-byte bundle).
pub const MAX_ERC7730_PROOF_SET_LEN: usize =
    ERC7730_PROOF_SET_HEADER_LEN + ERC7730_PROOF_SET_COUNT * (2 + MAX_ERC7730_BUNDLE_LEN);

/// One verified legacy bundle and its exact zero-copy wire identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedBundleRef<'a> {
    /// Parsed descriptor authenticated by this bundle.
    pub descriptor: VerifiedDescriptor<'a>,
    /// Exact legacy bundle bytes inside the secure-side snapshot.
    pub raw_bundle: &'a [u8],
    /// Canonical catalogue leaf index authenticated by the proof.
    pub leaf_index: u32,
}

impl VerifiedBundleRef<'_> {
    /// Domain-separated catalogue leaf identity used by transcript binding.
    #[must_use]
    pub fn leaf_hash(&self) -> [u8; 32] {
        leaf_hash(self.descriptor.ir.raw)
    }
}

/// Ordered, rooted evidence for one contract-call render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedProofSet<'a> {
    /// Exact legacy bundle or complete wrapper bytes supplied by the caller.
    /// Later FI proofs can reparse the whole authenticated structure without
    /// reconstructing wrapper offsets in a signing handler.
    pub raw_payload: &'a [u8],
    /// Bundle zero. Callers bind this descriptor to the outer signed call.
    pub outer: VerifiedBundleRef<'a>,
    /// Bundle one for a distinct child, or `None` for the legacy wire.
    pub child: Option<VerifiedBundleRef<'a>>,
}

impl VerifiedProofSet<'_> {
    /// Whether the versioned two-bundle envelope was supplied.
    #[must_use]
    pub const fn has_distinct_child(&self) -> bool {
        self.child.is_some()
    }
}

/// Proof-set parsing or membership failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofSetError {
    /// The complete trailer exceeds [`MAX_ERC7730_PROOF_SET_LEN`].
    TooLong,
    /// A wrapper header, length prefix, or declared payload is truncated.
    Truncated,
    /// Bytes remain after the exact two declared bundles.
    TrailingBytes,
    /// The wrapper syntax version is not supported.
    Version,
    /// Version 1 did not declare exactly two bundles.
    Count,
    /// A declared legacy sub-bundle exceeds [`MAX_ERC7730_BUNDLE_LEN`].
    BundleLenCap { index: u8 },
    /// Both wrapper records authenticate the same descriptor leaf. This is
    /// rejected even when distinct proof bytes or catalogue indices were used;
    /// same-descriptor nesting must use the legacy one-bundle reuse path.
    DuplicateDescriptor,
    /// A legacy bundle failed its existing parser or Merkle verifier.
    Bundle { index: u8, error: BundleError },
}

/// Verify either the exact legacy one-bundle wire or the versioned proof set.
///
/// This root-only entry point is retained for host tooling. Firmware signing
/// must use [`verify_erc7730_proof_set_with_leaf_count`] so duplicate-tail
/// padding positions cannot masquerade as canonical catalogue indices.
pub fn verify_erc7730_proof_set<'a>(
    payload: &'a [u8],
    root: &[u8; 32],
) -> Result<VerifiedProofSet<'a>, ProofSetError> {
    verify_erc7730_proof_set_inner(payload, root, None)
}

/// Verify a legacy bundle or proof set while enforcing the real catalogue
/// leaf-count bound on every contained bundle.
pub fn verify_erc7730_proof_set_with_leaf_count<'a>(
    payload: &'a [u8],
    root: &[u8; 32],
    leaf_count: usize,
) -> Result<VerifiedProofSet<'a>, ProofSetError> {
    verify_erc7730_proof_set_inner(payload, root, Some(leaf_count))
}

fn verify_erc7730_proof_set_inner<'a>(
    payload: &'a [u8],
    root: &[u8; 32],
    leaf_count: Option<usize>,
) -> Result<VerifiedProofSet<'a>, ProofSetError> {
    if payload.len() > MAX_ERC7730_PROOF_SET_LEN {
        return Err(ProofSetError::TooLong);
    }

    let wrapped = payload
        .get(..2)
        .is_some_and(|prefix| prefix == ERC7730_PROOF_SET_MAGIC.to_be_bytes());
    if !wrapped {
        if payload.len() > MAX_ERC7730_BUNDLE_LEN {
            return Err(ProofSetError::TooLong);
        }
        let outer = verify_one(payload, root, leaf_count, 0)?;
        return Ok(VerifiedProofSet {
            raw_payload: payload,
            outer,
            child: None,
        });
    }

    if payload.len() < ERC7730_PROOF_SET_HEADER_LEN {
        return Err(ProofSetError::Truncated);
    }
    if payload[2] != ERC7730_PROOF_SET_VERSION {
        return Err(ProofSetError::Version);
    }
    if usize::from(payload[3]) != ERC7730_PROOF_SET_COUNT {
        return Err(ProofSetError::Count);
    }

    let (outer_raw, cursor) = take_bundle(payload, ERC7730_PROOF_SET_HEADER_LEN, 0)?;
    let (child_raw, cursor) = take_bundle(payload, cursor, 1)?;
    if cursor != payload.len() {
        return Err(ProofSetError::TrailingBytes);
    }
    let outer = verify_one(outer_raw, root, leaf_count, 0)?;
    let child = verify_one(child_raw, root, leaf_count, 1)?;
    // Compare the authenticated leaf identity after both proofs verify. Raw
    // bundle comparison is insufficient: the same IR may have different
    // proof paths or appear at two catalogue indices.
    if outer.leaf_hash() == child.leaf_hash() {
        return Err(ProofSetError::DuplicateDescriptor);
    }
    Ok(VerifiedProofSet {
        raw_payload: payload,
        outer,
        child: Some(child),
    })
}

fn take_bundle(payload: &[u8], cursor: usize, index: u8) -> Result<(&[u8], usize), ProofSetError> {
    let len_end = cursor.checked_add(2).ok_or(ProofSetError::Truncated)?;
    let len_bytes = payload
        .get(cursor..len_end)
        .ok_or(ProofSetError::Truncated)?;
    let len = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
    if len > MAX_ERC7730_BUNDLE_LEN {
        return Err(ProofSetError::BundleLenCap { index });
    }
    let end = len_end.checked_add(len).ok_or(ProofSetError::Truncated)?;
    let bundle = payload.get(len_end..end).ok_or(ProofSetError::Truncated)?;
    Ok((bundle, end))
}

fn verify_one<'a>(
    raw_bundle: &'a [u8],
    root: &[u8; 32],
    leaf_count: Option<usize>,
    index: u8,
) -> Result<VerifiedBundleRef<'a>, ProofSetError> {
    let descriptor = match leaf_count {
        Some(count) => verify_erc7730_bundle_with_leaf_count(raw_bundle, root, count),
        None => verify_erc7730_bundle(raw_bundle, root),
    }
    .map_err(|error| ProofSetError::Bundle { index, error })?;

    // A successful legacy verification proves this location exists. Read it
    // through checked slicing anyway so this handle never relies on an
    // unchecked duplicate of the legacy parser's bounds arithmetic.
    let leaf_off = 2usize
        .checked_add(descriptor.ir.raw.len())
        .ok_or(ProofSetError::Truncated)?;
    let leaf_end = leaf_off.checked_add(4).ok_or(ProofSetError::Truncated)?;
    let leaf_bytes = raw_bundle
        .get(leaf_off..leaf_end)
        .ok_or(ProofSetError::Truncated)?;
    let leaf_index =
        u32::from_be_bytes([leaf_bytes[0], leaf_bytes[1], leaf_bytes[2], leaf_bytes[3]]);

    Ok(VerifiedBundleRef {
        descriptor,
        raw_bundle,
        leaf_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::cross_check_contract;
    use crate::bundle::verify_erc7730_bundle;
    use crate::ir::{CTX_CONTRACT, HEADER_LEN, SCHEMA_VER};
    use sha2::{Digest, Sha256};

    const OUTER: [u8; 20] = [0x11; 20];
    const CHILD: [u8; 20] = [0x22; 20];

    fn minimal_ir(chain_id: u64, contract: [u8; 20]) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; HEADER_LEN];
        buf[0] = SCHEMA_VER;
        buf[1] = CTX_CONTRACT;
        buf[2..10].copy_from_slice(&chain_id.to_be_bytes());
        buf[10..30].copy_from_slice(&contract);
        let pool_off = HEADER_LEN as u16;
        buf[126..128].copy_from_slice(&pool_off.to_be_bytes());
        buf[128..130].copy_from_slice(&pool_off.to_be_bytes());
        buf[132..134].copy_from_slice(&1u16.to_be_bytes());
        buf.push(0); // zero formats
        buf
    }

    fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    fn legacy_bundle(ir: &[u8], index: u32, sibling: &[u8; 32]) -> std::vec::Vec<u8> {
        let mut bundle = std::vec::Vec::new();
        bundle.extend_from_slice(&(ir.len() as u16).to_be_bytes());
        bundle.extend_from_slice(ir);
        bundle.extend_from_slice(&index.to_be_bytes());
        bundle.extend_from_slice(&1u32.to_be_bytes());
        bundle.extend_from_slice(sibling);
        bundle
    }

    fn fixture() -> (std::vec::Vec<u8>, std::vec::Vec<u8>, [u8; 32]) {
        let outer_ir = minimal_ir(1, OUTER);
        let child_ir = minimal_ir(1, CHILD);
        let outer_leaf = leaf_hash(&outer_ir);
        let child_leaf = leaf_hash(&child_ir);
        let root = node_hash(&outer_leaf, &child_leaf);
        (
            legacy_bundle(&outer_ir, 0, &child_leaf),
            legacy_bundle(&child_ir, 1, &outer_leaf),
            root,
        )
    }

    fn wrap(outer: &[u8], child: &[u8]) -> std::vec::Vec<u8> {
        let mut payload = std::vec::Vec::new();
        payload.extend_from_slice(&ERC7730_PROOF_SET_MAGIC.to_be_bytes());
        payload.push(ERC7730_PROOF_SET_VERSION);
        payload.push(ERC7730_PROOF_SET_COUNT as u8);
        payload.extend_from_slice(&(outer.len() as u16).to_be_bytes());
        payload.extend_from_slice(outer);
        payload.extend_from_slice(&(child.len() as u16).to_be_bytes());
        payload.extend_from_slice(child);
        payload
    }

    #[test]
    fn legacy_wire_remains_exact_and_surfaces_outer_only() {
        let (outer, _child, root) = fixture();
        let old = verify_erc7730_bundle(&outer, &root).expect("legacy verifier");
        let set = verify_erc7730_proof_set_with_leaf_count(&outer, &root, 2)
            .expect("proof-set verifier keeps legacy wire");
        assert_eq!(set.outer.descriptor, old);
        assert_eq!(set.raw_payload, outer.as_slice());
        assert_eq!(set.outer.raw_bundle, outer.as_slice());
        assert_eq!(set.outer.leaf_index, 0);
        assert_eq!(
            set.outer.leaf_hash(),
            leaf_hash(set.outer.descriptor.ir.raw)
        );
        assert_eq!(set.child, None);
        assert!(!set.has_distinct_child());
    }

    #[test]
    fn wrapper_verifies_both_bundles_and_preserves_order_and_raw_slices() {
        let (outer, child, root) = fixture();
        let payload = wrap(&outer, &child);
        let set =
            verify_erc7730_proof_set_with_leaf_count(&payload, &root, 2).expect("valid proof set");
        let child_ref = set.child.expect("distinct child");
        assert_eq!(set.raw_payload, payload.as_slice());
        assert_eq!(set.outer.descriptor.ir.contract, OUTER);
        assert_eq!(child_ref.descriptor.ir.contract, CHILD);
        assert_eq!(set.outer.raw_bundle, outer.as_slice());
        assert_eq!(child_ref.raw_bundle, child.as_slice());
        assert_eq!(set.outer.leaf_index, 0);
        assert_eq!(child_ref.leaf_index, 1);
        assert!(set.has_distinct_child());
    }

    #[test]
    fn reversed_records_cannot_bind_as_the_expected_outer_call() {
        let (outer, child, root) = fixture();
        let reversed = wrap(&child, &outer);
        let set = verify_erc7730_proof_set_with_leaf_count(&reversed, &root, 2)
            .expect("membership is independent of semantic role");
        assert!(cross_check_contract(&set.outer.descriptor.ir, 1, &OUTER).is_err());
        assert_eq!(set.outer.descriptor.ir.contract, CHILD);
    }

    #[test]
    fn legacy_verifier_rejects_wrapper_magic_as_an_over_cap_ir_length() {
        let (outer, child, root) = fixture();
        let payload = wrap(&outer, &child);
        assert_eq!(
            verify_erc7730_bundle(&payload, &root),
            Err(BundleError::IrLenCap)
        );
    }

    #[test]
    fn bad_magic_fails_closed_as_an_invalid_legacy_bundle() {
        let (outer, child, root) = fixture();
        let mut payload = wrap(&outer, &child);
        payload[0] ^= 1;
        assert!(verify_erc7730_proof_set(&payload, &root).is_err());
    }

    #[test]
    fn bad_version_and_every_other_count_refuse() {
        let (outer, child, root) = fixture();
        let mut payload = wrap(&outer, &child);
        payload[2] = ERC7730_PROOF_SET_VERSION + 1;
        assert_eq!(
            verify_erc7730_proof_set(&payload, &root),
            Err(ProofSetError::Version)
        );
        for count in [0u8, 1, 3, u8::MAX] {
            let mut payload = wrap(&outer, &child);
            payload[3] = count;
            assert_eq!(
                verify_erc7730_proof_set(&payload, &root),
                Err(ProofSetError::Count)
            );
        }
    }

    #[test]
    fn every_truncated_wrapper_prefix_refuses() {
        let (outer, child, root) = fixture();
        let payload = wrap(&outer, &child);
        for end in 2..payload.len() {
            assert!(
                verify_erc7730_proof_set(&payload[..end], &root).is_err(),
                "prefix length {end} unexpectedly accepted"
            );
        }
    }

    #[test]
    fn trailing_bytes_refuse() {
        let (outer, child, root) = fixture();
        let mut payload = wrap(&outer, &child);
        payload.push(0);
        assert_eq!(
            verify_erc7730_proof_set(&payload, &root),
            Err(ProofSetError::TrailingBytes)
        );
    }

    #[test]
    fn duplicate_exact_bundles_refuse() {
        let (outer, _child, root) = fixture();
        let payload = wrap(&outer, &outer);
        assert_eq!(
            verify_erc7730_proof_set(&payload, &root),
            Err(ProofSetError::DuplicateDescriptor)
        );
    }

    #[test]
    fn duplicate_descriptor_with_distinct_proof_bytes_refuses() {
        let ir = minimal_ir(1, OUTER);
        let leaf = leaf_hash(&ir);
        let root = node_hash(&leaf, &leaf);
        // Same descriptor at two canonical catalogue positions gives distinct
        // raw proof bytes (the indices differ) but the same authenticated leaf.
        let at_zero = legacy_bundle(&ir, 0, &leaf);
        let at_one = legacy_bundle(&ir, 1, &leaf);
        assert_ne!(at_zero, at_one);
        let payload = wrap(&at_zero, &at_one);
        assert_eq!(
            verify_erc7730_proof_set_with_leaf_count(&payload, &root, 2),
            Err(ProofSetError::DuplicateDescriptor)
        );
    }

    #[test]
    fn declared_sub_bundle_over_cap_refuses_before_slice() {
        let mut payload = std::vec::Vec::new();
        payload.extend_from_slice(&ERC7730_PROOF_SET_MAGIC.to_be_bytes());
        payload.push(ERC7730_PROOF_SET_VERSION);
        payload.push(ERC7730_PROOF_SET_COUNT as u8);
        payload.extend_from_slice(&((MAX_ERC7730_BUNDLE_LEN + 1) as u16).to_be_bytes());
        assert_eq!(
            verify_erc7730_proof_set(&payload, &[0; 32]),
            Err(ProofSetError::BundleLenCap { index: 0 })
        );
    }

    #[test]
    fn complete_payload_over_cap_refuses() {
        let payload = std::vec![0u8; MAX_ERC7730_PROOF_SET_LEN + 1];
        assert_eq!(
            verify_erc7730_proof_set(&payload, &[0; 32]),
            Err(ProofSetError::TooLong)
        );
    }

    #[test]
    fn child_membership_failure_is_attributed_to_record_one() {
        let (outer, child, root) = fixture();
        let mut payload = wrap(&outer, &child);
        let child_start = ERC7730_PROOF_SET_HEADER_LEN + 2 + outer.len() + 2;
        let ir_len = usize::from(u16::from_be_bytes([
            payload[child_start],
            payload[child_start + 1],
        ]));
        let index_off = child_start + 2 + ir_len;
        payload[index_off..index_off + 4].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            verify_erc7730_proof_set(&payload, &root),
            Err(ProofSetError::Bundle {
                index: 1,
                error: BundleError::Merkle,
            })
        );
    }

    #[test]
    fn canonical_leaf_count_applies_to_each_record() {
        let (outer, child, root) = fixture();
        let payload = wrap(&outer, &child);
        assert!(verify_erc7730_proof_set(&payload, &root).is_ok());
        // Artificially pin the real catalogue length to one. Bundle zero at
        // canonical index zero remains valid, while bundle one must fail the
        // independent count check at its own index.
        assert_eq!(
            verify_erc7730_proof_set_with_leaf_count(&payload, &root, 1),
            Err(ProofSetError::Bundle {
                index: 1,
                error: BundleError::LeafIndexCap,
            })
        );
    }

    #[test]
    fn frozen_size_constants_match_wire_formula() {
        assert_eq!(MAX_ERC7730_BUNDLE_LEN, 5_130);
        assert_eq!(MAX_ERC7730_PROOF_SET_LEN, 10_268);
        assert_eq!(
            MAX_ERC7730_PROOF_SET_LEN,
            4 + 2 * (2 + MAX_ERC7730_BUNDLE_LEN)
        );
        assert!(usize::from(ERC7730_PROOF_SET_MAGIC) > crate::ir::MAX_IR_LEN);
    }
}
