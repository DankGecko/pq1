//! Re-export shim over `pqsigner-erc7730`.
//!
//! Symmetric to `secure/src/tx/mod.rs` re-exporting `pqsigner-tx-core`
//! and `secure/src/erc20/mod.rs` re-exporting `pqsigner-tx::erc20`.
//! Existing call sites (`crate::tx::erc7730::verify_erc7730_bundle`)
//! reach through this shim rather than naming the workspace crate
//! directly, so a future move of the crate's path doesn't ripple
//! into the secure code.
//!
//! The shim also funnels the firmware-pinned Merkle root through a
//! thin wrapper so call sites don't have to reach into `db_roots`
//! every time.

pub use pqsigner_erc7730::binding::{
    cross_check_contract, cross_check_eip712, BindingError,
};
pub use pqsigner_erc7730::bundle::{
    leaf_hash, BundleError, VerifiedDescriptor, MAX_ERC7730_BUNDLE_LEN,
    MAX_PROOF_DEPTH,
};
pub use pqsigner_erc7730::display::render::{
    derive_nested_call, nested_binding_commitment, CanonicalChildInterval, LeafIdentity,
    NestedCallBinding,
};
pub use pqsigner_erc7730::ir::{
    ContextKind, Erc7730Ir, FieldEntry, FieldIter, FormatHeader, FormatIter,
    FormatOp, IrError, PathOp, Visibility, HEADER_LEN, MAX_FIELDS_PER_FORMAT,
    MAX_FORMATS, MAX_IR_LEN, MAX_NESTING, MAX_POOL_ENTRY_LEN, SCHEMA_VER,
};
pub use pqsigner_erc7730::proof_set::{
    ProofSetError, VerifiedBundleRef, VerifiedProofSet, ERC7730_PROOF_SET_COUNT,
    ERC7730_PROOF_SET_MAGIC, ERC7730_PROOF_SET_VERSION, MAX_ERC7730_PROOF_SET_LEN,
};

// The protocol crate owns the cross-world wire caps while the pure interpreter
// owns the parser. Make any drift a build failure rather than accepting more
// bytes than the verifier can consume (or silently truncating a valid set).
const _: () = assert!(
    sphincs_tz_shared::ERC7730_LEGACY_BUNDLE_MAX_LEN == MAX_ERC7730_BUNDLE_LEN
);
const _: () =
    assert!(sphincs_tz_shared::ERC7730_MAX_TRAILER_LEN == MAX_ERC7730_PROOF_SET_LEN);
const _: () =
    assert!(sphincs_tz_shared::ERC7730_PROOF_SET_MAGIC == ERC7730_PROOF_SET_MAGIC);
const _: () =
    assert!(sphincs_tz_shared::ERC7730_PROOF_SET_VERSION == ERC7730_PROOF_SET_VERSION);
const _: () =
    assert!(sphincs_tz_shared::ERC7730_PROOF_SET_COUNT == ERC7730_PROOF_SET_COUNT);

/// Firmware verifier with canonical-index enforcement tied to the generated
/// root's real leaf count. The generic host verifier intentionally remains
/// available in `pqsigner-erc7730`; signing code must pass through this shim.
pub fn verify_erc7730_bundle<'a>(
    bundle: &'a [u8],
    root: &[u8; 32],
) -> Result<VerifiedDescriptor<'a>, BundleError> {
    pqsigner_erc7730::bundle::verify_erc7730_bundle_with_leaf_count(
        bundle,
        root,
        crate::db_roots::ERC7730_DESCRIPTOR_COUNT,
    )
}

/// Firmware proof-set verifier with canonical-index enforcement tied to the
/// generated root's real leaf count. The returned raw handles borrow directly
/// from the secure-side TOCTOU snapshot.
pub fn verify_erc7730_proof_set<'a>(
    payload: &'a [u8],
    root: &[u8; 32],
) -> Result<VerifiedProofSet<'a>, ProofSetError> {
    pqsigner_erc7730::proof_set::verify_erc7730_proof_set_with_leaf_count(
        payload,
        root,
        crate::db_roots::ERC7730_DESCRIPTOR_COUNT,
    )
}

const CFI_CONTRACT_BIND_A: u32 = 0x43A9_17D2;
const CFI_CONTRACT_BIND_B: u32 = 0xB65C_E821;
const CFI_CONTRACT_BIND_VERDICT: u32 = 0x1DF2_6A94;
const CFI_CONTRACT_BIND_PUBLISH: u32 = 0xE807_35CB;
pub(crate) const CFI_CONTRACT_BIND_EXPECTED: u32 = crate::cfi_expected!(
    CFI_CONTRACT_BIND_A,
    CFI_CONTRACT_BIND_B,
    CFI_CONTRACT_BIND_VERDICT,
    CFI_CONTRACT_BIND_PUBLISH,
);

const CFI_EIP712_BIND_A: u32 = 0x52D7_A31C;
const CFI_EIP712_BIND_B: u32 = 0xAD28_5CE3;
const CFI_EIP712_BIND_VERDICT: u32 = 0x276B_D849;
const CFI_EIP712_BIND_PUBLISH: u32 = 0xD894_27B6;
pub(crate) const CFI_EIP712_BIND_EXPECTED: u32 = crate::cfi_expected!(
    CFI_EIP712_BIND_A,
    CFI_EIP712_BIND_B,
    CFI_EIP712_BIND_VERDICT,
    CFI_EIP712_BIND_PUBLISH,
);

/// FI-hardened proof-set membership + complete contract/nested binding proof.
///
/// The caller must volatile-initialize `verdict_out` to `FAIL_SENTINEL` and
/// later require both its independent readback and the caller-owned CFI
/// transcript. Keeping the counter caller-owned detects a skipped whole call;
/// reparsing the complete proof-set payload and deriving the exact nested
/// binding around a randomized gap detects a fault in either Merkle, wrapper,
/// context, interval, target, selector, policy, or child-preflight decision.
/// Each independent parse must reproduce the caller's exact verified set and
/// caller-owned expected nested binding (including an authoritative `None`),
/// preventing an unrooted child from gaining display authority.
#[inline(never)]
pub fn prove_contract_proof_set_binding(
    set: &VerifiedProofSet<'_>,
    root: &[u8; 32],
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    device_signer: &[u8; 20],
    expected_nested: Option<&NestedCallBinding>,
    verdict_out: &mut u32,
    cfi: &mut crate::fi::CfiCounter,
) {
    let expected_nested = expected_nested.copied();
    let ok_a = verify_erc7730_proof_set(set.raw_payload, root).is_ok_and(|verified| {
        core::hint::black_box(verified == *set)
            && derive_nested_call(tx, inner_data, &verified, device_signer)
                .is_ok_and(|derived| core::hint::black_box(derived == expected_nested))
    });
    cfi.bump(CFI_CONTRACT_BIND_A);
    crate::fi::wait_random();
    let ok_b = verify_erc7730_proof_set(
        core::hint::black_box(set.raw_payload),
        core::hint::black_box(root),
    )
    .is_ok_and(|verified| {
        core::hint::black_box(verified == *core::hint::black_box(set))
            && derive_nested_call(
                core::hint::black_box(tx),
                core::hint::black_box(inner_data),
                &verified,
                core::hint::black_box(device_signer),
            )
            .is_ok_and(|derived| {
                core::hint::black_box(derived == core::hint::black_box(expected_nested))
            })
    });
    cfi.bump(CFI_CONTRACT_BIND_B);
    let verdict = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(ok_a) && core::hint::black_box(ok_b)
    });
    cfi.bump(CFI_CONTRACT_BIND_VERDICT);
    // SAFETY: unique valid mutable reference supplied by the caller.
    unsafe { core::ptr::write_volatile(verdict_out, verdict) };
    cfi.bump(CFI_CONTRACT_BIND_PUBLISH);
}

/// FI-hardened Merkle-membership + EIP-712 domain binding proof. Caller
/// contract is identical to [`prove_contract_proof_set_binding`].
#[inline(never)]
pub fn prove_eip712_binding(
    ir: &Erc7730Ir<'_>,
    bundle: &[u8],
    root: &[u8; 32],
    chain_id: u64,
    domain_separator: &[u8; 32],
    verdict_out: &mut u32,
    cfi: &mut crate::fi::CfiCounter,
) {
    let ok_a = verify_erc7730_bundle(bundle, root).is_ok_and(|verified| {
        core::hint::black_box(verified.ir == *ir)
            && cross_check_eip712(&verified.ir, chain_id, domain_separator).is_ok()
    });
    cfi.bump(CFI_EIP712_BIND_A);
    crate::fi::wait_random();
    let ok_b = verify_erc7730_bundle(
        core::hint::black_box(bundle),
        core::hint::black_box(root),
    )
    .is_ok_and(|verified| {
        core::hint::black_box(verified.ir == *core::hint::black_box(ir))
            && cross_check_eip712(
                &verified.ir,
                core::hint::black_box(chain_id),
                core::hint::black_box(domain_separator),
            )
            .is_ok()
    });
    cfi.bump(CFI_EIP712_BIND_B);
    let verdict = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(ok_a) && core::hint::black_box(ok_b)
    });
    cfi.bump(CFI_EIP712_BIND_VERDICT);
    // SAFETY: unique valid mutable reference supplied by the caller.
    unsafe { core::ptr::write_volatile(verdict_out, verdict) };
    cfi.bump(CFI_EIP712_BIND_PUBLISH);
}

const CFI_KNOWN_QUERY_A: u32 = 0x6A31_9D47;
const CFI_KNOWN_QUERY_B: u32 = 0xB4C2_53E9;
const CFI_KNOWN_VERDICT: u32 = 0x19EF_A635;
const CFI_KNOWN_PUBLISH: u32 = 0xD827_4B13;
// `pub(crate)` because the production dispatcher lives under `tx::display`
// while the host WYSIWYS harness mounts that exact source under
// `crate::display_under_test`; both must validate the same caller-owned CFI
// transcript.
pub(crate) const CFI_KNOWN_EXPECTED: u32 = crate::cfi_expected!(
    CFI_KNOWN_QUERY_A,
    CFI_KNOWN_QUERY_B,
    CFI_KNOWN_VERDICT,
    CFI_KNOWN_PUBLISH,
);

/// Prove that the firmware catalogue does **not** contain a clear-sign
/// descriptor for this exact contract-call tuple.
///
/// The generated Bloom filter has no false negatives for compiled entries
/// (`dbgen::erc7730::round_trip_check` enforces that). False positives only
/// refuse an otherwise-unknown call, which is the safe failure direction. The
/// independent second query, sentinel verdict, and CFI counter make the
/// dangerous permission direction explicit: lower-rung fallback is allowed
/// only when this function publishes [`crate::fi::OK_SENTINEL`] into the
/// caller-owned, FAIL-preinitialized `verdict_out`. The caller-owned CFI
/// counter is bumped *inside* this non-inlined function, so skipping the whole
/// call leaves both independent proofs in their rejecting state.
#[inline(never)]
pub fn prove_unknown_contract_call(
    chain_id: u64,
    contract: &[u8; 20],
    selector: &[u8; 4],
    verdict_out: &mut u32,
    cfi: &mut crate::fi::CfiCounter,
) {
    let absent_a = !pqsigner_erc7730::known_calls::may_contain(
        crate::db_roots::ERC7730_KNOWN_CALLS_BLOOM,
        chain_id,
        contract,
        selector,
    );
    cfi.bump(CFI_KNOWN_QUERY_A);
    crate::fi::wait_random();
    let absent_b = !pqsigner_erc7730::known_calls::may_contain(
        crate::db_roots::ERC7730_KNOWN_CALLS_BLOOM,
        core::hint::black_box(chain_id),
        core::hint::black_box(contract),
        core::hint::black_box(selector),
    );
    cfi.bump(CFI_KNOWN_QUERY_B);

    let absent_verdict = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(absent_a) && core::hint::black_box(absent_b)
    });
    cfi.bump(CFI_KNOWN_VERDICT);
    // SAFETY: `verdict_out` is a unique, valid mutable reference supplied by
    // the caller. Volatile publication prevents LLVM from replacing the
    // caller's independent readback with this local SSA value.
    unsafe { core::ptr::write_volatile(verdict_out, absent_verdict) };
    cfi.bump(CFI_KNOWN_PUBLISH);
}

#[cfg(test)]
mod known_call_tests {
    use super::{prove_unknown_contract_call, CFI_KNOWN_EXPECTED};

    fn proof(chain_id: u64, contract: &[u8; 20], selector: &[u8; 4]) -> u32 {
        let mut verdict = crate::fi::FAIL_SENTINEL;
        let mut cfi = crate::fi::CfiCounter::new();
        prove_unknown_contract_call(chain_id, contract, selector, &mut verdict, &mut cfi);
        assert_eq!(
            cfi.check_into_sentinel(CFI_KNOWN_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        verdict
    }

    #[test]
    fn pinned_filter_requires_weth_deposit_descriptor() {
        let weth = hex::decode("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&weth);
        assert_ne!(
            proof(
                1,
                &contract,
                &[0xd0, 0xe3, 0x0d, 0xb0], // deposit()
            ),
            crate::fi::OK_SENTINEL,
        );
        assert_eq!(
            proof(1, &contract, &[0xff, 0xff, 0xff, 0xff]),
            crate::fi::OK_SENTINEL,
        );
    }

    #[test]
    fn pinned_filter_requires_descriptors_for_all_locked_celo_deployments() {
        let deployments = [
            (
                "stale mainnet implementation",
                42_220,
                "55e1a0c8f376964bd339167476063bfed7f213d5",
            ),
            (
                "canonical mainnet proxy",
                42_220,
                "6cc083aed9e3ebe302a6336dbc7c921c9f03349e",
            ),
            (
                "stale Alfajores deployment",
                44_787,
                "6a4cc5693dc5bfa3799c699f3b941ba2cb00c341",
            ),
        ];
        let selectors = [
            [0x58, 0xf8, 0x4a, 0x78], // delegateGovernanceVotes(address,uint256)
            [0xf8, 0x3d, 0x08, 0xba], // lock()
            [0xb2, 0xfb, 0x30, 0xcb], // relock(uint256,uint256)
            [0x18, 0x62, 0x9a, 0x92], // revokeDelegatedGovernanceVotes(address,uint256)
            [0x61, 0x98, 0xe3, 0x39], // unlock(uint256)
            [0x2e, 0x1a, 0x7d, 0x4d], // withdraw(uint256)
        ];

        for (deployment, chain_id, address) in deployments {
            let decoded = hex::decode(address).expect("valid LockedCelo address");
            let mut contract = [0u8; 20];
            contract.copy_from_slice(&decoded);
            for selector in selectors {
                assert_ne!(
                    proof(chain_id, &contract, &selector),
                    crate::fi::OK_SENTINEL,
                    "{deployment} LockedCelo tuple must require its descriptor: chain={chain_id} contract=0x{address} selector=0x{}",
                    hex::encode(selector),
                );
            }
        }
    }
}
// The live render path walks path programs through `render::resolve`.
// Deliberately expose only the container-field constants needed by that path;
// the retired `AbiView`/`AbiNode` interpreter stays off the secure-world API so
// it cannot be wired back in and create a second, incompatible walker.
pub use pqsigner_erc7730::abi::container_field;
