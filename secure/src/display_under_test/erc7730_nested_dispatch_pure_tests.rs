//! Feature-backed behavior tests for the production proof-set dispatcher.
//!
//! These tests deliberately compile the checked-in synthetic parent/child
//! descriptors through dbgen, authenticate their generated Merkle proofs, and
//! then call the exact dispatcher used by the single and batch sign handlers.

use std::path::PathBuf;

use pqsigner_erc7730::{
    display::render::{nested_binding_commitment, INTENT_PUBLICATION_STATIC},
    proof_set::{
        verify_erc7730_proof_set_with_leaf_count, VerifiedProofSet, ERC7730_PROOF_SET_COUNT,
        ERC7730_PROOF_SET_MAGIC, ERC7730_PROOF_SET_VERSION,
    },
    render::{
        calldata_policy::{
            TEST_NESTED_CALLDATA_PARENT_CONTRACT, TEST_NESTED_CALLDATA_PARENT_SELECTOR,
        },
        RenderErr,
    },
};
use pqsigner_tx_core::hash::keccak256;
use sphincs_tz_shared::{
    APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, EXEC_TRANSACTION_SELECTOR,
    MULTI_SEND_SELECTOR, SAFE_OFF_CHAIN_ID, SAFE_OFF_DATA_HASH, SAFE_OFF_NONCE, SAFE_OFF_OPERATION,
    SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_TO, SAFE_V1_CANONICAL_LEN, SET_PRE_SIGNATURE_SELECTOR,
};

use super::dispatch::{
    legacy_fee_pages_required, pick_sign_pages_with_erc7730_evidence, DispatchPageProofs,
};
use super::erc7730_render_pure_tests::{build_registry, synth_bundle};
use crate::{
    names::NameResolver,
    tx::{
        eip1559::{Eip1559Tx, U256},
        eip712::safe::{compute_safe_tx_hash, verify_and_bind_trailer},
        erc7730::derive_nested_call,
    },
};

const CHAIN_ID: u64 = 31_337;
const CHILD_CONTRACT: [u8; 20] = [0x56; 20];
const CHILD_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const SIGNER: [u8; 20] = [0xa5; 20];
const SAFE_CONTRACT: [u8; 20] = [
    0x41, 0x67, 0x5c, 0x09, 0x9f, 0x32, 0x34, 0x1b, 0xf8, 0x4b, 0xfc, 0x53, 0x82, 0xaf, 0x53, 0x4d,
    0xf5, 0xc7, 0x46, 0x1a,
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("secure sits below the workspace root")
        .to_path_buf()
}

fn build_e2e() -> &'static dbgen::erc7730::Erc7730BuildResult {
    static E2E: std::sync::OnceLock<dbgen::erc7730::Erc7730BuildResult> =
        std::sync::OnceLock::new();
    E2E.get_or_init(|| {
        let root = workspace_root();
        let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20-e2e.json"))
            .expect("build E2E ERC-20 capabilities");
        dbgen::erc7730::build_e2e_db_with_policy_override_and_erc20_capabilities(
            &root.join("secure/data/erc7730-e2e"),
            &root.join("secure/data/erc7730/policy.toml"),
            false,
            None,
            &erc20.capabilities,
        )
        .expect("build explicitly authorized nested E2E catalogue")
    })
}

fn entry_for<'a>(
    result: &'a dbgen::erc7730::Erc7730BuildResult,
    contract: &[u8; 20],
) -> &'a dbgen::erc7730::Emitted {
    result
        .entries
        .iter()
        .find(|entry| entry.chain_id == CHAIN_ID && entry.contract == *contract)
        .expect("exact synthetic deployment is present")
}

fn nested_payload() -> Vec<u8> {
    let result = build_e2e();
    let outer_entry = entry_for(result, &TEST_NESTED_CALLDATA_PARENT_CONTRACT);
    let child_entry = entry_for(result, &CHILD_CONTRACT);
    let outer = synth_bundle(&result.blob, &outer_entry.ir_bytes, outer_entry.leaf_index);
    let child = synth_bundle(&result.blob, &child_entry.ir_bytes, child_entry.leaf_index);
    let mut payload = Vec::with_capacity(8 + outer.len() + child.len());
    payload.extend_from_slice(&ERC7730_PROOF_SET_MAGIC.to_be_bytes());
    payload.push(ERC7730_PROOF_SET_VERSION);
    payload.push(ERC7730_PROOF_SET_COUNT as u8);
    for bundle in [&outer, &child] {
        payload.extend_from_slice(&(bundle.len() as u16).to_be_bytes());
        payload.extend_from_slice(bundle);
    }
    payload
}

fn verify_e2e_set(payload: &[u8]) -> VerifiedProofSet<'_> {
    let result = build_e2e();
    verify_erc7730_proof_set_with_leaf_count(payload, &result.root, result.leaf_count)
        .expect("generated E2E proof set verifies")
}

fn word_from_usize(value: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&(value as u64).to_be_bytes());
    word
}

fn child_calldata(selector: [u8; 4]) -> Vec<u8> {
    let mut data = selector.to_vec();
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&[0x78; 20]);
    data.extend_from_slice(&word_from_usize(123_456));
    data
}

fn outer_calldata(child: &[u8]) -> Vec<u8> {
    let mut data = TEST_NESTED_CALLDATA_PARENT_SELECTOR.to_vec();
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&CHILD_CONTRACT);
    data.extend_from_slice(&word_from_usize(64));
    data.extend_from_slice(&word_from_usize(child.len()));
    data.extend_from_slice(child);
    data.resize(data.len() + (32 - child.len() % 32) % 32, 0);
    data
}

fn tx(chain_id: u64, contract: [u8; 20], data_len: usize) -> Eip1559Tx {
    Eip1559Tx {
        chain_id,
        nonce: 9,
        max_priority_fee_per_gas: U256(word_from_usize(1_500_000_000)),
        max_fee_per_gas: U256(word_from_usize(30_000_000_000)),
        gas_limit: 100_000,
        to: Some(contract),
        value: U256::zero(),
        data_len,
        ..Eip1559Tx::default()
    }
}

fn final_verdict(
    proofs: &DispatchPageProofs,
    pages: &super::Pages,
    tx: &Eip1559Tx,
    safe_present: bool,
) -> u32 {
    let mut verdict = crate::fi::FAIL_SENTINEL;
    proofs.final_set_proof(
        pages,
        tx,
        legacy_fee_pages_required(false, safe_present, false),
        &mut verdict,
    );
    verdict
}

fn contains_row(pages: &super::Pages, expected: &[u8]) -> bool {
    pages.as_slice().iter().flatten().any(|row| {
        let end = row
            .iter()
            .rposition(|byte| *byte != b' ')
            .map_or(0, |position| position + 1);
        &row[..end] == expected
    })
}

#[test]
fn production_dispatcher_nested_fixture_uses_v2_and_refuses_binding_or_commitment_faults() {
    let payload = nested_payload();
    let set = verify_e2e_set(&payload);
    let calldata = outer_calldata(&child_calldata(CHILD_SELECTOR));
    let tx = tx(
        CHAIN_ID,
        TEST_NESTED_CALLDATA_PARENT_CONTRACT,
        calldata.len(),
    );
    let binding = derive_nested_call(&tx, &calldata, &set, &SIGNER)
        .expect("nested derivation succeeds")
        .expect("fixture selects a nested child");
    let commitment = nested_binding_commitment(&binding);
    let resolver = NameResolver::new();

    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let pages = pick_sign_pages_with_erc7730_evidence(
        &tx,
        &calldata,
        &SIGNER,
        None,
        None,
        None,
        Some(&set),
        Some(&binding),
        None,
        None,
        &resolver,
        &mut proofs,
    )
    .expect("exact production dispatcher accepts the rooted nested fixture");
    assert!(contains_row(&pages, b"Forward call"));
    assert!(contains_row(&pages, b"Transfer"));

    let (receipt, retained_commitment) = proofs.erc7730_transcript_for_test();
    assert_eq!(receipt.state_code(), INTENT_PUBLICATION_STATIC);
    assert_eq!(retained_commitment, Some(commitment));
    assert!(receipt.range_matches_with_nested(&pages, 0, &commitment));
    assert!(
        !receipt.range_matches(&pages, 0),
        "V2 must be domain-disjoint from V1"
    );
    assert_eq!(
        final_verdict(&proofs, &pages, &tx, false),
        crate::fi::OK_SENTINEL
    );

    let mut wrong_binding = binding;
    wrong_binding.child_leaf.hash[0] ^= 1;
    let mut wrong_proofs = DispatchPageProofs::new();
    wrong_proofs.fail_initialize();
    assert!(pick_sign_pages_with_erc7730_evidence(
        &tx,
        &calldata,
        &SIGNER,
        None,
        None,
        None,
        Some(&set),
        Some(&wrong_binding),
        None,
        None,
        &resolver,
        &mut wrong_proofs,
    )
    .is_err());

    let mut wrong_commitment = commitment;
    wrong_commitment[0] ^= 1;
    assert!(!receipt.range_matches_with_nested(&pages, 0, &wrong_commitment));
    proofs.corrupt_erc7730_nested_commitment_for_test();
    assert_ne!(
        final_verdict(&proofs, &pages, &tx, false),
        crate::fi::OK_SENTINEL,
        "a retained commitment fault must fail the final production proof"
    );
}

#[test]
fn production_dispatcher_legacy_one_bundle_stays_v1() {
    let result = build_e2e();
    let child = entry_for(result, &CHILD_CONTRACT);
    let payload = synth_bundle(&result.blob, &child.ir_bytes, child.leaf_index);
    let set = verify_e2e_set(&payload);
    assert!(set.child.is_none());
    let calldata = child_calldata(CHILD_SELECTOR);
    let tx = tx(CHAIN_ID, CHILD_CONTRACT, calldata.len());
    assert_eq!(derive_nested_call(&tx, &calldata, &set, &SIGNER), Ok(None));

    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let pages = pick_sign_pages_with_erc7730_evidence(
        &tx,
        &calldata,
        &SIGNER,
        None,
        None,
        None,
        Some(&set),
        None,
        None,
        None,
        &NameResolver::new(),
        &mut proofs,
    )
    .expect("legacy one-bundle proof set renders through the production API");
    let (receipt, retained_commitment) = proofs.erc7730_transcript_for_test();
    assert_eq!(retained_commitment, None);
    assert!(receipt.range_matches(&pages, 0));
    assert!(!receipt.range_matches_with_nested(&pages, 0, &[0x42; 32]));
    assert_eq!(
        final_verdict(&proofs, &pages, &tx, false),
        crate::fi::OK_SENTINEL
    );
}

fn safe_trailer(raw_data: &[u8]) -> (Vec<u8>, [u8; APPROVE_HASH_CALLDATA_LEN]) {
    let mut canonical = [0u8; SAFE_V1_CANONICAL_LEN];
    canonical[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&1u64.to_be_bytes());
    canonical[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(&SAFE_CONTRACT);
    canonical[SAFE_OFF_TO..SAFE_OFF_TO + 20].copy_from_slice(&[0x70; 20]);
    canonical[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&keccak256(raw_data));
    canonical[SAFE_OFF_OPERATION] = 0;
    canonical[SAFE_OFF_NONCE + 31] = 7;

    let safe_hash = compute_safe_tx_hash(&canonical).expect("compute Safe hash");
    let mut calldata = [0u8; APPROVE_HASH_CALLDATA_LEN];
    calldata[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    calldata[4..].copy_from_slice(&safe_hash);

    let mut trailer = Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + raw_data.len());
    trailer.extend_from_slice(&canonical);
    trailer.extend_from_slice(&(raw_data.len() as u16).to_be_bytes());
    trailer.extend_from_slice(raw_data);
    (trailer, calldata)
}

#[test]
fn valid_generic_evidence_beside_safe_preserves_native_precedence() {
    let registry = build_registry();
    let safe_entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == 1
                && entry.contract == SAFE_CONTRACT
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-Safe-1.4.1.json")
        })
        .expect("production Safe 1.4.1 descriptor");
    let generic_payload = synth_bundle(&registry.blob, &safe_entry.ir_bytes, safe_entry.leaf_index);
    let generic = verify_erc7730_proof_set_with_leaf_count(
        &generic_payload,
        &registry.root,
        registry.leaf_count,
    )
    .expect("production Safe descriptor proof is rooted and canonical");
    let raw_safe_call = child_calldata(CHILD_SELECTOR);
    let (safe_bundle, calldata) = safe_trailer(&raw_safe_call);
    let safe = verify_and_bind_trailer(&safe_bundle, &calldata, 1, &SAFE_CONTRACT)
        .expect("Safe trailer verifies and binds");
    let tx = tx(1, SAFE_CONTRACT, calldata.len());
    assert_eq!(
        derive_nested_call(&tx, &calldata, &generic, &SIGNER),
        Ok(None),
        "generic evidence is valid for the same signed call"
    );
    let resolver = NameResolver::new();

    let mut native_only_proofs = DispatchPageProofs::new();
    native_only_proofs.fail_initialize();
    let native_only = pick_sign_pages_with_erc7730_evidence(
        &tx,
        &calldata,
        &SIGNER,
        None,
        Some(&safe),
        None,
        None,
        None,
        None,
        None,
        &resolver,
        &mut native_only_proofs,
    )
    .expect("native Safe route renders");

    let mut competing_proofs = DispatchPageProofs::new();
    competing_proofs.fail_initialize();
    let competing = pick_sign_pages_with_erc7730_evidence(
        &tx,
        &calldata,
        &SIGNER,
        None,
        Some(&safe),
        None,
        Some(&generic),
        None,
        None,
        None,
        &resolver,
        &mut competing_proofs,
    )
    .expect("valid generic evidence must not displace Safe");
    assert_eq!(competing.as_slice(), native_only.as_slice());
    let (receipt, commitment) = competing_proofs.erc7730_transcript_for_test();
    assert_eq!(commitment, None);
    assert_eq!(
        receipt,
        pqsigner_erc7730::display::render::ContractTranscriptReceipt::unpublished()
    );
    assert_eq!(
        final_verdict(&competing_proofs, &competing, &tx, true),
        crate::fi::OK_SENTINEL
    );
}

#[test]
fn reserved_child_selectors_refuse_at_shared_single_batch_derivation_seam() {
    let payload = nested_payload();
    let set = verify_e2e_set(&payload);
    for selector in [
        APPROVE_HASH_SELECTOR,
        EXEC_TRANSACTION_SELECTOR,
        SET_PRE_SIGNATURE_SELECTOR,
        MULTI_SEND_SELECTOR,
    ] {
        let calldata = outer_calldata(&child_calldata(selector));
        let tx = tx(
            CHAIN_ID,
            TEST_NESTED_CALLDATA_PARENT_CONTRACT,
            calldata.len(),
        );
        assert!(matches!(
            derive_nested_call(&tx, &calldata, &set, &SIGNER),
            Err(RenderErr::Reject("7730 nested native child selector"))
        ));
    }
}
