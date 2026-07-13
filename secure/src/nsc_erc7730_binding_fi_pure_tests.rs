//! Host-side structural regressions for ERC-7730 FI binding gates.
//!
//! A descriptor is useful only after its exact bytes are proven under the
//! firmware root and bound to the exact transaction context. The non-inlined
//! proof helpers independently re-verify the bundle/root + full cross-check
//! twice, require both parsed views to equal the caller's IR, publish into a
//! caller-owned volatile FAIL slot, and bump a caller-owned CFI transcript.
//! That composition covers a faulted initial Merkle reject, either independent
//! membership/binding decision, and a skipped whole proof call.

const CMD_SIGN_USEROP: &str = include_str!("nsc/cmd_sign_userop.rs");
const CMD_SIGN_USEROP_BATCH: &str = include_str!("nsc/cmd_sign_userop_batch.rs");
const CMD_SIGN_OFFCHAIN: &str = include_str!("nsc/cmd_sign_offchain.rs");
const ERC7730_GLUE: &str = include_str!("tx/erc7730.rs");
const DISPLAY_DISPATCH: &str = include_str!("tx/display/dispatch.rs");
const SAFE_DISPLAY: &str = include_str!("tx/display/safe_display.rs");

fn count_substr(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

fn assert_ordered(source: &str, first: &str, second: &str, third: &str, fourth: &str) {
    let a = source.find(first).unwrap_or_else(|| panic!("missing {first}"));
    let b = source[a..]
        .find(second)
        .map(|p| a + p)
        .unwrap_or_else(|| panic!("missing {second} after {first}"));
    let c = source[b..]
        .find(third)
        .map(|p| b + p)
        .unwrap_or_else(|| panic!("missing {third} after {second}"));
    let d = source[c..]
        .find(fourth)
        .map(|p| c + p)
        .unwrap_or_else(|| panic!("missing {fourth} after {third}"));
    assert!(a < b && b < c && c < d);
}

fn assert_dual_reject_gates(
    source: &str,
    volatile_read: &str,
    cfi_check: &str,
    gate_a: &str,
    gate_b: &str,
) {
    let normalized = source
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" .", ".");
    assert_eq!(
        count_substr(&normalized, volatile_read),
        2,
        "permission evidence must be volatile-read independently for both gates",
    );
    assert_eq!(
        count_substr(&normalized, cfi_check),
        2,
        "caller-owned CFI must be independently checked by both gates",
    );
    assert_eq!(count_substr(&normalized, gate_a), 1, "missing first reject gate");
    assert_eq!(count_substr(&normalized, gate_b), 1, "missing second reject gate");
    assert_ordered(
        &normalized,
        gate_a,
        "crate::fi::wait_random();",
        cfi_check,
        gate_b,
    );
}

#[test]
fn proof_helpers_recompute_membership_and_binding_twice() {
    let contract_start = ERC7730_GLUE
        .find("pub fn prove_contract_binding(")
        .expect("missing contract proof helper");
    let eip712_start = ERC7730_GLUE
        .find("pub fn prove_eip712_binding(")
        .expect("missing EIP-712 proof helper");
    let known_start = ERC7730_GLUE[eip712_start..]
        .find("const CFI_KNOWN_QUERY_A")
        .map(|offset| eip712_start + offset)
        .expect("missing end anchor for EIP-712 proof helper");
    let contract = &ERC7730_GLUE[contract_start..eip712_start];
    let eip712 = &ERC7730_GLUE[eip712_start..known_start];

    for (proof, cross_check) in [
        (contract, "cross_check_contract("),
        (eip712, "cross_check_eip712("),
    ] {
        assert_eq!(
            count_substr(proof, "verify_erc7730_bundle("),
            2,
            "each proof helper must independently verify membership twice",
        );
        assert_eq!(
            count_substr(proof, "verified.ir == *"),
            2,
            "each parse must equal the caller's exact IR view",
        );
        assert_eq!(
            count_substr(proof, cross_check),
            2,
            "each independently verified IR must also pass its context check",
        );
        assert_ordered(
            proof,
            "let ok_a = verify_erc7730_bundle(",
            cross_check,
            "crate::fi::wait_random();",
            "let ok_b = verify_erc7730_bundle(",
        );
        assert_ordered(
            proof,
            "let ok_b = verify_erc7730_bundle(",
            cross_check,
            "core::hint::black_box(ok_a) && core::hint::black_box(ok_b)",
            "core::ptr::write_volatile(verdict_out, verdict)",
        );
    }

    assert_eq!(
        count_substr(ERC7730_GLUE, "verify_erc7730_bundle("),
        4,
        "both binding helpers must independently verify membership twice",
    );
    assert!(ERC7730_GLUE.contains("pub fn verify_erc7730_bundle<'a>("));
    assert_ordered(
        ERC7730_GLUE,
        "pqsigner_erc7730::bundle::verify_erc7730_bundle_with_leaf_count(",
        "bundle,",
        "root,",
        "crate::db_roots::ERC7730_DESCRIPTOR_COUNT",
    );
    assert_eq!(count_substr(ERC7730_GLUE, "verified.ir == *"), 4);
    assert_eq!(count_substr(ERC7730_GLUE, "cross_check_contract("), 2);
    assert_eq!(count_substr(ERC7730_GLUE, "cross_check_eip712("), 2);
    assert!(ERC7730_GLUE.contains("core::ptr::write_volatile(verdict_out, verdict)"));
}

#[test]
fn every_signing_surface_requires_volatile_verdict_and_caller_cfi() {
    for (source, proof, expected) in [
        (
            CMD_SIGN_USEROP,
            "prove_contract_binding(",
            "CFI_CONTRACT_BIND_EXPECTED",
        ),
        (
            CMD_SIGN_USEROP_BATCH,
            "prove_contract_binding(",
            "CFI_CONTRACT_BIND_EXPECTED",
        ),
        (
            CMD_SIGN_OFFCHAIN,
            "prove_eip712_binding(",
            "CFI_EIP712_BIND_EXPECTED",
        ),
    ] {
        assert_eq!(count_substr(source, proof), 1, "missing unique {proof}");
        assert!(source.contains("ERC7730_DESCRIPTORS_ROOT"));
        assert!(source.contains("core::ptr::write_volatile("));
        assert!(source.contains("crate::fi::FAIL_SENTINEL"));
        assert_eq!(
            count_substr(
                source,
                "core::ptr::read_volatile(&bind_verdict_slot)",
            ),
            2,
        );
        assert!(source.contains(expected));
        assert!(source.contains("crate::fi::scrub_sentinel_register();"));
        assert!(source.contains("bind_cfi_verdict_a"));
        assert!(source.contains("bind_cfi_verdict_b"));
    }
}

#[test]
fn every_permission_surface_has_two_independent_final_reject_gates() {
    for source in [CMD_SIGN_USEROP, CMD_SIGN_USEROP_BATCH, CMD_SIGN_OFFCHAIN] {
        assert_dual_reject_gates(
            source,
            "core::ptr::read_volatile(&bind_verdict_slot)",
            "bind_cfi.check_into_sentinel(",
            "if bind_gate_a != crate::fi::OK_SENTINEL",
            "if bind_gate_b != crate::fi::OK_SENTINEL",
        );
        assert_eq!(
            count_substr(source, "7730 binding fail"),
            2,
            "each independent binding reject must terminate visibly",
        );
    }

    assert_dual_reject_gates(
        DISPLAY_DISPATCH,
        "core::ptr::read_volatile(&unknown_verdict_slot)",
        "unknown_cfi.check_into_sentinel(",
        "if unknown_gate_a != crate::fi::OK_SENTINEL",
        "if unknown_gate_b != crate::fi::OK_SENTINEL",
    );
    assert_eq!(
        count_substr(DISPLAY_DISPATCH, "7730 proof needed"),
        2,
        "both direct-dispatch reject gates must refuse signing",
    );

    assert_dual_reject_gates(
        SAFE_DISPLAY,
        "core::ptr::read_volatile(&unknown_verdict_slot)",
        "unknown_cfi.check_into_sentinel(",
        "if unknown_gate_a != crate::fi::OK_SENTINEL",
        "if unknown_gate_b != crate::fi::OK_SENTINEL",
    );
}

#[test]
fn no_binding_site_claims_one_cached_verdict_is_recomputation() {
    for source in [CMD_SIGN_USEROP, CMD_SIGN_USEROP_BATCH, CMD_SIGN_OFFCHAIN] {
        assert!(!source.contains("Compute the verdict once"));
        assert!(!source.contains("computed once into `bind_ok`"));
        assert!(!source.contains("double-evaluate without re-running"));
    }
}
