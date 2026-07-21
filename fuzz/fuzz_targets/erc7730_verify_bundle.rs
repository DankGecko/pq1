//! libFuzzer harness for the legacy ERC-7730 bundle verifier and the
//! backward-compatible proof-set verifier. Contract-call handlers consume the
//! latter; off-chain EIP-712 remains legacy-only. Same model as
//! `tx_erc20_verify_bundle`: a zero root so the Merkle walk always rejects,
//! exercising every path before the final root compare (wrapper and bundle
//! length prefixes, IR parse, pool/formats bounds, proof cap, exact EOF).
//!
//! Property: both verifier calls must terminate without panicking for any
//! input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_erc7730::bundle::verify_erc7730_bundle;
use pqsigner_erc7730::proof_set::verify_erc7730_proof_set;

const ZERO_ROOT: [u8; 32] = [0u8; 32];

fuzz_target!(|data: &[u8]| {
    let _ = verify_erc7730_bundle(data, &ZERO_ROOT);
    let _ = verify_erc7730_proof_set(data, &ZERO_ROOT);
});
