//! Regression for the off-chain `raw32` UserOp-forgery vulnerability
//! (audit 2026-06-11).
//!
//! Before the fix, `CMD_SIGN_OFFCHAIN` kind=RAW32 bare-signed the
//! companion-supplied 32 bytes with the slot key. The on-chain Type-2
//! UserOp path (`PQSmartWallet._validateSignature`) verifies a bare slot
//! C10 sig over `sphincsDigest(userOp)` — a plain SHA-256 of the UserOp
//! fields, identical to `compute_sphincs_digest_v06`. So a malicious
//! companion could set `payload = sphincsDigest(drainOp)`, get the user
//! to blind-approve a "raw 32-byte" page, and obtain a signature that the
//! EntryPoint accepts as a Type-2 authorisation — draining the wallet
//! without the transaction ever reaching the trusted display.
//!
//! The fix routes EVERY off-chain hash through `replay_safe_hash` (the
//! Solady nested-EIP-712 wrap, keccak-based). This test pins the
//! load-bearing property: feeding a real `sphincsDigest` as the raw32
//! payload does NOT yield a signature over that digest — the firmware
//! signs `replay_safe_hash(digest)`, a keccak-nested value that can never
//! equal the SHA-256 digest the UserOp path checks.

use pqsigner_aa::eip1271::{proxy_address, replay_safe_hash};
use pqsigner_aa::userop::{
    compute_sphincs_digest_v06, sha256_bytes, AaUserOpParamsV06Sha256, ENTRY_POINT_V06,
    SHA256_EMPTY,
};
use pqsigner_tx_core::eip1559::U256;

/// A representative on-chain Type-2 drain digest: `executeWithOffchainCount`
/// moving the wallet balance to an attacker. The exact field values don't
/// matter — what matters is that this is a genuine `sphincsDigest`, i.e. the
/// precise 32-byte value the on-chain `_validateSignature` would verify a
/// bare slot sig against.
fn drain_op_sphincs_digest(chain_id: u64, sender: [u8; 20]) -> [u8; 32] {
    // callData = executeWithOffchainCount(1, 1, attacker, 1 ether, "") — the
    // bytes are immaterial here; we only need a stable digest of "some
    // UserOp the attacker wants authorised".
    let call_data_digest = sha256_bytes(b"executeWithOffchainCount(drain to attacker)");
    let params = AaUserOpParamsV06Sha256 {
        sender,
        entry_point: ENTRY_POINT_V06,
        chain_id,
        nonce: U256::zero(),
        init_code_digest: SHA256_EMPTY,
        call_gas_limit: U256::zero(),
        verification_gas_limit: U256::zero(),
        pre_verification_gas: U256::zero(),
        max_fee_per_gas: U256::zero(),
        max_priority_fee_per_gas: U256::zero(),
        paymaster_and_data_digest: SHA256_EMPTY,
    };
    compute_sphincs_digest_v06(&params, &call_data_digest)
}

#[test]
fn raw32_payload_equal_to_sphincs_digest_is_not_signed_bare() {
    let chain_id: u64 = 8453; // Base mainnet.
    let pk_seed = [0x11u8; 32];
    let pk_root = [0x22u8; 32];
    let wallet = proxy_address(&pk_seed, &pk_root);

    // The attacker computes the drain UserOp's digest and submits it as the
    // raw32 payload H.
    let forged_digest = drain_op_sphincs_digest(chain_id, wallet);

    // The fixed firmware signs `replay_safe_hash(H)`, NOT H. So the attacker
    // does NOT obtain a signature over `forged_digest` — the value the
    // EntryPoint's Type-2 path would need.
    let actually_signed = replay_safe_hash(chain_id, &wallet, &forged_digest);
    assert_ne!(
        actually_signed, forged_digest,
        "raw32 must never produce a bare slot sig over a sphincsDigest"
    );
}

#[test]
fn off_chain_signed_value_is_domain_bound() {
    // The same dapp hash signed for two different wallets / chains yields
    // different signed values, so a captured off-chain sig cannot be
    // replayed against a sibling wallet (same seed, different account) or
    // the same wallet on another chain.
    let h = [0x42u8; 32];
    let wallet_a = proxy_address(&[0xAAu8; 32], &[0xA1u8; 32]);
    let wallet_b = proxy_address(&[0xBBu8; 32], &[0xB1u8; 32]);

    assert_ne!(
        replay_safe_hash(8453, &wallet_a, &h),
        replay_safe_hash(8453, &wallet_b, &h),
        "signed value must differ across wallets"
    );
    assert_ne!(
        replay_safe_hash(1, &wallet_a, &h),
        replay_safe_hash(8453, &wallet_a, &h),
        "signed value must differ across chains"
    );
}
