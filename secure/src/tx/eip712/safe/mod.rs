//! Safe multisig (`approveHash`) EIP-712 typed-data clear-signing.
//!
//! Targets Safe contracts v1.3.0 and later — the dominant deployments on
//! Ethereum mainnet and L2s today. Older Safes (v1.1.x) used a domain
//! separator without `chainId`, which produces a different `safeTxHash`
//! and therefore self-rejects via the calldata cross-check below.
//!
//! ## How it differs from the CowSwap v3 path
//!
//! Both protocols are EIP-712 typed-data approvals signed by the
//! wallet, but the bind story is structurally different:
//!
//!   * **CowSwap setPreSignature**: the calldata carries an opaque
//!     `orderUid` (a 32-byte EIP-712 digest + 20-byte owner + 4-byte
//!     validTo). The order's actual *fields* are nowhere in the
//!     calldata, so the native CoW trailer carries the canonical order;
//!     firmware re-hashes it on-device and cross-checks the orderUid.
//!   * **Safe approveHash**: the calldata carries the EIP-712
//!     `safeTxHash` *itself*. The trailer brings the canonical SafeTx
//!     fields plus the raw inner-call data. The firmware natively
//!     keccaks (raw_data → data_hash, then canonical → safeTxHash)
//!     and byte-compares the result against `inner_data[4..36]` using the
//!     firmware's native keccak primitive.
//!
//! This module exposes:
//!
//!   * [`SafeTx`] — typed accessor over a verified canonical buffer.
//!   * [`decode_canonical`] — parse + range-check the 281-byte canonical.
//!   * [`compute_safe_tx_hash`] — natively recompute the Safe v1.3.0+
//!     EIP-712 digest from a canonical buffer.
//!   * [`verify`] — top-level trailer verification that
//!     `cmd_sign_userop` invokes (gated off host tests like CoW v3).

use super::{keccak, Eip712Error};
use sphincs_tz_shared::{
    APPROVE_HASH_SELECTOR, SAFE_DOMAIN_TYPEHASH, SAFE_TX_TYPEHASH, SAFE_V1_CANONICAL_LEN,
};

// Like the native CoW path, the Safe verifier depends only on keccak and
// our own decode + digest helpers, all available on host.
pub mod verify;
pub use verify::{verify_and_bind_trailer, VerifiedSafeV1};

// Pure-logic Safe-mgmt decoder. Host-runnable; renderer lives in the
// `#[cfg(not(test))]`-gated `crate::tx::display::safe_mgmt` shim.
pub mod mgmt_decode;

// Pure-logic `execTransaction` decoder + lightweight verifier. Used by
// `cmd_sign_userop` when the inner calldata directly invokes a Safe's
// `execTransaction(...)` rather than `approveHash(bytes32)`; no separate
// trailer is needed because the SafeTx fields are encoded into the
// calldata's argument list.
pub mod exec_decode;
pub use exec_decode::{verify_and_bind_exec, DecodedExec, VerifiedSafeExec};

// Pure-logic CoW-binding resolution for Safe-wrapped `setPreSignature`
// orders. Host-runnable; shared by both gateway handlers and their
// downgrade gates so the "is this Safe inner call a CoW presign?"
// predicate has exactly one definition.
pub mod cow_binding;
pub use cow_binding::{
    direct_cow_target_ok, resolve_cow_binding, safe_inner_is_cow_presign, CowBinding,
};

// Pure-logic strict decoder + classifier for Safe `MultiSendCallOnly`
// batches (SafeTx DELEGATECALL into the pinned multiSend deployments).
// Host-runnable; owns the single `operation == 1` acceptance predicate
// shared by both Safe verifiers, the CoW-binding resolver and the
// renderer. Consumers path through `multi_send::` directly.
pub mod multi_send;

/// Does metadata name the direct target, or a record inside an actual pinned
/// `MultiSendCallOnly` delegatecall?
///
/// Callers must supply facts decoded from a verified Safe context. Keeping the
/// execution-shape predicate here prevents a merely MultiSend-shaped ordinary
/// call from becoming nested metadata authority, and gives the handler and
/// display dispatcher one rule instead of two security-sensitive copies.
#[must_use]
pub(crate) fn erc20_metadata_matches_verified_safe_call(
    operation: u8,
    inner_to: &[u8; 20],
    data: &[u8],
    token_contract: &[u8; 20],
) -> bool {
    inner_to == token_contract
        || (multi_send::is_multisend_claim(operation, inner_to, data)
            && multi_send::any_record_to_matches(data, token_contract))
}

#[cfg(test)]
mod erc20_metadata_context_tests {
    use super::*;

    fn exec_with_data<'a>(to: [u8; 20], operation: u8, data: &'a [u8]) -> VerifiedSafeExec<'a> {
        VerifiedSafeExec {
            chain_id: 1,
            safe_address: [0x55; 20],
            decoded: DecodedExec {
                to,
                value: [0u8; 32],
                operation,
                safe_tx_gas: [0u8; 32],
                base_gas: [0u8; 32],
                gas_price: [0u8; 32],
                gas_token: [0u8; 20],
                refund_receiver: [0u8; 20],
                data,
                signatures: &[],
            },
        }
    }

    #[test]
    fn verified_safe_direct_target_is_accepted() {
        let token = [0x22; 20];
        let exec = exec_with_data(token, 0, &[]);
        assert!(erc20_metadata_matches_verified_safe_call(
            exec.decoded.operation,
            &exec.decoded.to,
            exec.decoded.data,
            &token,
        ));
    }

    #[test]
    fn ordinary_verified_exec_cannot_borrow_from_multisend_shaped_data() {
        use super::multi_send::test_util::{encode_multisend, pack_record};

        let token = [0x22; 20];
        let packed = pack_record(0, &token, &[0u8; 32], &[]);
        let data = encode_multisend(&packed);
        assert!(multi_send::any_record_to_matches(&data, &token));

        // A CALL to an arbitrary contract is a valid Safe execution, but it
        // is not a pinned MultiSendCallOnly DELEGATECALL. Its calldata must
        // not be interpreted as a nested metadata-capability list.
        let ordinary = exec_with_data([0x33; 20], 0, &data);
        assert!(!erc20_metadata_matches_verified_safe_call(
            ordinary.decoded.operation,
            &ordinary.decoded.to,
            ordinary.decoded.data,
            &token,
        ));

        let multisend = exec_with_data(
            sphincs_tz_shared::MULTISEND_CALL_ONLY_ADDRESSES[0],
            1,
            &data,
        );
        assert!(erc20_metadata_matches_verified_safe_call(
            multisend.decoded.operation,
            &multisend.decoded.to,
            multisend.decoded.data,
            &token,
        ));
    }
}

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod extra_tests;

// ---------------------------------------------------------------------------
// Decoded SafeTx
// ---------------------------------------------------------------------------

/// Decoded SafeTx fields — re-exported from the host-compilable,
/// Kani-verified [`pqsigner_tx::safe_tx`] (decode-soundness: accept ⟺
/// `operation ≤ 1`, every field a verbatim copy from its canonical
/// offset). Borrows nothing — every field is owned and the struct is
/// `Copy`. Re-exported here so `struct_hash`, `compute_safe_tx_hash`,
/// the renderer, and every test/caller stay byte-identical.
pub use pqsigner_tx::safe_tx::SafeTx;

/// True when `inner_data` bears the Safe `approveHash(bytes32)` selector and
/// therefore MUST clear-sign through a verified `safe_v1` trailer — keyed on
/// the **selector alone** (audit 2026-06-28 — approveHash gate length bypass).
///
/// The handler-side mandatory gate that forces `approveHash` to clear-sign
/// previously required an *exact* calldata length (`== APPROVE_HASH_CALLDATA_LEN`,
/// 36 B). That is a parser differential against the on-chain Safe singleton:
/// `Safe.approveHash(bytes32)` decodes word `[4..36]` and **ignores trailing
/// calldata** (Solidity external dispatch never reverts on extra bytes). So a
/// hostile companion could append a single padding byte — `selector ‖ hash(32)
/// ‖ 0x00`, length 37 — to make the exact-length test false, skip the gate, and
/// fall through to a *generic blind-sign* of an `approveHash` that on-chain
/// pre-approves an arbitrary, never-displayed SafeTx (a Safe treats an owner's
/// `approveHash` as that owner's full signature on the whole SafeTx). The
/// `safe_v1` verifier (`verify.rs`) also bails on `len != 36`, so an over-long
/// `approveHash` has no clear-sign path at all — it could ONLY blind-sign.
///
/// Keying on the selector alone (matching the CoW `setPreSignature` gate, which
/// was already length-robust) closes the differential: any `approveHash`-
/// selectored inner call that did not produce a verified `safe_v1` canonical is
/// refused, never blind-signed. A well-formed clear-signable `approveHash` is
/// exactly 36 B and always arrives with its verifying trailer, so this never
/// refuses a legitimate one.
#[must_use]
pub fn is_approve_hash_claim(inner_data: &[u8]) -> bool {
    inner_data.len() >= 4 && inner_data[..4] == APPROVE_HASH_SELECTOR
}

/// Parse the 281-byte canonical packed SafeTx into structured fields.
///
/// The only range check is on `operation`: Safe's Solidity definition
/// uses an `Enum.Operation` whose only legal values are 0 (`Call`) and 1
/// (`DelegateCall`). Anything else is rejected so `compute_safe_tx_hash`
/// and the rendering path never see an invalid canonical.
///
/// Thin shim over the Kani-verified
/// [`pqsigner_tx::safe_tx::decode_canonical`] (decode-soundness: accept ⟺
/// `operation ≤ 1`, every field a verbatim copy from its canonical
/// offset); maps its single failure mode onto the secure-world
/// [`Eip712Error`] so the signature and every caller stay byte-identical.
pub fn decode_canonical(canonical: &[u8; SAFE_V1_CANONICAL_LEN]) -> Result<SafeTx, Eip712Error> {
    // `SafeTxDecodeError` has exactly one variant (`EnumOutOfRange`); the
    // map is total.
    pqsigner_tx::safe_tx::decode_canonical(canonical).map_err(|_| Eip712Error::EnumOutOfRange)
}

// ---------------------------------------------------------------------------
// EIP-712 struct hash
// ---------------------------------------------------------------------------

/// Compute the SafeTx EIP-712 struct hash from a decoded order.
///
/// Layout follows Safe's Solidity `encodeTransactionData`:
///
/// ```text
///   keccak256(
///     SAFE_TX_TYPEHASH ||
///     to                                  (left-padded to 32) ||
///     value                               (uint256) ||
///     data_hash                           (keccak256(data), bytes32) ||
///     operation                           (left-padded to 32) ||
///     safe_tx_gas                         (uint256) ||
///     base_gas                            (uint256) ||
///     gas_price                           (uint256) ||
///     gas_token                           (left-padded to 32) ||
///     refund_receiver                     (left-padded to 32) ||
///     nonce                               (uint256)
///   )
/// ```
///
/// 11 × 32 = 352 bytes total preimage.
pub fn struct_hash(tx: &SafeTx) -> [u8; 32] {
    let mut buf = [0u8; 32 * 11];
    buf[0..32].copy_from_slice(&SAFE_TX_TYPEHASH);
    // [1] to (left-padded address)
    buf[32 + 12..32 + 32].copy_from_slice(&tx.to);
    // [2] value (uint256)
    buf[64..96].copy_from_slice(&tx.value);
    // [3] data_hash (bytes32)
    buf[96..128].copy_from_slice(&tx.data_hash);
    // [4] operation (uint8 left-padded)
    buf[128 + 31] = tx.operation;
    // [5] safe_tx_gas (uint256)
    buf[160..192].copy_from_slice(&tx.safe_tx_gas);
    // [6] base_gas (uint256)
    buf[192..224].copy_from_slice(&tx.base_gas);
    // [7] gas_price (uint256)
    buf[224..256].copy_from_slice(&tx.gas_price);
    // [8] gas_token (left-padded address)
    buf[256 + 12..256 + 32].copy_from_slice(&tx.gas_token);
    // [9] refund_receiver (left-padded address)
    buf[288 + 12..288 + 32].copy_from_slice(&tx.refund_receiver);
    // [10] nonce (uint256)
    buf[320..352].copy_from_slice(&tx.nonce);

    keccak(&buf)
}

// ---------------------------------------------------------------------------
// EIP-712 domain separator (Safe v1.3.0+)
// ---------------------------------------------------------------------------

/// `keccak256(abi.encode(SAFE_DOMAIN_TYPEHASH, chain_id, verifying_contract))`.
///
/// Safe v1.3.0+ uses a slimmer domain than CoW (no `name` / `version`
/// — just `chainId` + `verifyingContract`), so it gets its own helper
/// rather than reusing the protocol-agnostic
/// `eip712_domain_separator` in the parent module.
pub fn domain_separator(chain_id: u64, verifying_contract: &[u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 32 * 3];
    buf[0..32].copy_from_slice(&SAFE_DOMAIN_TYPEHASH);
    // chainId as uint256: 24 zero bytes, then 8 BE bytes.
    buf[32 + 24..32 + 32].copy_from_slice(&chain_id.to_be_bytes());
    // verifyingContract as address (left-padded to 32 bytes).
    buf[64 + 12..64 + 32].copy_from_slice(verifying_contract);
    keccak(&buf)
}

// ---------------------------------------------------------------------------
// Top-level digest entry point
// ---------------------------------------------------------------------------

/// Compute the EIP-712 `safeTxHash` from a 281-byte canonical SafeTx.
///
/// Returns the 32-byte digest the on-chain Safe will check
/// `approvedHashes[msg.sender][safeTxHash]` against. The firmware
/// byte-compares this against `inner_data[4..36]` (the bytes32 argument
/// to `approveHash`) — a successful match means the canonical we just
/// rendered to the OLED is exactly the SafeTx that on-chain `approveHash`
/// will record.
pub fn compute_safe_tx_hash(
    canonical: &[u8; SAFE_V1_CANONICAL_LEN],
) -> Result<[u8; 32], Eip712Error> {
    let tx = decode_canonical(canonical)?;
    let dom = domain_separator(tx.chain_id, &tx.safe_address);
    let sh = struct_hash(&tx);
    Ok(super::final_digest(&dom, &sh))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod typehash_tests {
    //! Sanity-check that the hardcoded typehash byte arrays match the
    //! preimages they claim. Catches typos in the `[u8; 32]` literals
    //! before they propagate into a fixture mismatch.

    use super::*;

    const SAFE_DOMAIN_TYPEHASH_PREIMAGE: &[u8] =
        b"EIP712Domain(uint256 chainId,address verifyingContract)";

    const SAFE_TX_TYPEHASH_PREIMAGE: &[u8] = b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";

    #[test]
    fn safe_domain_typehash_matches_preimage() {
        assert_eq!(keccak(SAFE_DOMAIN_TYPEHASH_PREIMAGE), SAFE_DOMAIN_TYPEHASH);
    }

    #[test]
    fn safe_tx_typehash_matches_preimage() {
        assert_eq!(keccak(SAFE_TX_TYPEHASH_PREIMAGE), SAFE_TX_TYPEHASH);
    }

    // Safe-mgmt selector keccak self-checks. Catches typos in the
    // hardcoded byte literals in `proto/src/lib.rs` before they
    // propagate into an on-device classifier mismatch.
    use sphincs_tz_shared::{
        EXEC_TRANSACTION_SELECTOR, SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
        SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD, SAFE_MGMT_SELECTOR_DISABLE_MODULE,
        SAFE_MGMT_SELECTOR_ENABLE_MODULE, SAFE_MGMT_SELECTOR_REMOVE_OWNER,
        SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER, SAFE_MGMT_SELECTOR_SET_GUARD,
        SAFE_MGMT_SELECTOR_SWAP_OWNER,
    };

    fn selector_of(sig: &[u8]) -> [u8; 4] {
        let h = keccak(sig);
        [h[0], h[1], h[2], h[3]]
    }

    #[test]
    fn safe_mgmt_selectors_match_signatures() {
        assert_eq!(
            selector_of(b"addOwnerWithThreshold(address,uint256)"),
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD
        );
        assert_eq!(
            selector_of(b"removeOwner(address,address,uint256)"),
            SAFE_MGMT_SELECTOR_REMOVE_OWNER
        );
        assert_eq!(
            selector_of(b"swapOwner(address,address,address)"),
            SAFE_MGMT_SELECTOR_SWAP_OWNER
        );
        assert_eq!(
            selector_of(b"changeThreshold(uint256)"),
            SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD
        );
        assert_eq!(
            selector_of(b"enableModule(address)"),
            SAFE_MGMT_SELECTOR_ENABLE_MODULE
        );
        assert_eq!(
            selector_of(b"disableModule(address,address)"),
            SAFE_MGMT_SELECTOR_DISABLE_MODULE
        );
        assert_eq!(
            selector_of(b"setGuard(address)"),
            SAFE_MGMT_SELECTOR_SET_GUARD
        );
        assert_eq!(
            selector_of(b"setFallbackHandler(address)"),
            SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER
        );
    }

    #[test]
    fn exec_transaction_selector_matches_signature() {
        // Safe v1.3.0+ `execTransaction(...)`: `Enum.Operation` is encoded
        // as `uint8` in the canonical text signature.
        let sig: &[u8] = b"execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)";
        assert_eq!(selector_of(sig), EXEC_TRANSACTION_SELECTOR);
    }

    /// Audit 2026-06-28 regression — `approveHash` gate length bypass.
    ///
    /// The mandatory clear-sign gate must fire on the SELECTOR ALONE, never
    /// on an exact calldata length, because `Safe.approveHash(bytes32)`
    /// ignores trailing calldata on-chain. A trailing-byte-padded
    /// `approveHash` (length 37) must still be claimed by the gate so the
    /// handler refuses rather than blind-signing an invisible SafeTx
    /// pre-approval.
    #[test]
    fn approve_hash_claim_keys_on_selector_not_length() {
        let sel = APPROVE_HASH_SELECTOR;
        // Canonical, clear-signable shape: selector + 32-byte hash = 36 B.
        let mut exact = [0u8; 36];
        exact[..4].copy_from_slice(&sel);
        assert!(
            is_approve_hash_claim(&exact),
            "exact-36 approveHash claimed"
        );

        // THE BYPASS: selector + hash + one trailing padding byte = 37 B.
        // Must STILL be claimed (old `== 36` test missed this and let it
        // fall through to a generic blind-sign).
        let mut padded = [0u8; 37];
        padded[..4].copy_from_slice(&sel);
        assert!(
            is_approve_hash_claim(&padded),
            "trailing-byte approveHash must still be claimed"
        );

        // Over-long by many bytes: still claimed.
        let mut long = [0u8; 200];
        long[..4].copy_from_slice(&sel);
        assert!(is_approve_hash_claim(&long), "long approveHash claimed");

        // Selector-only (no hash word yet): still claimed (the Safe would
        // zero-pad the arg; refusing is the only safe outcome).
        assert!(
            is_approve_hash_claim(&sel),
            "selector-only approveHash claimed"
        );

        // A non-approveHash selector is NOT claimed (must not over-gate
        // legitimate ordinary calls into refusal).
        let mut other = [0u8; 68];
        other[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // erc20 transfer
        assert!(!is_approve_hash_claim(&other), "erc20 transfer not claimed");

        // Calldata shorter than a selector cannot be an approveHash claim.
        assert!(
            !is_approve_hash_claim(&[0xd4, 0xd9, 0xbd]),
            "sub-selector not claimed"
        );
        assert!(!is_approve_hash_claim(&[]), "empty not claimed");
    }
}
