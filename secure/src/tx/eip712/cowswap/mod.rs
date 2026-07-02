//! CowSwap GPv2Order — EIP-712 typed-data clear-signing protocol.
//!
//! See `docs/companion/m4-cowswap-eip712-impl.md` for the rationale behind the
//! 204-byte packed canonical encoding (which is shared with the
//! Groth16 circuit at `circuits/cowswap/eip712_order/circuit.circom`).
//!
//! ## Canonical layout (204 bytes — v3)
//!
//! ```text
//!   [  0..  8 )  chain_id           (u64 BE)          ← NEW in v3
//!   [  8..  28)  sellToken          (20 B address)
//!   [ 28..  48)  buyToken           (20 B address)
//!   [ 48..  68)  receiver           (20 B address)
//!   [ 68..  100) sellAmount         (uint256 BE)
//!   [100.. 132)  buyAmount          (uint256 BE)
//!   [132.. 164)  feeAmount          (uint256 BE)
//!   [164.. 168)  validTo            (uint32 BE)
//!   [168]        kind               (0 = sell, 1 = buy)
//!   [169]        partiallyFillable  (0 / 1)
//!   [170]        sellTokenBalance   (0 / 1 / 2)
//!   [171]        buyTokenBalance    (0 / 1)
//!   [172.. 204)  appData            (bytes32)         ← NEW in v3
//! ```
//!
//! `chain_id` is bound via Poseidon so a single proof can't be
//! replayed across chains (the Merkle lookup in the circuit also
//! cross-checks that the resolved token entry came from the same
//! chain). `compute_digest` further verifies that `canonical.chain_id
//! === verified.chain_id` from the VK bundle before deriving the
//! EIP-712 digest, so NS can't supply a mismatched VK.
//!
//! `appData` is now genuinely bound — v2 pinned it to `bytes32(0)`.
//!
//! ## Submodule layout
//!
//! Keeping this module tight for auditors — domain/struct/digest and
//! the setPreSignature cross-check live in this file; wrapper glue
//! and test fixtures sit in siblings:
//!
//!   * [`verify`] — the top-level `verify_and_bind_trailer` that the
//!     gateway handler calls. Runs the length + shape + keccak
//!     orderDigest cross-check (the trust anchor) and decodes each swap
//!     leg's token metadata on-device from an ERC-20 Merkle bundle. No
//!     Groth16 / Poseidon registry — those were retired in favour of the
//!     on-device decode (which lifts the old 256-token circuit cap).
//!   * `test_vectors` (cfg(test) only) — 1000 USDC → WETH fixture and
//!     the 9 cross-check / shape regression tests, kept off the
//!     production build entirely.

use super::{eip712_domain_separator, final_digest, keccak, Eip712Error};

// `verify` no longer depends on `crate::zk` (the CoW Groth16 path was
// retired in favour of on-device ERC-20 bundle decode), so it now
// compiles under host tests too — letting `test_vectors` exercise the
// full trailer→cross-check→leg-decode pipeline, not just the primitives.
pub mod verify;
pub use verify::{verify_and_bind_trailer, CowLeg, VerifiedCowswapV3};

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod extra_tests;

// Accurate end-to-end decode vectors (CowSwap / Safe-wrapped / Safe-MultiSend)
// whose digests + safeTxHashes are cross-checked against an independent ethers
// v6 reference. See `e2e_decode_tests.rs`.
#[cfg(test)]
mod e2e_decode_tests;

// ---------------------------------------------------------------------------
// Public addresses
// ---------------------------------------------------------------------------

/// CowSwap GPv2Settlement is deployed at this CREATE2 address on
/// every chain CowSwap supports (Mainnet, Gnosis Chain, Arbitrum,
/// Base). Used as the `verifyingContract` field in the EIP-712
/// domain separator.
pub const GPV2_SETTLEMENT_ADDRESS: [u8; 20] = [
    0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6,
    0x09, 0x71, 0x56, 0x5a, 0xa8, 0x51, 0x05, 0x60, 0xab, 0x41,
];

// ---------------------------------------------------------------------------
// EIP-712 typehashes (constant preimages, hashed lazily on first use).
// ---------------------------------------------------------------------------

// NOTE: the CoW EIP-712 TYPE_HASH preimage declares `kind`,
// `sellTokenBalance`, and `buyTokenBalance` as `string`, not `bytes32`,
// even though the Solidity `GPv2Order.Data` struct stores them as
// `bytes32`. The value hashed into the struct is the same 32-byte
// `keccak256` of an ASCII identifier ("sell"/"buy"/"erc20"/"external"/
// "internal"), which matches EIP-712's `keccak256(bytes(string_value))`
// rule — but the typehash itself differs. Getting this wrong yields
// `0x1a59c8ff…` instead of the canonical `0xd5a25ba2…` and every
// orderUid we derive diverges from what the orderbook + on-chain
// settlement compute. Verified against a real filled Base order
// (`0x59ebcff5…`).
/// `keccak256("Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)")`.
const ORDER_TYPEHASH_PREIMAGE: &[u8] = b"Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)";

const COWSWAP_DOMAIN_NAME: &[u8] = b"Gnosis Protocol";
const COWSWAP_DOMAIN_VERSION: &[u8] = b"v2";

// ---------------------------------------------------------------------------
// Decoded order
// ---------------------------------------------------------------------------

// `GpV2Order` and the pure 204-byte canonical field-decode live in the
// host-compilable, Kani-verified `pqsigner_tx::cowswap_order` (decode
// soundness: accept ⟺ enum bytes in range, every field a verbatim copy
// from its canonical offset). Re-exported here so `struct_hash`,
// `compute_digest`, the cross-check, and every test/caller are unchanged.
pub use pqsigner_tx::cowswap_order::GpV2Order;

/// Parse the 204-byte canonical packed encoding into structured
/// fields. Validates the small-enum byte ranges (kind,
/// partiallyFillable, balance kinds) so an out-of-range NS payload
/// is rejected before it can produce a digest.
///
/// Thin shim over the Kani-verified [`pqsigner_tx::cowswap_order::decode_canonical`];
/// maps its single failure mode onto the secure-world [`Eip712Error`] so
/// the signature and every caller stay byte-identical.
pub fn decode_canonical(canonical: &[u8; 204]) -> Result<GpV2Order, Eip712Error> {
    // `CowOrderDecodeError` has exactly one variant (`EnumOutOfRange`); the
    // map is total.
    pqsigner_tx::cowswap_order::decode_canonical(canonical)
        .map_err(|_| Eip712Error::EnumOutOfRange)
}

// ---------------------------------------------------------------------------
// Struct hash
// ---------------------------------------------------------------------------

/// `keccak256("sell")` / `keccak256("buy")` for the kind enum.
fn kind_hash(kind: u8) -> [u8; 32] {
    if kind == 0 {
        keccak(b"sell")
    } else {
        keccak(b"buy")
    }
}

/// Balance enum: `keccak256("erc20" | "external" | "internal")`.
/// `is_sell_side` distinguishes the sell-side enum (0/1/2) from
/// the buy-side enum (0/1) — the buy-side never resolves to
/// `external`.
fn balance_hash(b: u8, is_sell_side: bool) -> [u8; 32] {
    match (is_sell_side, b) {
        (_, 0) => keccak(b"erc20"),
        (true, 1) => keccak(b"external"),
        (false, 1) => keccak(b"internal"),
        (true, 2) => keccak(b"internal"),
        _ => keccak(b"erc20"),
    }
}

/// Compute the GPv2Order EIP-712 struct hash from a decoded order.
/// `appData` is now bound from the canonical buffer (v3) — v2 pinned
/// it to `bytes32(0)`, which meant orders with non-empty appCode
/// couldn't be clear-signed.
pub fn struct_hash(order: &GpV2Order) -> [u8; 32] {
    // 13 fields × 32 bytes = 416 bytes.
    let mut buf = [0u8; 32 * 13];

    let typehash = keccak(ORDER_TYPEHASH_PREIMAGE);
    buf[0..32].copy_from_slice(&typehash);

    // [1] sellToken (left-padded address)
    buf[32 + 12..32 + 32].copy_from_slice(&order.sell_token);
    // [2] buyToken
    buf[64 + 12..64 + 32].copy_from_slice(&order.buy_token);
    // [3] receiver
    buf[96 + 12..96 + 32].copy_from_slice(&order.receiver);
    // [4] sellAmount
    buf[128..160].copy_from_slice(&order.sell_amount);
    // [5] buyAmount
    buf[160..192].copy_from_slice(&order.buy_amount);
    // [6] validTo (uint32 left-padded)
    buf[192 + 28..192 + 32].copy_from_slice(&order.valid_to.to_be_bytes());
    // [7] appData (bytes32) — bound verbatim from canonical in v3.
    buf[224..256].copy_from_slice(&order.app_data);
    // [8] feeAmount
    buf[256..288].copy_from_slice(&order.fee_amount);
    // [9] kind
    buf[288..320].copy_from_slice(&kind_hash(order.kind));
    // [10] partiallyFillable (bool, 31 zero + 1 byte)
    buf[320 + 31] = order.partially_fillable;
    // [11] sellTokenBalance
    buf[352..384].copy_from_slice(&balance_hash(order.sell_token_balance, true));
    // [12] buyTokenBalance
    buf[384..416].copy_from_slice(&balance_hash(order.buy_token_balance, false));

    keccak(&buf)
}

// ---------------------------------------------------------------------------
// Top-level digest entrypoint
// ---------------------------------------------------------------------------

/// Compute the EIP-712 digest the wallet signs for a CowSwap
/// GPv2Order, given the 204-byte canonical bytes the Groth16 proof
/// has already bound and the chain id from the verified VK bundle.
///
/// Cross-checks that `canonical.chain_id === verified_chain_id`: the
/// Groth16 proof binds the chain_id inside the canonical buffer via
/// Poseidon, and this check prevents NS from pairing a legitimate
/// proof with a mismatched VK bundle (e.g. mainnet proof + Gnosis
/// bundle — the digest would otherwise be signed against the wrong
/// domain separator).
pub fn compute_digest(canonical: &[u8; 204], chain_id: u64) -> Result<[u8; 32], Eip712Error> {
    let order = decode_canonical(canonical)?;
    if order.chain_id != chain_id {
        return Err(Eip712Error::ChainIdMismatch);
    }
    let name_hash = keccak(COWSWAP_DOMAIN_NAME);
    let version_hash = keccak(COWSWAP_DOMAIN_VERSION);
    let dom = eip712_domain_separator(&name_hash, &version_hash, chain_id, &GPV2_SETTLEMENT_ADDRESS);
    let sh = struct_hash(&order);
    Ok(final_digest(&dom, &sh))
}

// ---------------------------------------------------------------------------
// setPreSignature orderUid cross-check — the v3 security gate
// ---------------------------------------------------------------------------
//
// When a UserOp's inner calldata is `setPreSignature(orderUid, true)`
// and the companion attaches a v3 trailer (canonical GPv2Order), the
// secure world must prove that the canonical the user *saw* on the
// 8-page display is the order the *on-chain* settlement contract will
// act on. The only thing bridging those two worlds is the 56-byte
// `orderUid` in the setPreSignature calldata. So: compute the orderUid
// natively from the canonical bytes + the UserOp's sender, and
// byte-compare it against the calldata.

/// Extents of the 56-byte orderUid inside a 164-byte setPreSignature
/// calldata. The calldata ABI layout is
/// `selector(4) || bytes_offset(32)=0x40 || bool_signed(32)=1 ||
///  bytes_len(32)=56 || orderUid(56) || zero_pad(8)` — so the orderUid
/// starts at byte 100 and is 56 bytes wide.
pub const SETPRESIG_ORDERUID_OFFSET: usize = 100;
/// Slice of `orderUid` that is the 32-byte EIP-712 order digest.
pub const SETPRESIG_ORDER_DIGEST_OFFSET: usize = SETPRESIG_ORDERUID_OFFSET;
pub const SETPRESIG_ORDER_DIGEST_LEN: usize = 32;
/// Slice of `orderUid` that is the 20-byte owner.
pub const SETPRESIG_OWNER_OFFSET: usize = SETPRESIG_ORDERUID_OFFSET + 32;
pub const SETPRESIG_OWNER_LEN: usize = 20;
/// Slice of `orderUid` that is the 4-byte BE validTo.
pub const SETPRESIG_VALID_TO_OFFSET: usize = SETPRESIG_OWNER_OFFSET + SETPRESIG_OWNER_LEN;
pub const SETPRESIG_VALID_TO_LEN: usize = 4;

// ---------------------------------------------------------------------------
// Field-overflow defense-in-depth (see docs/security/vulns/VULN-cowswap-zk-amount-overflow.md)
// ---------------------------------------------------------------------------

/// Bit-width the CoW Groth16 circuit range-checks `raw_amount` to, so
/// that `raw_amount * scale_factor` cannot wrap the BLS12-381 scalar
/// field (r ≈ 2^254.86) — `2^190 · 10^18 < 2^249.8 < r` over ℤ. The
/// firmware mirrors the same bound natively as belt-and-braces.
pub const RAW_AMOUNT_FIELD_SAFE_BITS: u32 = 190;

/// Returns `true` iff the 32-byte big-endian amount is `< 2^190`.
///
/// The CoW circuit formats `sellAmount`/`buyAmount` via
/// `FormatTrimmedAmount`, whose recomposition multiplies `raw_amount` by
/// `scale_factor` in the scalar field. A *legitimate* displayable amount
/// is tiny — with `MAX_INT_DIGITS = 10` and 18 decimals,
/// `raw_amount ≤ 10^10 · 10^18 = 10^28 ≈ 2^93.4`. Any amount `≥ 2^190`
/// therefore could only have come from a field-overflow forgery: a proof
/// where the device displays a benign amount while signing an
/// astronomically large one. Rejecting `≥ 2^190` here closes that class
/// from the firmware side, independent of (and redundant with) the
/// circuit's own `Num2Bits(190)` guard.
///
/// `2^190` lands inside byte index 8 (which holds bits 184..191), so the
/// value is `< 2^190` exactly when bytes[0..8] (bits 192..255) are all
/// zero and the top two bits of byte 8 (bits 190, 191) are clear, i.e.
/// `bytes[8] < 0x40`. Bytes 9..32 are unconstrained.
#[must_use]
pub fn amount_within_field_safe_bound(amount_be: &[u8; 32]) -> bool {
    amount_be[..8].iter().all(|&b| b == 0) && amount_be[8] < 0x40
}

/// Failure modes for the v3 `setPreSignature` cross-check. Kept as a
/// discriminated enum (rather than a `Result<(), ()>`) so the caller
/// can surface a precise error to telemetry + trusted UI even when the
/// outer return value is unit-valued rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderUidMismatch {
    /// Canonical bytes failed to decode (malformed enum byte).
    CanonicalDecode,
    /// `canonical.chain_id` did not equal the VK bundle's chain_id.
    ChainIdMismatch,
    /// `canonical.valid_to` ≠ calldata's validTo.
    ValidToMismatch,
    /// The 32-byte orderDigest derived from the canonical does not
    /// match the orderDigest in the calldata's orderUid.
    OrderDigestMismatch,
    /// The 20-byte owner in the calldata's orderUid does not match
    /// the UserOp's sender (the smart account address).
    OwnerMismatch,
}

/// Cross-check a v3-verified canonical GPv2Order against the
/// setPreSignature calldata + UserOp sender.
///
/// Invariants enforced (in order — first failure wins so the reject
/// reason maps cleanly to a user-facing error):
///
///  1. `canonical.chain_id == bundle_chain_id` (also enforced
///     internally by `compute_digest`, duplicated here so the caller
///     can distinguish this failure from a bad digest).
///  2. `canonical.valid_to` == `orderUid[52..56]` (byte-compare, no
///     integer parse — a zero-validTo attacker can't get a false pass
///     via endianness confusion).
///  3. `compute_digest(canonical)[..]` equals `orderUid[0..32]`. This
///     binds EVERY field of the GPv2Order struct (appData, fee, kind,
///     balance enums, amounts, both token addresses, receiver, …) —
///     struct_hash is a keccak over all 12 fields plus ORDER_TYPEHASH,
///     so equality here subsumes the per-field byte checks.
///  4. `orderUid[32..52]` == UserOp sender (the smart account
///     address). CoW's settlement contract requires
///     `msg.sender == uid.owner` for pre-signing; signing an
///     orderUid whose owner is someone else would either revert
///     on-chain (wasted gas) or, worse, pre-sign a third party's
///     order as ours. Either way: reject.
pub fn cross_check_setpresig_calldata(
    canonical: &[u8; 204],
    calldata: &[u8; 164],
    bundle_chain_id: u64,
    userop_sender: &[u8; 20],
) -> Result<(), OrderUidMismatch> {
    // (1) decode + chain_id match — compute_digest does both.
    let order_digest = match compute_digest(canonical, bundle_chain_id) {
        Ok(d) => d,
        Err(Eip712Error::ChainIdMismatch) => return Err(OrderUidMismatch::ChainIdMismatch),
        Err(_) => return Err(OrderUidMismatch::CanonicalDecode),
    };

    // (2) validTo — byte-for-byte.
    let canonical_valid_to = &canonical[164..168];
    let calldata_valid_to =
        &calldata[SETPRESIG_VALID_TO_OFFSET..SETPRESIG_VALID_TO_OFFSET + SETPRESIG_VALID_TO_LEN];
    if canonical_valid_to != calldata_valid_to {
        return Err(OrderUidMismatch::ValidToMismatch);
    }

    // (3) orderDigest — the heavy invariant. struct_hash covers every
    //     GPv2Order field, so byte equality here locks the entire
    //     order into the calldata the chain will see.
    let calldata_digest = &calldata
        [SETPRESIG_ORDER_DIGEST_OFFSET..SETPRESIG_ORDER_DIGEST_OFFSET + SETPRESIG_ORDER_DIGEST_LEN];
    if order_digest.as_slice() != calldata_digest {
        return Err(OrderUidMismatch::OrderDigestMismatch);
    }

    // (4) owner — must equal the UserOp sender.
    let calldata_owner = &calldata[SETPRESIG_OWNER_OFFSET..SETPRESIG_OWNER_OFFSET + SETPRESIG_OWNER_LEN];
    if calldata_owner != userop_sender.as_slice() {
        return Err(OrderUidMismatch::OwnerMismatch);
    }

    Ok(())
}

/// Check the structural shape of a setPreSignature calldata — the
/// selector, ABI encoding bytes, `signed == true` flag, bytes-length
/// prefix, and zero-padding tail. This replaces the bytes-level
/// guarantees that the v1 `cowswap_set_pre_signature` circuit used to
/// make; the firmware checks them natively now instead of running a
/// separate proof.
pub fn check_setpresig_calldata_shape(calldata: &[u8; 164]) -> Result<(), OrderUidMismatch> {
    // Selector.
    if &calldata[0..4] != &[0xec, 0x6c, 0xb1, 0x3f] {
        return Err(OrderUidMismatch::CanonicalDecode);
    }
    // ABI bytes offset = 0x40 at slot 0.
    for b in &calldata[4..35] {
        if *b != 0 {
            return Err(OrderUidMismatch::CanonicalDecode);
        }
    }
    if calldata[35] != 0x40 {
        return Err(OrderUidMismatch::CanonicalDecode);
    }
    // Bool signed == true at slot 1.
    for b in &calldata[36..67] {
        if *b != 0 {
            return Err(OrderUidMismatch::CanonicalDecode);
        }
    }
    if calldata[67] != 1 {
        return Err(OrderUidMismatch::CanonicalDecode);
    }
    // Bytes length = 56 at slot 2.
    for b in &calldata[68..99] {
        if *b != 0 {
            return Err(OrderUidMismatch::CanonicalDecode);
        }
    }
    if calldata[99] != 56 {
        return Err(OrderUidMismatch::CanonicalDecode);
    }
    // Zero padding at [156..164).
    for b in &calldata[156..164] {
        if *b != 0 {
            return Err(OrderUidMismatch::CanonicalDecode);
        }
    }
    Ok(())
}
