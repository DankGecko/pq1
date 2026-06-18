//! ZK clear signing verification module.
//!
//! Implements on-device Groth16 proof verification for the ZKlarity clear
//! signing circuit. The circuit proves that a human-readable string is a
//! faithful ABI interpretation of raw Aave v3 calldata.
//!
//! Architecture:
//!   1. Receive (calldata, readable_string, proof) from NS world
//!   2. Compute H_tx  = Poseidon(calldata)  — bind the transaction
//!   3. Compute H_str = Poseidon(readable)  — bind the display string
//!   4. Verify Groth16 proof against (H_tx, H_str) and embedded VK
//!   5. If valid: display readable_string on trusted UI

pub mod groth16;
pub mod poseidon;
/// Generated Poseidon round constants + MDS matrices (BLS12-381 Scalar field).
/// Emitted by `tools/export_poseidon_constants.js` and lives under `generated/`
/// so grep/readers can tell at a glance this is machine-written code.
#[path = "generated/poseidon_constants.rs"]
mod poseidon_constants;
#[cfg(feature = "debug-log")]
pub mod test_vectors;
pub mod vk_bundle;

pub use groth16::{verify_clear_signing_proof, Groth16Proof, VerificationKey};
// Deeper items (`poseidon::poseidon_bytes`, `vk_bundle::{verify_vk_bundle,
// VerifiedVk}`) are imported through their sub-path at the call site so
// the compiler can flag dead code — no flat re-exports.

/// Maximum calldata size (must match ZKlarity circuit MAX_CALLDATA = 164)
pub const MAX_CALLDATA: usize = 164;

/// Human-readable string length (must match ZKlarity circuit STRING_LEN = 64)
pub const STRING_LEN: usize = 64;

/// Groth16 proof size: π.A (96) + π.B (192) + π.C (96) = 384 bytes
pub const PROOF_LEN: usize = 384;

/// Unit-return error indicating the supplied ZK clear-sign bundle did
/// not verify (VK bundle failed Merkle check, Groth16 pairing rejected
/// the proof, or the proof bytes were structurally malformed).
#[derive(Debug, Clone, Copy)]
pub struct ClearSignError;

/// Metadata returned on a successful `verify_clear_sign_proof` — the
/// caller uses these fields to cross-check the proof against the
/// transaction it claims to describe (HIGH-5).
#[derive(Clone, Copy)]
pub struct VerifiedClearSign {
    pub chain_id: u64,
    pub contract: [u8; 20],
}

/// End-to-end verification of a ZK clear-sign bundle supplied as three
/// byte buffers: the 384-byte Groth16 proof, the 164-byte calldata, the
/// 64-byte readable string, and the variable-length VK bundle that
/// proves the verification key is Merkle-committed to the firmware-
/// embedded `VK_DB_ROOT`.
///
/// On success the proof was valid *and* returns the VK's claimed
/// `(chain_id, contract)` pair so the caller can confirm it matches
/// the tx being signed. Without that cross-check, a VK for protocol A
/// on chain A could validate a readable string for protocol B on
/// chain B.
pub fn verify_clear_sign_proof(
    proof_bytes: &[u8; PROOF_LEN],
    calldata: &[u8; MAX_CALLDATA],
    readable: &[u8; STRING_LEN],
    vk_bundle: &[u8],
) -> Result<VerifiedClearSign, ClearSignError> {
    let proof = Groth16Proof::from_bytes(proof_bytes).ok_or(ClearSignError)?;
    let verified_vk = vk_bundle::verify_vk_bundle(vk_bundle).ok_or(ClearSignError)?;
    let vk = VerificationKey::from_bytes(verified_vk.vk_as_2pub()).ok_or(ClearSignError)?;
    if !verify_clear_signing_proof(calldata, readable, &proof, &vk) {
        return Err(ClearSignError);
    }
    Ok(VerifiedClearSign {
        chain_id: verified_vk.chain_id,
        contract: verified_vk.contract,
    })
}

/// A v1 ZK clear-sign trailer that passed the full verify-and-bind
/// pipeline. The handler holds both byte arrays on the stack until the
/// trusted-UI render is done; nothing else references them.
pub struct VerifiedClearSignV1 {
    pub calldata: [u8; MAX_CALLDATA],
    pub readable: [u8; STRING_LEN],
}

/// End-to-end verification of a v1 ZK clear-sign trailer against the
/// surrounding UserOp.
///
/// Wraps `verify_clear_sign_proof` with the four additional binding
/// checks the gateway handler needs:
///
///   1. Trailer length ≥ `ZK_CLEAR_SIGN_FIXED_LEN` — anything shorter
///      is a malformed bundle and returns `None`.
///   2. Groth16 + VK bundle Merkle verification via
///      `verify_clear_sign_proof`.
///   3. The verified VK must claim the tx's `chain_id` AND the tx's
///      `to_address`. (v3 uses a sentinel address for the same role;
///      v1 keys off the real contract because the v1 VK *is* the
///      target-contract VK.)
///   4. The tx's `inner_data` must match the circuit-attested
///      calldata byte-for-byte — prefix equality plus a zero-tail
///      check closes the "attester signs calldata A, we execute
///      calldata B" gap.
///
/// Returns owned copies of the calldata + readable string on success
/// so the caller can drop the snapshot buffer before rendering.
pub fn verify_and_bind_trailer_v1(
    zk_bundle: &[u8],
    inner_data: &[u8],
    chain_id: u64,
    to_address: &[u8; 20],
) -> Option<VerifiedClearSignV1> {
    use sphincs_tz_shared::ZK_CLEAR_SIGN_FIXED_LEN;

    if zk_bundle.len() < ZK_CLEAR_SIGN_FIXED_LEN {
        return None;
    }
    if inner_data.len() > MAX_CALLDATA {
        return None;
    }

    let proof_bytes: &[u8; PROOF_LEN] = zk_bundle[..PROOF_LEN].try_into().ok()?;
    let calldata_bytes: &[u8; MAX_CALLDATA] = zk_bundle[PROOF_LEN..PROOF_LEN + MAX_CALLDATA]
        .try_into()
        .ok()?;
    let readable_bytes: &[u8; STRING_LEN] = zk_bundle
        [PROOF_LEN + MAX_CALLDATA..ZK_CLEAR_SIGN_FIXED_LEN]
        .try_into()
        .ok()?;
    let vk_bundle = &zk_bundle[ZK_CLEAR_SIGN_FIXED_LEN..];

    let verified = verify_clear_sign_proof(proof_bytes, calldata_bytes, readable_bytes, vk_bundle)
        .ok()?;
    if verified.chain_id != chain_id || verified.contract != *to_address {
        return None;
    }

    // Native field-overflow guard (defense-in-depth — mirrors the cowswap
    // step 1b; see docs/security/VULN-cowswap-zk-amount-overflow.md).
    //
    // The amount-formatting v1 circuit (Aave Pool: supply/borrow/repay/
    // withdraw) renders the uint256 `amount`, which is ABI arg #2 at
    // calldata bytes 36..68, via `FormatAmount`. That formatter multiplies
    // the amount by a scale factor in the BLS12-381 scalar field; a
    // field-overflow forgery could make the recomposition wrap r so the
    // device displays a benign amount while signing a huge one. The fixed
    // circuit range-checks the amount to 190 bits; we re-assert the SAME
    // 190-bit bound natively here so the class is closed on-device even
    // against a future circuit regression — independent of, and redundant
    // with, the in-circuit `Num2Bits(190)`.
    //
    // This is safe for the only other current v1 protocol, cowswap
    // `setPreSignature(bytes orderUid, bool signed)`: its arg-#2 slot is
    // the `signed` bool (≤ 1), far below 2^190. A future v1 clear-sign
    // protocol whose arg #2 is legitimately ≥ 2^190 (not an amount) would
    // need to revisit this gate.
    let amount_slot: &[u8; 32] = calldata_bytes[36..68].try_into().ok()?;
    if !crate::tx::eip712::cowswap::amount_within_field_safe_bound(amount_slot) {
        return None;
    }

    // Calldata binding: attested prefix must equal what the tx will
    // actually execute, and the rest of the attested slot must be
    // zero-padded (the circuit right-pads to MAX_CALLDATA).
    let user_len = inner_data.len();
    let calldata_prefix = &inner_data[..user_len];
    let attested_prefix = &calldata_bytes[..user_len];
    if calldata_prefix != attested_prefix {
        return None;
    }
    if calldata_bytes[user_len..].iter().any(|&b| b != 0) {
        return None;
    }

    let mut calldata = [0u8; MAX_CALLDATA];
    calldata.copy_from_slice(calldata_bytes);
    let mut readable = [0u8; STRING_LEN];
    readable.copy_from_slice(readable_bytes);
    Some(VerifiedClearSignV1 { calldata, readable })
}

/// Render a trusted-UI confirmation screen for a ZK-verified clear-sign
/// tx. The 64-byte readable string is displayed across the first three
/// rows (12 visible cols × 4 = 48 chars + continuation), followed by a
/// chain / recipient / amount summary and the L/R confirm buttons.
#[cfg(not(test))]
pub fn render_clear_sign_pages(
    tx: &crate::tx::eip1559::Eip1559Tx,
    readable: &[u8; STRING_LEN],
    resolver: &crate::names::NameResolver<'_>,
) -> crate::tx::display::Pages {
    use crate::tx::display::Pages;
    use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

    let mut pages = Pages::empty_with_len(4);

    // Page 0: the ZK-attested readable string. Chunk 16 bytes per row
    // (our row is exactly DISPLAY_COLS) and drop trailing NULs.
    let trimmed_end = {
        let mut end = STRING_LEN;
        while end > 0 && readable[end - 1] == 0 {
            end -= 1;
        }
        end
    };
    let trimmed = &readable[..trimmed_end];
    // Row 0: "✓ Verified"-style header.
    {
        let row = pages.row_mut(0, 0);
        *row = [b' '; DISPLAY_COLS];
        let hdr = b"> Clear-signed";
        let n = core::cmp::min(hdr.len(), DISPLAY_COLS);
        row[..n].copy_from_slice(&hdr[..n]);
    }
    for row_idx in 1..DISPLAY_ROWS {
        let row = pages.row_mut(0, row_idx);
        *row = [b' '; DISPLAY_COLS];
        let start = (row_idx - 1) * DISPLAY_COLS;
        if start >= trimmed.len() {
            break;
        }
        let end = core::cmp::min(start + DISPLAY_COLS, trimmed.len());
        row[..end - start].copy_from_slice(&trimmed[start..end]);
    }

    // Page 1-3: chain / recipient / amount + confirm.
    // Delegate to the normal value-transfer renderer for those pages by
    // calling `render_pages` on the tx and copying the produced pages
    // 1..4 into our pages 1..4. (We already used page 0 for the readable.)
    let base = crate::tx::display::render_pages(tx, resolver);
    let base_slice = base.as_slice();
    let copy_count = core::cmp::min(base_slice.len(), 3);
    for i in 0..copy_count {
        let dst = pages.page_mut(1 + i);
        *dst = base_slice[i];
    }

    pages
}
