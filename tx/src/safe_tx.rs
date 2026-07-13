//! Pure byte-layout decoders for the Safe (Gnosis Safe v1.3.0+) SafeTx
//! clear-sign path — the WYSIWYS surface where the user confirms the
//! inner `to / value / data / operation` of a Safe transaction.
//!
//! Two host-compilable, Kani-friendly decoders are extracted here,
//! verbatim and behaviour-identical, so they can be bounded-verified
//! with Kani (`cargo kani -p pqsigner-tx`). The secure-world modules
//! `secure/src/tx/eip712/safe/{mod,exec_decode}.rs` re-export the types
//! and wrap each `decode_*` (mapping the local error onto the
//! secure-world `Eip712Error`), so every existing caller, the
//! keccak struct-hash / domain-separator / digest pipeline, and the
//! full test suite keep working unchanged.
//!
//! ## What lives here vs what stays in `secure/`
//!
//! Only the **pure byte-layout decode** moves: fixed-offset field copies,
//! the `operation ∈ {0, 1}` enum gate, and the dynamic-tail bounds checks.
//! The keccak `struct_hash` / `domain_separator` / `compute_safe_tx_hash`
//! (the EIP-712 digest) stay in `secure/src/tx/eip712/safe/mod.rs`, and
//! the `MultiSendCallOnly` operation-gate / CoW-binding glue stays in
//! `secure/` — none of it is pulled in here (no keccak, no `multi_send`,
//! no `cow_binding`, no hardware). Dependency closure is just
//! the `pqsigner-proto` layout constants.
//!
//! ## A. Canonical SafeTx typed-data — [`decode_canonical`]
//!
//! The 281-byte canonical packed buffer the companion sends as the
//! `approveHash` clear-sign trailer. Decodes the literal SafeTx EIP-712
//! typed-data —
//! `SafeTx(address to, uint256 value, bytes data, uint8 operation,
//! uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken,
//! address refundReceiver, uint256 nonce)` — where `data` is carried as
//! its keccak `data_hash` (fixed 32 bytes). The only failure mode is an
//! out-of-range `operation` byte, so the accept set is fully
//! characterised: `decode_canonical(c).is_ok()` **iff** `operation ≤ 1`.
//!
//! ```text
//!   [  0..  8 )  chain_id          (u64 BE)            SAFE_OFF_CHAIN_ID
//!   [  8.. 28 )  safe_address      (20 B address)      SAFE_OFF_SAFE_ADDRESS
//!   [ 28.. 48 )  to                (20 B address)      SAFE_OFF_TO
//!   [ 48.. 80 )  value             (uint256 BE)        SAFE_OFF_VALUE
//!   [ 80..112 )  data_hash         (bytes32)           SAFE_OFF_DATA_HASH
//!   [112]        operation         (0 = Call, 1 = DC)  SAFE_OFF_OPERATION
//!   [113..145 )  safe_tx_gas       (uint256 BE)        SAFE_OFF_SAFE_TX_GAS
//!   [145..177 )  base_gas          (uint256 BE)        SAFE_OFF_BASE_GAS
//!   [177..209 )  gas_price         (uint256 BE)        SAFE_OFF_GAS_PRICE
//!   [209..229 )  gas_token         (20 B address)      SAFE_OFF_GAS_TOKEN
//!   [229..249 )  refund_receiver   (20 B address)      SAFE_OFF_REFUND_RECEIVER
//!   [249..281 )  nonce             (uint256 BE)        SAFE_OFF_NONCE
//! ```
//!
//! ## B. `execTransaction(...)` calldata — [`decode_exec_transaction`]
//!
//! When the wallet's UserOp directly invokes `execTransaction(...)` on a
//! Safe, the same SafeTx fields are encoded straight into the calldata,
//! and the inner `data` is a genuine **dynamic `bytes`** argument (offset
//! + length tail) rather than a pre-computed hash. This decoder is the
//! Safe analogue of the typed-call ABI walker: fixed head words plus two
//! dynamic tails (`data`, `signatures`), with strict canonical-address,
//! operation-range, and tail-in-bounds gates. The verified guarantee on
//! the dynamic part is **panic / OOB-freedom (no read past end) over all
//! symbolic offset/length words** plus the on-point reject set; the
//! strong, decoder-independent *content* soundness lives in the
//! fixed-offset head fields.

use pqsigner_proto::{
    EXEC_TRANSACTION_MIN_CALLDATA_LEN, EXEC_TRANSACTION_SELECTOR, SAFE_OFF_BASE_GAS,
    SAFE_OFF_CHAIN_ID, SAFE_OFF_DATA_HASH, SAFE_OFF_GAS_PRICE, SAFE_OFF_GAS_TOKEN, SAFE_OFF_NONCE,
    SAFE_OFF_OPERATION, SAFE_OFF_REFUND_RECEIVER, SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_SAFE_TX_GAS,
    SAFE_OFF_TO, SAFE_OFF_VALUE, SAFE_V1_CANONICAL_LEN,
};

// ===========================================================================
// A. Canonical SafeTx typed-data decode
// ===========================================================================

/// Decode failure for the 281-byte canonical packed SafeTx.
///
/// The only failure mode is an out-of-range `operation` byte (`> 1`);
/// every other field is a fixed-width byte copy that cannot fail. The
/// secure-world shim maps this onto its broader `Eip712Error::EnumOutOfRange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeTxDecodeError {
    /// The `operation` byte was outside its valid `{0, 1}` range.
    EnumOutOfRange,
}

/// Decoded SafeTx fields. Borrows nothing — every field is owned and
/// the returned struct is `Copy`. Mirrors Safe's Solidity struct order
/// for the EIP-712 typehash, with byte arrays preserved at their natural
/// width (addresses 20 B, uint256 32 B BE).
#[derive(Clone, Copy, Debug)]
pub struct SafeTx {
    pub chain_id: u64,
    pub safe_address: [u8; 20],
    pub to: [u8; 20],
    pub value: [u8; 32],
    pub data_hash: [u8; 32],
    /// Operation byte: `0` = Call, `1` = DelegateCall. Other values are
    /// rejected by [`decode_canonical`].
    pub operation: u8,
    pub safe_tx_gas: [u8; 32],
    pub base_gas: [u8; 32],
    pub gas_price: [u8; 32],
    pub gas_token: [u8; 20],
    pub refund_receiver: [u8; 20],
    pub nonce: [u8; 32],
}

/// Parse the 281-byte canonical packed SafeTx into structured fields.
///
/// The only range check is on `operation`: Safe's Solidity definition
/// uses an `Enum.Operation` whose only legal values are `0` (`Call`) and
/// `1` (`DelegateCall`). Anything else is rejected here so the keccak
/// digest and the rendering path never see an invalid canonical. Every
/// other field is a fixed-offset copy at the canonical layout above.
pub fn decode_canonical(
    canonical: &[u8; SAFE_V1_CANONICAL_LEN],
) -> Result<SafeTx, SafeTxDecodeError> {
    let chain_id = u64::from_be_bytes([
        canonical[SAFE_OFF_CHAIN_ID],
        canonical[SAFE_OFF_CHAIN_ID + 1],
        canonical[SAFE_OFF_CHAIN_ID + 2],
        canonical[SAFE_OFF_CHAIN_ID + 3],
        canonical[SAFE_OFF_CHAIN_ID + 4],
        canonical[SAFE_OFF_CHAIN_ID + 5],
        canonical[SAFE_OFF_CHAIN_ID + 6],
        canonical[SAFE_OFF_CHAIN_ID + 7],
    ]);
    let mut safe_address = [0u8; 20];
    safe_address.copy_from_slice(&canonical[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20]);
    let mut to = [0u8; 20];
    to.copy_from_slice(&canonical[SAFE_OFF_TO..SAFE_OFF_TO + 20]);
    let mut value = [0u8; 32];
    value.copy_from_slice(&canonical[SAFE_OFF_VALUE..SAFE_OFF_VALUE + 32]);
    let mut data_hash = [0u8; 32];
    data_hash.copy_from_slice(&canonical[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32]);
    let operation = canonical[SAFE_OFF_OPERATION];
    if operation > 1 {
        return Err(SafeTxDecodeError::EnumOutOfRange);
    }
    let mut safe_tx_gas = [0u8; 32];
    safe_tx_gas.copy_from_slice(&canonical[SAFE_OFF_SAFE_TX_GAS..SAFE_OFF_SAFE_TX_GAS + 32]);
    let mut base_gas = [0u8; 32];
    base_gas.copy_from_slice(&canonical[SAFE_OFF_BASE_GAS..SAFE_OFF_BASE_GAS + 32]);
    let mut gas_price = [0u8; 32];
    gas_price.copy_from_slice(&canonical[SAFE_OFF_GAS_PRICE..SAFE_OFF_GAS_PRICE + 32]);
    let mut gas_token = [0u8; 20];
    gas_token.copy_from_slice(&canonical[SAFE_OFF_GAS_TOKEN..SAFE_OFF_GAS_TOKEN + 20]);
    let mut refund_receiver = [0u8; 20];
    refund_receiver
        .copy_from_slice(&canonical[SAFE_OFF_REFUND_RECEIVER..SAFE_OFF_REFUND_RECEIVER + 20]);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&canonical[SAFE_OFF_NONCE..SAFE_OFF_NONCE + 32]);

    Ok(SafeTx {
        chain_id,
        safe_address,
        to,
        value,
        data_hash,
        operation,
        safe_tx_gas,
        base_gas,
        gas_price,
        gas_token,
        refund_receiver,
        nonce,
    })
}

// ===========================================================================
// B. execTransaction(...) calldata decode
// ===========================================================================

/// Decode failure for `execTransaction(...)` calldata.
///
/// The secure-world shim maps each variant 1:1 onto the matching
/// `Eip712Error` variant so the firmware signature and every caller stay
/// byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeExecDecodeError {
    /// Calldata is shorter than the minimum fixed-head ABI encoding.
    ShortInput,
    /// First four bytes don't match `execTransaction`'s selector.
    WrongSelector,
    /// An ABI address word had non-zero bytes in its top 12-byte padding.
    NonCanonicalAddress,
    /// A `uint256` offset / length word had bits beyond the low 32, or the
    /// resolved offset would land outside the calldata.
    OffsetOverflow,
    /// The `operation` enum byte (or its left-padding) was out of range.
    EnumOutOfRange,
    /// A dynamic tail (the bytes payload an offset points to) is not fully
    /// present inside the calldata.
    TruncatedDynamic,
}

/// Decoded `execTransaction` arguments. `data` and `signatures` borrow
/// from the input calldata; everything else is owned by value so the
/// struct is `Copy`-friendly except for those two slice fields.
#[derive(Clone, Copy, Debug)]
pub struct DecodedExec<'a> {
    pub to: [u8; 20],
    pub value: [u8; 32],
    /// `0` = `Call`, `1` = `DelegateCall`. Already range-checked.
    pub operation: u8,
    pub safe_tx_gas: [u8; 32],
    pub base_gas: [u8; 32],
    pub gas_price: [u8; 32],
    pub gas_token: [u8; 20],
    pub refund_receiver: [u8; 20],
    pub data: &'a [u8],
    pub signatures: &'a [u8],
}

/// Decode a 32-byte ABI word interpreted as a canonical `address`:
/// top 12 bytes MUST be zero, low 20 bytes are the address.
fn read_address_word_off(word: &[u8; 32]) -> Result<[u8; 20], SafeExecDecodeError> {
    if word[..12].iter().any(|&b| b != 0) {
        return Err(SafeExecDecodeError::NonCanonicalAddress);
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&word[12..32]);
    Ok(a)
}

/// Decode a 32-byte ABI word as a `usize` (offset or length). Bits above
/// 32 must be zero — offsets / lengths fit in u32 by construction
/// (calldata length is u16-bounded upstream anyway).
fn read_offset_word_off(word: &[u8; 32]) -> Result<usize, SafeExecDecodeError> {
    if word[..28].iter().any(|&b| b != 0) {
        return Err(SafeExecDecodeError::OffsetOverflow);
    }
    Ok(u32::from_be_bytes([word[28], word[29], word[30], word[31]]) as usize)
}

/// Parse `execTransaction(...)` calldata into structured fields.
///
/// Returns the decoded struct on success, or a specific
/// [`SafeExecDecodeError`] on any hardening-rule violation. Callers drop
/// the trailer to "refuse to sign" on `Err`.
pub fn decode_exec_transaction(cd: &[u8]) -> Result<DecodedExec<'_>, SafeExecDecodeError> {
    // Minimum-length / selector gate.
    if cd.len() < EXEC_TRANSACTION_MIN_CALLDATA_LEN {
        return Err(SafeExecDecodeError::ShortInput);
    }
    if cd[..4] != EXEC_TRANSACTION_SELECTOR {
        return Err(SafeExecDecodeError::WrongSelector);
    }

    // The head starts immediately after the selector. All offsets in the
    // ABI encoding are measured from the start of this head region.
    let head = &cd[4..];

    // Helper that pulls a fixed-size word out of `head` by word index
    // (0..=9). Bounded by the `cd.len() >= MIN_CALLDATA_LEN` check above.
    let word_at = |idx: usize| -> &[u8; 32] {
        let off = idx * 32;
        let s: &[u8; 32] = head[off..off + 32].try_into().expect("word slice");
        s
    };

    // 10 head words = 320 bytes. We checked `cd.len() >= MIN_CALLDATA_LEN`
    // (selector + 10*32 + 2*32) so `head[..320]` always exists.
    let to = read_address_word_off(word_at(0))?;
    let value: [u8; 32] = *word_at(1);
    let data_off_w = *word_at(2);
    let operation_w = word_at(3);
    let safe_tx_gas: [u8; 32] = *word_at(4);
    let base_gas: [u8; 32] = *word_at(5);
    let gas_price: [u8; 32] = *word_at(6);
    let gas_token = read_address_word_off(word_at(7))?;
    let refund_receiver = read_address_word_off(word_at(8))?;
    let sigs_off_w = *word_at(9);

    // Operation = uint8 left-padded to 32. Top 31 bytes must be zero.
    if operation_w[..31].iter().any(|&b| b != 0) {
        return Err(SafeExecDecodeError::EnumOutOfRange);
    }
    let operation = operation_w[31];
    if operation > 1 {
        return Err(SafeExecDecodeError::EnumOutOfRange);
    }

    let data_off = read_offset_word_off(&data_off_w)?;
    let sigs_off = read_offset_word_off(&sigs_off_w)?;

    // Each tail starts with a u256 length, followed by the bytes. The
    // tails MUST sit after the 320-byte head; that's the canonical
    // encoding Solidity produces. Pathologically-formed calldata could
    // point earlier, which we refuse — the on-device display would
    // otherwise show whatever bytes were before the head.
    let data = read_dynamic_bytes(head, data_off)?;
    let signatures = read_dynamic_bytes(head, sigs_off)?;

    Ok(DecodedExec {
        to,
        value,
        operation,
        safe_tx_gas,
        base_gas,
        gas_price,
        gas_token,
        refund_receiver,
        data,
        signatures,
    })
}

/// Read a dynamic `bytes` argument out of `head` at the given offset.
/// The 32 bytes at `head[offset..offset+32]` are the length; the payload
/// follows. Returns `Err` if the offset / length addresses any byte
/// outside `head`.
fn read_dynamic_bytes(head: &[u8], offset: usize) -> Result<&[u8], SafeExecDecodeError> {
    // Tail must start after the 320-byte head (10 words × 32). Solidity
    // encodes it that way; refusing earlier offsets prevents an attacker
    // from pointing the bytes argument back into the head and confusing
    // the renderer.
    if offset < 10 * 32 {
        return Err(SafeExecDecodeError::OffsetOverflow);
    }
    if offset.checked_add(32).map_or(true, |end| end > head.len()) {
        return Err(SafeExecDecodeError::TruncatedDynamic);
    }
    let len_word: &[u8; 32] = head[offset..offset + 32]
        .try_into()
        .expect("length word slice");
    let len = read_offset_word_off(len_word)?;
    let payload_start = offset + 32;
    let payload_end = payload_start
        .checked_add(len)
        .ok_or(SafeExecDecodeError::OffsetOverflow)?;
    if payload_end > head.len() {
        return Err(SafeExecDecodeError::TruncatedDynamic);
    }
    Ok(&head[payload_start..payload_end])
}

// ===========================================================================
// Bounded verification (Kani)
// ===========================================================================
//
// Two surfaces, two property shapes:
//
//   A. `decode_canonical` — fixed 281-byte input, no length parameter and
//      no dynamic offsets, so the soundness harness is EXHAUSTIVE: a full
//      biconditional `is_ok() ⟺ operation ≤ 1`, every field a verbatim
//      copy reconstructed from its canonical offset in the ORIGINAL input
//      (never the decoder's cursor). This mirrors `cowswap_order.rs`.
//
//   B. `decode_exec_transaction` — dynamic `bytes` calldata. The decoder
//      reads two SYMBOLIC offset/length words, so:
//        * panic / arithmetic-overflow / slice-OOB freedom ("no read past
//          end") is proven over all symbolic offset+length inputs (Kani's
//          default checks);
//        * the strong, decoder-independent CONTENT soundness is asserted
//          on the FIXED-OFFSET head fields (`to / value / operation /
//          gases / gas_token / refund_receiver`) — reconstructed from the
//          original bytes at the canonical word offsets — plus the
//          `operation ∈ {0,1}` accept gate;
//        * the dynamic-tail discipline is pinned by on-point NEGATIVE
//          controls (OOB length ⇒ `TruncatedDynamic`, offset-into-head ⇒
//          `OffsetOverflow`). We deliberately do NOT dress the dynamic
//          part up as a content biconditional: with no ABI padding gap the
//          returned `data` slice equals `head[off+32..off+32+len]` by
//          construction, so re-deriving it from the same offset/length
//          would only echo the decoder. The honest dynamic guarantee is
//          OOB-freedom + the reject set.
//      Bound: the symbolic soundness harness fixes the calldata length at
//      the 388-byte minimal canonical (`MIN = 4 + 10·32 + 2·32`); head
//      field offsets are length-independent, so the fixed-field property
//      morally extends to longer calldata, but the stated proof bound is
//      N = 388. Panic-freedom additionally ranges over symbolic lengths
//      `≤ N`.
//
// Every symbolic-body soundness harness carries its own in-Kani
// reachability witness (`assert!(decode(&canonical).is_ok())` against a
// concrete canonical the SAME decoder accepts), so a reject-everything
// regression fails loudly instead of passing vacuously.

#[cfg(kani)]
mod verification {
    use super::*;

    // -- A. decode_canonical -------------------------------------------------

    /// Panic / arithmetic-overflow / slice-OOB freedom over ALL symbolic
    /// 281-byte canonical inputs.
    #[kani::proof]
    fn safe_decode_canonical_panic_free() {
        let data: [u8; SAFE_V1_CANONICAL_LEN] = kani::any();
        let _ = decode_canonical(&data);
    }

    /// EXHAUSTIVE decode-soundness biconditional. `decode_canonical(data)`
    /// accepts **iff** `data[SAFE_OFF_OPERATION] ≤ 1`, and on accept every
    /// field is the verbatim copy of its canonical byte range — read from
    /// the correct, in-bounds offset with the correct endianness,
    /// reconstructed independently from the ORIGINAL input (never the
    /// decoder's intermediate values). Exhaustive over the full 281-byte
    /// input space (the canonical length is fixed — no length parameter to
    /// bound).
    #[kani::proof]
    fn safe_decode_canonical_soundness() {
        let data: [u8; SAFE_V1_CANONICAL_LEN] = kani::any();
        let operation = data[SAFE_OFF_OPERATION];
        let op_in_range = operation <= 1;

        match decode_canonical(&data) {
            Ok(tx) => {
                // accept ⟹ operation in range (forward direction).
                assert!(op_in_range);

                let mut chain_id_be = [0u8; 8];
                chain_id_be.copy_from_slice(&data[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8]);
                assert_eq!(tx.chain_id, u64::from_be_bytes(chain_id_be));

                let mut safe_address = [0u8; 20];
                safe_address
                    .copy_from_slice(&data[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20]);
                assert_eq!(tx.safe_address, safe_address);

                let mut to = [0u8; 20];
                to.copy_from_slice(&data[SAFE_OFF_TO..SAFE_OFF_TO + 20]);
                assert_eq!(tx.to, to);

                let mut value = [0u8; 32];
                value.copy_from_slice(&data[SAFE_OFF_VALUE..SAFE_OFF_VALUE + 32]);
                assert_eq!(tx.value, value);

                let mut data_hash = [0u8; 32];
                data_hash.copy_from_slice(&data[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32]);
                assert_eq!(tx.data_hash, data_hash);

                assert_eq!(tx.operation, operation);

                let mut safe_tx_gas = [0u8; 32];
                safe_tx_gas.copy_from_slice(&data[SAFE_OFF_SAFE_TX_GAS..SAFE_OFF_SAFE_TX_GAS + 32]);
                assert_eq!(tx.safe_tx_gas, safe_tx_gas);

                let mut base_gas = [0u8; 32];
                base_gas.copy_from_slice(&data[SAFE_OFF_BASE_GAS..SAFE_OFF_BASE_GAS + 32]);
                assert_eq!(tx.base_gas, base_gas);

                let mut gas_price = [0u8; 32];
                gas_price.copy_from_slice(&data[SAFE_OFF_GAS_PRICE..SAFE_OFF_GAS_PRICE + 32]);
                assert_eq!(tx.gas_price, gas_price);

                let mut gas_token = [0u8; 20];
                gas_token.copy_from_slice(&data[SAFE_OFF_GAS_TOKEN..SAFE_OFF_GAS_TOKEN + 20]);
                assert_eq!(tx.gas_token, gas_token);

                let mut refund_receiver = [0u8; 20];
                refund_receiver.copy_from_slice(
                    &data[SAFE_OFF_REFUND_RECEIVER..SAFE_OFF_REFUND_RECEIVER + 20],
                );
                assert_eq!(tx.refund_receiver, refund_receiver);

                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(&data[SAFE_OFF_NONCE..SAFE_OFF_NONCE + 32]);
                assert_eq!(tx.nonce, nonce);
            }
            Err(SafeTxDecodeError::EnumOutOfRange) => {
                // reject ⟹ operation out of range (reverse direction).
                // Together with the Ok branch this proves the
                // accept ⇔ operation-in-range biconditional.
                assert!(!op_in_range);
            }
        }
    }

    /// Non-vacuity (positive control): a concrete canonical SafeTx with an
    /// in-range `operation` is ACCEPTED and decodes to exactly the expected
    /// fields. Distinctive sentinel bytes at field edges also catch an
    /// offset shared between harness and decoder.
    #[kani::proof]
    fn safe_decode_canonical_accepts_concrete() {
        let mut buf = [0u8; SAFE_V1_CANONICAL_LEN];
        // chain_id = 8453 (Base) = 0x…2105 BE in the low 8 bytes.
        buf[SAFE_OFF_CHAIN_ID + 6] = 0x21;
        buf[SAFE_OFF_CHAIN_ID + 7] = 0x05;
        // safe_address edge sentinels.
        buf[SAFE_OFF_SAFE_ADDRESS] = 0x5a;
        buf[SAFE_OFF_SAFE_ADDRESS + 19] = 0x5b;
        // to edge sentinels.
        buf[SAFE_OFF_TO] = 0xaa;
        buf[SAFE_OFF_TO + 19] = 0xbb;
        // operation = 1 (DelegateCall, max valid).
        buf[SAFE_OFF_OPERATION] = 1;
        // nonce edge sentinels.
        buf[SAFE_OFF_NONCE] = 0xee;
        buf[SAFE_OFF_NONCE + 31] = 0xff;

        match decode_canonical(&buf) {
            Ok(tx) => {
                assert_eq!(tx.chain_id, 8453);
                assert_eq!(tx.safe_address[0], 0x5a);
                assert_eq!(tx.safe_address[19], 0x5b);
                assert_eq!(tx.to[0], 0xaa);
                assert_eq!(tx.to[19], 0xbb);
                assert_eq!(tx.operation, 1);
                assert_eq!(tx.nonce[0], 0xee);
                assert_eq!(tx.nonce[31], 0xff);
            }
            Err(_) => panic!("a canonical SafeTx with operation=1 must decode"),
        }
    }

    /// Non-vacuity (on-point negative control): an out-of-range `operation`
    /// byte (2; valid is 0/1) must be REJECTED with `EnumOutOfRange`. This
    /// is exactly the "NS supplies an out-of-range operation selector"
    /// threat the soundness property forecloses (operation=2 silently
    /// rendered as Call/DelegateCall would be a clear-sign spoof).
    #[kani::proof]
    fn safe_decode_canonical_rejects_out_of_range_operation() {
        let mut buf = [0u8; SAFE_V1_CANONICAL_LEN];
        buf[SAFE_OFF_OPERATION] = 2;
        assert!(matches!(
            decode_canonical(&buf),
            Err(SafeTxDecodeError::EnumOutOfRange)
        ));
    }

    // -- B. decode_exec_transaction -----------------------------------------

    /// Selector + minimal-canonical builder for the exec harnesses: a
    /// well-formed `execTransaction(...)` calldata with empty `data` and
    /// empty `signatures` (the 388-byte minimal canonical). The negatives
    /// tweak one field of this to isolate a single reject reason.
    fn minimal_exec_calldata() -> [u8; EXEC_TRANSACTION_MIN_CALLDATA_LEN] {
        let mut cd = [0u8; EXEC_TRANSACTION_MIN_CALLDATA_LEN];
        cd[..4].copy_from_slice(&EXEC_TRANSACTION_SELECTOR);
        // word 2 = data offset = 320 (0x0140), measured from head start.
        cd[4 + 2 * 32 + 30] = 0x01;
        cd[4 + 2 * 32 + 31] = 0x40;
        // word 9 = signatures offset = 352 (0x0160).
        cd[4 + 9 * 32 + 30] = 0x01;
        cd[4 + 9 * 32 + 31] = 0x60;
        // operation (word 3) = 0; data len word @ head[320]=0; sigs len
        // word @ head[352]=0 — all already zero.
        cd
    }

    /// PANIC / ARITHMETIC-OVERFLOW / SLICE-OOB FREEDOM ("no read past end")
    /// over symbolic calldata of length ≤ N, including the dynamic-tail
    /// path with fully symbolic offset and length words. A length word
    /// claiming more payload than the calldata holds, or an offset pointing
    /// anywhere, can never make the decoder index out of bounds — it
    /// returns `Err` instead. This is the mechanized "no read past end"
    /// guarantee for the dynamic `data` / `signatures` arguments.
    #[kani::proof]
    #[kani::unwind(33)]
    fn decode_exec_panic_free() {
        const N: usize = EXEC_TRANSACTION_MIN_CALLDATA_LEN; // 388
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let _ = decode_exec_transaction(&data[..len]);
    }

    /// SOUNDNESS — fixed-offset head fields + `operation` accept gate over
    /// fully symbolic 388-byte calldata (symbolic offset/length words
    /// included). On accept, every FIXED head field is the verbatim copy of
    /// its canonical word offset reconstructed from the ORIGINAL input, and
    /// `operation ∈ {0,1}`. The dynamic `data` / `signatures` content is
    /// NOT re-asserted here (it would echo the decoder — see the module
    /// note); its in-bounds guarantee is `decode_exec_panic_free` and the
    /// reject controls below.
    #[kani::proof]
    #[kani::unwind(33)]
    fn decode_exec_soundness() {
        // In-Kani reachability witness: a concrete minimal canonical the
        // SAME decoder accepts, so the Ok-branch postcondition below is
        // provably reachable and a reject-everything regression fails HERE.
        let canon = minimal_exec_calldata();
        assert!(decode_exec_transaction(&canon).is_ok());

        let cd: [u8; EXEC_TRANSACTION_MIN_CALLDATA_LEN] = kani::any();
        if let Ok(d) = decode_exec_transaction(&cd) {
            // accept ⟹ operation in {0,1}.
            assert!(d.operation <= 1);

            // head starts at cd[4..]; word i occupies cd[4 + i*32 .. +32].
            // `to`: word 0, canonical address (low 20 bytes; top 12 zero
            // enforced by the decoder).
            let mut to = [0u8; 20];
            to.copy_from_slice(&cd[4 + 12..4 + 32]);
            assert_eq!(d.to, to);
            // accept ⟹ `to`'s top-12 padding is zero (canonical address — the
            // `read_address_word_off` reject; finding 3b/#4). Without this a
            // deleted reject would accept a dirty-padding address unseen.
            assert!(cd[4..4 + 12].iter().all(|&b| b == 0));

            // `value`: word 1 (uint256).
            let mut value = [0u8; 32];
            value.copy_from_slice(&cd[4 + 32..4 + 64]);
            assert_eq!(d.value, value);

            // `operation`: low byte of word 3.
            assert_eq!(d.operation, cd[4 + 3 * 32 + 31]);

            // `safe_tx_gas` / `base_gas` / `gas_price`: words 4/5/6.
            let mut safe_tx_gas = [0u8; 32];
            safe_tx_gas.copy_from_slice(&cd[4 + 4 * 32..4 + 5 * 32]);
            assert_eq!(d.safe_tx_gas, safe_tx_gas);
            let mut base_gas = [0u8; 32];
            base_gas.copy_from_slice(&cd[4 + 5 * 32..4 + 6 * 32]);
            assert_eq!(d.base_gas, base_gas);
            let mut gas_price = [0u8; 32];
            gas_price.copy_from_slice(&cd[4 + 6 * 32..4 + 7 * 32]);
            assert_eq!(d.gas_price, gas_price);

            // `gas_token` / `refund_receiver`: words 7/8 (canonical address).
            let mut gas_token = [0u8; 20];
            gas_token.copy_from_slice(&cd[4 + 7 * 32 + 12..4 + 8 * 32]);
            assert_eq!(d.gas_token, gas_token);
            let mut refund_receiver = [0u8; 20];
            refund_receiver.copy_from_slice(&cd[4 + 8 * 32 + 12..4 + 9 * 32]);
            assert_eq!(d.refund_receiver, refund_receiver);
            // accept ⟹ gas_token (word 7) / refund_receiver (word 8) top-12
            // padding is zero (canonical addresses; finding 3b/#4).
            assert!(cd[4 + 7 * 32..4 + 7 * 32 + 12].iter().all(|&b| b == 0));
            assert!(cd[4 + 8 * 32..4 + 8 * 32 + 12].iter().all(|&b| b == 0));
        }
    }

    /// Non-vacuity (positive control): a concrete `execTransaction(...)`
    /// with NON-EMPTY `data` and `signatures`, `operation = 1`, and field
    /// sentinels is ACCEPTED and decodes to exactly the expected fields —
    /// including the dynamic tails. Anchors the dynamic-payload accept path
    /// (the witness inside `decode_exec_soundness` only covers empty tails).
    #[kani::proof]
    #[kani::unwind(33)]
    fn decode_exec_accepts_canonical() {
        // Layout: selector(4) + head(320) + data tail(len word + 4 B + pad
        // to 32) + sigs tail(len word + 3 B + pad to 32). data_off = 320,
        // sigs_off = 320 + 32 + 32 = 384.
        const TOTAL: usize = 4 + 320 + 32 + 32 + 32 + 32; // 452
        let mut cd = [0u8; TOTAL];
        cd[..4].copy_from_slice(&EXEC_TRANSACTION_SELECTOR);
        // word 0: to = 0xAA.. (low 20 bytes).
        for b in cd[4 + 12..4 + 32].iter_mut() {
            *b = 0xAA;
        }
        // word 1: value low byte = 7.
        cd[4 + 32 + 31] = 7;
        // word 2: data offset = 320 (0x0140).
        cd[4 + 2 * 32 + 30] = 0x01;
        cd[4 + 2 * 32 + 31] = 0x40;
        // word 3: operation = 1 (DelegateCall).
        cd[4 + 3 * 32 + 31] = 1;
        // word 7: gas_token = 0x40.. ; word 8: refund_receiver = 0x50..
        for b in cd[4 + 7 * 32 + 12..4 + 8 * 32].iter_mut() {
            *b = 0x40;
        }
        for b in cd[4 + 8 * 32 + 12..4 + 9 * 32].iter_mut() {
            *b = 0x50;
        }
        // word 9: signatures offset = 384 (0x0180).
        cd[4 + 9 * 32 + 30] = 0x01;
        cd[4 + 9 * 32 + 31] = 0x80;
        // data tail @ head[320]: length = 4, payload = DE AD BE EF.
        let data_pos = 4 + 320;
        cd[data_pos + 31] = 4;
        cd[data_pos + 32] = 0xDE;
        cd[data_pos + 33] = 0xAD;
        cd[data_pos + 34] = 0xBE;
        cd[data_pos + 35] = 0xEF;
        // sigs tail @ head[384] = cd[388]: length = 3, payload = 01 02 03.
        let sigs_pos = 4 + 384;
        cd[sigs_pos + 31] = 3;
        cd[sigs_pos + 32] = 0x01;
        cd[sigs_pos + 33] = 0x02;
        cd[sigs_pos + 34] = 0x03;

        match decode_exec_transaction(&cd) {
            Ok(d) => {
                assert_eq!(d.to, [0xAA; 20]);
                assert_eq!(d.value[31], 7);
                assert_eq!(d.operation, 1);
                assert_eq!(d.gas_token, [0x40; 20]);
                assert_eq!(d.refund_receiver, [0x50; 20]);
                assert_eq!(d.data, &[0xDE, 0xAD, 0xBE, 0xEF]);
                assert_eq!(d.signatures, &[0x01, 0x02, 0x03]);
            }
            Err(_) => panic!("a canonical execTransaction must decode"),
        }
    }

    /// Non-vacuity (negative): out-of-range `operation` byte (2) ⇒
    /// `EnumOutOfRange`. The on-point clear-sign threat — an operation the
    /// renderer can't classify as Call/DelegateCall must never be signed.
    #[kani::proof]
    #[kani::unwind(33)]
    fn decode_exec_rejects_operation_2() {
        let mut cd = minimal_exec_calldata();
        cd[4 + 3 * 32 + 31] = 2; // operation low byte
        assert!(matches!(
            decode_exec_transaction(&cd),
            Err(SafeExecDecodeError::EnumOutOfRange)
        ));
    }

    /// Non-vacuity (negative): a non-zero byte in the top 31 bytes of the
    /// `operation` word (a "dirty" left-padding) ⇒ `EnumOutOfRange`.
    #[kani::proof]
    #[kani::unwind(33)]
    fn decode_exec_rejects_operation_high_bits() {
        let mut cd = minimal_exec_calldata();
        cd[4 + 3 * 32] = 1; // top byte of the operation word
        assert!(matches!(
            decode_exec_transaction(&cd),
            Err(SafeExecDecodeError::EnumOutOfRange)
        ));
    }

    /// Non-vacuity (negative, finding 3b/#4): a non-zero byte in the top-12
    /// padding of ANY address word — `to` (word 0), `gas_token` (word 7), or
    /// `refund_receiver` (word 8) — ⇒ `NonCanonicalAddress`. The `to`/gas_token/
    /// refund_receiver reject shares `read_address_word_off`; deleting its
    /// top-12 check leaves this control AND the `decode_exec_soundness`
    /// accept-direction asserts red. Stops an attacker smuggling high-order
    /// bytes past the address padding (`kani_mutations.json:
    /// safe_exec_noncanonical_address`).
    #[kani::proof]
    #[kani::unwind(33)]
    fn decode_exec_rejects_noncanonical_address() {
        // `to` — word 0, dirty top byte.
        let mut cd = minimal_exec_calldata();
        cd[4] = 1;
        assert!(matches!(
            decode_exec_transaction(&cd),
            Err(SafeExecDecodeError::NonCanonicalAddress)
        ));
        // `gas_token` — word 7, dirty top byte.
        let mut cd = minimal_exec_calldata();
        cd[4 + 7 * 32] = 1;
        assert!(matches!(
            decode_exec_transaction(&cd),
            Err(SafeExecDecodeError::NonCanonicalAddress)
        ));
        // `refund_receiver` — word 8, dirty top byte.
        let mut cd = minimal_exec_calldata();
        cd[4 + 8 * 32] = 1;
        assert!(matches!(
            decode_exec_transaction(&cd),
            Err(SafeExecDecodeError::NonCanonicalAddress)
        ));
    }

    /// Non-vacuity (the on-point "read past end" negative): a dynamic
    /// `data` length word that claims MORE payload than the calldata holds
    /// must be REFUSED with `TruncatedDynamic`. The offset is canonical
    /// (320) and the buffer is the minimal canonical, so the
    /// `payload_end > head.len()` bounds check is the SOLE discriminator —
    /// exactly the hidden-OOB-read threat the panic-free proof forecloses.
    #[kani::proof]
    #[kani::unwind(33)]
    fn decode_exec_rejects_oob_data_length() {
        let mut cd = minimal_exec_calldata();
        // data length word @ head[320] = cd[324..356]; set it to 1000
        // (0x03E8) — far past the 64 bytes of tail the buffer actually has.
        cd[4 + 320 + 30] = 0x03;
        cd[4 + 320 + 31] = 0xE8;
        assert!(matches!(
            decode_exec_transaction(&cd),
            Err(SafeExecDecodeError::TruncatedDynamic)
        ));
    }

    /// Non-vacuity (negative): a `data` offset pointing INTO the head
    /// region (0, < 320) ⇒ `OffsetOverflow`. Refusing this stops an
    /// attacker pointing the bytes argument back over the head words so the
    /// renderer would show head bytes as `data`.
    #[kani::proof]
    #[kani::unwind(33)]
    fn decode_exec_rejects_data_offset_into_head() {
        let mut cd = minimal_exec_calldata();
        // word 2 (data offset) → 0 (points at head word 0).
        cd[4 + 2 * 32 + 30] = 0;
        cd[4 + 2 * 32 + 31] = 0;
        assert!(matches!(
            decode_exec_transaction(&cd),
            Err(SafeExecDecodeError::OffsetOverflow)
        ));
    }

    /// Non-vacuity (negative): calldata one byte short of the fixed-head
    /// minimum ⇒ `ShortInput` (never a panic on the under-length read).
    #[kani::proof]
    fn decode_exec_rejects_short_input() {
        let cd = [0u8; EXEC_TRANSACTION_MIN_CALLDATA_LEN - 1];
        assert!(matches!(
            decode_exec_transaction(&cd),
            Err(SafeExecDecodeError::ShortInput)
        ));
    }

    /// Data-slice fidelity (finding §2 #5): upgrades the dynamic `data` guarantee from
    /// "OOB-freedom + reject set" (the module note above) to "the rendered slice is the
    /// VERBATIM payload bytes at the canonically-computed position" — for BOUNDED
    /// payloads (≤ 8 bytes, to keep the byte-compare finite). `data_off` (word 2's low
    /// bytes) and the declared length are re-read INDEPENDENTLY from the raw head bytes
    /// (not the decoder's variables), so a payload-shift mutation in `read_dynamic_bytes`
    /// (`payload_start = offset` instead of `offset + 32`) — which makes `d.data` start
    /// 32 bytes early at ANY accepted offset — flips this to FAILED. The empty-tail
    /// `decode_exec_soundness` + the single concrete `decode_exec_accepts_canonical`
    /// witness (fixed offset 320) do not close that shift for symbolic offsets
    /// (`kani_mutations.json: safe_exec_data_slice_shift`).
    #[kani::proof]
    #[kani::unwind(41)]
    fn decode_exec_data_slice_fidelity() {
        let cd: [u8; 452] = kani::any();
        if let Ok(d) = decode_exec_transaction(&cd) {
            let data_len = d.data.len();
            kani::assume(data_len <= 8); // keep the byte-compare loop finite
            let head = &cd[4..];
            // word 2 (data offset), low 4 bytes — equals the decoder's `data_off` on
            // accept (accept ⟹ the offset word's high bytes are zero).
            let data_off = u32::from_be_bytes([head[92], head[93], head[94], head[95]]) as usize;
            // declared length re-read from the length word at `data_off` (low 4 bytes).
            let decl_len = u32::from_be_bytes([
                head[data_off + 28],
                head[data_off + 29],
                head[data_off + 30],
                head[data_off + 31],
            ]) as usize;
            assert_eq!(data_len, decl_len);
            // Verbatim content: d.data[i] == head[data_off + 32 + i] for every i.
            let mut i = 0usize;
            while i < data_len {
                assert_eq!(d.data[i], head[data_off + 32 + i]);
                i += 1;
            }
        }
    }
}
