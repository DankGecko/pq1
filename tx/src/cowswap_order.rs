//! Pure field-decode for the CowSwap `GPv2Order` clear-sign trailer.
//!
//! This is the host-compilable, Kani-friendly core of the CoW Swap
//! WYSIWYS path: the fixed-offset extraction of the 204-byte canonical
//! packed `GPv2Order` encoding into the typed [`GpV2Order`] struct, plus
//! the small-enum range validation. It is extracted here, verbatim and
//! behaviour-identical, so it can be host-compiled and bounded-verified
//! with Kani (`cargo kani -p pqsigner-tx`) — the firmware-side
//! `secure/src/tx/eip712/cowswap/mod.rs` re-exports [`GpV2Order`] and
//! wraps [`decode_canonical`] (mapping the error into the secure-world
//! `Eip712Error`), so every existing caller, the struct-hash / digest
//! pipeline, the cross-check, and the full test suite keep working.
//!
//! Dependency closure is intentionally empty: pure byte copies and
//! comparisons, no hashing, no `cow_binding`, no
//! hardware. The keccak `struct_hash` / `compute_digest` and the
//! `setPreSignature` cross-check stay in `secure/` — only the byte-layout
//! decode lives here.
//!
//! ## Canonical layout (204 bytes — v3)
//!
//! ```text
//!   [  0..  8 )  chain_id           (u64 BE)
//!   [  8..  28)  sellToken          (20 B address)
//!   [ 28..  48)  buyToken           (20 B address)
//!   [ 48..  68)  receiver           (20 B address)
//!   [ 68.. 100)  sellAmount         (uint256 BE)
//!   [100.. 132)  buyAmount          (uint256 BE)
//!   [132.. 164)  feeAmount          (uint256 BE)
//!   [164.. 168)  validTo            (uint32 BE)
//!   [168]        kind               (0 = sell, 1 = buy)
//!   [169]        partiallyFillable  (0 / 1)
//!   [170]        sellTokenBalance   (0 / 1 / 2)
//!   [171]        buyTokenBalance    (0 / 1)
//!   [172.. 204)  appData            (bytes32)
//! ```
//!
//! ## The proven property (decode-soundness)
//!
//! `decode_canonical(c) == Ok(order)` ⟹ every field of `order` is the
//! verbatim copy of its canonical byte range (correct offset, correct
//! endianness) AND each of the four small-enum bytes is in range. The
//! accept set is fully characterised: `decode_canonical(c).is_ok()`
//! **iff** all four enum bytes are within their valid ranges. So an
//! out-of-range enum selector (or any mis-offset read) is foreclosed over
//! ALL symbolic 204-byte inputs. See the `#[cfg(kani)] mod verification`
//! harnesses at the bottom of this file.

/// Canonical packed `GPv2Order` encoding length (v3).
pub const COW_CANONICAL_LEN: usize = 204;

/// Decode failure for the canonical `GPv2Order` packed encoding.
///
/// The only failure mode is an out-of-range small-enum byte (`kind`,
/// `partiallyFillable`, `sellTokenBalance`, or `buyTokenBalance`); every
/// other field is a fixed-width byte copy that cannot fail. The
/// secure-world shim maps this onto its broader `Eip712Error::EnumOutOfRange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowOrderDecodeError {
    /// One of the byte-encoded enum fields was outside its valid range.
    EnumOutOfRange,
}

/// Decoded `GPv2Order` fields. Borrows nothing — every field is owned.
#[derive(Clone, Copy, Debug)]
pub struct GpV2Order {
    pub chain_id: u64,
    pub sell_token: [u8; 20],
    pub buy_token: [u8; 20],
    pub receiver: [u8; 20],
    pub sell_amount: [u8; 32],
    pub buy_amount: [u8; 32],
    pub fee_amount: [u8; 32],
    pub valid_to: u32,
    pub kind: u8,
    pub partially_fillable: u8,
    pub sell_token_balance: u8,
    pub buy_token_balance: u8,
    pub app_data: [u8; 32],
}

/// Parse the 204-byte canonical packed encoding into structured fields.
///
/// Validates the small-enum byte ranges (`kind`, `partiallyFillable`,
/// `sellTokenBalance`, `buyTokenBalance`) so an out-of-range payload is
/// rejected before it can ever produce a digest. Every other field is a
/// fixed-offset copy at the canonical layout above.
pub fn decode_canonical(canonical: &[u8; COW_CANONICAL_LEN]) -> Result<GpV2Order, CowOrderDecodeError> {
    let chain_id = u64::from_be_bytes([
        canonical[0], canonical[1], canonical[2], canonical[3],
        canonical[4], canonical[5], canonical[6], canonical[7],
    ]);

    let mut sell_token = [0u8; 20];
    sell_token.copy_from_slice(&canonical[8..28]);
    let mut buy_token = [0u8; 20];
    buy_token.copy_from_slice(&canonical[28..48]);
    let mut receiver = [0u8; 20];
    receiver.copy_from_slice(&canonical[48..68]);

    let mut sell_amount = [0u8; 32];
    sell_amount.copy_from_slice(&canonical[68..100]);
    let mut buy_amount = [0u8; 32];
    buy_amount.copy_from_slice(&canonical[100..132]);
    let mut fee_amount = [0u8; 32];
    fee_amount.copy_from_slice(&canonical[132..164]);

    let valid_to = u32::from_be_bytes([
        canonical[164],
        canonical[165],
        canonical[166],
        canonical[167],
    ]);

    let kind = canonical[168];
    let partially_fillable = canonical[169];
    let sell_token_balance = canonical[170];
    let buy_token_balance = canonical[171];

    if kind > 1
        || partially_fillable > 1
        || sell_token_balance > 2
        || buy_token_balance > 1
    {
        return Err(CowOrderDecodeError::EnumOutOfRange);
    }

    let mut app_data = [0u8; 32];
    app_data.copy_from_slice(&canonical[172..204]);

    Ok(GpV2Order {
        chain_id,
        sell_token,
        buy_token,
        receiver,
        sell_amount,
        buy_amount,
        fee_amount,
        valid_to,
        kind,
        partially_fillable,
        sell_token_balance,
        buy_token_balance,
        app_data,
    })
}

// ---------------------------------------------------------------------------
// setPreSignature(orderUid, signed) calldata — shape + orderUid field decode.
//
// The trusted-display binding for a CoW pre-sign: the C10 signature commits to
// this 164-byte `setPreSignature(bytes,bool)` calldata, and the orderUid it
// carries is `orderDigest(32) ‖ owner(20) ‖ validTo(4)`. The secure world
// (`secure/src/tx/eip712/cowswap`) rebuilds the orderDigest with keccak and
// byte-compares it, the validTo, and — the P1.2 owner-UID binding — the OWNER
// against the expected owner (the wallet `sender` for a direct pre-sign, the
// SAFE for a Safe-wrapped one; see `secure/.../safe/cow_binding.rs`).
//
// This is the host-linkable, Kani-friendly kernel for the SHAPE + fixed-offset
// orderUid field extraction (no hashing — the digest rebuild/compare stays in
// secure/). `decode_setpresig_orderuid(c) == Some(uid)` iff `c` is the canonical
// `setPreSignature(orderUid, true)` encoding, and then `uid.{order_digest,owner,
// valid_to}` are the verbatim bytes at the canonical orderUid offsets. So the
// owner the secure world binds against is provably the owner embedded in the
// signed calldata — read from the right offset, over ALL symbolic inputs.
// ---------------------------------------------------------------------------

/// Canonical `setPreSignature(bytes orderUid, bool signed)` calldata length.
pub const COW_SETPRESIG_CALLDATA_LEN: usize = 164;

/// `setPreSignature(bytes,bool)` selector.
pub const SETPRESIG_SELECTOR: [u8; 4] = [0xec, 0x6c, 0xb1, 0x3f];

/// orderUid = `orderDigest(32) ‖ owner(20) ‖ validTo(4)` starting at byte 100.
pub const SETPRESIG_ORDER_DIGEST_OFFSET: usize = 100; // [100..132)
pub const SETPRESIG_OWNER_OFFSET: usize = 132; //        [132..152)
pub const SETPRESIG_VALID_TO_OFFSET: usize = 152; //     [152..156)

/// The three orderUid sub-fields carried by a setPreSignature calldata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetPresigOrderUid {
    pub order_digest: [u8; 32],
    pub owner: [u8; 20],
    pub valid_to: [u8; 4],
}

/// Decode a 164-byte `setPreSignature(orderUid, true)` calldata: verify its
/// canonical ABI shape (selector, `bytes` offset `0x40`, `signed == true`,
/// `orderUid` length `56`, and the `[156..164)` zero-pad tail) and, if canonical,
/// extract the orderUid's `(order_digest, owner, valid_to)` at their fixed
/// offsets. `None` iff the shape is non-canonical — so a non-canonical calldata
/// can never bind an owner/digest the display does not derive from these exact
/// bytes. Pure: no hashing, no allocation.
pub fn decode_setpresig_orderuid(
    calldata: &[u8; COW_SETPRESIG_CALLDATA_LEN],
) -> Option<SetPresigOrderUid> {
    // ── canonical shape ──
    if calldata[0..4] != SETPRESIG_SELECTOR {
        return None;
    }
    // `bytes` arg offset = 0x40 at slot 0 (word [4..36)).
    if calldata[4..35].iter().any(|&b| b != 0) || calldata[35] != 0x40 {
        return None;
    }
    // `signed` bool == true at slot 1 (word [36..68)).
    if calldata[36..67].iter().any(|&b| b != 0) || calldata[67] != 1 {
        return None;
    }
    // orderUid `bytes` length == 56 at slot 2 (word [68..100)).
    if calldata[68..99].iter().any(|&b| b != 0) || calldata[99] != 56 {
        return None;
    }
    // ABI tail zero-pad [156..164) (56-byte orderUid padded to 64).
    if calldata[156..164].iter().any(|&b| b != 0) {
        return None;
    }
    // ── extract orderUid fields at their canonical offsets ──
    let mut order_digest = [0u8; 32];
    order_digest.copy_from_slice(&calldata[SETPRESIG_ORDER_DIGEST_OFFSET..SETPRESIG_ORDER_DIGEST_OFFSET + 32]);
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&calldata[SETPRESIG_OWNER_OFFSET..SETPRESIG_OWNER_OFFSET + 20]);
    let mut valid_to = [0u8; 4];
    valid_to.copy_from_slice(&calldata[SETPRESIG_VALID_TO_OFFSET..SETPRESIG_VALID_TO_OFFSET + 4]);
    Some(SetPresigOrderUid { order_digest, owner, valid_to })
}

// ---------------------------------------------------------------------------
// Bounded verification (Kani)
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod verification {
    use super::*;

    /// Panic / arithmetic-overflow / slice-OOB freedom over ALL symbolic
    /// 204-byte canonical inputs. The decoder must never panic regardless
    /// of what NS supplies. (Kani runs these default checks on every
    /// harness, but a dedicated one documents the panic-freedom guarantee
    /// directly on the untrusted-bytes parse surface.)
    #[kani::proof]
    fn decode_canonical_panic_free() {
        let data: [u8; COW_CANONICAL_LEN] = kani::any();
        let _ = decode_canonical(&data);
    }

    /// Decode-soundness: `decode_canonical(data) == Ok(order)` ⟹ every
    /// field of `order` is the verbatim copy of its canonical byte range
    /// — read from the **correct, in-bounds offset** with the correct
    /// endianness — and each of the four small-enum bytes is in range.
    ///
    /// The accept set is fully characterised as a biconditional against
    /// the ORIGINAL input bytes (never the decoder's cursor):
    /// `decode_canonical(data).is_ok()` **iff** the four enum bytes
    /// (`data[168..172]`) are all within range. So this forecloses, over
    /// ALL symbolic 204-byte calldata, both an out-of-range enum selector
    /// being accepted AND any field being read from a wrong offset / with
    /// wrong endianness.
    ///
    /// Bound: exhaustive over the full 204-byte input space (the canonical
    /// length is fixed — there is no length parameter to bound). The proof
    /// is therefore complete for this fixed-layout decoder, not bounded by
    /// an `N`.
    #[kani::proof]
    fn decode_canonical_soundness() {
        let data: [u8; COW_CANONICAL_LEN] = kani::any();

        let kind = data[168];
        let partially_fillable = data[169];
        let sell_token_balance = data[170];
        let buy_token_balance = data[171];
        let enums_in_range = kind <= 1
            && partially_fillable <= 1
            && sell_token_balance <= 2
            && buy_token_balance <= 1;

        match decode_canonical(&data) {
            Ok(order) => {
                // accept ⟹ all enum bytes in range (forward direction).
                assert!(enums_in_range);

                // Every field == verbatim copy from its canonical offset,
                // reconstructed independently from the ORIGINAL input.
                let mut chain_id_be = [0u8; 8];
                chain_id_be.copy_from_slice(&data[0..8]);
                assert_eq!(order.chain_id, u64::from_be_bytes(chain_id_be));

                let mut sell_token = [0u8; 20];
                sell_token.copy_from_slice(&data[8..28]);
                assert_eq!(order.sell_token, sell_token);

                let mut buy_token = [0u8; 20];
                buy_token.copy_from_slice(&data[28..48]);
                assert_eq!(order.buy_token, buy_token);

                let mut receiver = [0u8; 20];
                receiver.copy_from_slice(&data[48..68]);
                assert_eq!(order.receiver, receiver);

                let mut sell_amount = [0u8; 32];
                sell_amount.copy_from_slice(&data[68..100]);
                assert_eq!(order.sell_amount, sell_amount);

                let mut buy_amount = [0u8; 32];
                buy_amount.copy_from_slice(&data[100..132]);
                assert_eq!(order.buy_amount, buy_amount);

                let mut fee_amount = [0u8; 32];
                fee_amount.copy_from_slice(&data[132..164]);
                assert_eq!(order.fee_amount, fee_amount);

                let mut valid_to_be = [0u8; 4];
                valid_to_be.copy_from_slice(&data[164..168]);
                assert_eq!(order.valid_to, u32::from_be_bytes(valid_to_be));

                assert_eq!(order.kind, kind);
                assert_eq!(order.partially_fillable, partially_fillable);
                assert_eq!(order.sell_token_balance, sell_token_balance);
                assert_eq!(order.buy_token_balance, buy_token_balance);

                let mut app_data = [0u8; 32];
                app_data.copy_from_slice(&data[172..204]);
                assert_eq!(order.app_data, app_data);
            }
            Err(CowOrderDecodeError::EnumOutOfRange) => {
                // reject ⟹ at least one enum byte out of range (reverse
                // direction). Together with the Ok branch this proves the
                // accept ⇔ in-range biconditional.
                assert!(!enums_in_range);
            }
        }
    }

    /// Non-vacuity (positive control): a concrete canonical `GPv2Order`
    /// with in-range enum bytes is ACCEPTED and decodes to exactly the
    /// expected fields. Without this the soundness proof above could pass
    /// vacuously (a decoder that rejected everything satisfies the
    /// implications trivially). Distinctive sentinel bytes at the field
    /// edges also catch an offset shared between harness and decoder.
    #[kani::proof]
    fn decode_canonical_accepts_concrete() {
        let mut buf = [0u8; COW_CANONICAL_LEN];
        // chain_id = 8453 (Base) = 0x0000_0000_0000_2105 BE.
        buf[6] = 0x21;
        buf[7] = 0x05;
        // sell_token edge sentinels.
        buf[8] = 0xaa;
        buf[27] = 0xbb;
        // buy_token / receiver edge sentinels.
        buf[28] = 0xcc;
        buf[67] = 0xdd;
        // validTo = 1.
        buf[167] = 1;
        // enums: all at their maximum valid value.
        buf[168] = 1; // kind = buy
        buf[169] = 1; // partiallyFillable
        buf[170] = 2; // sellTokenBalance = internal (sell side, max valid)
        buf[171] = 1; // buyTokenBalance
        // appData edge sentinels.
        buf[172] = 0xee;
        buf[203] = 0xff;

        match decode_canonical(&buf) {
            Ok(o) => {
                assert_eq!(o.chain_id, 8453);
                assert_eq!(o.sell_token[0], 0xaa);
                assert_eq!(o.sell_token[19], 0xbb);
                assert_eq!(o.buy_token[0], 0xcc);
                assert_eq!(o.receiver[19], 0xdd);
                assert_eq!(o.valid_to, 1);
                assert_eq!(o.kind, 1);
                assert_eq!(o.partially_fillable, 1);
                assert_eq!(o.sell_token_balance, 2);
                assert_eq!(o.buy_token_balance, 1);
                assert_eq!(o.app_data[0], 0xee);
                assert_eq!(o.app_data[31], 0xff);
            }
            Err(_) => panic!("a canonical GPv2Order with in-range enums must decode"),
        }
    }

    /// Non-vacuity (negative control — the on-point one): an out-of-range
    /// `kind` byte (2; valid is 0/1) must be REJECTED with
    /// `EnumOutOfRange`. This is exactly the "NS supplies an out-of-range
    /// enum selector" threat the soundness property exists to foreclose.
    #[kani::proof]
    fn decode_canonical_rejects_out_of_range_kind() {
        let mut buf = [0u8; COW_CANONICAL_LEN];
        buf[168] = 2; // kind out of range
        assert!(matches!(
            decode_canonical(&buf),
            Err(CowOrderDecodeError::EnumOutOfRange)
        ));
    }

    /// Non-vacuity (negative control B): an out-of-range `sellTokenBalance`
    /// byte (3; valid is 0/1/2) must be REJECTED — covers the wider 0..=2
    /// enum whose bound differs from the 0..=1 ones.
    #[kani::proof]
    fn decode_canonical_rejects_out_of_range_balance() {
        let mut buf = [0u8; COW_CANONICAL_LEN];
        buf[170] = 3; // sellTokenBalance out of range
        assert!(matches!(
            decode_canonical(&buf),
            Err(CowOrderDecodeError::EnumOutOfRange)
        ));
    }

    // ----- setPreSignature orderUid decode (P1.2 CoW owner-UID binding) -----

    /// CANONICITY / show⇒signed-bytes for the CoW owner-UID binding: over ALL
    /// symbolic 164-byte calldata, IF `decode_setpresig_orderuid` accepts and
    /// returns `uid` (so the secure world will bind the order to `uid.owner` /
    /// `uid.order_digest` / `uid.valid_to`), THEN the calldata is the canonical
    /// `setPreSignature(orderUid, true)` encoding AND every orderUid field is the
    /// verbatim bytes at its canonical offset — in particular `uid.owner ==
    /// calldata[132..152]`. So the owner the display/verifier binds against is
    /// provably the owner embedded in the SIGNED calldata, read from the right
    /// offset. Exhaustive over the fixed 164-byte layout (no length parameter).
    #[kani::proof]
    fn decode_setpresig_orderuid_canonical() {
        let c: [u8; COW_SETPRESIG_CALLDATA_LEN] = kani::any();
        if let Some(uid) = decode_setpresig_orderuid(&c) {
            // accept ⟹ canonical shape (selector / offset / signed / len / pad)
            assert!(c[0..4] == SETPRESIG_SELECTOR);
            assert!(c[35] == 0x40 && c[67] == 1 && c[99] == 56);
            assert!(c[4..35].iter().all(|&b| b == 0));
            assert!(c[36..67].iter().all(|&b| b == 0));
            assert!(c[68..99].iter().all(|&b| b == 0));
            assert!(c[156..164].iter().all(|&b| b == 0));
            // accept ⟹ fields are the verbatim orderUid bytes (correct offsets),
            // reconstructed independently from the ORIGINAL calldata.
            let mut od = [0u8; 32];
            od.copy_from_slice(&c[100..132]);
            assert!(uid.order_digest == od);
            let mut ow = [0u8; 20];
            ow.copy_from_slice(&c[132..152]);
            assert!(uid.owner == ow);
            let mut vt = [0u8; 4];
            vt.copy_from_slice(&c[152..156]);
            assert!(uid.valid_to == vt);
        }
    }

    /// Non-vacuity (positive control): a canonical setPreSignature calldata is
    /// ACCEPTED and the orderUid fields decode to exactly the embedded bytes
    /// (edge sentinels catch an offset shared between harness and decoder).
    #[kani::proof]
    fn decode_setpresig_orderuid_accepts_concrete() {
        let mut c = [0u8; COW_SETPRESIG_CALLDATA_LEN];
        c[0..4].copy_from_slice(&SETPRESIG_SELECTOR);
        c[35] = 0x40;
        c[67] = 1;
        c[99] = 56;
        // orderDigest / owner / validTo edge sentinels.
        c[100] = 0x11;
        c[131] = 0x22;
        c[132] = 0x33; // owner[0]
        c[151] = 0x44; // owner[19]
        c[152] = 0x55; // validTo[0]
        c[155] = 0x66; // validTo[3]
        match decode_setpresig_orderuid(&c) {
            Some(uid) => {
                assert!(uid.order_digest[0] == 0x11 && uid.order_digest[31] == 0x22);
                assert!(uid.owner[0] == 0x33 && uid.owner[19] == 0x44);
                assert!(uid.valid_to[0] == 0x55 && uid.valid_to[3] == 0x66);
            }
            None => panic!("a canonical setPreSignature calldata must decode"),
        }
    }

    /// Non-vacuity (negative control): a wrong selector — the "NS supplies a
    /// different call than setPreSignature" threat — must be REJECTED.
    #[kani::proof]
    fn decode_setpresig_orderuid_rejects_bad_selector() {
        let mut c = [0u8; COW_SETPRESIG_CALLDATA_LEN];
        c[35] = 0x40;
        c[67] = 1;
        c[99] = 56;
        c[0] = 0xde; // selector != setPreSignature
        assert!(decode_setpresig_orderuid(&c).is_none());
    }
}
