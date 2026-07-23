//! EIP-1559 typed transaction envelope parser and the shared `U256`
//! big-endian integer used throughout the display / sign pipeline.
//!
//! Format (EIP-2718 typed envelope, EIP-1559 type 0x02):
//!
//! ```text
//! 0x02 ‖ rlp([
//!     chain_id,
//!     nonce,
//!     max_priority_fee_per_gas,
//!     max_fee_per_gas,
//!     gas_limit,
//!     to,            // 20 bytes or empty (contract creation)
//!     value,
//!     data,
//!     access_list,   // RLP list of [address(20), [storage_key(32)...]]
//!     // signature appended after signing — omitted in unsigned form
//! ])
//! ```
//!
//! Strict parser: rejects malformed RLP, leading zeros, oversized
//! integers, malformed access lists, EIP-155 chain_id == 0, gas below
//! the 21 000 intrinsic floor, max_priority > max_fee, and any envelope
//! outside `1 < len ≤ MAX_TX_LEN`.

use crate::rlp::{self, Item, ListIter, RlpError};

/// EIP-1559 intrinsic gas floor for a signed tx. Nothing below this can
/// execute on an EVM chain, so accepting it would mean the user
/// confirmed a tx that can never land.
pub const MIN_INTRINSIC_GAS: u64 = 21_000;

#[derive(Debug, PartialEq, Eq)]
pub enum TxError {
    NotEip1559,
    EmptyEnvelope,
    Rlp(RlpError),
    BadToLength,
    TrailingBytes,
    EnvelopeTooLong,
    /// `chain_id` was zero — forbidden by EIP-155.
    BadChainId,
    /// `gas_limit` was below the 21 000-gas intrinsic floor.
    GasLimitTooLow,
    /// `max_priority_fee_per_gas > max_fee_per_gas`, forbidden by EIP-1559.
    PriorityExceedsFee,
    /// Access list entry was not `[address(20), [key(32)...]]`.
    BadAccessList,
}

impl From<RlpError> for TxError {
    fn from(e: RlpError) -> Self {
        TxError::Rlp(e)
    }
}

// ---------------------------------------------------------------------------
// U256
// ---------------------------------------------------------------------------

/// Big-endian 256-bit unsigned integer.
///
/// Stored most-significant-byte first: `self.0[0]` is bits 248..255,
/// `self.0[31]` is bits 0..7. All public accessors preserve that.
///
/// The derived `PartialOrd`/`Ord` compare the inner `[u8; 32]`
/// lexicographically, which — because the bytes are big-endian — is
/// exactly the numeric magnitude ordering. Callers can use `<`, `>`,
/// `<=`, `>=` directly.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U256(pub [u8; 32]);

impl U256 {
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Saturating `self * rhs -> U256` for fee-budget display
    /// (`max_fee * gas_limit`). Returns `(product, overflow)`; the
    /// product saturates at `U256::MAX` on overflow.
    #[must_use]
    pub fn saturating_mul_u64(&self, rhs: u64) -> (U256, bool) {
        let mut out = [0u8; 32];
        let mut carry: u128 = 0;
        // LS-first multiply. Indexed form (i = 31 - j) instead of
        // `(0..32).rev()` so the Aeneas model is a plain Range loop —
        // see contracts/verification §33 rank 10. Identical sequence.
        for j in 0..32 {
            let i = 31 - j;
            let prod = (self.0[i] as u128) * (rhs as u128) + carry;
            out[i] = prod as u8;
            carry = prod >> 8;
        }
        let overflow = carry != 0;
        if overflow {
            (U256([0xffu8; 32]), true)
        } else {
            (U256(out), false)
        }
    }

    /// Format `self / 10^decimals` as a human-readable decimal. Writes
    /// at most `out.len()` bytes. Returns the number of bytes on
    /// success or `None` if the full output would not fit — the
    /// function is **overflow-safe**: on overflow, it writes nothing
    /// and the caller renders a truncation banner rather than a
    /// silently-shortened number.
    ///
    /// `frac_digits` fractional digits are always emitted when
    /// `trim_trailing_zeros = false`; when true, trailing '0' bytes and
    /// the decimal point are removed if the fraction collapses to
    /// zeros.
    ///
    /// The value is **rounded half-up** at the `frac_digits` boundary, not
    /// truncated: `0.6666666` at `frac=6` renders `0.666667`, and a carry
    /// can ripple into the integer part (`0.9999996` → `1.000000`). This
    /// keeps the displayed figure the nearest representable value rather
    /// than always understating it.
    ///
    /// Examples (decimals=18, ETH):
    ///
    ///   - value = 0,                    frac=6, trim=false → "0.000000"
    ///   - value = 0,                    frac=6, trim=true  → "0"
    ///   - value = 1_500_000_000_000_000_000, frac=6, trim=false → "1.500000"
    ///   - value = 1,                    frac=18, trim=false → "0.000000000000000001"
    ///   - value = U256::MAX,            frac=0                → 78-digit integer
    #[must_use]
    pub fn format_decimal(
        &self,
        decimals: u32,
        frac_digits: u32,
        trim_trailing_zeros: bool,
        out: &mut [u8],
    ) -> Option<usize> {
        // The four phases live in free helper fns (`fmt_*` below) so the
        // Aeneas §33 extraction can model each loop separately — the fused
        // single-body form hits an `Unimplemented` in aeneas' symbolic
        // interpreter. Behavior-identical to the pre-split body; the host
        // tests + Kani shape harness + the extraction regen-diff bind it.
        let mut digits = [0u8; 80];
        let n_digits = fmt_extract_digits(&self.0, &mut digits);

        let total_decimals = decimals as usize;
        let frac = frac_digits as usize;

        let n_digits = fmt_round_half_up(&mut digits, n_digits, total_decimals, frac);

        // When trim_trailing_zeros, recompute `frac_emit` from the last
        // non-zero fractional digit backwards; else emit exactly `frac`
        // digits so the visual width is stable (frac > total_decimals
        // positions are structural zeros: value 5 at decimals=0, frac=3
        // → "5.000").
        let frac_emit = if trim_trailing_zeros {
            fmt_trim_frac(&digits, n_digits, total_decimals, frac)
        } else {
            frac
        };

        fmt_emit(&digits, n_digits, total_decimals, frac_emit, out)
    }
}

// ---------------------------------------------------------------------------
// format_decimal phases — free fns so the Aeneas §33 extraction can model
// each loop separately (see the note inside `format_decimal`). Private;
// reachable for extraction via `--start-from u256_format_decimal`.
// ---------------------------------------------------------------------------

/// Phase 1 — digit extraction. Max 78 decimal digits for 2^256-1. On return,
/// `digits[i]` holds the i-th least-significant decimal digit as a raw 0..=9
/// value (ASCII-encoded on write in `fmt_emit`); the count is returned.
fn fmt_extract_digits(value: &[u8; 32], digits: &mut [u8; 80]) -> usize {
    let mut v = *value;
    if is_zero(&v) {
        digits[0] = 0;
        return 1;
    }
    let mut n_digits = 0usize;
    while !is_zero(&v) {
        let r = div10_inplace(&mut v);
        digits[n_digits] = r;
        n_digits += 1;
    }
    n_digits
}

/// Phase 1b — round half-up at the `frac` fractional boundary; returns the
/// (possibly grown) digit count.
///
/// We only ever DISPLAY `frac` fractional digits. Truncating the rest
/// understates the magnitude (a WYSIWYS hazard — a sell of 0.6666666 would
/// read 0.666666, less than reality). Round to nearest instead: if the first
/// DROPPED fractional digit is >= 5, add one ulp at the last kept position
/// and propagate the carry up through the integer part. The carry can grow
/// the digit count (e.g. 0.9999996 -> 1.000000, or 9.9999996 -> 10.000000),
/// so this runs BEFORE the integer-width is computed in `fmt_emit`.
///
/// When `frac >= total_decimals` every dropped position is a structural zero
/// (the value has no digits that fine), so there is nothing to round and
/// `round_idx` would underflow — guard on it.
fn fmt_round_half_up(
    digits: &mut [u8; 80],
    n_digits: usize,
    total_decimals: usize,
    frac: usize,
) -> usize {
    let mut n = n_digits;
    if total_decimals > frac {
        let round_idx = total_decimals - frac; // index of first KEPT digit
        let drop_digit = if round_idx - 1 < n { digits[round_idx - 1] } else { 0 };
        if drop_digit >= 5 {
            let mut carry = 1u8;
            let mut i = round_idx;
            // `digits` is [0u8; 80]; a 78-digit (2^256-1) value rounds
            // up to at most 79 digits, so the carry stays in bounds.
            while carry > 0 && i < digits.len() {
                let sum = digits[i] + carry;
                digits[i] = sum % 10;
                carry = sum / 10;
                if i >= n && digits[i] != 0 {
                    n = i + 1;
                }
                i += 1;
            }
        }
    }
    n
}

/// Phase 2 (trim) — recompute the emitted-fraction count from the last
/// non-zero fractional digit backwards (positions `1..=frac` from the
/// decimal point; a position past the value's digits is a structural zero).
fn fmt_trim_frac(
    digits: &[u8; 80],
    n_digits: usize,
    total_decimals: usize,
    frac: usize,
) -> usize {
    let mut frac_emit = frac;
    while frac_emit > 0 {
        let pos = frac_emit; // positions 1..=frac
        let digit_idx = total_decimals.saturating_sub(pos);
        let d = if total_decimals >= pos && digit_idx < n_digits {
            digits[digit_idx]
        } else {
            0
        };
        if d != 0 {
            break;
        }
        frac_emit -= 1;
    }
    frac_emit
}

/// Phases 3–5 — integer width, required output width (`None` = would not
/// fit, nothing written), then the ASCII write. Returns the byte count.
fn fmt_emit(
    digits: &[u8; 80],
    n_digits: usize,
    total_decimals: usize,
    frac_emit: usize,
    out: &mut [u8],
) -> Option<usize> {
    // --- 3. Compute integer-part width --------------------------------
    let int_digits = if n_digits > total_decimals {
        n_digits - total_decimals
    } else {
        0
    };
    // always at least "0" (if-form of core::cmp::max for the extraction)
    let int_emit = if int_digits == 0 { 1 } else { int_digits };

    // --- 4. Required output width -------------------------------------
    let mut need = int_emit;
    let emit_point = frac_emit > 0;
    if emit_point {
        need += 1 + frac_emit;
    }
    if need > out.len() {
        return None;
    }

    // --- 5. Write -----------------------------------------------------
    let mut w = 0usize;
    if int_digits == 0 {
        out[w] = b'0';
        w += 1;
    } else {
        // MS-first: indexed form (i = int_digits-1-j) instead of
        // `(0..int_digits).rev()` so the Aeneas model is a plain Range
        // loop (§33 rank-10 pattern). Identical sequence.
        for j in 0..int_digits {
            let i = int_digits - 1 - j;
            let d = digits[total_decimals + i];
            out[w] = b'0' + d;
            w += 1;
        }
    }
    if emit_point {
        out[w] = b'.';
        w += 1;
        // Emit fractional positions 1..=frac_emit (most-significant
        // first); indexed form pos = p+1 (plain Range loop for Aeneas).
        for p in 0..frac_emit {
            let pos = p + 1;
            let digit_idx = total_decimals.saturating_sub(pos);
            let d = if total_decimals >= pos && digit_idx < n_digits {
                digits[digit_idx]
            } else {
                0
            };
            out[w] = b'0' + d;
            w += 1;
        }
    }
    debug_assert_eq!(w, need);
    Some(w)
}

/// Free-function wrapper for the Aeneas extraction (`--start-from` cannot
/// target inherent-impl methods directly); see contracts/verification §33
/// rank 10. Semantically identical to `v.saturating_mul_u64(rhs)`.
#[doc(hidden)]
#[must_use]
pub fn u256_saturating_mul_u64(v: &U256, rhs: u64) -> (U256, bool) {
    v.saturating_mul_u64(rhs)
}

/// Free-function wrapper for the Aeneas extraction of `format_decimal`
/// (same `--start-from` constraint as `u256_saturating_mul_u64`).
/// Semantically identical to `v.format_decimal(...)`.
#[doc(hidden)]
#[must_use]
pub fn u256_format_decimal(
    v: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    out: &mut [u8],
) -> Option<usize> {
    v.format_decimal(decimals, frac_digits, trim_trailing_zeros, out)
}

/// Divide a 32-byte big-endian U256 by 10 in place; returns remainder.
/// Indexed form instead of `iter_mut` so the Aeneas model is a plain Range
/// loop (§33 rank-10 pattern, same as `saturating_mul_u64`). Its functional
/// correctness for ALL 2^256 values (quotient + remainder) is Lean-proven —
/// see `contracts/verification/extracted` `FormatDecimal`/`Div10Spec`.
fn div10_inplace(v: &mut [u8; 32]) -> u8 {
    let mut rem: u16 = 0;
    for i in 0..32 {
        let acc = (rem << 8) | (v[i] as u16);
        v[i] = (acc / 10) as u8;
        rem = acc % 10;
    }
    rem as u8
}

/// Indexed form of `iter().all(..)` — extractable by Aeneas (a closure-based
/// `all` becomes an opaque axiom in the Lean model).
fn is_zero(v: &[u8; 32]) -> bool {
    let mut i = 0usize;
    while i < 32 {
        if v[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

// ---------------------------------------------------------------------------
// Eip1559Tx + strict envelope parser
// ---------------------------------------------------------------------------

/// Original ERC-4337 gas/nonce words carried alongside the legacy
/// [`Eip1559Tx`] display envelope. UserOperations sign three independent gas
/// limits and a full 256-bit nonce; collapsing them into one `u64` aggregate
/// creates display collisions. Native EIP-1559 transactions leave this `None`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UserOpDisplayFields {
    pub nonce: U256,
    pub call_gas_limit: U256,
    pub verification_gas_limit: U256,
    pub pre_verification_gas: U256,
}

#[derive(Default, Debug)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: U256,
    pub data_len: usize,
    pub access_list_count: usize,
    /// keccak256 of the unsigned envelope. Set by `parse()`.
    pub signing_hash: [u8; 32],
    /// Full signed UserOperation fields when this value is a display shim for
    /// EntryPoint v0.6 rather than a native EIP-1559 transaction.
    pub userop_fields: Option<UserOpDisplayFields>,
}

/// Output of [`parse`]. Borrows from the input envelope so the calldata
/// slice cannot outlive the buffer it points into — the borrow checker
/// enforces what was previously a convention.
#[derive(Debug)]
pub struct ParsedTx<'a> {
    pub tx: Eip1559Tx,
    /// Raw calldata bytes (`tx.data` from the EIP-1559 envelope). Empty
    /// for plain value transfers and contract creations.
    pub data: &'a [u8],
    /// The complete unsigned envelope (leading 0x02 byte + RLP body).
    /// Useful if a caller needs to re-hash or re-serialize.
    pub envelope: &'a [u8],
}

/// Parse a complete unsigned EIP-1559 envelope: leading 0x02 byte
/// followed by an RLP-encoded list of nine fields. Enforces every
/// structural invariant the EVM requires, so a successful return
/// guarantees the transaction can be displayed to the user as-is
/// without further validation.
pub fn parse(envelope: &[u8]) -> Result<ParsedTx<'_>, TxError> {
    if envelope.len() > pqsigner_proto::MAX_TX_LEN {
        return Err(TxError::EnvelopeTooLong);
    }
    let first = *envelope.first().ok_or(TxError::EmptyEnvelope)?;
    if first != 0x02 {
        return Err(TxError::NotEip1559);
    }

    let payload = &envelope[1..];
    let (item, used) = rlp::decode_item(payload)?;
    if used != payload.len() {
        return Err(TxError::TrailingBytes);
    }
    let list_payload = match item {
        Item::List(l) => l,
        Item::Bytes(_) => return Err(TxError::Rlp(RlpError::UnexpectedType)),
    };

    let mut iter = ListIter::new(list_payload);

    let chain_id = rlp::bytes_to_u64(iter.expect_bytes()?)?;
    if chain_id == 0 {
        return Err(TxError::BadChainId);
    }
    let nonce = rlp::bytes_to_u64(iter.expect_bytes()?)?;
    let max_priority = U256(rlp::bytes_to_u256(iter.expect_bytes()?)?);
    let max_fee = U256(rlp::bytes_to_u256(iter.expect_bytes()?)?);
    if max_priority > max_fee {
        return Err(TxError::PriorityExceedsFee);
    }
    let gas_limit = rlp::bytes_to_u64(iter.expect_bytes()?)?;

    let to_bytes = iter.expect_bytes()?;
    let to = match to_bytes.len() {
        0 => None,
        20 => {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(to_bytes);
            Some(arr)
        }
        _ => return Err(TxError::BadToLength),
    };

    // Contract-creation txs need not hit the 21 000 floor (CREATE has
    // its own intrinsic cost of 53 000, but enforcing both would reject
    // simulations); plain txs must.
    if to.is_some() && gas_limit < MIN_INTRINSIC_GAS {
        return Err(TxError::GasLimitTooLow);
    }

    let value = U256(rlp::bytes_to_u256(iter.expect_bytes()?)?);
    let data = iter.expect_bytes()?;
    let access_list_payload = iter.expect_list()?;

    // Validate each access list entry structurally: `[address(20),
    // [storage_key(32)...]]`. The EVM reverts on malformed entries, so
    // letting them through here lets NS signal "valid" on a tx that
    // can never land.
    let access_list_count = validate_access_list(access_list_payload)?;

    // The unsigned form must have no further fields.
    if iter.next_item()?.is_some() {
        return Err(TxError::TrailingBytes);
    }

    let signing_hash = crate::hash::keccak256(envelope);

    Ok(ParsedTx {
        tx: Eip1559Tx {
            chain_id,
            nonce,
            max_priority_fee_per_gas: max_priority,
            max_fee_per_gas: max_fee,
            gas_limit,
            to,
            value,
            data_len: data.len(),
            access_list_count,
            signing_hash,
            userop_fields: None,
        },
        data,
        envelope,
    })
}

/// Walk the access list payload, enforcing that every entry is a pair
/// `[address(20), [storage_key(32)...]]`. Returns the number of
/// entries.
fn validate_access_list(payload: &[u8]) -> Result<usize, TxError> {
    let mut iter = ListIter::new(payload);
    let mut count = 0usize;
    while let Some(item) = iter.next_item()? {
        let tuple = match item {
            Item::List(l) => l,
            Item::Bytes(_) => return Err(TxError::BadAccessList),
        };
        let mut inner = ListIter::new(tuple);
        // Field 1: 20-byte address.
        let addr = match inner.next_item()? {
            Some(Item::Bytes(b)) => b,
            _ => return Err(TxError::BadAccessList),
        };
        if addr.len() != 20 {
            return Err(TxError::BadAccessList);
        }
        // Field 2: list of 32-byte storage keys.
        let keys = match inner.next_item()? {
            Some(Item::List(l)) => l,
            _ => return Err(TxError::BadAccessList),
        };
        let mut key_iter = ListIter::new(keys);
        while let Some(k) = key_iter.next_item()? {
            match k {
                Item::Bytes(b) if b.len() == 32 => {}
                _ => return Err(TxError::BadAccessList),
            }
        }
        // No extra fields in the tuple.
        if inner.next_item()?.is_some() {
            return Err(TxError::BadAccessList);
        }
        count += 1;
    }
    Ok(count)
}

// NOTE: a `validate_access_list` Kani harness was attempted but is intractable
// for CBMC (nested ListIter × decode_item × decode_length_be loops explode the
// path count) AND redundant: the walker's panic-freedom reduces to `decode_item`
// being panic-free with `used <= input.len()` — already proved in rlp.rs. The
// nested re-slices `&self.rest[used..]` are in-bounds by that invariant.

// ---------------------------------------------------------------------------
// Kani harnesses (bounded model checking).
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod kani_harness {
    use super::*;

    /// Panic/OOB-freedom + well-formed output for `U256::format_decimal` — the
    /// amount-rendering primitive where the trusted-display HIGHs lived (the CoW
    /// 100-WETH-as-0.06 low-word read, the M-6 digit-aliasing, the F14#3
    /// nonzero-collapse). It had ZERO Kani coverage. A panic or OOB write here is
    /// a DoS on the trusted display; a byte that is not a digit or '.' would
    /// render garbage the user is asked to sign against.
    ///
    /// Scope (honest): the VALUE is CONCRETE (a symbolic U256 — even a symbolic
    /// selection among concrete values — makes CBMC unwind the byte-wise
    /// long-division `div10_inplace` symbolically, which does not converge; four
    /// bounds down to 2^16 each ran > 10 min. So the value is fixed and the
    /// `decimals`/`frac`/`trim` inputs are FULLY SYMBOLIC — this proves
    /// panic/OOB-freedom + well-formed output (every byte a digit or '.') over
    /// EVERY format SHAPE, which is exactly the round-half-up-carry / trailing-
    /// zero-trim / structural-zero (`frac > decimals`) branch space where the
    /// M-6 digit-aliasing and F14#3 nonzero-collapse display HIGHs lived. The
    /// value `666_667` is chosen because at `decimals > frac` its first dropped
    /// digit is >= 5, exercising the carry that can ripple into and grow the
    /// integer part. The full symbolic-VALUE ∀ (+ a value-injectivity / no-
    /// collapse post-condition over the digit-extraction) is the heavier CBMC
    /// follow-up the symbolic-division cost blocks in-session.
    #[kani::proof]
    #[kani::unwind(52)]
    fn format_decimal_panic_free_over_format_shapes() {
        // CONCRETE value (rounding-carry trigger): digit extraction is concrete.
        let v = {
            let mut b = [0u8; 32];
            b[24..32].copy_from_slice(&666_667u64.to_be_bytes());
            U256(b)
        };

        let decimals: u32 = kani::any();
        kani::assume(decimals <= 18);
        let frac: u32 = kani::any();
        kani::assume(frac <= 18);
        let trim: bool = kani::any();

        // 10 int digits + '.' + 18 frac digits = 29 max; 64 leaves margin so the
        // Some-path (not the too-small-buffer None early-return) is exercised.
        let mut out = [0u8; 64];
        if let Some(len) = v.format_decimal(decimals, frac, trim, &mut out) {
            assert!(len <= out.len());
            let mut i = 0usize;
            while i < len {
                let b = out[i];
                // every emitted byte is an ASCII digit or the decimal point.
                assert!(b == b'.' || (b'0'..=b'9').contains(&b));
                i += 1;
            }
        }
    }

    /// Byte-EXACT boundary companion to `format_decimal_panic_free_over_format_shapes`
    /// (finding F10, fv-deep-review 2026-07-19). The shape harness proves
    /// panic/OOB-freedom + digit-or-'.' charset over EVERY (decimals, frac, trim)
    /// shape for one concrete value — but a charset assertion cannot redden on a
    /// wrong-DIGIT bug: a rounding `>= 5` -> `> 5` swap, the `round_idx - 1` ->
    /// `round_idx / 1` slip, or a broken trim still emits digits. This harness pins
    /// the exact emitted bytes on a small set of boundary inputs chosen against
    /// the 2026-06-26 cargo-mutants survivors (mutants.out/missed.txt, all 7 in
    /// this function) and F10's executed `drop_digit >= 5` -> `> 5` PoC:
    ///
    ///   (15,1,0) -> "2", (14,1,0) -> "1"   — drop_digit == 5 EXACTLY: pins `>= 5`
    ///     (a `> 5` mutant renders 1.5 as "1", understating the amount).
    ///   (5,2,1) -> "0.1", (4,2,1) -> "0.0" — the dropped digit is the value's ONLY
    ///     significant digit: pins the `round_idx - 1 < n` guard (missed mutant
    ///     177:43 `round_idx / 1` makes the guard false here and reads drop_digit=0
    ///     — the display silently understates 0.05 as 0.0).
    ///   (95,1,0) -> "10", (9995,2,1) -> "100.0" — the round carry ripples into and
    ///     GROWS the integer part (exercises every carry-loop iteration).
    ///   (1500,3,3,trim) -> "1.5", (1000,3,3,trim) -> "1", (1500,3,3,!trim) ->
    ///     "1.500" — trailing-zero trim incl. full fraction + decimal-point collapse.
    ///   (0,18,6) -> "0.000000" / "0" (trim) — zero in both trim modes.
    ///   (u64::MAX,0,0) -> "18446744073709551615" — 20-digit extraction ceiling.
    ///
    /// Why concrete + exact, and why this is still a proof (not a test): a symbolic
    /// VALUE makes CBMC unwind the byte-wise long division symbolically and does not
    /// converge (see the shape harness's docstring), so exactness is pinned on
    /// concrete boundary inputs — but here the model checker re-proves them on every
    /// mutation-gate run, which is the instrument the cargo-mutants survivors
    /// escaped. The three instruments partition the gap: THIS harness = Kani-level
    /// decision coverage + the mutation pin; the shape harness = panic-freedom and
    /// charset over ALL format shapes; contracts/verification/extracted/Extracted/
    /// FormatDecimal/FormatDecimalSpec.lean = the universal for-all-values exact
    /// theorem. This harness COMPLEMENTS FormatDecimalSpec.lean rather than
    /// duplicating it: the Lean theorem is not executable by check_kani_mutations.py.
    ///
    /// unwind(48): the deepest legitimate loop on these inputs is div10_inplace's
    /// fixed 32 (u64::MAX extraction = 20 outer iterations; carry/trim/emit <= 21;
    /// the case loop = 12). 48 leaves 50% margin and — deliberately — stays BELOW
    /// the 80-element digit-array bound: the missed `carry > 0 && i < digits.len()`
    /// -> `||` mutant (missed.txt 187:33) is output-EQUIVALENT (a 19.4M-tuple
    /// differential against the original shows zero output drift: once carry=0 the
    /// extra iterations are the identity on 0..=9 digits), so no byte assertion can
    /// kill it — but it destroys the carry loop's early exit, forcing EVERY
    /// rounding to spin to the 80 bound, which trips THIS harness's unwinding
    /// assertion. That structural pin is enrolled as format_decimal_carry_and_or;
    /// its manifest note records the equivalence honestly.
    #[kani::proof]
    #[kani::unwind(48)]
    fn format_decimal_exact_on_boundaries() {
        // (value, decimals, frac, trim, expected bytes). Every expected string is
        // cross-verified by the host suite (boundary KATs / zero / MAX tests) and a
        // standalone differential run of this formatter, so a mismatch here is a
        // formatter bug to fix, never an expectation to weaken.
        let cases: [(u64, u32, u32, bool, &[u8]); 12] = [
            (15, 1, 0, false, b"2"),
            (14, 1, 0, false, b"1"),
            (5, 2, 1, false, b"0.1"),
            (4, 2, 1, false, b"0.0"),
            (95, 1, 0, false, b"10"),
            (9995, 2, 1, false, b"100.0"),
            (1500, 3, 3, true, b"1.5"),
            (1500, 3, 3, false, b"1.500"),
            (1000, 3, 3, true, b"1"),
            (0, 18, 6, false, b"0.000000"),
            (0, 18, 6, true, b"0"),
            (u64::MAX, 0, 0, false, b"18446744073709551615"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (val, decimals, frac, trim, expected) = cases[i];
            let v = {
                let mut b = [0u8; 32];
                b[24..32].copy_from_slice(&val.to_be_bytes());
                U256(b)
            };
            let mut out = [0u8; 32];
            // None (output would not fit) is IMPOSSIBLE for these cases (max 20
            // digits + point + 6 frac < 32 bytes) and would be a formatter bug —
            // .expect turns it into a hard verification failure, not a silent skip.
            let n = v
                .format_decimal(decimals, frac, trim, &mut out)
                .expect("boundary output must fit in 32 bytes");
            assert!(n == expected.len());
            let mut j = 0usize;
            while j < n {
                assert!(out[j] == expected[j]);
                j += 1;
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (host-only).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn u256_from_u64(x: u64) -> U256 {
        let mut buf = [0u8; 32];
        buf[24..32].copy_from_slice(&x.to_be_bytes());
        U256(buf)
    }

    fn u256_from_bigint_pow10(exp: u32) -> U256 {
        // Returns 10^exp as a U256. exp must be <= 77.
        let mut v = [0u8; 32];
        v[31] = 1;
        let mut u = U256(v);
        for _ in 0..exp {
            let (p, over) = u.saturating_mul_u64(10);
            assert!(!over);
            u = p;
        }
        u
    }

    fn format_to_string(v: &U256, decimals: u32, frac: u32, trim: bool) -> Option<std::string::String> {
        let mut out = [0u8; 96];
        let n = v.format_decimal(decimals, frac, trim, &mut out)?;
        Some(std::string::String::from_utf8(out[..n].to_vec()).unwrap())
    }

    #[test]
    fn format_zero_no_frac() {
        let v = U256::zero();
        assert_eq!(format_to_string(&v, 0, 0, false).as_deref(), Some("0"));
    }

    #[test]
    fn format_zero_with_frac_fixed() {
        let v = U256::zero();
        assert_eq!(format_to_string(&v, 18, 6, false).as_deref(), Some("0.000000"));
    }

    #[test]
    fn format_zero_with_frac_trim() {
        let v = U256::zero();
        assert_eq!(format_to_string(&v, 18, 6, true).as_deref(), Some("0"));
    }

    #[test]
    fn format_one_wei_as_eth() {
        let v = u256_from_u64(1);
        // 1 wei with 18 decimals + 18 frac = "0.000000000000000001"
        assert_eq!(
            format_to_string(&v, 18, 18, false).as_deref(),
            Some("0.000000000000000001"),
        );
    }

    #[test]
    fn format_one_wei_as_eth_trimmed() {
        let v = u256_from_u64(1);
        // trim=true keeps exactly the non-zero fractional tail
        assert_eq!(
            format_to_string(&v, 18, 18, true).as_deref(),
            Some("0.000000000000000001"),
        );
    }

    #[test]
    fn format_one_eth_fixed6() {
        // 10^18 wei = 1 ETH
        let v = u256_from_bigint_pow10(18);
        assert_eq!(format_to_string(&v, 18, 6, false).as_deref(), Some("1.000000"));
        assert_eq!(format_to_string(&v, 18, 6, true).as_deref(), Some("1"));
    }

    #[test]
    fn format_1_5_eth() {
        // 1.5 * 10^18 wei = 0x14D1_120D_7B16_0000
        let raw: u128 = 1_500_000_000_000_000_000u128;
        let mut buf = [0u8; 32];
        buf[16..32].copy_from_slice(&raw.to_be_bytes());
        let v = U256(buf);
        assert_eq!(format_to_string(&v, 18, 6, false).as_deref(), Some("1.500000"));
        assert_eq!(format_to_string(&v, 18, 6, true).as_deref(), Some("1.5"));
    }

    #[test]
    fn format_rounds_half_up_at_frac() {
        // 0.66666666666 ETH (18 decimals) shown at 6 frac digits: the 7th
        // fractional digit is 6 (>= 5) so it rounds up to 0.666667 rather
        // than truncating to 0.666666.
        let v = u256_from_u64(666_666_666_660_000_000);
        assert_eq!(format_to_string(&v, 18, 6, false).as_deref(), Some("0.666667"));
    }

    #[test]
    fn format_rounds_down_below_half() {
        // 0.6666664 → 7th digit is 4 (< 5) → stays 0.666666.
        let v = u256_from_u64(666_666_400_000_000_000);
        assert_eq!(format_to_string(&v, 18, 6, false).as_deref(), Some("0.666666"));
    }

    #[test]
    fn format_round_carries_into_integer() {
        // 0.9999996 → rounding the 6 kept digits carries all the way into
        // the integer part: 1.000000 (int_digits grows 0 -> 1).
        let v = u256_from_u64(999_999_600_000_000_000);
        assert_eq!(format_to_string(&v, 18, 6, false).as_deref(), Some("1.000000"));
        // trim drops the now-zero fraction → "1".
        assert_eq!(format_to_string(&v, 18, 6, true).as_deref(), Some("1"));
    }

    #[test]
    fn format_round_grows_integer_digit_count() {
        // 9.9999996 → 10.000000: the carry adds a NEW most-significant
        // integer digit (n_digits extends past the existing top).
        let v = u256_from_u64(9_999_999_600_000_000_000);
        assert_eq!(format_to_string(&v, 18, 6, false).as_deref(), Some("10.000000"));
    }

    #[test]
    fn format_round_noop_when_frac_ge_decimals() {
        // frac >= decimals: every dropped position is a structural zero,
        // so no rounding occurs (1 wei stays exact, not rounded up).
        let v = u256_from_u64(1);
        assert_eq!(
            format_to_string(&v, 18, 18, false).as_deref(),
            Some("0.000000000000000001"),
        );
    }

    #[test]
    fn format_inflated_decimals_still_zero() {
        // Documents the WYSIWYS finding: rounding does NOT rescue an
        // inflated `decimals`. 10^21 base units (e.g. 1000 of an 18-dec
        // token) labelled with a wrong 30-decimal value renders 0.000000
        // — the magnitude vanishes regardless of rounding mode. Only a
        // firmware decimals bound (see project_erc20_decimals_unbounded_
        // wysiwys) closes this; the formatter is faithful to its input.
        let v = u256_from_bigint_pow10(21);
        assert_eq!(format_to_string(&v, 30, 6, false).as_deref(), Some("0.000000"));
        // At 27 decimals the same amount shows 0.000001 — still a gross
        // understatement of a 1000-token transfer, just not a clean zero.
        assert_eq!(format_to_string(&v, 27, 6, false).as_deref(), Some("0.000001"));
    }

    #[test]
    fn format_overflow_returns_none() {
        // 10^18 = "1.000000" needs 8 bytes.
        let v = u256_from_bigint_pow10(18);
        let mut out = [0u8; 4];
        assert_eq!(v.format_decimal(18, 6, false, &mut out), None);
    }

    #[test]
    fn format_u256_max_integer() {
        let v = U256([0xffu8; 32]);
        let mut out = [0u8; 96];
        let n = v.format_decimal(0, 0, false, &mut out).unwrap();
        let s = core::str::from_utf8(&out[..n]).unwrap();
        // 2^256 - 1 = 78-digit number:
        // 115792089237316195423570985008687907853269984665640564039457584007913129639935
        assert_eq!(n, 78);
        assert!(s.starts_with("115792089237"));
    }

    #[test]
    fn format_decimals_greater_than_digits() {
        // 1 wei, 18 decimals, 18 frac → "0.000000000000000001"
        let v = u256_from_u64(1);
        assert_eq!(
            format_to_string(&v, 18, 18, false).as_deref(),
            Some("0.000000000000000001"),
        );
    }

    // Boundary KATs hardening U256::format_decimal — each pins an exact
    // <-> / >-vs->= / round / carry / trim boundary that mutation testing
    // (cargo-mutants, 2026-06-26) found the prior suite did NOT distinguish.
    // The amount-display / WYSIWYS path: a boundary bug = the user confirms a
    // different amount than was rendered, so these are security-relevant.
    fn fd(val: u64, decimals: u32, frac: u32, trim: bool) -> Option<std::string::String> {
        format_to_string(&u256_from_u64(val), decimals, frac, trim)
    }

    #[test]
    fn format_decimal_round_half_up_boundary() {
        // drop_digit >= 5 rounds up; drop_digit < 5 stays. Pins `>= 5` (a `> 5`
        // mutant would make 1.5 render as "1") and the round_idx arithmetic.
        assert_eq!(fd(15, 1, 0, false).as_deref(), Some("2"));  // 1.5 -> 2
        assert_eq!(fd(14, 1, 0, false).as_deref(), Some("1"));  // 1.4 -> 1
        assert_eq!(fd(25, 1, 0, false).as_deref(), Some("3"));  // 2.5 -> 3
        assert_eq!(fd(249, 2, 1, false).as_deref(), Some("2.5")); // 2.49 -> 2.5
        assert_eq!(fd(244, 2, 1, false).as_deref(), Some("2.4")); // 2.44 -> 2.4
    }

    #[test]
    fn format_decimal_round_carry_propagates() {
        // 9.5 -> 10 and 99.5 -> 100 exercise the carry loop (digits[i] = 9 + 1
        // overflows, n_digits grows). Pins the `carry > 0 && i < len` loop —
        // a `&&`->`||` or `>`->`>=` mutant mis-renders the carry.
        assert_eq!(fd(95, 1, 0, false).as_deref(), Some("10"));   // 9.5 -> 10
        assert_eq!(fd(995, 1, 0, false).as_deref(), Some("100")); // 99.5 -> 100
        assert_eq!(fd(9995, 2, 1, false).as_deref(), Some("100.0")); // 99.95 -> 100.0
    }

    #[test]
    fn format_decimal_subone_integer_is_zero() {
        // value < 1 (n_digits <= total_decimals): integer part must be "0".
        // Pins `n_digits > total_decimals` (a `>=` mutant drops the leading 0).
        assert_eq!(fd(5, 2, 2, false).as_deref(), Some("0.05"));
        assert_eq!(fd(50, 2, 2, false).as_deref(), Some("0.50"));
        assert_eq!(fd(0, 2, 2, false).as_deref(), Some("0.00"));
    }

    #[test]
    fn format_decimal_round_drop_is_only_significant_digit() {
        // The dropped digit IS the value's only significant digit (kept
        // position is a structural zero) — the "smallest-magnitude amount
        // rounds up, not to zero" WYSIWYS case. 0.05 at frac=1 rounds to 0.1;
        // 0.04 stays 0.0. Pins the `round_idx - 1 < n_digits` drop-digit guard
        // (a `round_idx / 1` == `round_idx` mutant, cargo-mutants 177:43, reads
        // drop_digit=0 here and understates 0.05 as "0.0"). This is a distinct
        // survivor from the fd(15,…)="2" boundary above (there the kept digit
        // is non-zero, so n_digits != round_idx and the mutant is inert).
        assert_eq!(fd(5, 2, 1, false).as_deref(), Some("0.1")); // 0.05 -> 0.1
        assert_eq!(fd(4, 2, 1, false).as_deref(), Some("0.0")); // 0.04 -> 0.0
    }

    #[test]
    fn format_decimal_trailing_zero_trim_boundary() {
        // trim collapses trailing fractional zeros (and the point if all go).
        // Pins the `frac_emit > 0` / `d != 0` trim loop against `>=`/`==` mutants.
        assert_eq!(fd(1500, 3, 3, true).as_deref(),  Some("1.5"));
        assert_eq!(fd(1500, 3, 3, false).as_deref(), Some("1.500"));
        assert_eq!(fd(1000, 3, 3, true).as_deref(),  Some("1"));     // all frac zeros + point gone
        assert_eq!(fd(1000, 3, 3, false).as_deref(), Some("1.000"));
        assert_eq!(fd(1050, 3, 3, true).as_deref(),  Some("1.05"));  // inner zero kept, trailing trimmed
    }

    #[test]
    fn format_decimal_exact_multidigit_no_round() {
        assert_eq!(fd(123456, 3, 3, false).as_deref(), Some("123.456"));
        assert_eq!(fd(123456, 3, 2, false).as_deref(), Some("123.46")); // 123.456 -> 2 frac rounds
        assert_eq!(fd(100, 2, 2, false).as_deref(),    Some("1.00"));
    }

    #[test]
    fn format_huge_integer_returns_none_on_tight_buffer() {
        // Regression guard: the old formatter silently truncated the
        // MOST significant digits of values whose decimal form didn't
        // fit in the scratch buffer, so a whale trying to send
        // 1_234_567_890_123.123456 ETH would see the display claim a
        // 10× smaller amount. The new formatter refuses to fit and
        // returns None so the display layer can raise an overflow
        // banner instead.
        let mut buf = [0u8; 32];
        let raw: u128 = 1_234_567_890_123_000_000_000_000_000_000u128;
        let mut bytes = [0u8; 32];
        bytes[16..32].copy_from_slice(&raw.to_be_bytes());
        let v = U256(bytes);
        // Rendered as ETH (18 decimals, 6 frac, trim=true) the result
        // is "1234567890123.000000" trimmed to "1234567890123" (13
        // chars). Fits in 16 but trips the 12-byte scratch that the
        // pre-fix helpers used:
        assert_eq!(v.format_decimal(18, 6, true, &mut buf[..12]), None);
        // And renders correctly in a wide-enough buffer:
        let n = v.format_decimal(18, 6, true, &mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..n]).unwrap(),
            "1234567890123",
        );
    }

    #[test]
    fn format_whale_transfer_preserves_fractional_tail() {
        // 12_345_678_901.234567 ETH as wei.
        let raw: u128 = 12_345_678_901_234_567_000_000_000_000u128;
        let mut bytes = [0u8; 32];
        bytes[16..32].copy_from_slice(&raw.to_be_bytes());
        let v = U256(bytes);
        let s = format_to_string(&v, 18, 6, false).unwrap();
        assert_eq!(s, "12345678901.234567");
    }

    #[test]
    fn format_frac_greater_than_decimals() {
        // 1 unit with 2 decimals, 6 frac digits → "0.010000"?
        // Actually value = 1, decimals = 2 means 1 / 100 = 0.01. With
        // 6 frac digits that's "0.010000".
        let v = u256_from_u64(1);
        assert_eq!(format_to_string(&v, 2, 6, false).as_deref(), Some("0.010000"));
        // Integer 5 unit with 0 decimals, 3 frac → "5.000"
        let v = u256_from_u64(5);
        assert_eq!(format_to_string(&v, 0, 3, false).as_deref(), Some("5.000"));
    }

    #[test]
    fn saturating_mul_basic() {
        let v = u256_from_u64(1_000_000);
        let (p, over) = v.saturating_mul_u64(2_000);
        assert!(!over);
        let mut out = [0u8; 96];
        let n = p.format_decimal(0, 0, false, &mut out).unwrap();
        assert_eq!(&out[..n], b"2000000000");
    }

    #[test]
    fn saturating_mul_overflow_saturates() {
        let v = U256([0xffu8; 32]);
        let (p, over) = v.saturating_mul_u64(2);
        assert!(over);
        assert_eq!(p, U256([0xffu8; 32]));
    }

    #[test]
    fn ord_matches_numeric_magnitude() {
        // Derived Ord on `[u8; 32]` is lex-byte compare; because the
        // bytes are big-endian, that equals numeric magnitude compare.
        let a = u256_from_u64(10);
        let b = u256_from_u64(5);
        assert!(a > b);
        assert!(!(b > a));
        assert!(a >= a);
        // Cross-byte boundary: 0x0100 (16-bit) > 0xff (8-bit).
        let mut high = [0u8; 32];
        high[30] = 0x01;
        let mut low = [0u8; 32];
        low[31] = 0xff;
        assert!(U256(high) > U256(low));
    }

    // --- parser tests -----------------------------------------------------

    fn rlp_encode_bytes(bytes: &[u8]) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        if bytes.len() == 1 && bytes[0] <= 0x7f {
            out.push(bytes[0]);
        } else if bytes.len() <= 55 {
            out.push(0x80 + bytes.len() as u8);
            out.extend_from_slice(bytes);
        } else {
            // Long form
            let len_bytes = (bytes.len() as u64).to_be_bytes();
            let first_nonzero = len_bytes.iter().position(|&b| b != 0).unwrap();
            let len_enc = &len_bytes[first_nonzero..];
            out.push(0xb7 + len_enc.len() as u8);
            out.extend_from_slice(len_enc);
            out.extend_from_slice(bytes);
        }
        out
    }

    fn rlp_encode_list(items: &[std::vec::Vec<u8>]) -> std::vec::Vec<u8> {
        let mut body = std::vec::Vec::new();
        for it in items {
            body.extend_from_slice(it);
        }
        let mut out = std::vec::Vec::new();
        if body.len() <= 55 {
            out.push(0xc0 + body.len() as u8);
        } else {
            let len_bytes = (body.len() as u64).to_be_bytes();
            let first_nonzero = len_bytes.iter().position(|&b| b != 0).unwrap();
            let len_enc = &len_bytes[first_nonzero..];
            out.push(0xf7 + len_enc.len() as u8);
            out.extend_from_slice(len_enc);
        }
        out.extend_from_slice(&body);
        out
    }

    fn be_trim(bytes: &[u8]) -> std::vec::Vec<u8> {
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        bytes[first..].to_vec()
    }

    fn build_envelope(
        chain_id: u64,
        nonce: u64,
        max_prio_gwei: u64,
        max_fee_gwei: u64,
        gas_limit: u64,
        to: Option<[u8; 20]>,
        value_wei: u64,
        data: &[u8],
    ) -> std::vec::Vec<u8> {
        let items = std::vec![
            rlp_encode_bytes(&be_trim(&chain_id.to_be_bytes())),
            rlp_encode_bytes(&be_trim(&nonce.to_be_bytes())),
            rlp_encode_bytes(&be_trim(&max_prio_gwei.to_be_bytes())),
            rlp_encode_bytes(&be_trim(&max_fee_gwei.to_be_bytes())),
            rlp_encode_bytes(&be_trim(&gas_limit.to_be_bytes())),
            match to {
                Some(a) => rlp_encode_bytes(&a),
                None => rlp_encode_bytes(&[]),
            },
            rlp_encode_bytes(&be_trim(&value_wei.to_be_bytes())),
            rlp_encode_bytes(data),
            rlp_encode_list(&[]),
        ];
        let list = rlp_encode_list(&items);
        let mut env = std::vec![0x02u8];
        env.extend_from_slice(&list);
        env
    }

    #[test]
    fn parse_minimal_tx() {
        let to = [0x11u8; 20];
        let env = build_envelope(1, 0, 1, 2, 21_000, Some(to), 0, &[]);
        let parsed = parse(&env).unwrap();
        assert_eq!(parsed.tx.chain_id, 1);
        assert_eq!(parsed.tx.gas_limit, 21_000);
        assert_eq!(parsed.tx.to, Some(to));
    }

    #[test]
    fn reject_chain_zero() {
        let to = [0x11u8; 20];
        let env = build_envelope(0, 0, 1, 2, 21_000, Some(to), 0, &[]);
        assert_eq!(parse(&env).unwrap_err(), TxError::BadChainId);
    }

    #[test]
    fn reject_gas_too_low() {
        let to = [0x11u8; 20];
        let env = build_envelope(1, 0, 1, 2, 20_000, Some(to), 0, &[]);
        assert_eq!(parse(&env).unwrap_err(), TxError::GasLimitTooLow);
    }

    #[test]
    fn reject_priority_greater_than_fee() {
        let to = [0x11u8; 20];
        let env = build_envelope(1, 0, 10, 5, 21_000, Some(to), 0, &[]);
        assert_eq!(parse(&env).unwrap_err(), TxError::PriorityExceedsFee);
    }

    #[test]
    fn allow_priority_equal_to_fee() {
        let to = [0x11u8; 20];
        let env = build_envelope(1, 0, 5, 5, 21_000, Some(to), 0, &[]);
        let parsed = parse(&env).unwrap();
        assert_eq!(parsed.tx.max_fee_per_gas.0[31], 5);
        assert_eq!(parsed.tx.max_priority_fee_per_gas.0[31], 5);
    }

    #[test]
    fn reject_wrong_envelope_type() {
        let mut env = build_envelope(1, 0, 1, 2, 21_000, Some([0u8; 20]), 0, &[]);
        env[0] = 0x01;
        assert_eq!(parse(&env).unwrap_err(), TxError::NotEip1559);
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut env = build_envelope(1, 0, 1, 2, 21_000, Some([0u8; 20]), 0, &[]);
        env.push(0x00);
        assert_eq!(parse(&env).unwrap_err(), TxError::TrailingBytes);
    }
}
