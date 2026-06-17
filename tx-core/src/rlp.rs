//! Minimal RLP decoder for EIP-1559 transaction envelopes.
//!
//! Strict, no_std, no allocator. Returns slices into the original buffer
//! rather than copying. Rejects malformed RLP, leading zeros where forbidden,
//! and any payload that doesn't fit in the input.

#[derive(Debug, PartialEq, Eq)]
pub enum RlpError {
    /// Truncated input
    Truncated,
    /// Length encoding violates the canonical form (e.g. leading zero in
    /// the length field, or short-form length used for a long-form value).
    NonCanonical,
    /// A length field claimed more bytes than the buffer holds.
    LengthOverflow,
    /// Expected a byte string but got a list (or vice versa).
    UnexpectedType,
    /// An integer field had leading zeros (forbidden by EIP-1559 / RLP spec
    /// for non-zero values).
    LeadingZero,
    /// Integer doesn't fit in the requested type.
    IntTooLarge,
}

/// A decoded RLP item: either a byte string or a list of items (referenced
/// as a slice into the input buffer that the caller can re-iterate over).
#[derive(Copy, Clone, Debug)]
pub enum Item<'a> {
    Bytes(&'a [u8]),
    List(&'a [u8]),
}

/// Decode the next RLP item starting at `input[0]`. Returns the item and the
/// number of bytes consumed.
pub fn decode_item(input: &[u8]) -> Result<(Item<'_>, usize), RlpError> {
    let first = *input.first().ok_or(RlpError::Truncated)?;

    if first <= 0x7f {
        // Single byte payload, no length prefix
        Ok((Item::Bytes(&input[..1]), 1))
    } else if first <= 0xb7 {
        // Short string, 0-55 bytes
        let len = (first - 0x80) as usize;
        let header = 1;
        let total = header + len;
        if input.len() < total {
            return Err(RlpError::Truncated);
        }
        if len == 1 && input[1] <= 0x7f {
            // Should have been encoded as the single byte form.
            return Err(RlpError::NonCanonical);
        }
        Ok((Item::Bytes(&input[header..total]), total))
    } else if first <= 0xbf {
        // Long string
        let len_of_len = (first - 0xb7) as usize;
        if len_of_len == 0 || len_of_len > 8 {
            return Err(RlpError::NonCanonical);
        }
        if input.len() < 1 + len_of_len {
            return Err(RlpError::Truncated);
        }
        let len = decode_length_be(&input[1..1 + len_of_len])?;
        if len <= 55 {
            return Err(RlpError::NonCanonical);
        }
        let header = 1 + len_of_len;
        let total = header.checked_add(len).ok_or(RlpError::LengthOverflow)?;
        if input.len() < total {
            return Err(RlpError::LengthOverflow);
        }
        Ok((Item::Bytes(&input[header..total]), total))
    } else if first <= 0xf7 {
        // Short list, 0-55 bytes
        let len = (first - 0xc0) as usize;
        let header = 1;
        let total = header + len;
        if input.len() < total {
            return Err(RlpError::Truncated);
        }
        Ok((Item::List(&input[header..total]), total))
    } else {
        // Long list
        let len_of_len = (first - 0xf7) as usize;
        if len_of_len == 0 || len_of_len > 8 {
            return Err(RlpError::NonCanonical);
        }
        if input.len() < 1 + len_of_len {
            return Err(RlpError::Truncated);
        }
        let len = decode_length_be(&input[1..1 + len_of_len])?;
        if len <= 55 {
            return Err(RlpError::NonCanonical);
        }
        let header = 1 + len_of_len;
        let total = header.checked_add(len).ok_or(RlpError::LengthOverflow)?;
        if input.len() < total {
            return Err(RlpError::LengthOverflow);
        }
        Ok((Item::List(&input[header..total]), total))
    }
}

fn decode_length_be(bytes: &[u8]) -> Result<usize, RlpError> {
    if bytes.is_empty() {
        return Err(RlpError::NonCanonical);
    }
    if bytes[0] == 0 {
        return Err(RlpError::LeadingZero);
    }
    let mut acc: usize = 0;
    for &b in bytes {
        // checked_mul, NOT checked_shl: checked_shl(8) only fails when
        // 8 >= usize::BITS and silently DISCARDS bits shifted out of the
        // top, so on a 32-bit usize (thumbv8m) a >4-byte length field
        // would wrap instead of erroring — a parse-desync against any
        // 64-bit decoder. Found by the §33 rank-8 Lean proof.
        acc = acc.checked_mul(256).ok_or(RlpError::LengthOverflow)?;
        acc = acc.checked_add(b as usize).ok_or(RlpError::LengthOverflow)?;
    }
    Ok(acc)
}

/// Iterator over the items in an RLP list payload.
pub struct ListIter<'a> {
    rest: &'a [u8],
}

impl<'a> ListIter<'a> {
    pub const fn new(payload: &'a [u8]) -> Self {
        Self { rest: payload }
    }

    pub fn next_item(&mut self) -> Result<Option<Item<'a>>, RlpError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let (item, used) = decode_item(self.rest)?;
        self.rest = &self.rest[used..];
        Ok(Some(item))
    }

    pub fn expect_bytes(&mut self) -> Result<&'a [u8], RlpError> {
        match self.next_item()? {
            Some(Item::Bytes(b)) => Ok(b),
            Some(Item::List(_)) => Err(RlpError::UnexpectedType),
            None => Err(RlpError::Truncated),
        }
    }

    pub fn expect_list(&mut self) -> Result<&'a [u8], RlpError> {
        match self.next_item()? {
            Some(Item::List(l)) => Ok(l),
            Some(Item::Bytes(_)) => Err(RlpError::UnexpectedType),
            None => Err(RlpError::Truncated),
        }
    }
}

#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    /// Panic / overflow / OOB-freedom for the RLP item decoder over arbitrary
    /// (adversarial companion) bytes, PLUS the load-bearing invariant
    /// `used <= input.len()` — the consumed count never exceeds the input, so
    /// the slices `decode_item` hands back and `ListIter`'s `&self.rest[used..]`
    /// re-slice are always in-bounds. Kani additionally auto-checks for
    /// arithmetic overflow, slice index OOB, unreachable, and panics over EVERY
    /// input of length <= N.
    ///
    /// Scope: host-reachable pure-logic decoder (no_std, no hardware deps);
    /// this is the untrusted-companion-bytes parse surface (EIP-1559 envelopes).
    #[kani::proof]
    #[kani::unwind(11)]
    fn decode_item_panic_free_and_used_in_bounds() {
        const N: usize = 10;
        let len: usize = kani::any();
        kani::assume(len <= N);
        let mut buf = [0u8; N];
        let mut i = 0;
        while i < len {
            buf[i] = kani::any();
            i += 1;
        }
        if let Ok((_item, used)) = decode_item(&buf[..len]) {
            assert!(used <= len, "decode_item consumed past the input");
        }
    }

    /// Panic / underflow / OOB-freedom for the RLP big-endian → U256 leaf
    /// decoder over arbitrary bytes. Kani proves the `32 - bytes.len()` offset
    /// never underflows (the `len > 32` guard suffices) and that
    /// `out[off..].copy_from_slice(bytes)` has matching slice lengths — so no
    /// numeric field of any companion-supplied tx can panic this decoder.
    /// Scope: host-reachable pure-logic decoder (no_std).
    #[kani::proof]
    #[kani::unwind(34)]
    fn bytes_to_u256_panic_free() {
        const N: usize = 33; // exercises the len==32 boundary + the len>32 reject
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let _ = bytes_to_u256(&buf[..len]);
    }
}

/// Decode an RLP-encoded big-endian unsigned integer (canonical: no leading
/// zero unless the value is exactly zero, which is encoded as the empty
/// string).
pub fn bytes_to_u64(bytes: &[u8]) -> Result<u64, RlpError> {
    if bytes.len() > 8 {
        return Err(RlpError::IntTooLarge);
    }
    if !bytes.is_empty() && bytes[0] == 0 {
        return Err(RlpError::LeadingZero);
    }
    let mut acc: u64 = 0;
    for &b in bytes {
        acc = (acc << 8) | (b as u64);
    }
    Ok(acc)
}

/// Decode an RLP-encoded big-endian unsigned integer up to 256 bits.
/// Returns a left-padded 32-byte big-endian array.
pub fn bytes_to_u256(bytes: &[u8]) -> Result<[u8; 32], RlpError> {
    if bytes.len() > 32 {
        return Err(RlpError::IntTooLarge);
    }
    if !bytes.is_empty() && bytes[0] == 0 {
        return Err(RlpError::LeadingZero);
    }
    let mut out = [0u8; 32];
    let off = 32 - bytes.len();
    out[off..].copy_from_slice(bytes);
    Ok(out)
}
