//! Allocation-free parser for Uniswap V3 packed paths and the exact
//! Router02 `exactInput` / `exactOutput` ABI body shape.
//!
//! A V3 path is `token (fee token)+`, where each token is the complete
//! 20-byte address and each fee is the complete big-endian `uint24`.  The
//! display direction is explicit because Router02 encodes `exactOutput` paths
//! in reverse execution order.  Neither direction drops a signed byte.
//!
//! [`parse_router02_body`] is deliberately narrower than a general ABI tuple
//! walker.  It accepts one outer dynamic tuple whose path is the tuple's sole
//! dynamic member, at its canonical four-word-head offset, and requires the
//! padded path object to consume the exact remainder of the calldata body.

use pqsigner_tx::typed_call::abi::{read_length_word, read_offset_word};

use super::RenderErr;

/// Bytes in one packed token address.
pub const TOKEN_LEN: usize = 20;
/// Bytes in one packed `uint24` pool fee.
pub const FEE_LEN: usize = 3;
/// Bytes added by every hop (`fee || next_token`).
pub const HOP_STRIDE: usize = FEE_LEN + TOKEN_LEN;
/// A path must traverse at least one pool.
pub const MIN_HOPS: usize = 1;
/// Human-review and page-budget cap for one packed route.
pub const MAX_HOPS: usize = 5;

const WORD_LEN: usize = 32;
const OUTER_HEAD_LEN: usize = WORD_LEN;
const TUPLE_HEAD_WORDS: usize = 4;
const TUPLE_HEAD_LEN: usize = TUPLE_HEAD_WORDS * WORD_LEN;
const MAX_PATH_LEN: usize = TOKEN_LEN + MAX_HOPS * HOP_STRIDE;

/// Order in which the trusted display traverses a packed path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Packed byte order (`exactInput`).
    Forward,
    /// Reverse packed byte order (`exactOutput`).
    Reverse,
}

/// A validated, borrowed Uniswap V3 packed path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UniswapV3Path<'a> {
    bytes: &'a [u8],
    hops: usize,
}

impl<'a> UniswapV3Path<'a> {
    /// Validate `token (fee token)+` framing and the configured hop cap.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, RenderErr> {
        let tail_len = bytes
            .len()
            .checked_sub(TOKEN_LEN)
            .ok_or(RenderErr::Reject("7730 v3 path too short"))?;
        if tail_len % HOP_STRIDE != 0 {
            return Err(RenderErr::Reject("7730 v3 path bad length"));
        }

        let hops = tail_len / HOP_STRIDE;
        if hops < MIN_HOPS {
            return Err(RenderErr::Reject("7730 v3 path no hops"));
        }
        if hops > MAX_HOPS {
            return Err(RenderErr::Reject("7730 v3 path too many hops"));
        }

        Ok(Self { bytes, hops })
    }

    /// Number of pools traversed by this path.
    #[must_use]
    pub const fn hop_count(&self) -> usize {
        self.hops
    }

    /// Return the complete token address at `display_index`.
    ///
    /// There are `hop_count() + 1` token indices.  Reverse direction maps
    /// display index zero to the last packed token.
    pub fn token(
        &self,
        display_index: usize,
        direction: Direction,
    ) -> Result<[u8; TOKEN_LEN], RenderErr> {
        if display_index > self.hops {
            return Err(RenderErr::Reject("7730 v3 token index"));
        }
        let packed_index = match direction {
            Direction::Forward => display_index,
            Direction::Reverse => self.hops - display_index,
        };
        let start = packed_index
            .checked_mul(HOP_STRIDE)
            .ok_or(RenderErr::Reject("7730 v3 token offset"))?;
        let end = start
            .checked_add(TOKEN_LEN)
            .ok_or(RenderErr::Reject("7730 v3 token offset"))?;
        let src = self
            .bytes
            .get(start..end)
            .ok_or(RenderErr::Reject("7730 v3 token oob"))?;
        let mut token = [0u8; TOKEN_LEN];
        token.copy_from_slice(src);
        Ok(token)
    }

    /// Return the exact big-endian `uint24` fee at `display_index`.
    ///
    /// There are `hop_count()` fee indices.  In reverse direction the fee
    /// adjacent to the first displayed token is returned first.
    pub fn fee(&self, display_index: usize, direction: Direction) -> Result<u32, RenderErr> {
        if display_index >= self.hops {
            return Err(RenderErr::Reject("7730 v3 fee index"));
        }
        let packed_index = match direction {
            Direction::Forward => display_index,
            Direction::Reverse => self.hops - 1 - display_index,
        };
        let start = packed_index
            .checked_mul(HOP_STRIDE)
            .and_then(|off| off.checked_add(TOKEN_LEN))
            .ok_or(RenderErr::Reject("7730 v3 fee offset"))?;
        let end = start
            .checked_add(FEE_LEN)
            .ok_or(RenderErr::Reject("7730 v3 fee offset"))?;
        let fee = self
            .bytes
            .get(start..end)
            .ok_or(RenderErr::Reject("7730 v3 fee oob"))?;
        Ok(u32::from_be_bytes([0, fee[0], fee[1], fee[2]]))
    }
}

/// Validate and borrow the packed path from an exact Router02 call body.
///
/// `body` starts immediately after the four-byte function selector and must be
/// the canonical ABI encoding of one dynamic
/// `(bytes,address,uint256,uint256)` tuple:
///
/// * the sole outer offset is exactly 32;
/// * the tuple's path offset is exactly 128 (its four-word head);
/// * the dynamic length word is canonical;
/// * right padding is all zero; and
/// * the padded path ends exactly at `body.len()`.
pub fn parse_router02_body(body: &[u8]) -> Result<UniswapV3Path<'_>, RenderErr> {
    let outer_word = body
        .get(..WORD_LEN)
        .ok_or(RenderErr::Reject("7730 v3 body no outer head"))?;
    let tuple_off =
        read_offset_word(outer_word).ok_or(RenderErr::Reject("7730 v3 body bad outer offset"))?;
    if tuple_off != OUTER_HEAD_LEN {
        return Err(RenderErr::Reject("7730 v3 body outer offset"));
    }

    let tuple = body
        .get(tuple_off..)
        .ok_or(RenderErr::Reject("7730 v3 body no tuple"))?;
    let path_offset_word = tuple
        .get(..WORD_LEN)
        .ok_or(RenderErr::Reject("7730 v3 body no tuple head"))?;
    let path_off = read_offset_word(path_offset_word)
        .ok_or(RenderErr::Reject("7730 v3 body bad path offset"))?;
    if path_off != TUPLE_HEAD_LEN {
        return Err(RenderErr::Reject("7730 v3 body path offset"));
    }

    // The recipient is the tuple's second word. Dirty high padding changes
    // the signed calldata while leaving the low 20 displayed address bytes
    // unchanged, so reject it as part of the whole-body preflight (before any
    // guard or page can be evaluated).
    let recipient = tuple
        .get(WORD_LEN..2 * WORD_LEN)
        .ok_or(RenderErr::Reject("7730 v3 body no recipient"))?;
    if recipient[..12].iter().any(|&byte| byte != 0) {
        return Err(RenderErr::Reject("7730 v3 recipient noncanonical"));
    }

    // Requiring the length word exactly after a four-word tuple head proves
    // the complete head is present before reading the dynamic object.
    let len_end = path_off
        .checked_add(WORD_LEN)
        .ok_or(RenderErr::Reject("7730 v3 body overflow"))?;
    let len_word = tuple
        .get(path_off..len_end)
        .ok_or(RenderErr::Reject("7730 v3 body no path length"))?;
    let path_len = read_length_word(len_word)
        .ok_or(RenderErr::Reject("7730 v3 body bad path length"))? as usize;

    // This stricter cap precedes all length-derived slicing and arithmetic.
    if path_len > MAX_PATH_LEN {
        return Err(RenderErr::Reject("7730 v3 path too many hops"));
    }
    let data_end = len_end
        .checked_add(path_len)
        .ok_or(RenderErr::Reject("7730 v3 body overflow"))?;
    let padded_len = path_len
        .checked_add(WORD_LEN - 1)
        .ok_or(RenderErr::Reject("7730 v3 body overflow"))?
        / WORD_LEN
        * WORD_LEN;
    let padded_end = len_end
        .checked_add(padded_len)
        .ok_or(RenderErr::Reject("7730 v3 body overflow"))?;
    if padded_end != tuple.len() {
        return Err(RenderErr::Reject("7730 v3 body not whole tail"));
    }

    let path = tuple
        .get(len_end..data_end)
        .ok_or(RenderErr::Reject("7730 v3 body path oob"))?;
    let padding = tuple
        .get(data_end..padded_end)
        .ok_or(RenderErr::Reject("7730 v3 body pad oob"))?;
    if padding.iter().any(|&byte| byte != 0) {
        return Err(RenderErr::Reject("7730 v3 body dirty pad"));
    }

    UniswapV3Path::parse(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(value: u32) -> [u8; WORD_LEN] {
        let mut word = [0u8; WORD_LEN];
        word[WORD_LEN - 4..].copy_from_slice(&value.to_be_bytes());
        word
    }

    fn token(value: u8) -> [u8; TOKEN_LEN] {
        [value; TOKEN_LEN]
    }

    fn packed_path(hops: usize) -> std::vec::Vec<u8> {
        let mut path = std::vec::Vec::new();
        path.extend_from_slice(&token(0x10));
        for i in 0..hops {
            let fee = (0x01_0203u32 + i as u32).to_be_bytes();
            path.extend_from_slice(&fee[1..]);
            path.extend_from_slice(&token(0x20 + i as u8));
        }
        path
    }

    fn router02_body(path: &[u8]) -> std::vec::Vec<u8> {
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&word(OUTER_HEAD_LEN as u32));
        body.extend_from_slice(&word(TUPLE_HEAD_LEN as u32));

        // recipient, amount A, amount B
        body.extend_from_slice(&[0u8; WORD_LEN]);
        body.extend_from_slice(&word(7));
        body.extend_from_slice(&word(11));

        body.extend_from_slice(&word(path.len() as u32));
        body.extend_from_slice(path);
        let padded_len = (path.len() + WORD_LEN - 1) / WORD_LEN * WORD_LEN;
        body.resize(body.len() + padded_len - path.len(), 0);
        body
    }

    #[test]
    fn one_hop_path_and_exact_body_are_accepted() {
        let bytes = packed_path(1);
        let path = UniswapV3Path::parse(&bytes).unwrap();
        assert_eq!(path.hop_count(), 1);
        assert_eq!(path.token(0, Direction::Forward), Ok(token(0x10)));
        assert_eq!(path.token(1, Direction::Forward), Ok(token(0x20)));
        assert_eq!(path.fee(0, Direction::Forward), Ok(0x01_0203));

        let body = router02_body(&bytes);
        assert_eq!(parse_router02_body(&body), Ok(path));
    }

    #[test]
    fn five_hops_are_accepted_and_every_component_is_addressable() {
        let bytes = packed_path(MAX_HOPS);
        let path = UniswapV3Path::parse(&bytes).unwrap();
        assert_eq!(path.hop_count(), MAX_HOPS);
        for i in 0..=MAX_HOPS {
            let expected = if i == 0 {
                token(0x10)
            } else {
                token(0x20 + (i - 1) as u8)
            };
            assert_eq!(path.token(i, Direction::Forward), Ok(expected));
        }
        for i in 0..MAX_HOPS {
            assert_eq!(path.fee(i, Direction::Forward), Ok(0x01_0203 + i as u32));
        }
        assert_eq!(parse_router02_body(&router02_body(&bytes)), Ok(path));
    }

    #[test]
    fn reverse_direction_is_asymmetric_and_exact() {
        let bytes = packed_path(3);
        let path = UniswapV3Path::parse(&bytes).unwrap();

        assert_eq!(path.token(0, Direction::Reverse), Ok(token(0x22)));
        assert_eq!(path.token(1, Direction::Reverse), Ok(token(0x21)));
        assert_eq!(path.token(2, Direction::Reverse), Ok(token(0x20)));
        assert_eq!(path.token(3, Direction::Reverse), Ok(token(0x10)));
        assert_eq!(path.fee(0, Direction::Reverse), Ok(0x01_0205));
        assert_eq!(path.fee(1, Direction::Reverse), Ok(0x01_0204));
        assert_eq!(path.fee(2, Direction::Reverse), Ok(0x01_0203));
    }

    #[test]
    fn zero_six_and_non_integral_hop_counts_reject() {
        assert!(matches!(
            UniswapV3Path::parse(&token(0x10)),
            Err(RenderErr::Reject("7730 v3 path no hops"))
        ));
        assert!(matches!(
            UniswapV3Path::parse(&packed_path(MAX_HOPS + 1)),
            Err(RenderErr::Reject("7730 v3 path too many hops"))
        ));

        let mut bad_modulo = packed_path(1);
        bad_modulo.push(0);
        assert!(matches!(
            UniswapV3Path::parse(&bad_modulo),
            Err(RenderErr::Reject("7730 v3 path bad length"))
        ));
        assert!(UniswapV3Path::parse(&[]).is_err());
    }

    #[test]
    fn token_and_fee_indices_are_bounded_in_both_directions() {
        let bytes = packed_path(1);
        let path = UniswapV3Path::parse(&bytes).unwrap();
        for direction in [Direction::Forward, Direction::Reverse] {
            assert!(path.token(2, direction).is_err());
            assert!(path.fee(1, direction).is_err());
        }
    }

    #[test]
    fn outer_and_tuple_offsets_must_be_canonical_and_exact() {
        let bytes = packed_path(1);
        let canonical = router02_body(&bytes);

        let mut wrong_outer = canonical.clone();
        wrong_outer[..WORD_LEN].copy_from_slice(&word(64));
        assert!(parse_router02_body(&wrong_outer).is_err());

        let mut dirty_outer = canonical.clone();
        dirty_outer[0] = 1;
        assert!(parse_router02_body(&dirty_outer).is_err());

        let mut wrong_path = canonical.clone();
        wrong_path[OUTER_HEAD_LEN..OUTER_HEAD_LEN + WORD_LEN].copy_from_slice(&word(96));
        assert!(parse_router02_body(&wrong_path).is_err());

        let mut dirty_path = canonical;
        dirty_path[OUTER_HEAD_LEN] = 1;
        assert!(parse_router02_body(&dirty_path).is_err());
    }

    #[test]
    fn dynamic_length_word_must_be_canonical_and_match_available_data() {
        let bytes = packed_path(1);
        let canonical = router02_body(&bytes);
        let len_off = OUTER_HEAD_LEN + TUPLE_HEAD_LEN;

        let mut dirty_length = canonical.clone();
        dirty_length[len_off] = 1;
        assert!(parse_router02_body(&dirty_length).is_err());

        let mut too_short = canonical.clone();
        too_short[len_off..len_off + WORD_LEN].copy_from_slice(&word(42));
        assert!(parse_router02_body(&too_short).is_err());

        let mut too_long = canonical;
        too_long[len_off..len_off + WORD_LEN].copy_from_slice(&word(44));
        assert!(parse_router02_body(&too_long).is_err());
    }

    #[test]
    fn dirty_padding_truncation_and_trailing_bytes_reject() {
        let bytes = packed_path(1);
        let canonical = router02_body(&bytes);
        let path_end = OUTER_HEAD_LEN + TUPLE_HEAD_LEN + WORD_LEN + bytes.len();

        let mut dirty_padding = canonical.clone();
        dirty_padding[path_end] = 1;
        assert!(matches!(
            parse_router02_body(&dirty_padding),
            Err(RenderErr::Reject("7730 v3 body dirty pad"))
        ));

        let mut truncated = canonical.clone();
        truncated.pop();
        assert!(parse_router02_body(&truncated).is_err());

        let mut trailing = canonical;
        trailing.push(0);
        assert!(parse_router02_body(&trailing).is_err());
    }

    #[test]
    fn dirty_recipient_padding_rejects_before_path_use() {
        let mut body = router02_body(&packed_path(1));
        // Outer tuple starts at byte 32; recipient starts one tuple word later.
        body[2 * WORD_LEN] = 1;
        assert!(matches!(
            parse_router02_body(&body),
            Err(RenderErr::Reject("7730 v3 recipient noncanonical"))
        ));
    }

    #[test]
    fn truncated_heads_and_path_data_reject_without_panicking() {
        let bytes = packed_path(1);
        let canonical = router02_body(&bytes);
        for end in [0, WORD_LEN - 1, WORD_LEN, OUTER_HEAD_LEN + TUPLE_HEAD_LEN] {
            assert!(parse_router02_body(&canonical[..end]).is_err());
        }

        let path_end = OUTER_HEAD_LEN + TUPLE_HEAD_LEN + WORD_LEN + bytes.len();
        assert!(parse_router02_body(&canonical[..path_end - 1]).is_err());
    }
}
