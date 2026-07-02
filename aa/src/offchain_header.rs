//! Pure framing parser for the off-chain `EIP712_TYPED` / `EIP712_TYPED_V3`
//! sign-request payload.
//!
//! Extracted **verbatim and behaviour-identical** from the inline walker in
//! `secure/src/nsc/cmd_sign_offchain.rs` so the untrusted-companion-bytes
//! framing decode — the first thing the secure world does with the payload of
//! a `CMD_SIGN_OFFCHAIN` typed-data request — is host-compilable and
//! Kani-bounded (`cargo kani -p pqsigner-aa`). The secure caller keeps the
//! same upstream `payload_len` min/max gate in the kind dispatch and then
//! calls [`parse_eip712_typed_frame`]; on `Err` it maps
//! [`Eip712FrameError::status_str`] to the same `show_status` banner it showed
//! before and refuses. The downstream (ERC-7730 bundle verify, FI-hardened
//! binding, keccak digest) stays in the secure world and consumes the frame's
//! slices unchanged.
//!
//! Wire layout (all lengths `u16` big-endian):
//! ```text
//!   [dsep_present:2][domain_separator:32][primary_type_hash:32]
//!   [encoded_data_len:2][encoded_data:encoded_data_len]
//!   (V3 only) [nested_blob_len:2][nested_blob:nested_blob_len]
//!   [trailer_len:2][trailer:trailer_len]
//! ```
//! The final `trailer` MUST end exactly at `payload.len()` — the wire-level
//! EXACT-consumption guard: every byte is accounted, no hidden trailing data.

use pqsigner_proto::{MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN, MAX_OFFCHAIN_EIP712_NESTED_LEN};

/// The five sections a typed-data frame decodes to. `encoded_data` /
/// `nested_blob` / `trailer` borrow from the input payload; the two 32-byte
/// hashes are copied out (the caller folds them into the EIP-712 digest).
#[derive(Debug)]
pub struct Eip712TypedFrame<'a> {
    /// Companion-supplied EIP-712 `domainSeparator` (folded into the final hash).
    pub domain_separator: [u8; 32],
    /// EIP-712 `primaryType` type hash.
    pub primary_type_hash: [u8; 32],
    /// ABI-encoded struct data (`keccak256(typehash || encoded_data)`).
    pub encoded_data: &'a [u8],
    /// V3 nested-encodeData blob (DISPLAY-only; empty for non-V3).
    pub nested_blob: &'a [u8],
    /// The ERC-7730 descriptor bundle trailer.
    pub trailer: &'a [u8],
}

/// Why a typed-data frame was refused. `status_str` is the ≤16-col banner the
/// secure `show_status` shows — byte-identical to the pre-extraction messages.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Eip712FrameError {
    /// Payload shorter than the fixed header (`dsep_present + dsep + pth +
    /// edl + trailer_len`, or `+ nested_len` for V3).
    ShortHeader,
    /// `dsep_present == 0` — no domain separator supplied.
    MissingDomainSep,
    /// `encoded_data_len` over the cap or past the payload end.
    BadEncodedDataLen,
    /// V3: no room for the `nested_blob_len` word.
    NoNestedLen,
    /// V3: `nested_blob_len` over the cap or past the payload end.
    BadNestedLen,
    /// No room for the `trailer_len` word.
    NoTrailerLen,
    /// `trailer_len == 0`.
    EmptyTrailer,
    /// `trailer_len` does not consume the payload EXACTLY (hidden bytes).
    BadTrailerLen,
}

impl Eip712FrameError {
    /// The exact `show_status` banner the inline walker showed for this reason.
    #[must_use]
    pub fn status_str(self) -> &'static str {
        match self {
            Eip712FrameError::ShortHeader => "typed too short",
            Eip712FrameError::MissingDomainSep => "7730 missing ds",
            Eip712FrameError::BadEncodedDataLen => "bad ed_len",
            Eip712FrameError::NoNestedLen => "no nested len",
            Eip712FrameError::BadNestedLen => "bad nested len",
            Eip712FrameError::NoTrailerLen => "no trailer",
            Eip712FrameError::EmptyTrailer => "empty trailer",
            Eip712FrameError::BadTrailerLen => "bad trailer_len",
        }
    }
}

#[inline]
fn read_u16(payload: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([payload[p], payload[p + 1]])
}

/// Strictly decode the typed-data framing. Panic/OOB-free for ANY input: every
/// read is bounds-checked, so a truncated or over-claiming length returns `Err`
/// rather than indexing out of bounds. `Ok` guarantees the trailer ends exactly
/// at `payload.len()` (no hidden trailing bytes).
pub fn parse_eip712_typed_frame(
    payload: &[u8],
    is_v3: bool,
) -> Result<Eip712TypedFrame<'_>, Eip712FrameError> {
    // Fixed header: dsep_present(2) + dsep(32) + pth(32) + edl(2) +
    // trailer_len(2) [+ nested_blob_len(2) for V3]. This makes every fixed-word
    // read below in-bounds without a per-read length test.
    let min = 2 + 32 + 32 + 2 + 2 + if is_v3 { 2 } else { 0 };
    if payload.len() < min {
        return Err(Eip712FrameError::ShortHeader);
    }

    let mut p = 0usize;
    let domain_sep_present = read_u16(payload, p) != 0;
    p += 2;
    if !domain_sep_present {
        return Err(Eip712FrameError::MissingDomainSep);
    }
    let mut domain_separator = [0u8; 32];
    domain_separator.copy_from_slice(&payload[p..p + 32]);
    p += 32;
    let mut primary_type_hash = [0u8; 32];
    primary_type_hash.copy_from_slice(&payload[p..p + 32]);
    p += 32;

    let encoded_data_len = read_u16(payload, p) as usize;
    p += 2;
    if encoded_data_len > MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN
        || p + encoded_data_len > payload.len()
    {
        return Err(Eip712FrameError::BadEncodedDataLen);
    }
    let encoded_data = &payload[p..p + encoded_data_len];
    p += encoded_data_len;

    let nested_blob: &[u8] = if is_v3 {
        if p + 2 > payload.len() {
            return Err(Eip712FrameError::NoNestedLen);
        }
        let nb_len = read_u16(payload, p) as usize;
        p += 2;
        if nb_len > MAX_OFFCHAIN_EIP712_NESTED_LEN || p + nb_len > payload.len() {
            return Err(Eip712FrameError::BadNestedLen);
        }
        let nb = &payload[p..p + nb_len];
        p += nb_len;
        nb
    } else {
        &[]
    };

    if p + 2 > payload.len() {
        return Err(Eip712FrameError::NoTrailerLen);
    }
    let trailer_len = read_u16(payload, p) as usize;
    p += 2;
    if trailer_len == 0 {
        return Err(Eip712FrameError::EmptyTrailer);
    }
    // EXACT consumption: the trailer must be the rest of the payload.
    if p + trailer_len != payload.len() {
        return Err(Eip712FrameError::BadTrailerLen);
    }
    let trailer = &payload[p..p + trailer_len];

    Ok(Eip712TypedFrame {
        domain_separator,
        primary_type_hash,
        encoded_data,
        nested_blob,
        trailer,
    })
}

#[cfg(kani)]
mod verification {
    use super::*;

    /// Panic / arithmetic-overflow / slice-OOB freedom AND framing-exactness for
    /// the untrusted `EIP712_TYPED` / `_V3` header over symbolic payloads of
    /// length ≤ N. No crafted payload — any lengths, any content — can index the
    /// decoder out of bounds (it returns `Err` instead), and on ACCEPT the
    /// trailer ends EXACTLY at `payload.len()` (`p_after_walk == len`), so no
    /// hidden trailing bytes ride an accepted frame. Bounded N=90 admits the
    /// fixed header (70/72 B) + short variable tails; the framing logic is
    /// length-uniform (each section is a `read_u16` + a `p + n > len` gate), so
    /// N=90 is representative of the OOB/exactness surface.
    #[kani::proof]
    #[kani::unwind(4)]
    fn parse_frame_panic_free_and_exact() {
        const N: usize = 90;
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let is_v3: bool = kani::any();
        let payload = &buf[..len];

        if let Ok(f) = parse_eip712_typed_frame(payload, is_v3) {
            // Every returned slice lies inside the payload …
            let base = payload.as_ptr() as usize;
            let ed = f.encoded_data.as_ptr() as usize;
            let tr = f.trailer.as_ptr() as usize;
            assert!(ed >= base && ed + f.encoded_data.len() <= base + len);
            assert!(tr >= base && tr + f.trailer.len() <= base + len);
            // … and the trailer ends EXACTLY at the payload end (exact consumption).
            assert_eq!(tr + f.trailer.len(), base + len);
            // is_v3 ⟺ a nested blob section was parsed (possibly empty).
            if !is_v3 {
                assert!(f.nested_blob.is_empty());
            }
        }
    }

    /// Non-vacuity (positive control): a concrete minimal well-formed non-V3
    /// frame (empty encoded_data, 1-byte trailer) is ACCEPTED and the trailer is
    /// the final byte.
    #[kani::proof]
    fn parse_frame_accepts_minimal() {
        // dsep_present=1, dsep(32)=0, pth(32)=0, edl=0, trailer_len=1, trailer=[0xAB]
        let mut buf = [0u8; 71];
        buf[1] = 1; // dsep_present low byte
        // edl word @ 66..68 = 0 (already). trailer_len word @ 68..70 = 1.
        buf[69] = 1;
        buf[70] = 0xAB;
        let f = parse_eip712_typed_frame(&buf, false).expect("minimal frame accepts");
        assert_eq!(f.trailer, &[0xAB]);
        assert!(f.encoded_data.is_empty() && f.nested_blob.is_empty());
    }
}
