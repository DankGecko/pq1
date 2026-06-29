//! Strict outer-framing decoder for Safe `MultiSendCallOnly` calldata.
//!
//! This is the pure-logic core of the Safe multiSend WYSIWYS path
//! (layer 1 — outer ABI framing): the `multiSend(bytes)` argument
//! decoder and its 32-byte-word reader, plus the [`MsError`] refusal
//! taxonomy shared across the whole pipeline. It is extracted here,
//! verbatim and behaviour-identical, so it can be host-compiled and
//! bounded-verified with Kani (`cargo kani -p pqsigner-tx`) — the
//! firmware-side `secure/src/tx/eip712/safe/multi_send.rs` re-exports
//! these three items unchanged, so every existing caller, the record
//! iterator, the classifier, and the full test suite keep working.
//!
//! Dependency closure is intentionally tiny: only
//! [`sphincs_tz_shared::MULTI_SEND_SELECTOR`] (a `pqsigner-proto`
//! constant, re-exported). No hashing, no `cow_binding`, no record
//! classification — those stay in `secure/`.
//!
//! ## The proven property (canonical-acceptance / soundness)
//!
//! `decode_multisend(data) == Ok(payload)` ⟹ `data` is **byte-exactly**
//! the unique canonical Solidity encoding
//! `selector ‖ offset_word(==0x20) ‖ len_word(==payload.len())
//! ‖ payload ‖ zero-pad-to-32`, with nothing trailing and every pad
//! byte zero. So the on-device decode can never structurally disagree
//! with on-chain decoding, and no hidden trailing "second payload" can
//! ride a DELEGATECALL batch the user blind-confirms. See the
//! `#[cfg(kani)] mod verification` harnesses at the bottom of this file.

use sphincs_tz_shared::MULTI_SEND_SELECTOR;

/// Decode / classification failures. Every variant is a hard refusal —
/// there is no degraded render for a DELEGATECALL payload.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MsError {
    /// Calldata shorter than `selector + offset word + length word`.
    ShortInput,
    /// `calldata[..4] != multiSend(bytes)`.
    WrongSelector,
    /// The `bytes` head offset is not exactly 32 (the only value the
    /// canonical Solidity encoding produces).
    BadOffset,
    /// The `bytes` length word has bits above u32, or the declared
    /// payload runs past the calldata end.
    BadLength,
    /// Calldata extends past the zero-padded payload end, or the
    /// padding bytes are non-zero. Trailing garbage could carry a
    /// second, undisplayed payload interpretation.
    BadPadding,
    /// A record header or its declared `data` runs past the packed
    /// slice end.
    TruncatedRecord,
    /// A record's `dataLen` word has bits above u32.
    BadRecordDataLen,
    /// A record's `operation` byte is not 0 (Call). MultiSendCallOnly
    /// reverts on-chain for these; we refuse on-device for the same
    /// reason — a nested DELEGATECALL is not honestly clear-signable.
    RecordOpNotCall,
    /// Zero records, or more than `MULTISEND_MAX_RECORDS`.
    BadRecordCount,
}

impl MsError {
    /// Short (≤16 col) status-line reason for the refusal banner.
    #[must_use]
    pub fn as_status_str(self) -> &'static str {
        match self {
            MsError::ShortInput
            | MsError::WrongSelector
            | MsError::BadOffset
            | MsError::BadLength
            | MsError::BadPadding
            | MsError::TruncatedRecord
            | MsError::BadRecordDataLen => "msend malformed",
            MsError::RecordOpNotCall => "msend rec op!=0",
            MsError::BadRecordCount => "msend rec count",
        }
    }
}

/// Read a 32-byte ABI word as `usize`, requiring all bits above u32 to
/// be zero (calldata is u16-bounded upstream anyway).
pub fn read_u32_word(word: &[u8]) -> Result<usize, MsError> {
    debug_assert_eq!(word.len(), 32);
    if word[..28].iter().any(|&b| b != 0) {
        return Err(MsError::BadLength);
    }
    Ok(u32::from_be_bytes([word[28], word[29], word[30], word[31]]) as usize)
}

/// Strictly decode `multiSend(bytes)` calldata down to the packed
/// records slice.
///
/// Canonical-encoding-only: head offset must be exactly 0x20, the
/// total calldata length must equal `4 + 64 + ceil32(len)` and every
/// padding byte must be zero. Anything else is refused — the firmware
/// never renders a payload whose on-chain decoding could differ from
/// the on-device one.
pub fn decode_multisend(data: &[u8]) -> Result<&[u8], MsError> {
    if data.len() < 4 + 64 {
        return Err(MsError::ShortInput);
    }
    if data[..4] != MULTI_SEND_SELECTOR {
        return Err(MsError::WrongSelector);
    }
    let head = &data[4..];
    // Offset word: the canonical encoding of a single dynamic `bytes`
    // argument always places the tail immediately after the one-word
    // head, i.e. offset == 32.
    if read_u32_word(&head[0..32]).map_err(|_| MsError::BadOffset)? != 32 {
        return Err(MsError::BadOffset);
    }
    let len = read_u32_word(&head[32..64])?;
    let payload_start = 64usize;
    let payload_end = payload_start.checked_add(len).ok_or(MsError::BadLength)?;
    if payload_end > head.len() {
        return Err(MsError::BadLength);
    }
    // Exact-length + zero-padding: Solidity pads the bytes tail to a
    // 32-byte boundary with zeros and emits nothing after it.
    let padded_end = payload_end
        .checked_add(31)
        .ok_or(MsError::BadLength)?
        / 32
        * 32;
    if head.len() != padded_end {
        return Err(MsError::BadPadding);
    }
    if head[payload_end..padded_end].iter().any(|&b| b != 0) {
        return Err(MsError::BadPadding);
    }
    Ok(&head[payload_start..payload_end])
}

// ---------------------------------------------------------------------------
// Inner packed-record walk (layer 2)
// ---------------------------------------------------------------------------
//
// Extracted here, verbatim and behaviour-identical, alongside the
// outer-framing decoder so the per-record loop is host-runnable and can
// be exercised by the `revm`/MultiSendCallOnly bytecode differential
// (move 3 of the firmware bounded-verification plan) — the one layer the
// Kani canonical-acceptance proof on `decode_multisend` structurally
// cannot reach, because the packed-record encoding mirrors
// MultiSendCallOnly's hand-rolled assembly rather than standard ABI.
// `secure/src/tx/eip712/safe/multi_send.rs` re-exports `MsRecord` and
// `MsRecordIter` unchanged, so `summarize`, `classify_record_kind`, the
// renderer, and the full test suite keep working.

/// Fixed per-record header: `operation(1) || to(20) || value(32) ||
/// dataLen(32)`, followed by `data(dataLen)`. Packed encoding — no
/// padding between records.
pub const MS_RECORD_HEADER_LEN: usize = 1 + 20 + 32 + 32;

/// One packed multiSend record. `data` borrows from the same snapshot
/// the multiSend calldata lives in.
#[derive(Copy, Clone, Debug)]
pub struct MsRecord<'a> {
    /// Raw operation byte. `summarize` (and therefore every accepted
    /// payload) requires this to be 0; the iterator itself reports it
    /// verbatim so tests can probe the rejection.
    pub operation: u8,
    pub to: [u8; 20],
    /// Native value forwarded with the record's call, uint256 BE.
    pub value: [u8; 32],
    pub data: &'a [u8],
}

impl MsRecord<'_> {
    #[must_use]
    pub fn value_is_zero(&self) -> bool {
        self.value.iter().all(|&b| b == 0)
    }
}

/// Iterator over the packed records slice returned by
/// [`decode_multisend`]. Yields `Err` once on the first malformed
/// record, then `None`. The cursor must land exactly on the slice end
/// — a partial trailing record is [`MsError::TruncatedRecord`].
pub struct MsRecordIter<'a> {
    packed: &'a [u8],
    cursor: usize,
    failed: bool,
}

impl<'a> MsRecordIter<'a> {
    #[must_use]
    pub fn new(packed: &'a [u8]) -> Self {
        Self {
            packed,
            cursor: 0,
            failed: false,
        }
    }
}

impl<'a> Iterator for MsRecordIter<'a> {
    type Item = Result<MsRecord<'a>, MsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.cursor == self.packed.len() {
            return None;
        }
        let rest = &self.packed[self.cursor..];
        if rest.len() < MS_RECORD_HEADER_LEN {
            self.failed = true;
            return Some(Err(MsError::TruncatedRecord));
        }
        let operation = rest[0];
        let mut to = [0u8; 20];
        to.copy_from_slice(&rest[1..21]);
        let mut value = [0u8; 32];
        value.copy_from_slice(&rest[21..53]);
        let data_len = match read_u32_word(&rest[53..85]) {
            Ok(l) => l,
            Err(_) => {
                self.failed = true;
                return Some(Err(MsError::BadRecordDataLen));
            }
        };
        let data_end = match MS_RECORD_HEADER_LEN.checked_add(data_len) {
            Some(e) if e <= rest.len() => e,
            _ => {
                self.failed = true;
                return Some(Err(MsError::TruncatedRecord));
            }
        };
        let data = &rest[MS_RECORD_HEADER_LEN..data_end];
        self.cursor += data_end;
        Some(Ok(MsRecord {
            operation,
            to,
            value,
            data,
        }))
    }
}

// ---------------------------------------------------------------------------
// Bounded verification (Kani)
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod verification {
    use super::*;

    /// Canonical-acceptance (soundness): `decode_multisend(s) == Ok(payload)`
    /// ⟹ `s` is **byte-for-byte** the unique canonical Solidity encoding of
    /// `payload`:
    ///
    /// ```text
    /// selector(4) ‖ offset_word(==0x20)(32) ‖ len_word(==payload.len())(32)
    ///            ‖ payload ‖ zero-pad to a 32-byte multiple
    /// ```
    ///
    /// with NOTHING trailing and EVERY pad byte zero. We reconstruct that
    /// canonical buffer purely from the input length, the returned `payload`,
    /// and the proto selector constant, then assert byte equality against the
    /// accepted input — so a green run forecloses, over ALL symbolic calldata
    /// ≤ `N`, any non-canonical input the decoder might admit (a different
    /// offset, an over/under-length word, non-zero padding, or a hidden
    /// trailing second payload).
    ///
    /// Bound: `N = 100` covers the empty-payload frame (`len == 0` → 68 B) and
    /// non-empty payloads up to 32 B (`len ∈ 1..=32` → 100 B), exercising both
    /// the pad-empty and pad-non-empty branches of the `ceil32` rounding and
    /// the zero-pad scan. The property is sound at this bound; a larger `N`
    /// only re-runs the same rounding at the next 32-byte boundary.
    #[kani::proof]
    #[kani::unwind(101)] // ≥ N+1: bounds the ≤N-byte canonical-equality compare
    fn decode_multisend_canonical_acceptance() {
        const N: usize = 100;
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let s = &data[..len];

        if let Ok(payload) = decode_multisend(s) {
            let plen = payload.len();
            // Exact total length = 68 + ceil32(payload.len()).
            let total = 68 + plen.next_multiple_of(32);
            assert_eq!(s.len(), total);

            // Reconstruct the unique canonical framing from (input length,
            // payload, selector) — never from the decoder's internals.
            let mut expected = [0u8; N];
            expected[0..4].copy_from_slice(&MULTI_SEND_SELECTOR);
            expected[35] = 0x20; // offset word == 0x20 (all higher bytes zero)
            expected[64..68].copy_from_slice(&(plen as u32).to_be_bytes()); // len word
            expected[68..68 + plen].copy_from_slice(payload);
            // expected[68+plen .. total] stays zero — the canonical pad.

            assert_eq!(&expected[..total], s);
        }
    }

    /// Non-vacuity (positive control): a concrete, hand-built canonical frame
    /// with a 2-byte payload is ACCEPTED and yields exactly that payload.
    /// Without this, the acceptance proof above could pass vacuously (a
    /// decoder that rejected everything would satisfy it trivially).
    #[kani::proof]
    #[kani::unwind(40)]
    fn decode_multisend_accepts_canonical() {
        // total = 68 + ceil32(2) = 100
        let mut buf = [0u8; 100];
        buf[0..4].copy_from_slice(&MULTI_SEND_SELECTOR);
        buf[35] = 0x20; // offset == 0x20
        buf[67] = 2; // length word == 2
        buf[68] = 0xaa;
        buf[69] = 0xbb;
        // buf[70..100] zero pad
        match decode_multisend(&buf) {
            Ok(payload) => {
                assert_eq!(payload.len(), 2);
                assert_eq!(payload[0], 0xaa);
                assert_eq!(payload[1], 0xbb);
            }
            Err(_) => panic!("a canonical multiSend frame must be accepted"),
        }
    }

    /// Non-vacuity (negative control A — the on-point one): a frame whose
    /// declared payload is empty but which carries a NON-ZERO byte in the
    /// 32-byte pad must be refused with `BadPadding`. This is exactly the
    /// "hidden second payload riding in the padding" threat the
    /// canonical-acceptance property exists to foreclose.
    #[kani::proof]
    #[kani::unwind(40)]
    fn decode_multisend_rejects_nonzero_pad() {
        // Canonical empty-payload frame is 68 B; declare len = 1 so the
        // payload occupies one byte and the remaining 31 pad bytes must be
        // zero. Put a non-zero byte in the pad.
        let mut buf = [0u8; 100];
        buf[0..4].copy_from_slice(&MULTI_SEND_SELECTOR);
        buf[35] = 0x20; // offset == 0x20
        buf[67] = 1; // length word == 1
        buf[68] = 0x11; // the one payload byte
        buf[99] = 0xff; // non-zero PAD byte → must be refused
        assert_eq!(decode_multisend(&buf), Err(MsError::BadPadding));
    }

    /// Non-vacuity (negative control B): a canonical empty-payload frame
    /// (68 B) with one extra trailing byte must be refused with `BadPadding`
    /// (exact-length branch — nothing may follow the padded tail).
    #[kani::proof]
    #[kani::unwind(40)]
    fn decode_multisend_rejects_trailing_byte() {
        let mut buf = [0u8; 69];
        buf[0..4].copy_from_slice(&MULTI_SEND_SELECTOR);
        buf[35] = 0x20; // offset == 0x20, length word == 0 (empty payload)
        // one extra byte at [68] beyond the 68-byte canonical empty frame
        assert_eq!(decode_multisend(&buf), Err(MsError::BadPadding));
    }
}
