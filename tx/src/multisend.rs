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
//! ride a DELEGATECALL batch the user blind-confirms.
//!
//! The inner packed-record walk ([`MsRecordIter`]) is proven too: over
//! symbolic payloads, an all-`Ok` walk **exactly partitions** the payload
//! (`Σ (header + data) == payload.len()` — no hidden trailing record/data
//! the device never renders) and every displayed field (`operation`,
//! `to`, `value`, `data`) is the verbatim payload bytes. See the
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

    // -----------------------------------------------------------------------
    // Inner packed-record walk (`MsRecordIter`) — the layer the
    // canonical-acceptance proof above structurally cannot reach (the packed
    // encoding mirrors MultiSendCallOnly's hand-rolled assembly, not standard
    // ABI). Slice 3 sampled it differentially against the real deployed
    // bytecode in revm; these harnesses prove it as theorems over symbolic
    // payloads: the records exactly partition the payload (no hidden trailing
    // record/data the device never renders) and every displayed field is the
    // verbatim payload bytes.
    // -----------------------------------------------------------------------

    /// Exact tiling / partition soundness: if the walk over a symbolic packed
    /// slice yields a sequence of records that are all `Ok` and then `None`
    /// (never an `Err`), the records consume **every** payload byte —
    /// `Σ (MS_RECORD_HEADER_LEN + rec.data.len()) == packed.len()`, with
    /// nothing trailing and nothing overlapping.
    ///
    /// We track an independent record-start offset `off` and, on each accepted
    /// record, re-read the declared `dataLen` straight from the header bytes at
    /// `off` (`assert_eq!(rec.data.len(), dl)`). Over ALL symbolic input this
    /// forces the iterator's cursor to equal `off` (a divergent cursor would
    /// read a different `dataLen` word for some input), so `off += 85 + dl`
    /// provably tracks the cursor and the closing `off == len` is the real
    /// no-hidden-trailing-bytes statement — scalar-only, no pointer arithmetic.
    ///
    /// Bound: `N = 180` admits ≤ 2 records (`2 * 85 = 170 ≤ 180 < 255`). The
    /// per-record step is uniform, so two records exercise the cross-record
    /// induction; the `> MULTISEND_MAX_RECORDS` cap lives in `summarize`, not
    /// the iterator, and is out of scope here.
    #[kani::proof]
    #[kani::unwind(40)]
    fn record_walk_exact_tiling() {
        const N: usize = 180;
        let packed: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let p = &packed[..len];

        let mut iter = MsRecordIter::new(p);
        let mut off = 0usize;
        let mut all_ok = true;
        // ≤ 2 accepted records fit in N; +2 polls of headroom for the
        // terminating None/Err (a too-small loop would only ever make the
        // closing assert FAIL on a partial walk, never pass spuriously).
        for _ in 0..4 {
            match iter.next() {
                Some(Ok(rec)) => {
                    // A record is only yielded with its full header in-bounds
                    // at the cursor; pin `off` to it by matching the declared
                    // dataLen read directly from the header bytes at `off`.
                    assert!(off + MS_RECORD_HEADER_LEN <= p.len());
                    let dl = u32::from_be_bytes([
                        p[off + 81],
                        p[off + 82],
                        p[off + 83],
                        p[off + 84],
                    ]) as usize;
                    assert_eq!(rec.data.len(), dl);
                    off += MS_RECORD_HEADER_LEN + dl;
                    assert!(off <= p.len());
                }
                Some(Err(_)) => {
                    all_ok = false;
                    break;
                }
                None => break,
            }
        }
        if all_ok {
            // No hidden trailing record/data: an all-`Ok` walk consumes every
            // payload byte (the iterator returns `None` only at cursor == len,
            // and cursor == off was pinned per record above).
            assert_eq!(off, p.len());
        }
    }

    /// Field fidelity (soundness): every field the trusted UI would render from
    /// an accepted record — `operation`, `to`, `value`, and the `data` slice —
    /// is the **verbatim** payload bytes at the record's position, not a
    /// misaligned or corrupted copy. The declared `dataLen` is re-read
    /// independently from the header word so the `data` compare is anchored to
    /// the header position, not to the iterator's own length.
    ///
    /// Bound: `N = 120` (one record: 85-byte header + ≤ 35 data) at offset 0.
    /// The per-record field logic reads relative to the cursor, so offset 0 is
    /// representative; the concrete two-record control below pins a record at a
    /// non-zero offset, and `record_walk_exact_tiling` pins the cross-record
    /// offset advance.
    #[kani::proof]
    #[kani::unwind(121)]
    fn record_walk_field_fidelity() {
        const N: usize = 120;
        let packed: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let p = &packed[..len];

        let mut iter = MsRecordIter::new(p);
        if let Some(Ok(rec)) = iter.next() {
            // The first record sits at offset 0.
            assert_eq!(rec.operation, p[0]);
            let mut i = 0usize;
            while i < 20 {
                assert_eq!(rec.to[i], p[1 + i]);
                i += 1;
            }
            let mut j = 0usize;
            while j < 32 {
                assert_eq!(rec.value[j], p[21 + j]);
                j += 1;
            }
            let dl = u32::from_be_bytes([p[81], p[82], p[83], p[84]]) as usize;
            assert_eq!(rec.data.len(), dl);
            let mut k = 0usize;
            while k < dl {
                assert_eq!(rec.data[k], p[MS_RECORD_HEADER_LEN + k]);
                k += 1;
            }
        }
    }

    /// Non-vacuity (positive control): a concrete two-record payload — record A
    /// (`to = 0x11..`, `data = aa bb` → 87 B) then record B (`to = 0x22..`,
    /// empty data → 85 B), total 172 B with no trailing — is walked to exactly
    /// two records with the expected fields and then `None`. This also pins a
    /// record (B) at a non-zero offset (87), covering cross-boundary field
    /// reads the symbolic offset-0 harness cannot.
    #[kani::proof]
    #[kani::unwind(40)]
    fn record_walk_accepts_two_records() {
        let mut packed = [0u8; 172];
        // Record A header at 0: op 0, to = 0x11.., value 0, dataLen 2.
        let mut i = 1usize;
        while i < 21 {
            packed[i] = 0x11;
            i += 1;
        }
        packed[84] = 2; // dataLen word low byte
        packed[85] = 0xaa;
        packed[86] = 0xbb;
        // Record B header at 87: op 0, to = 0x22.., value 0, dataLen 0.
        let mut j = 88usize;
        while j < 108 {
            packed[j] = 0x22;
            j += 1;
        }

        let mut iter = MsRecordIter::new(&packed);
        match iter.next() {
            Some(Ok(r)) => {
                assert_eq!(r.operation, 0);
                assert_eq!(r.to, [0x11u8; 20]);
                assert!(r.value_is_zero());
                assert_eq!(r.data.len(), 2);
                assert_eq!(r.data[0], 0xaa);
                assert_eq!(r.data[1], 0xbb);
            }
            _ => panic!("record A must decode Ok"),
        }
        match iter.next() {
            Some(Ok(r)) => {
                assert_eq!(r.to, [0x22u8; 20]);
                assert_eq!(r.data.len(), 0);
            }
            _ => panic!("record B must decode Ok"),
        }
        // Exact tiling: nothing left after the two records.
        assert!(iter.next().is_none());
    }

    /// Non-vacuity (on-point negative control): one full 85-byte record
    /// followed by 10 trailing bytes — too few for another header — must be
    /// surfaced as `Err(TruncatedRecord)`, NOT silently dropped via `None`.
    /// This is exactly the "hidden trailing bytes the device never renders"
    /// threat that `record_walk_exact_tiling` forecloses.
    #[kani::proof]
    #[kani::unwind(40)]
    fn record_walk_rejects_trailing_partial() {
        let packed = [0u8; 95]; // 85-byte header (op 0, dataLen 0) + 10 trailing
        let mut iter = MsRecordIter::new(&packed);
        assert!(matches!(iter.next(), Some(Ok(_))));
        assert!(matches!(
            iter.next(),
            Some(Err(MsError::TruncatedRecord))
        ));
    }

    /// Non-vacuity (negative control): a lone header declaring `dataLen = 1`
    /// with no byte to back it must be refused (`TruncatedRecord`) rather than
    /// fabricating an out-of-bounds `data` slice.
    #[kani::proof]
    #[kani::unwind(40)]
    fn record_walk_rejects_data_overrun() {
        let mut packed = [0u8; 85];
        packed[84] = 1; // dataLen = 1, but the slice ends at the header
        let mut iter = MsRecordIter::new(&packed);
        assert!(matches!(
            iter.next(),
            Some(Err(MsError::TruncatedRecord))
        ));
    }
}
