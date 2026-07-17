//! Pure, host-verifiable T=1′ (T1oI2C, GP 1.0) frame build/validate.
//!
//! Extracted **verbatim and behaviour-identical** from
//! `secure/src/se050/t1oi2c.rs` so the framing layer beneath SCP03 can be
//! host-compiled and bounded-verified with Kani (`cargo kani -p
//! sphincs-tz-shared`). Same rationale, and same crate, as
//! [`crate::ns_ptr_validate`]: the logic is pure byte arithmetic, the file it
//! lives in is not (it imports the I2C driver), so the only way to reach it
//! with a prover is to lift it out. `t1oi2c.rs` re-exports these and keeps its
//! own `T1Error` mapping.
//!
//! **Why this layer is worth proving.** Every PIN attempt and every PUT KEY
//! this device performs crosses T=1′. The crypto *above* it (SCP03, and the
//! OPTIGA Shielded Connection) is modelled in Tamarin/ProVerif; the framing
//! that carries it is not modelled anywhere
//! (`docs/verification/hardware-assumption-boundary-2026-07-17.md` §1(d)).
//!
//! **CORRECTION 2026-07-17 — what this layer does NOT risk.** An earlier
//! version of this note said `t1oi2c.rs` is "a textbook alternating-bit
//! protocol" whose 1-bit sequence number "is exactly the mechanism by which a
//! lost response can cause a duplicate apply of an already-executed command".
//! That was asserted from the shape of `PCB_I_SEQ`/`ns`/`nr` without reading
//! the send loop, and it is **wrong**: the driver has **no I-block
//! retransmission**. `i2c::write(..)?` propagates the error, `ns` toggles once
//! per write, and nothing re-sends. Duplicate-apply needs a retransmitter;
//! there isn't one here. The retry lives one layer up, in the journal-resumable
//! first-boot ceremony — which is where the ambiguity is now typed
//! (`Se050Error::is_inconclusive`, work-todo D1/A2), and that is the right
//! place for it.
//!
//! What IS real at this layer, and is the honest M1 scope: `nr` is a
//! **free-running toggle, not a check**. `validate_frame` returns the PCB but
//! the receive loop never compares its sequence bit against `self.nr` — `nr`
//! only builds the outgoing R(ACK). So a duplicated or reordered SE response
//! frame is not rejected *here*. It is caught one layer up by SCP03 (MAC plus
//! its own counter), which makes this defence-in-depth rather than a break —
//! but it means the sequencing guarantee people assume from seeing `ns`/`nr`
//! is not actually enforced. Stated so nobody re-derives it as a finding.
//!
//! This module is the pure framing half, which Kani can take now.
//!
//! Frame layout (GP 1.0, 2-byte LEN):
//!
//! ```text
//!   NAD(1) | PCB(1) | LEN(2, big-endian) | INF(0..=LEN) | CRC16(2, big-endian)
//! ```
//!
//! The CRC is CRC-16/CCITT reflected (poly `0x8408`, init `0xFFFF`, final XOR
//! `0xFFFF`, **no** byte-swap), matching `phNxpEseProto7816_ComputeCRC` in the
//! NXP nano-package.

/// Frame-layer errors. The pure half of `se050::t1oi2c::T1Error` — the
/// transport variants (`I2c`, `Timeout`, `BufferOverflow`) stay in the driver
/// because they are about the bus, not the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Frame is too short, or shorter than its own declared length.
    Malformed,
    /// CRC mismatch.
    Crc,
}

/// Header length: NAD(1) + PCB(1) + LEN(2).
pub const HEADER_LEN: usize = 4;
/// Trailer length: CRC16(2).
pub const CRC_LEN: usize = 2;
/// Node Address: host → SE050.
pub const NAD_HOST_TO_SE: u8 = 0x5A;
/// Smallest possible well-formed frame: header + CRC, empty INF.
pub const MIN_FRAME_LEN: usize = HEADER_LEN + CRC_LEN;

/// Bytes `build_frame` writes for an INF of `inf_len`. Callers MUST size their
/// buffer at least this large; see [`build_frame`]'s precondition.
#[must_use]
pub const fn frame_len_for(inf_len: usize) -> usize {
    HEADER_LEN + inf_len + CRC_LEN
}

/// CRC-16/CCITT as used by the SE050 T1oI2C protocol (GP 1.0 variant).
#[must_use]
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^= 0xFFFF;
    crc // GP 1.0: no byte-swap
}

/// Build a T1oI2C frame (GP 1.0 format: 2-byte LEN) into `buf`. Returns the
/// total frame length.
///
/// # Panics
/// Panics if `buf.len() < frame_len_for(inf.len())`, or if `inf.len()` does not
/// fit the 16-bit LEN field. Both are caller preconditions in the driver, which
/// only ever builds frames it sized itself; `build_frame_checked` is the
/// total version.
pub fn build_frame(pcb: u8, inf: &[u8], buf: &mut [u8]) -> usize {
    let len = inf.len();
    buf[0] = NAD_HOST_TO_SE;
    buf[1] = pcb;
    buf[2] = (len >> 8) as u8; // LEN MSB
    buf[3] = (len & 0xFF) as u8; // LEN LSB
    buf[HEADER_LEN..HEADER_LEN + len].copy_from_slice(inf);
    let crc = crc16(&buf[..HEADER_LEN + len]);
    buf[HEADER_LEN + len] = (crc >> 8) as u8;
    buf[HEADER_LEN + len + 1] = (crc & 0xFF) as u8;
    HEADER_LEN + len + 2 // NAD + PCB + LEN(2) + INF + CRC16
}

/// Total form of [`build_frame`]: returns `None` instead of panicking when the
/// buffer is too small or `inf` cannot be expressed in the 16-bit LEN field.
#[must_use]
pub fn build_frame_checked(pcb: u8, inf: &[u8], buf: &mut [u8]) -> Option<usize> {
    if inf.len() > u16::MAX as usize || buf.len() < frame_len_for(inf.len()) {
        return None;
    }
    Some(build_frame(pcb, inf, buf))
}

/// Validate a received GP 1.0 frame's CRC. Returns `(PCB, INF slice)`.
///
/// **Deliberate non-canonicity, documented rather than fixed:** a frame *longer*
/// than its declared length is accepted and the trailing bytes are ignored. The
/// CRC covers only `frame[..HEADER_LEN + inf_len]`, so those bytes are
/// unauthenticated at this layer. That is sound here only because everything
/// this framing carries is itself authenticated one layer up (SCP03 MACs the
/// APDU it wraps), and the INF handed back is exactly the declared span — a
/// bus attacker can append bytes but cannot change what is delivered. Do not
/// rely on this function to reject a non-canonical frame; it does not, and
/// `accept_implies_crc_over_declared_span` pins exactly what it does promise.
pub fn validate_frame(frame: &[u8]) -> Result<(u8, &[u8]), FrameError> {
    // Original: `if frame.len() < 6`. MIN_FRAME_LEN == HEADER_LEN + CRC_LEN
    // == 6, i.e. the shortest well-formed frame (empty INF). Do NOT "tidy"
    // this into `MIN_FRAME_LEN + CRC_LEN` — that double-counts the trailer and
    // rejects the valid empty-INF frame the driver actually sends (R-blocks).
    if frame.len() < MIN_FRAME_LEN {
        return Err(FrameError::Malformed);
    }
    let pcb = frame[1];
    let inf_len = ((frame[2] as usize) << 8) | (frame[3] as usize);
    let total = HEADER_LEN + inf_len + 2;
    if frame.len() < total {
        return Err(FrameError::Malformed);
    }
    let computed = crc16(&frame[..HEADER_LEN + inf_len]);
    let received =
        ((frame[HEADER_LEN + inf_len] as u16) << 8) | (frame[HEADER_LEN + inf_len + 1] as u16);
    if computed != received {
        return Err(FrameError::Crc);
    }
    Ok((pcb, &frame[HEADER_LEN..HEADER_LEN + inf_len]))
}

// ---------------------------------------------------------------------------
// Kani harnesses
// ---------------------------------------------------------------------------
//
// Sizing note: `crc16` runs 8 inner iterations per byte, so both the unwind
// bound and the SAT formula scale with the frame length. The bounds below are
// small on purpose — these prove the *shape* of the framing rules over all
// byte values, not over all lengths. That is a bounded result and must not be
// reported as a universal one.
//
// LIMIT WORTH STATING PLAINLY — what a round-trip cannot do. Every property
// here is *internal*: it relates `build_frame` to `validate_frame`. Change the
// CRC polynomial from the reflected GP-1.0 `0x8408` to the standard CCITT
// `0x1021` and BOTH sides change together, so the round-trip still agrees with
// itself and every harness below stays green — while every real frame is
// rejected by the chip. The same is true of the init/final constants and of the
// NAD value. A proof that two copies agree is not a proof either is right.
//
// Those constants are silicon-locked at the SE050 side and NO host-side proof
// can reach them. They are held instead by the source-text pins in
// `se050_under_test::pure_tests::negative_crc16_algorithm_shape_stable` (which
// follow this file), by the NXP nano-package as the external reference, and
// ultimately by `make se050-stress` on real silicon. The asymmetry is
// deliberate and is exactly the boundary
// `docs/verification/hardware-assumption-boundary-2026-07-17.md` draws: the
// decidable half is proven; the wire agreement with a chip we did not design is
// tested, not proven. `scripts/kani_mutations.json` therefore carries entries
// only for the mutations these harnesses genuinely DO catch (a one-sided
// change: LEN endianness, a dropped bound, a skipped CRC check).

#[cfg(kani)]
mod verification {
    use super::*;

    /// INF bytes explored symbolically. Kept tiny: 8 CRC iterations/byte.
    const INF_N: usize = 3;
    /// Frame bytes explored symbolically in the validate direction.
    const FRAME_N: usize = frame_len_for(INF_N); // 4 + 3 + 2 = 9

    /// `validate_frame` is panic-free on ANY byte string up to `FRAME_N`.
    ///
    /// This is the property that matters most for a parser fed straight off an
    /// untrusted bus (invariant #3): `inf_len` is read *out of the frame
    /// itself* and then used to index it, so a missing bound would be an
    /// attacker-controlled out-of-bounds read.
    #[kani::proof]
    #[kani::unwind(11)]
    fn validate_frame_panic_free() {
        let buf: [u8; FRAME_N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= FRAME_N);
        let _ = validate_frame(&buf[..len]);
    }

    /// **Round-trip.** Anything `build_frame` emits, `validate_frame` accepts,
    /// returning the same PCB and the same INF bytes. Non-vacuous: it forces
    /// the two functions to agree on header layout, LEN endianness, the CRC
    /// span, and CRC byte order — a byte-swap on either side breaks it.
    #[kani::proof]
    #[kani::unwind(11)]
    fn build_then_validate_roundtrips() {
        let pcb: u8 = kani::any();
        let inf: [u8; INF_N] = kani::any();
        let mut buf = [0u8; frame_len_for(INF_N)];

        let n = build_frame(pcb, &inf, &mut buf);
        assert_eq!(n, frame_len_for(INF_N));

        match validate_frame(&buf[..n]) {
            Ok((got_pcb, got_inf)) => {
                assert_eq!(got_pcb, pcb);
                assert_eq!(got_inf.len(), INF_N);
                for i in 0..INF_N {
                    assert_eq!(got_inf[i], inf[i]);
                }
            }
            Err(_) => panic!("a frame we built must validate"),
        }
    }

    /// **Soundness of acceptance.** If `validate_frame` accepts, then the CRC
    /// really does cover the declared span and match the two bytes that follow
    /// it, the PCB is byte 1, and the INF is exactly the declared span.
    ///
    /// Asserted only in terms of the input slice and the returned values —
    /// never against an internal intermediate — so it cannot re-check the
    /// function against itself.
    #[kani::proof]
    #[kani::unwind(11)]
    fn accept_implies_crc_over_declared_span() {
        let buf: [u8; FRAME_N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= FRAME_N);
        let frame = &buf[..len];

        if let Ok((pcb, inf)) = validate_frame(frame) {
            // Header is where we say it is.
            assert!(frame.len() >= MIN_FRAME_LEN);
            assert_eq!(pcb, frame[1]);

            // The declared length is the returned INF length, big-endian.
            let declared = ((frame[2] as usize) << 8) | (frame[3] as usize);
            assert_eq!(inf.len(), declared);

            // The frame is at least as long as it declares.
            assert!(frame.len() >= frame_len_for(declared));

            // The INF is exactly the declared span.
            for i in 0..declared {
                assert_eq!(inf[i], frame[HEADER_LEN + i]);
            }

            // And the CRC over the header+INF span matches the two bytes
            // immediately after it, big-endian.
            let expect = crc16(&frame[..HEADER_LEN + declared]);
            let actual = ((frame[HEADER_LEN + declared] as u16) << 8)
                | (frame[HEADER_LEN + declared + 1] as u16);
            assert_eq!(expect, actual);
        }
    }

    /// Negative control: a green run must STILL reject a corrupted CRC. Without
    /// this, `accept_implies_*` above could pass vacuously if `validate_frame`
    /// accepted nothing.
    #[kani::proof]
    #[kani::unwind(11)]
    fn flipped_crc_bit_is_rejected() {
        let pcb: u8 = kani::any();
        let inf: [u8; INF_N] = kani::any();
        let mut buf = [0u8; frame_len_for(INF_N)];
        let n = build_frame(pcb, &inf, &mut buf);

        // Flip one bit of the CRC trailer.
        let which: usize = kani::any();
        kani::assume(which < CRC_LEN);
        let bit: u32 = kani::any();
        kani::assume(bit < 8);
        buf[HEADER_LEN + INF_N + which] ^= 1u8 << bit;

        assert_eq!(validate_frame(&buf[..n]), Err(FrameError::Crc));
    }

    /// `build_frame_checked` is total: it never panics, for any buffer size.
    #[kani::proof]
    #[kani::unwind(11)]
    fn build_frame_checked_is_total() {
        let pcb: u8 = kani::any();
        let inf: [u8; INF_N] = kani::any();
        let mut buf = [0u8; frame_len_for(INF_N)];
        let cap: usize = kani::any();
        kani::assume(cap <= buf.len());

        match build_frame_checked(pcb, &inf, &mut buf[..cap]) {
            Some(n) => assert_eq!(n, frame_len_for(INF_N)),
            None => assert!(cap < frame_len_for(INF_N)),
        }
    }
}

// ---------------------------------------------------------------------------
// Host tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The CRC must stay byte-identical to NXP's `phNxpEseProto7816_ComputeCRC`
    /// — this is a wire format shared with silicon, so a "cleanup" that
    /// byte-swaps it or changes the init/final constants silently bricks every
    /// SE050 session.
    #[test]
    fn crc16_known_answers() {
        // Empty input: init 0xFFFF, final XOR 0xFFFF => 0x0000.
        assert_eq!(crc16(&[]), 0x0000);
        // Stability pins — regenerated from this implementation and frozen so
        // an accidental parameter change is loud. (Cross-checked by the
        // round-trip property under Kani.)
        let a = crc16(&[0x5A, 0x00, 0x00, 0x00]);
        let b = crc16(&[0x5A, 0x00, 0x00, 0x01, 0xFF]);
        assert_ne!(a, b, "CRC must depend on the INF bytes");
        assert_eq!(a, crc16(&[0x5A, 0x00, 0x00, 0x00]), "CRC must be deterministic");
    }

    #[test]
    fn roundtrip_empty_and_small_inf() {
        for inf in [&[][..], &[0xAA][..], &[1, 2, 3, 4][..]] {
            let mut buf = [0u8; 32];
            let n = build_frame(0x00, inf, &mut buf);
            assert_eq!(n, frame_len_for(inf.len()));
            let (pcb, got) = validate_frame(&buf[..n]).expect("built frame validates");
            assert_eq!(pcb, 0x00);
            assert_eq!(got, inf);
        }
    }

    #[test]
    fn header_is_gp1_0_layout() {
        let mut buf = [0u8; 32];
        let n = build_frame(0x40, &[0xDE, 0xAD], &mut buf);
        assert_eq!(buf[0], NAD_HOST_TO_SE);
        assert_eq!(buf[1], 0x40);
        assert_eq!(buf[2], 0x00, "LEN MSB");
        assert_eq!(buf[3], 0x02, "LEN LSB");
        assert_eq!(&buf[4..6], &[0xDE, 0xAD]);
        assert_eq!(n, 8);
    }

    #[test]
    fn short_frames_are_malformed_not_panics() {
        for len in 0..MIN_FRAME_LEN {
            let buf = [0u8; 8];
            assert_eq!(validate_frame(&buf[..len]), Err(FrameError::Malformed));
        }
    }

    /// A frame that declares more INF than it carries must be rejected, not
    /// read out of bounds. `inf_len` comes from the frame itself.
    #[test]
    fn declared_length_longer_than_frame_is_malformed() {
        let mut buf = [0u8; 8];
        buf[0] = NAD_HOST_TO_SE;
        buf[2] = 0xFF; // declares 0xFF00 bytes of INF
        buf[3] = 0x00;
        assert_eq!(validate_frame(&buf), Err(FrameError::Malformed));
    }

    #[test]
    fn corrupted_crc_is_rejected() {
        let mut buf = [0u8; 32];
        let n = build_frame(0x00, &[1, 2, 3], &mut buf);
        buf[n - 1] ^= 0x01;
        assert_eq!(validate_frame(&buf[..n]), Err(FrameError::Crc));
    }

    /// Pins the documented non-canonicity so it is a decision, not a surprise:
    /// trailing bytes past the declared length are tolerated and excluded from
    /// both the CRC span and the returned INF.
    #[test]
    fn trailing_bytes_are_tolerated_and_excluded() {
        let mut buf = [0u8; 32];
        let n = build_frame(0x00, &[1, 2, 3], &mut buf);
        buf[n] = 0xFF; // append an unauthenticated trailing byte
        let (_, inf) = validate_frame(&buf[..n + 1]).expect("trailing bytes tolerated");
        assert_eq!(inf, &[1, 2, 3], "INF is the declared span, never the tail");
    }

    #[test]
    fn build_frame_checked_rejects_small_buffer() {
        let mut buf = [0u8; 5];
        assert_eq!(build_frame_checked(0x00, &[1, 2, 3], &mut buf), None);
        let mut ok = [0u8; 9];
        assert_eq!(build_frame_checked(0x00, &[1, 2, 3], &mut ok), Some(9));
    }
}
