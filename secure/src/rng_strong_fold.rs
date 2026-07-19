//! Pure per-chunk SE-entropy fold for [`crate::rng_strong`].
//!
//! Split out of `rng_strong.rs` because that module is
//! `#[cfg(not(test))]` (it calls the hardware `crate::rng` /
//! `crate::se_random`), while this fold is pure logic the host test
//! suite can — and must — exercise directly (finding F27).

use zeroize::Zeroize;

/// XOR-fold SE randomness into `buf`, one ≤32-byte chunk at a time
/// (step 2 of `rng_strong::fill`). Generic over the SE draw so host
/// tests can drive the fold with scripted streams; `se_draw` is
/// invoked once per chunk and must return `true` when the SE
/// contributed.
///
/// Finding F27: the block is zeroed before EVERY draw because SE
/// backends XOR into the caller's buffer instead of overwriting it
/// (`DualSecureElement::random`). Reusing the previous chunk's block
/// would fold chunk N's `OPTIGA ⊕ SE050` bytes into chunk N+1, so a
/// repeat-stream fault on both SE TRNGs would silently cancel the SE
/// contribution for the tail — 3-source degrading to platform-only
/// with no alarm (the all-zero gate still passes on the STM32 bytes).
///
/// Returns `false` at the first failed draw; `block` is zeroed on
/// every exit path.
pub(crate) fn fold_se_blocks(buf: &mut [u8], mut se_draw: impl FnMut(&mut [u8]) -> bool) -> bool {
    let mut block = [0u8; 32];
    let mut off = 0;
    let mut all_ok = true;
    while off < buf.len() {
        let len = (buf.len() - off).min(block.len());
        // F27: fresh, zeroed block for THIS chunk (see fn doc).
        block[..len].fill(0);
        // SAFETY (hardware builds): the caller (sign path) has unlocked
        // the SE, so the global SE handle behind `se_draw` is
        // initialised.
        if !se_draw(&mut block[..len]) {
            all_ok = false;
            break;
        }
        for i in 0..len {
            buf[off + i] ^= block[i];
        }
        off += len;
    }
    block.zeroize();
    all_ok
}

#[cfg(test)]
mod tests {
    use super::fold_se_blocks;

    /// F27 regression: each chunk of a multi-chunk fill must fold its
    /// OWN fresh SE block. The scripted draw mimics
    /// `DualSecureElement::random`'s XOR-into-caller semantics; if the
    /// fold reused the previous chunk's block (the F27 bug), the tail
    /// would silently re-fold chunk 1's stream.
    #[test]
    fn fold_se_blocks_each_chunk_folds_fresh_block_only() {
        // Two scripted SE streams: chunk 1 (32 B) and chunk 2 (16 B).
        let s1 = [0xA5u8; 32];
        let s2 = [0x5Au8; 16];
        let mut chunks = [&s1[..], &s2[..]].into_iter();
        let mut draw = |block: &mut [u8]| {
            let s = chunks.next().expect("exactly one draw per chunk");
            assert_eq!(s.len(), block.len());
            // XOR semantics, exactly like the SE backend.
            for i in 0..block.len() {
                block[i] ^= s[i];
            }
            true
        };

        // 48-byte request → two chunks (32 + 16).
        let platform = [0x11u8; 48];
        let mut buf = platform;
        assert!(fold_se_blocks(&mut buf, &mut draw));

        let mut expected = platform;
        for i in 0..32 {
            expected[i] ^= s1[i];
        }
        for i in 0..16 {
            expected[32 + i] ^= s2[i];
        }
        assert_eq!(buf, expected);
        // The explicit F27 violation shape: the tail must NOT carry
        // chunk 1's stream folded in alongside chunk 2's.
        for i in 0..16 {
            assert_ne!(buf[32 + i], platform[32 + i] ^ s1[i] ^ s2[i]);
        }
    }

    /// A failed draw aborts the fold immediately (production treats an
    /// absent SE contribution as fatal) without touching the buffer.
    #[test]
    fn fold_se_blocks_stops_at_first_failed_draw() {
        let mut calls = 0usize;
        let mut buf = [0x11u8; 48];
        let ok = fold_se_blocks(&mut buf, &mut |_block: &mut [u8]| {
            calls += 1;
            false
        });
        assert!(!ok);
        assert_eq!(calls, 1);
        assert_eq!(buf, [0x11u8; 48]);
    }

    /// Chunk boundaries: a 32-byte request folds exactly one block; an
    /// empty buffer performs no draw at all.
    #[test]
    fn fold_se_blocks_chunk_boundaries() {
        let mut calls = 0usize;
        let mut buf = [0u8; 32];
        assert!(fold_se_blocks(&mut buf, &mut |block: &mut [u8]| {
            calls += 1;
            assert_eq!(block.len(), 32);
            true
        }));
        assert_eq!(calls, 1);

        let mut empty = [0u8; 0];
        assert!(fold_se_blocks(&mut empty, &mut |_block: &mut [u8]| {
            calls += 1;
            true
        }));
        assert_eq!(calls, 1, "empty buffer must not draw");
    }
}
