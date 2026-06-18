//! SE050 TRNG quality probes.

use crate::stress_test;
use crate::se050_stress::{StressCtx, StressError, StressResult, Tier};

// ---------------------------------------------------------------------------
// 6. trng_quality_basic
// ---------------------------------------------------------------------------

/// Draw 4096 bytes from the SE050 TRNG and apply two cheap-but-load-
/// bearing sanity checks:
///
/// 1. **Block degeneracy.** Slice the buffer into 64-byte blocks (64
///    blocks total). Reject if any block is all-`0x00` or all-`0xFF`.
///    These signal a stuck output stage.
/// 2. **Byte histogram χ².** Bin all 4096 bytes into 256 buckets (16
///    expected each, uniform). Compute χ² = Σ (obs - 16)² / 16 and
///    require χ² ≤ 330. For 255 degrees of freedom the 99.99%-tail
///    cutoff is ~331, so a healthy TRNG essentially never trips this;
///    a stuck-LFSR / constant-bias output trips it with overwhelming
///    probability.
///
/// This is not a cryptographic certification — it's a smoke detector
/// for "the TRNG fell off the bus" failure modes.
fn quality_basic(ctx: &mut StressCtx) -> StressResult {
    const TOTAL: usize = 4096;
    const BLOCK: usize = 64;
    let mut buf = [0u8; TOTAL];

    // Draw in SMALL (32-byte) per-call requests. The SE050 TRNG over
    // SCP03 accepts up to 224 B per `GetRandom` APDU (see
    // `apdu::GET_RANDOM_MAX_CHUNK` + `get_random_size_boundary`), but a
    // sustained stream of LARGE responses (≥~128 B) exhausts a T1oI2C
    // transport limit on this bench (~31 back-to-back 128-B responses →
    // SW=0x6d00 / transport fault; `docs/secure-elements/se050-silicon-findings.md`
    // §4d). Small responses are robust — `scp03_apdu_burst` does 256
    // sustained 16-B draws without issue, and production `rng_strong`
    // only ever requests 32-B blocks. So this χ² sample is gathered in
    // 32-B draws: production-representative AND inside the robust regime.
    let mut filled = 0usize;
    let mut chunk_idx = 0u32;
    while filled < TOTAL {
        ctx.set_iter(chunk_idx);
        let take = (TOTAL - filled).min(32);
        ctx.se().random(&mut buf[filled..filled + take])?;
        filled += take;
        chunk_idx += 1;
    }

    // Check 1: block degeneracy.
    for (idx, block) in buf.chunks(BLOCK).enumerate() {
        let all_zero = block.iter().all(|&b| b == 0x00);
        let all_one  = block.iter().all(|&b| b == 0xFF);
        if all_zero || all_one {
            secure_log!(
                "[S][stress][trng] degenerate block at offset {} (zero={} one={})",
                idx * BLOCK, all_zero, all_one,
            );
            return Err(StressError::Assertion {
                what: "TRNG block degeneracy",
                iter: idx as u32,
            });
        }
    }

    // Check 2: byte histogram χ².
    let mut hist = [0u32; 256];
    for &b in buf.iter() {
        hist[b as usize] += 1;
    }
    // Expected count per bucket: TOTAL / 256 = 16.
    let expected: i64 = (TOTAL / 256) as i64;
    let mut chi2_numer: u64 = 0;
    for &obs in hist.iter() {
        let d = obs as i64 - expected;
        chi2_numer += (d * d) as u64;
    }
    // χ² = sum / expected. Multiply by 100 to keep one decimal of
    // precision in an integer comparison: threshold becomes 33000.
    let chi2_x100 = chi2_numer * 100 / (expected as u64);
    secure_log!(
        "[S][stress][trng] χ²×100 = {} over 256 buckets (threshold 33000)",
        chi2_x100,
    );
    if chi2_x100 > 33_000 {
        return Err(StressError::Assertion {
            what: "TRNG χ² exceeds threshold",
            iter: 0,
        });
    }

    Ok(())
}
stress_test!(QUALITY_BASIC, "trng_quality_basic", Tier::Safe, quality_basic);
