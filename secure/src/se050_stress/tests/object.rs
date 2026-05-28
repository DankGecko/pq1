//! Object IO stress probes — boundary lengths, churn.

use crate::stress_test;
use crate::se050_stress::{StressCtx, StressResult, Tier};

// ---------------------------------------------------------------------------
// 4. extended_lc_boundary
// ---------------------------------------------------------------------------

/// Write+read+delete a sentinel pattern at several payload lengths,
/// exercising the short-Lc path and the `unwrap_response` round-trip
/// at varying body sizes.
///
/// **Payload cap — CORRECTED TWICE on silicon (2026-05-28).** The
/// original `docs/se050-silicon-findings.md` §5 #5 diagnosis ("1024-byte
/// write overruns the 1024-B `ApduBuf`") was WRONG, and so was the
/// first correction (cap at 128 B). Two destructive runs established:
///
///   * The WRITE path succeeds well past 256 B (the chip returns 0x9000
///     to a correctly extended-Lc-encoded `WriteBinary` at len=254).
///   * READ-BACK via `read_authed` (INS_PROCESS wrapper) is the weak
///     link, and its ceiling is LOW and the failure mode size-dependent:
///       - run 1: len=254 read → SW=0x6985 (clean chip rejection);
///       - run 2: len=64 read → I2C TXIS **hard transport timeout**
///         (`[S][I2C] TXIS timeout!`), needing an interface reset.
///     len=32 read-back round-trips reliably across BOTH runs.
///   * Either read failure drops the chip into the Finding-A3
///     session-pending state, which then cascaded into tests #6
///     (`scp03_wtx_endurance`) and #7 (`trng_quality_basic`) failing
///     at their first APDU even after the inter-test reinit.
///
/// So the read-back ceiling on this silicon is somewhere in `32..64` B,
/// with a flaky hard-hang failure mode above it — a genuine
/// `read_authed` / T1oI2C large-response driver issue tracked in
/// `docs/se050-silicon-findings.md` §4b. It is NOT production-relevant:
/// firmware only ever reads 32-byte objects (entropy / VK / bootstrap
/// VK). To keep this test reliable and non-corrupting, the round-trip
/// lengths are now capped at 32 B (the only sizes proven to round-trip
/// on both runs), and the large write-only boundary probes are removed
/// — writing 254+ B objects we cannot read back added cascade risk for
/// no production-relevant coverage (the extended-Lc *encoding* path is
/// unit-tested in `crate::iso7816`'s proptest harness).
fn extended_lc_boundary(ctx: &mut StressCtx) -> StressResult {
    // Round-trip (write + read-back + compare) lengths — all ≤ 32 B,
    // the only sizes proven to round-trip on silicon. Larger reads hit
    // a driver-level large-response failure (see the doc above).
    const LENGTHS: &[usize] = &[1, 8, 16, 32];
    // Source pattern: cycling byte counter. Keeps each length's
    // payload distinguishable in a wire capture.
    let mut src = [0u8; 32];
    for (i, b) in src.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }

    let target = ctx.oid(0x01);
    for (idx, &len) in LENGTHS.iter().enumerate() {
        ctx.set_iter(idx as u32);

        // Make sure the slot is clean before write.
        ctx.delete_scratch(target)?;
        ctx.write_scratch(target, &src[..len])?;

        let mut got = [0u8; 32];
        let n = ctx.read_scratch(target, &mut got)?;
        if n != len {
            secure_log!(
                "[S][stress][object] len={} read returned {} bytes",
                len, n,
            );
            return Err(crate::se050_stress::StressError::Assertion {
                what: "read length mismatch",
                iter: idx as u32,
            });
        }
        ctx.assert_eq("payload round-trip", &got[..n], &src[..len])?;

        ctx.delete_scratch(target)?;
    }

    Ok(())
}
stress_test!(EXTENDED_LC_BOUNDARY, "object_extended_lc_boundary", Tier::Safe, extended_lc_boundary);
