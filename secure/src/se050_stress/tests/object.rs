//! Object IO stress probes — boundary lengths, churn.

use crate::stress_test;
use crate::se050_stress::{StressCtx, StressResult, Tier};

// ---------------------------------------------------------------------------
// 4. extended_lc_boundary
// ---------------------------------------------------------------------------

/// Write+read+delete a sentinel pattern at several payload lengths
/// that straddle the SCP03 extended-Lc threshold. The `wrap_apdu` /
/// `send_apdu` path in `secure/src/se050/apdu.rs` handles short-Lc
/// (1-byte) and extended-Lc (0x00 + 2-byte) commands separately;
/// length-encoding off-by-ones bite at the 255↔256-byte boundary.
///
/// Also exercises the round-trip through `unwrap_response` at varying
/// body sizes — a subtle bug in AES-CBC padding or R-MAC offset
/// computation would surface here as a length mismatch or
/// `Se050Error::Scp03`.
///
/// **Max payload cap (2026-05-28).** `ApduBuf` is `MAX_APDU = 1024` B
/// total. `write_binary_gated` consumes ~34 B of header / fixed TLVs
/// (4 B APDU header, 3 B extended-Lc reserve, 20 B TAG_POLICY, 6 B
/// TAG_1 obj_id, 4 B TAG_3 file_len) plus 4 B of TAG_4 long-form
/// length encoding once data ≥ 256 — leaving ~983 B for the payload
/// itself. The first silicon stress run had `1024` here, which
/// overran the buffer and silently corrupted the SCP03 state
/// (`docs/se050-silicon-findings.md` §5 #5; chained failures cascaded
/// into #6 and #7). 960 B leaves a comfortable margin and still
/// exercises the >>256 extended-length encoding paths.
fn extended_lc_boundary(ctx: &mut StressCtx) -> StressResult {
    // Lengths that straddle the short/extended-Lc boundary. Largest
    // value kept ≤ 960 B per the cap above.
    const LENGTHS: &[usize] = &[1, 8, 32, 254, 255, 256, 257, 512, 960];
    // Source pattern: cycling byte counter. Keeps each length's
    // payload distinguishable in a wire capture.
    let mut src = [0u8; 960];
    for (i, b) in src.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }

    let target = ctx.oid(0x01);
    for (idx, &len) in LENGTHS.iter().enumerate() {
        ctx.set_iter(idx as u32);

        // Make sure the slot is clean before write.
        ctx.delete_scratch(target)?;
        ctx.write_scratch(target, &src[..len])?;

        let mut got = [0u8; 960];
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
