//! SCP03 channel tests — handshake freshness, MCV chain integrity,
//! WTX retry endurance.

use crate::stress_test;
use crate::se050_stress::{StressCtx, StressResult, Tier};

// ---------------------------------------------------------------------------
// 1. scp03_handshake_repeat
// ---------------------------------------------------------------------------

/// Re-establish SCP03 N times in a row, asserting that the derived
/// session keys (`s_enc`) differ between every pair of iterations —
/// proves the host-challenge → KDF path is genuinely fresh on each
/// handshake. A bug that cached or reset the host nonce would produce
/// identical keys here and lead to silent replay vulnerabilities.
fn handshake_repeat(ctx: &mut StressCtx) -> StressResult {
    const ROUNDS: usize = 8;
    let mut prev_enc = [0u8; 16];
    let mut prev_set = false;

    for i in 0..ROUNDS {
        ctx.set_iter(i as u32);

        // Force a fresh handshake by reinit'ing the driver. The
        // runner already does this between tests, but we do it inside
        // the loop to make every iteration a clean re-establish.
        ctx.se().reinit()?;

        let snap = ctx.scp03_snapshot();
        let s_enc_now = snap.s_enc;
        let active = snap.active;

        if prev_set {
            ctx.assert_ne("s_enc must differ across handshakes", &s_enc_now, &prev_enc)?;
        }
        prev_enc = s_enc_now;
        prev_set = true;

        ctx.assert_true("SCP03 must be active after establish", active)?;
    }
    Ok(())
}
stress_test!(HANDSHAKE_REPEAT, "scp03_handshake_repeat", Tier::Safe, handshake_repeat);

// ---------------------------------------------------------------------------
// 2. scp03_apdu_burst
// ---------------------------------------------------------------------------

/// Issue 256 wrapped GET_RANDOM commands in one SCP03 session. Every
/// one updates the MAC chaining value; any drift between wrap and
/// unwrap would manifest as `Se050Error::Scp03` mid-burst. The chip
/// also enforces SCP03 counter limits per AN12413 — running well below
/// the 2^16 ceiling but high enough to exercise multi-block MCV
/// updates.
fn apdu_burst(ctx: &mut StressCtx) -> StressResult {
    const BURST: u32 = 256;
    let mut buf = [0u8; 16];
    for i in 0..BURST {
        ctx.set_iter(i);
        // 16 bytes per draw — exercises the TLV-length / Le coding
        // boundary on every iteration without burning excessive time.
        ctx.se().random(&mut buf)?;
    }
    Ok(())
}
stress_test!(APDU_BURST, "scp03_apdu_burst", Tier::Safe, apdu_burst);

// ---------------------------------------------------------------------------
// 5. scp03_wtx_endurance
// ---------------------------------------------------------------------------

/// 100 back-to-back GET_RANDOM 256-byte calls. SE050 routinely
/// requests WTX (Wait Time Extension) for any long-running op; the
/// T=1' layer retries up to `MAX_WTX_RETRIES = 500`. This test
/// confirms we don't false-timeout near that ceiling under sustained
/// load. Any failure mode shows up as `Se050Error::Transport` (T=1'
/// gave up).
fn wtx_endurance(ctx: &mut StressCtx) -> StressResult {
    const ROUNDS: u32 = 100;
    let mut buf = [0u8; 256];
    for i in 0..ROUNDS {
        ctx.set_iter(i);
        ctx.se().random(&mut buf)?;
    }
    Ok(())
}
stress_test!(WTX_ENDURANCE, "scp03_wtx_endurance", Tier::Safe, wtx_endurance);
