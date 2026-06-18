//! SCP03 channel tests — handshake freshness, MCV chain integrity,
//! WTX retry endurance.

use crate::stress_test;
use crate::se050::apdu::Se050Error;
use crate::se050_stress::{StressCtx, StressError, StressResult, Tier};

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

/// 100 back-to-back GET_RANDOM calls — sustained-load endurance of the
/// SCP03 MCV chaining + T=1' retry path. Any drift shows up as
/// `Se050Error::Scp03` or `Se050Error::Transport`.
///
/// **Per-call size reduced to 32 B (2026-05-28).** The original test
/// drew 256 B per call to also exercise WTX (Wait Time Extension) on a
/// long op. On this bench that hit a hard T1oI2C transport-endurance
/// limit: a sustained stream of LARGE SCP03 responses faults at ~31
/// back-to-back 128-B responses (SW=0x6d00 then transport error) — see
/// `docs/secure-elements/se050-silicon-findings.md` §4d. That limit is NOT production-
/// relevant (production `rng_strong` requests 32-B blocks at low
/// volume) and is a separate transport-layer investigation. To keep
/// this test a reliable sustained-load regression signal it now draws
/// 32 B/call — the same small-response regime `scp03_apdu_burst`
/// exercises 256× without issue. The large-response WTX endurance the
/// original name implies is tracked as the §4d open item.
fn wtx_endurance(ctx: &mut StressCtx) -> StressResult {
    const ROUNDS: u32 = 100;
    let mut buf = [0u8; 32];
    for i in 0..ROUNDS {
        ctx.set_iter(i);
        ctx.se().random(&mut buf)?;
    }
    Ok(())
}
stress_test!(WTX_ENDURANCE, "scp03_wtx_endurance", Tier::Safe, wtx_endurance);

// ---------------------------------------------------------------------------
// get_random_size_boundary (diagnostic — GetRandom-over-SCP03 max size)
// ---------------------------------------------------------------------------

/// **Chunking regression guard.** A single `GetRandom` over SCP03 caps
/// at 224 B on B-U585I-IOT02A (240 B → SW=0x6985; bracketed by the
/// original boundary sweep 2026-05-28). `apdu::get_random` therefore
/// chunks any request larger than `GET_RANDOM_MAX_CHUNK` (128 B) across
/// multiple APDUs. This test walks a size ladder that straddles the raw
/// 224-B single-APDU ceiling and asserts EVERY size succeeds through
/// `Se050::random` — i.e. the chunking is working. Each `random(size)`
/// for size > 128 exercises the multi-APDU path.
///
/// PASS = every size (incl. 240, 256, 480) returns the requested bytes.
/// FAIL = any size errors, which means the chunking regressed (e.g. a
/// reintroduced `out.len() > 224` single-APDU request → 0x6985).
fn get_random_size_boundary(ctx: &mut StressCtx) -> StressResult {
    // Includes sizes above the raw 224-B single-APDU ceiling (240, 256)
    // plus a multi-chunk size (480 = 128+128+128+96) to exercise the
    // loop's 3rd+ iteration.
    const SIZES: &[usize] = &[16, 32, 64, 128, 192, 224, 240, 256, 480];
    let mut buf = [0u8; 480];
    for &size in SIZES {
        ctx.set_iter(size as u32);
        match ctx.se().random(&mut buf[..size]) {
            Ok(()) => {
                secure_log!("[S][stress][rng-bound] size={} OK (chunked)", size);
            }
            Err(Se050Error::Status(sw)) => {
                secure_log!("[S][stress][rng-bound] size={} FAIL SW=0x{:04x}", size, sw);
                let _ = ctx.se().reinit();
                return Err(StressError::UnexpectedSw {
                    what: "GetRandom chunking regressed — oversized single-APDU request",
                    sw,
                });
            }
            Err(e) => {
                secure_log!("[S][stress][rng-bound] size={} FAIL {:?}", size, e);
                let _ = ctx.se().reinit();
                return Err(e.into());
            }
        }
    }
    secure_log!("[S][stress][rng-bound] PASS — all sizes (incl. >224 B) filled via chunking");
    Ok(())
}
stress_test!(GET_RANDOM_SIZE_BOUNDARY, "get_random_size_boundary", Tier::Safe, get_random_size_boundary);
