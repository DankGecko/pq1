//! PQ-Signer SCA red-team harness: Welch's T-test (TVLA) + CPA over
//! rainbow-emulated `mem_address` Hamming-weight traces.
//!
//! Built for the PQSigner_OS `tools/sca` pipeline. The rainbow harness
//! (`leakage_kdf.collect` / `f9_*`) produces an in-RAM uint8 trace tensor
//! of shape `[n_traces, n_samples]` where each sample is the Hamming weight
//! (0..=32) of a memory-access ADDRESS. `f9_collect_for_scared.py` serialises
//! it to `out/f9_traces.npz` with arrays {samples,is_fixed,msg,...}.
//!
//! muscat's `ndarray-npy` reader consumes plain `.npy` (not `.npz`), so feed it
//! three `.npy` files unpacked from the `.npz` (see `npz_to_npy.py` shipped
//! alongside this example, or any `np.save`):
//!
//!   traces.npy      uint8   [n, samples]   the `samples` array (HW of mem addr)
//!   classes.npy     bool    [n]            the `is_fixed` flag per trace (TVLA)
//!   plaintexts.npy  uint8   [n, k]         the public input bytes (`msg`) for CPA
//!
//! Run:
//!   TRACES_DIR=/path/to/dir cargo run --release --example pqsigner_tvla_cpa
//!
//! Optional env:
//!   CPA_TARGET_BYTE  (default 0)   which column of plaintexts.npy CPA attacks
//!   T_THRESHOLD      (default 4.5) TVLA leakage verdict threshold
//!   BATCH_SIZE       (default 200) trace batch size for the parallel reducers
//!
//! Both passes run directly on the uint8 trace samples — NO ChipWhisperer
//! float→u16 conversion (that path in `examples/cpa.rs` is for analog scope
//! captures; these are already integer Hamming-weight samples).

use anyhow::{Context, Result};
use muscat::distinguishers::cpa::cpa;
use muscat::leakage_detection::ttest;
use muscat::leakage_model::aes::sbox;
use ndarray::{Array1, Array2};
use ndarray_npy::read_npy;
use std::{env, path::PathBuf};

/// Hamming weight of a byte (the leakage model for the `mem_address` channel:
/// the HW of the loaded byte / address-low nibble is the natural model for an
/// 8-bit-bus secret-indexed table access, mirroring `leakage_kdf.cpa_leaky`).
fn hw(x: usize) -> usize {
    (x as u8).count_ones() as usize
}

/// CPA leakage model: HW( SBOX[ plaintext_byte ^ key_guess ] ).
/// This is the standard first-round-AES model and the `mem_address` analogue
/// the PQ-Signer leaky-S-box positive control (`sca_leaky_sbox`) is built to
/// exercise — swap in any byte-indexed model for a different target.
fn leakage_model(plaintext_byte: usize, guess: usize) -> usize {
    hw(sbox((plaintext_byte ^ guess) as u8) as usize)
}

fn main() -> Result<()> {
    let dir = PathBuf::from(
        env::var("TRACES_DIR").context("set TRACES_DIR to the dir holding the .npy files")?,
    );
    let t_threshold: f32 = env::var("T_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4.5);
    let batch_size: usize = env::var("BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let target_byte: usize = env::var("CPA_TARGET_BYTE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // --- load: uint8 traces ([n, samples]) -------------------------------
    let traces: Array2<u8> =
        read_npy(dir.join("traces.npy")).context("read traces.npy (uint8 [n, samples])")?;
    let (n, samples) = (traces.shape()[0], traces.shape()[1]);
    println!("traces.npy : {n} traces x {samples} samples (uint8 mem-address HW)");

    // ====================================================================
    // PASS 1 — Welch's T-test (TVLA), fixed-vs-random
    // ====================================================================
    // classes.npy is the per-trace fixed/random flag. muscat's `ttest` takes
    // a bool array (true => group 2). We accept either a `bool` .npy directly
    // or a uint8 0/1 .npy and coerce.
    let classes: Array1<bool> = match read_npy::<_, Array1<bool>>(dir.join("classes.npy")) {
        Ok(c) => c,
        Err(_) => {
            let u: Array1<u8> = read_npy(dir.join("classes.npy"))
                .context("read classes.npy (bool or uint8 0/1 [n])")?;
            u.mapv(|v| v != 0)
        }
    };
    assert_eq!(
        classes.len(),
        n,
        "classes.npy length must equal trace count"
    );
    let n_fixed = classes.iter().filter(|&&b| b).count();
    println!(
        "classes.npy: {n_fixed} group-B (fixed) / {} group-A (random)",
        n - n_fixed
    );

    let t = ttest(traces.view(), classes.view(), batch_size);
    let (argmax, max_abs_t) = t.iter().enumerate().fold((0usize, 0f32), |(ai, av), (i, &v)| {
        if v.abs() > av {
            (i, v.abs())
        } else {
            (ai, av)
        }
    });
    let verdict = if max_abs_t > t_threshold {
        "LEAKAGE"
    } else {
        "flat"
    };
    println!(
        "TVLA       : max|t| = {max_abs_t:.3} @ sample {argmax}  (threshold {t_threshold}) -> {verdict}"
    );

    // ====================================================================
    // PASS 2 — CPA (Pearson correlation), recover target byte
    // ====================================================================
    // Skippable: on very wide trace sets (e.g. the full 10M-sample f9 set) the
    // 256-guess CPA accumulators are large; for a pure TVLA cross-check set
    // SKIP_CPA=1. (On the fixed/random TVLA set CPA is also degenerate — the
    // fixed group has constant msg, so the byte model has zero variance.)
    if std::env::var("SKIP_CPA").is_ok() {
        println!("CPA        : skipped (SKIP_CPA set)");
        return Ok(());
    }
    // plaintexts.npy is the public-input matrix [n, k]; we attack one byte.
    let plaintexts: Array2<u8> =
        read_npy(dir.join("plaintexts.npy")).context("read plaintexts.npy (uint8 [n, k])")?;
    assert_eq!(
        plaintexts.shape()[0],
        n,
        "plaintexts.npy rows must equal trace count"
    );
    assert!(
        target_byte < plaintexts.shape()[1],
        "CPA_TARGET_BYTE out of range for plaintexts.npy width"
    );

    let result = cpa(
        traces.view(),
        plaintexts.view(),
        256, // guess range
        target_byte,
        leakage_model,
        batch_size,
    );
    let best = result.best_guess();
    let max_corr = result.max_corr();
    println!(
        "CPA byte {target_byte} : best guess = {best:#04x} ({best})  |  corr = {:.4}",
        max_corr[best]
    );
    // Top-5 ranked guesses for context.
    let rank = result.rank(); // ascending by max_corr; last = best
    let top: Vec<(usize, f32)> = rank
        .iter()
        .rev()
        .take(5)
        .map(|&g| (g, max_corr[g]))
        .collect();
    println!("CPA top-5  : {top:?}");

    Ok(())
}
