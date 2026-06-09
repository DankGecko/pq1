#!/usr/bin/env python3
"""F-24 — secret glyph-render leakage analysis (trusted-display secret rows).

The seed wizard renders the master mnemonic on the OLED/LCD. The naive
`embedded_graphics::Text::draw` path does a `MonoFont::glyph(char)`
lookup keyed on each rendered character, loading from `FONT_5X8` at an
address that ENCODES the character — a 96-table-style `mem_address`
leak. For SECRET characters an attacker EM-scoping the CPU's address
bus (cache misses, prefetch, DMA descriptors visible to power/EM) can
reconstruct the displayed mnemonic from a single provisioning trace,
defeating every downstream defence.

`secure/src/ui/secret_text.rs` replaces that, for secret rows, with
`ct_glyph_col`: a constant-time scan over all 96 `FONT_FLAT_5X8`
entries whose load addresses are keyed on the PUBLIC loop counter `i`
(0..96), never the secret `ch`. The fetched 5 column-bytes then feed
the branchless RGB565 mask-select expansion in `ui::lcd::blit_glyph`,
which writes every one of the fixed CELL_N=360 pixels UNCONDITIONALLY
(no secret-dependent branch / address). Only the pixel VALUE depends
on the secret — the accepted F-24 stage-E display-broadcast residual
(the panel's own drivers physically emit the framebuffer), unfixable
in firmware.

Two TVLA subjects (fixed-vs-random 16-byte secret word, mem_address):

  1. `sca_glyph_secret_row_leaky` — REGRESSION SENTINEL. Fetches glyph
     columns via the DIRECT secret-indexed load (the pre-CT
     `public_glyph_cols` form, == the fold-target the `ct_glyph_col`
     doc comment warns LLVM produces if the black_box barriers are
     removed). EXPECTED to leak (`max|t| > 4.5`) — proves the harness
     detects the leak it is supposed to detect.

  2. `sca_glyph_secret_row_ct` — F-24 FIX VALIDATOR. Renders the SAME
     row through `ct_glyph_col` (black_box barriers kept) + the SAME
     branchless blit. EXPECTED flat (`max|t| <= 4.5`).

Both render through the SAME branchless blit; only the glyph FETCH
differs, isolating the fetch as the sole variable. If the CT probe
ever starts matching the leaky baseline, the `black_box` barriers in
`ct_glyph_col` have been folded away (re-run this harness).

NOTE (house caveat, cf. `sca_dual_se_xor`): this validates the ADDRESS
channel only. rainbow's `mem_address` model is value-blind, so the
dummy font VALUES in the target are irrelevant — only the access
PATTERN (96-entry × 5-byte stride) mirrors production. The pixel-value
channel is the accepted F-24 stage-E residual and out of this model's
scope.

Run: `make -C tools/sca glyph-leak`
"""
import os
import sys
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")
# lascar's TTestEngine emits a numpy warning + interactive prompt when
# the random group's per-sample variance is exactly zero (which is what
# we WANT to see — it means the trace is perfectly identical across
# inputs). Silence numpy's complaints so the prompt never fires.
import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)
import numpy as np
np.seterr(all="ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import leakage_kdf as lk  # noqa: E402

N_TRACES = 600


def make_inputs(n: int):
    """Half-fixed (zeros), half random 16-byte secret words — same
    fixed-vs-random split as `rand_inputs`."""
    return lk.rand_inputs(n, 16)


def run_tvla(label: str, fn_sym: str, *, out_size=32, max_samples=None):
    print(f"\n== {label} ==")
    print(f"   symbol:     {fn_sym}")
    inp, isf = make_inputs(N_TRACES)
    t0 = time.time()
    mem = lk.collect(fn_sym, inp, out_size=out_size, max_samples=max_samples)
    elapsed = time.time() - t0
    print(f"   collected {mem.shape[0]} traces × {mem.shape[1]:,} samples "
          f"({elapsed:.1f} s)")

    mt = lk.tvla(label, "mem_address", mem, isf)

    # Always report the peak so a "flat" result is also actionable.
    import lascar
    container = lascar.TraceBatchContainer(
        mem, np.array(isf, dtype=np.uint8).reshape(-1, 1)
    )
    eng = lascar.TTestEngine(lambda v: int(v[0]))
    lascar.Session(container, engine=eng).run(batch_size=200)
    t_raw = eng.finalize()

    # When the trace is PERFECTLY constant across inputs, the per-sample
    # variance is exactly zero in both groups → the t-statistic
    # denominator is zero. numpy may return inf/NaN OR a finite-but-absurd
    # value (~DBL_MAX = 1.7e308) depending on float ordering. Either way
    # "you cannot t-test a constant" — map to 0 so the verdict reads as
    # flat. Threshold of 1e6 separates real-but-unlikely values from
    # zero-variance sentinels (genuine max|t| past 1e6 would require
    # > 1 trillion traces to produce by chance).
    ZERO_VAR_SENTINEL = 1e6
    t = np.abs(np.nan_to_num(t_raw, nan=0.0, posinf=0.0, neginf=0.0))
    zero_var_mask = t > ZERO_VAR_SENTINEL
    n_zero_var_clip = int(zero_var_mask.sum())
    t[zero_var_mask] = 0.0
    mt = float(t.max()) if t.size else 0.0
    if t.size:
        peak = int(np.argmax(t))
        top5 = np.argsort(t)[-5:][::-1]
        print(f"   peak sample: {peak:,}/{mem.shape[1]:,}  |t|={t[peak]:.2f}")
        print(f"   top-5 samples:")
        for idx in top5:
            print(f"     sample {int(idx):>6,}  |t|={t[idx]:.2f}")
        # Honest report when variance was zero.
        n_zero_var = (
            int(np.isinf(t_raw).sum())
            + int(np.isnan(t_raw).sum())
            + n_zero_var_clip
        )
        if n_zero_var > 0:
            pct = 100.0 * n_zero_var / t_raw.size
            print(f"   note: {n_zero_var:,}/{t_raw.size:,} ({pct:.1f}%) samples")
            print(f"         had zero variance — perfectly constant across inputs;")
            print(f"         t-statistic undefined at those points (mapped to 0).")
    return mt


def main():
    if not os.path.exists(lk.ELF):
        print(f"ERROR: {lk.ELF} not found.")
        print("Run `make -C tools/sca build-kdf` first.")
        sys.exit(2)

    print("=" * 70)
    print("F-24 secret glyph-render leakage TVLA")
    print("=" * 70)

    # Regression sentinel: the DIRECT secret-indexed glyph fetch
    # (`public_glyph_cols` / pre-CT form). EXPECTED to leak — proves the
    # harness still detects the address-channel leak it must detect.
    mt_leaky = run_tvla(
        "sca_glyph_secret_row_leaky — DIRECT FONT[(ch-0x20)][col] fetch",
        "sca_glyph_secret_row_leaky", out_size=32,
    )

    # F-24 fix validator: the constant-time `ct_glyph_col` scan + the
    # branchless blit. EXPECTED flat. The CT scan is 16 chars × 5 cols ×
    # 96 entries + blit ≈ 40k+ mem events, well past the default 32768
    # max_samples — bump to 200_000 (same as bip39's `_ct`) so the flat
    # claim covers the whole function, not a truncated prefix.
    mt_ct = run_tvla(
        "sca_glyph_secret_row_ct — F-24 FIX (constant-time ct_glyph_col scan)",
        "sca_glyph_secret_row_ct", out_size=32, max_samples=200_000,
    )

    print()
    print("F-24 fix-vs-baseline:")
    print(f"  leaky glyph fetch        max|t| = {mt_leaky:6.2f}  "
          f"({'LEAKS (expected)' if mt_leaky > lk.T_THRESHOLD else 'NO LEAK (suspect!)'})")
    print(f"  ct_glyph_col (post-fix)  max|t| = {mt_ct:6.2f}  "
          f"({'CLEAN' if mt_ct <= lk.T_THRESHOLD else 'STILL LEAKS'})")
    if mt_ct > lk.T_THRESHOLD:
        print(f"  → constant-time scan STILL above threshold; the black_box")
        print(f"    barriers in ct_glyph_col may have been folded away — the")
        print(f"    CT path is matching the leaky baseline. Investigate the peak.")
    else:
        print(f"  → constant-time scan closes the F-24 glyph-address leak")

    # The "leaky glyph fetch" probe is a REGRESSION SENTINEL: it
    # intentionally uses the pre-CT secret-indexed load and is EXPECTED
    # to keep leaking. The post-fix verdict comes from `mt_ct`. Exit 0
    # iff the fix is clean AND the baseline still leaks (i.e. the harness
    # still detects what it's supposed to detect).
    if mt_ct <= lk.T_THRESHOLD and mt_leaky > lk.T_THRESHOLD:
        return 0
    if mt_ct > lk.T_THRESHOLD:
        # The fix regressed / the CT path leaks. This is the bad outcome.
        return 2
    if mt_leaky <= lk.T_THRESHOLD:
        print()
        print("WARNING: the baseline leaky probe no longer detects the leak.")
        print("         Either the harness is broken or the leaky font fetch")
        print("         got optimized to a constant — investigate before")
        print("         trusting `mt_ct` flat.")
        return 1
    # Unreachable.
    return 0


if __name__ == "__main__":
    sys.exit(main())
