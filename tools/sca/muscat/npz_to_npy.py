#!/usr/bin/env python3
"""Convert a PQ-Signer rainbow trace .npz (f9_collect_for_scared.py /
f9_traces.npz layout) into the three .npy files muscat's
`pqsigner_tvla_cpa` example reads.

f9_traces.npz arrays:  samples [n,S] uint8 | is_fixed [n] uint8 | msg [n,32] uint8
                       (+ opt_rand, shuffle_seed, meta — ignored here)

Emits into OUT_DIR:
  traces.npy     uint8  [n, S]   <- samples   (mem-address Hamming weights)
  classes.npy    bool   [n]      <- is_fixed  (TVLA fixed-vs-random)
  plaintexts.npy uint8  [n, 32]  <- msg       (public input bytes for CPA)

Usage:  python3 npz_to_npy.py f9_traces.npz OUT_DIR
        # then:  TRACES_DIR=OUT_DIR cargo run --release --example pqsigner_tvla_cpa
"""
import sys, os
import numpy as np

src = sys.argv[1] if len(sys.argv) > 1 else "f9_traces.npz"
out = sys.argv[2] if len(sys.argv) > 2 else "."
os.makedirs(out, exist_ok=True)

# mmap_mode='r' avoids materialising the (multi-GB) samples array in RAM until
# np.save streams it; allow_pickle for the object `meta` field.
z = np.load(src, allow_pickle=True, mmap_mode="r")
samples  = z["samples"]
is_fixed = np.asarray(z["is_fixed"]).astype(bool)
# CPA public bytes: prefer `msg`; fall back to a generic `plaintexts`/`pt` key.
for k in ("msg", "plaintexts", "pt", "public"):
    if k in z.files:
        pubs = np.asarray(z[k]).astype(np.uint8); break
else:
    pubs = np.zeros((samples.shape[0], 1), dtype=np.uint8)
if pubs.ndim == 1:
    pubs = pubs.reshape(-1, 1)

print(f"src={src}  samples={samples.shape}{samples.dtype}  "
      f"is_fixed={is_fixed.shape}(fixed={int(is_fixed.sum())})  pubs={pubs.shape}")
np.save(os.path.join(out, "traces.npy"),     np.asarray(samples, dtype=np.uint8))
np.save(os.path.join(out, "classes.npy"),    is_fixed)
np.save(os.path.join(out, "plaintexts.npy"), pubs)
print(f"wrote traces.npy / classes.npy / plaintexts.npy -> {out}")
