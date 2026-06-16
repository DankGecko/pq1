"""Synthesize a PQ-Signer-shaped mem_address-channel trace set:
   - uint8 traces [n, samples]  (Hamming weight of a memory ADDRESS, 0..32)
   - classes (is_fixed) bool [n]  for TVLA fixed-vs-random
   - plaintexts uint8 [n, k]      public input bytes for CPA
Mimics the `sca_leaky_sbox` positive control (out[i]=SBOX[in[i]^KEY[i]]):
a secret-indexed table access => the ADDRESS &SBOX+(in^key) leaks via HW.
So BOTH TVLA (fixed-vs-random input) and CPA (recover KEY[0]) have ground truth.
"""
import numpy as np
SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
SBOX_BASE = 0x6000_2000  # a plausible mem base; HW of (base+sbox_out) is the address-channel sample
rng = np.random.default_rng(0xF9C0FFEE)
N, S, K = 4000, 60, 16
KEY = bytes([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
             0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c])
def hw(x): return int(x).bit_count()

# Build fixed-vs-random groups, interleaved (k%2==0 fixed). Group A(fixed,is_fixed=1)
# msg=zeros; Group B(random,is_fixed=0) msg=random. Mirrors f9_retest.make_inputs.
pts = np.zeros((N, K), dtype=np.uint8)
is_fixed = np.zeros(N, dtype=bool)
for k in range(N):
    if k % 2 == 0:
        is_fixed[k] = True            # fixed group => all-zero msg
    else:
        pts[k] = rng.integers(0, 256, K, dtype=np.uint8)

# Base trace: random integer HW noise in 0..32 (uint8). Inject a key+input
# dependent address-HW at sample `leak_sample` for byte 0 (the CPA target),
# and a broader msg-dependent address pattern (so TVLA fires fixed-vs-random).
traces = rng.integers(8, 24, size=(N, S), dtype=np.uint8)  # ~centered HW noise
leak_sample = 25
for k in range(N):
    addr0 = SBOX_BASE + SBOX[pts[k,0] ^ KEY[0]]
    traces[k, leak_sample] = np.clip(hw(addr0), 0, 32)
    # a few more samples carry msg-dependent address HW (drives TVLA)
    for j, s in enumerate((10, 12, 30, 40)):
        addr = SBOX_BASE + SBOX[pts[k, j] ^ KEY[j]]
        traces[k, s] = np.clip(hw(addr), 0, 32)

np.save("muscat_demo/traces.npy", traces.astype(np.uint8))
np.save("muscat_demo/classes.npy", is_fixed)                    # bool
np.save("muscat_demo/plaintexts.npy", pts.astype(np.uint8))    # [n,16]
print("traces", traces.shape, traces.dtype, "classes", is_fixed.shape, is_fixed.dtype,
      "fixed=", int(is_fixed.sum()), "plaintexts", pts.shape, pts.dtype,
      "true KEY[0]=", hex(KEY[0]))

# Also emit a .npz in the f9_traces.npz layout, to exercise the converter.
np.savez("muscat_demo/f9_like.npz", samples=traces.astype(np.uint8),
         is_fixed=is_fixed.astype(np.uint8), msg=pts.astype(np.uint8))
print("wrote f9_like.npz (samples,is_fixed,msg)")
