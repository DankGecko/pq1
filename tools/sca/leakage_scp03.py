#!/usr/bin/env python3
"""SE050 SCP03 response-unwrap leakage analysis — work-todo §18b RANK 1 (b).

**What this tests**: the two secret-touching primitives on the SCP03 response
leg, `#[path]`-included BYTE-FOR-BYTE from `secure/src/scp03_logic.rs` into
`tools/sca/scp03_target/`:

  * `aes128_cbc_decrypt` (R-ENC) — decrypts the SE050 response body under the
    session `S-ENC` key. The plaintext is the secret the channel protects —
    most critically `half_E`, one XOR half of the BIP-39 seed (invariant #1).
  * `cmac_aes128` (R-MAC) — authenticates the response under `S-RMAC`.

Both use the `aes` crate's bitsliced soft backend (same one production falls
through to on thumbv8m — no AES-NI), so this is representative of the shipped
code, NOT of the SE050 silicon or the I2C bus.

**Measurement channel**: rainbow's `mem_address` Hamming-weight stream (HW of
each memory access ADDRESS, not the loaded VALUE). A TVLA flip means a memory
access whose ADDRESS depends on the variable input — the classic data-dependent
table-lookup (T-table) leak. Bitsliced AES has NO T-tables, so the expectation
is **flat** on all four modes: neither the R-ENC decrypt nor the R-MAC CMAC
indexes memory by the session key or `half_E`. (This is the same clean result
`leakage_kdf.py` / `leakage_saes_kdf.py` report for software AES + CMAC.)

**The four TVLA modes**:
  1. `sca_scp03_cbc_decrypt` vary KEY (S-ENC) — key-dependent addresses?
  2. `sca_scp03_cbc_decrypt` vary CIPHERTEXT (= the would-be half_E) — does the
     recovered secret index memory?
  3. `sca_scp03_cmac`        vary KEY (S-RMAC) — key-dependent addresses?
  4. `sca_scp03_cmac`        vary MESSAGE      — message-dependent addresses?

**Scope (honest).** A clean result rules out one specific leak class
(data-dependent memory addresses in the unwrap crypto) at audit-grade emulation
resolution. Power/EM leakage on register VALUES (S-box outputs landing in
registers, CBC state) and the SE050 silicon's own side-channel surface require
on-silicon SCA with a scope — out of scope for emulation.

Run: `make -C tools/sca scp03-leakage`
"""
import os
import sys
import time

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# Reuse the trace-collection + TVLA primitives from leakage_kdf — same
# rainbow-driven emulator, same `tvla()` definition + `T_THRESHOLD = 4.5`.
import leakage_kdf as lk  # noqa: E402

ELF = os.path.join(
    HERE, "scp03_target", "target", "thumbv8m.main-none-eabi", "release",
    "sca-scp03-target",
)
# Positive control lives in kdf_target (sca_leaky_sbox); used to prove the
# rainbow→lascar pipeline is alive before we trust a "flat" result.
KDF_ELF = os.path.join(
    HERE, "kdf_target", "target", "thumbv8m.main-none-eabi", "release",
    "sca-kdf-target",
)

N_TRACES = 600
N_TOY = 256


def vary_inputs(n: int, total_len: int, lo: int, hi: int):
    """Build `n` inputs of `total_len` bytes. Half are the all-zero "fixed"
    reference; the other half randomise bytes `[lo, hi)`."""
    rng = np.random.default_rng(0x5C_0003)
    fixed = bytes(total_len)
    out, is_fixed = [], []
    for k in range(n):
        if k % 2 == 0:
            out.append(fixed)
            is_fixed.append(1)
        else:
            buf = bytearray(fixed)
            buf[lo:hi] = bytes(rng.integers(0, 256, hi - lo, dtype=np.uint8))
            out.append(bytes(buf))
            is_fixed.append(0)
    return out, is_fixed


def run_tvla(label, fn_sym, *, total_len, lo, hi, out_size, n_traces=N_TRACES):
    print(f"\n== {label} ==")
    print(f"   symbol:    {fn_sym}")
    print(f"   varying:   bytes [{lo}:{hi}) of a {total_len}-B input")
    print(f"   {n_traces} traces")
    inp, isf = vary_inputs(n_traces, total_len, lo, hi)
    t0 = time.time()
    mem = lk.collect(fn_sym, inp, out_size=out_size)
    elapsed = time.time() - t0
    print(f"   collected {mem.shape[0]} × {mem.shape[1]:,} samples in {elapsed:.1f} s")
    mt = lk.tvla(label, "mem_address", mem, isf)
    return mt


def pipeline_check():
    """Run the deliberately-leaky S-box positive control through the SAME
    rainbow+lascar path so a 'flat' SCP03 result can't be a broken pipeline."""
    if not os.path.exists(KDF_ELF):
        print("(positive control skipped — build kdf_target for pipeline validation: "
              "make -C tools/sca build-kdf)")
        return
    saved = lk.ELF
    lk.ELF = KDF_ELF
    try:
        inp, isf = vary_inputs(N_TOY, 16, 0, 16)
        mem = lk.collect("sca_leaky_sbox", inp, out_size=16)
        mt = lk.tvla("positive-control sca_leaky_sbox", "mem_address", mem, isf)
        if mt <= lk.T_THRESHOLD:
            print("!!! positive control did NOT leak — rainbow/lascar pipeline broken; aborting.")
            sys.exit(2)
        print(f"→ pipeline verified: positive control leaks (max|t| = {mt:.1f} > {lk.T_THRESHOLD}).")
    finally:
        lk.ELF = saved


def main():
    if not os.path.exists(ELF):
        print(f"ERROR: {ELF} not found.")
        print("Run `make -C tools/sca build-scp03` first.")
        sys.exit(2)

    lk.ELF = ELF

    print("====================================================================")
    print("SCP03 response-unwrap leakage analysis (R-ENC decrypt + R-MAC CMAC)")
    print("====================================================================")
    print(f"ELF: {ELF}")

    pipeline_check()
    lk.ELF = ELF

    # cbc_decrypt input: key(16) || iv(16) || ct(32) = 64 B; out pt(32).
    mt_cbc_key = run_tvla(
        "sca_scp03_cbc_decrypt — VARY KEY (S-ENC, 16 B), FIX iv+ct",
        "sca_scp03_cbc_decrypt", total_len=64, lo=0, hi=16, out_size=32,
    )
    mt_cbc_ct = run_tvla(
        "sca_scp03_cbc_decrypt — VARY CIPHERTEXT (=half_E, 32 B), FIX key+iv",
        "sca_scp03_cbc_decrypt", total_len=64, lo=32, hi=64, out_size=32,
    )

    # cmac input: key(16) || msg(32) = 48 B; out tag(16).
    mt_cmac_key = run_tvla(
        "sca_scp03_cmac — VARY KEY (S-RMAC, 16 B), FIX msg",
        "sca_scp03_cmac", total_len=48, lo=0, hi=16, out_size=16,
    )
    mt_cmac_msg = run_tvla(
        "sca_scp03_cmac — FIX KEY, VARY MESSAGE (32 B)",
        "sca_scp03_cmac", total_len=48, lo=16, hi=48, out_size=16,
    )

    print()
    print("====================================================================")
    print("SUMMARY")
    print("====================================================================")
    print(f"  sca_scp03_cbc_decrypt  vary key (S-ENC):  max|t| = {mt_cbc_key:7.2f}")
    print(f"  sca_scp03_cbc_decrypt  vary half_E:       max|t| = {mt_cbc_ct:7.2f}")
    print(f"  sca_scp03_cmac         vary key (S-RMAC): max|t| = {mt_cmac_key:7.2f}")
    print(f"  sca_scp03_cmac         vary message:      max|t| = {mt_cmac_msg:7.2f}")
    print()
    worst = max(mt_cbc_key, mt_cbc_ct, mt_cmac_key, mt_cmac_msg)
    if worst > lk.T_THRESHOLD:
        print(f"  → LEAKAGE detected (max|t| {worst:.2f} > {lk.T_THRESHOLD}). Check whether the peak")
        print(f"    sample falls inside the AES rounds (inherent register-value leak the")
        print(f"    mem_address channel shouldn't even see) or in addressing logic (a real")
        print(f"    finding). A bitsliced AES should be flat on mem_address — investigate.")
        rc = 1
    else:
        print(f"  → flat on mem_address (max|t| {worst:.2f} ≤ {lk.T_THRESHOLD}). Neither the R-ENC")
        print(f"    decrypt nor the R-MAC CMAC makes a memory access whose ADDRESS depends on")
        print(f"    the session key or half_E. Same clean result as the AES-GCM / SAES-CMAC")
        print(f"    paths. (Register-VALUE leakage + SE050 silicon need on-silicon SCA.)")
        rc = 0
    return rc


if __name__ == "__main__":
    sys.exit(main())
