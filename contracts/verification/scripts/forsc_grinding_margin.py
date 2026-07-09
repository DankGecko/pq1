#!/usr/bin/env python3
"""
FORS+C grinding margin for C10 — is the +C variant ever WEAKER than plain FORS?

WHY THIS EXISTS
---------------
`theft_free`'s axiom closure contains `A5-ITSR` (`SphincsCVerify.Crypto.ITSR_F`),
cited to Barbosa et al. 2024 § 6 Thm 2 — which is **plain ITSR, for standard
SPHINCS+**. We ship SPHINCS+C10, whose FORS+C variant grinds the randomizer `R`
until the LAST FORS index is zero, then omits that tree's authentication path.

The published SPHINCS+C paper (IEEE S&P 2023) disposes of FORS+C's security in one
informal paragraph — *"we can use the previous ITSR analysis to bound the security
of FORS+C"* — with **no reduction and no theorem** (adversarial review 2026-07-09;
see docs/verification/easycrypt-euf-cma-port-feasibility-2026-07.md). This script
does not close that gap. It answers the narrower, decision-relevant question:

    For C10's ACTUAL parameters, is FORS+C's per-query forgery probability ever
    LARGER than plain FORS's?

THE ARGUMENT
------------
A forger picks `R` freely (R rides in the signature — this freedom exists in
standard SPHINCS+ too, so it is NOT new adversary power introduced by +C), and
computes `digest = H_msg(pkSeed, pkRoot, R, msg)`. To forge it needs:

  plain FORS : all k indices land on already-revealed leaves
               -> per-query success  p_FORS  = DS_g ** k
  FORS+C     : the last index must be 0 (BOTH our verifiers enforce this:
               sphincs-c10/src/hypertree.rs `if fors_indices[K-1] != 0 {return false}`
               and contracts/.../SPHINCsC10Asm.sol `if and(shr(132,dVal),0x7FF) {revert}`),
               and the remaining k-1 indices must be covered. Leaf 0 of the last
               tree is revealed by EVERY signature, so it is always covered.
               -> per-query success  p_FORSC = DS_g ** (k-1) * (1/t_last)

where `DS_g = 1 - (1 - 1/t)**g` is the paper's DarkSide_gamma (probability a given
index is covered after `g` signatures under the same FORS key), `t = 2**A` leaves
per tree, and `t_last` is the size of the REMOVED (forced-zero) tree.

    ratio = p_FORSC / p_FORS = 1 / (t_last * DS_g)

Since `DS_g >= 1/t` for every `g >= 1` (equality at g=1), the ratio is `<= 1`
**provided `t_last >= t`**. C10 has `t_last == t == 2**11` exactly — the EQUALITY
boundary. Shrink the removed tree (`t_last < t`, which the paper explicitly floats
as a size/security trade-off) and FORS+C becomes STRICTLY WEAKER than plain FORS.
That is the guardrail this script pins.

STATUS: this is a COMPUTED MARGIN, not a kernel theorem and not a reduction. It does
not discharge A5-ITSR. It bounds the blast radius of the literature gap for OUR
parameters.

Exit 0 iff every guardrail holds. Wire into CI to keep A/K/t_last honest.
"""
from __future__ import annotations

import math
import sys

# --- C10 parameters (must mirror sphincs-c10/src/params.rs) -------------------
N = 16   # bytes of hash output kept
H = 18   # hypertree height  -> 2**H FORS instances
D = 2    # hypertree layers
K = 13   # FORS trees
A = 11   # log2(leaves per FORS tree)

T = 2 ** A          # leaves per FORS tree
T_LAST = 2 ** A     # size of the REMOVED (forced-zero) tree. C10: same as T.


def darkside(gamma: int, t: int = T) -> float:
    """Pr[a given FORS index is already revealed] after `gamma` signatures."""
    return 1.0 - (1.0 - 1.0 / t) ** gamma


def p_plain_fors(gamma: int) -> float:
    return darkside(gamma) ** K


def p_forsc(gamma: int) -> float:
    return darkside(gamma) ** (K - 1) / T_LAST


def self_test() -> int:
    """WIRED-IN NEGATIVE CONTROL — prove the guardrails actually fire.

    Shrinks the removed forced-zero tree (t_last < t), which is exactly the
    size/security trade-off the paper floats. That MUST invert the inequality
    and make FORS+C strictly weaker than plain FORS. If this does not trip, the
    gate is vacuous.
    """
    global T_LAST
    saved = T_LAST
    try:
        T_LAST = 2 ** (A - 1)  # halve the removed tree: t_last = 1024 < t = 2048
        ratio = p_forsc(1) / p_plain_fors(1)
        fired = ratio > 1.0 + 1e-12 and T_LAST < T
        print(f"  self-test: t_last = {T_LAST} < t = {T} -> ratio at gamma=1 = "
              f"{ratio:.4f}")
        if not fired:
            print("  self-test FAIL: shrinking t_last did NOT trip the guardrails "
                  "-> the gate is vacuous")
            return 1
        print("  ok: shrinking the removed tree is caught (ratio > 1, t_last < t)")
        print("=== self-test PASS ===")
        return 0
    finally:
        T_LAST = saved


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()

    failures: list[str] = []

    print("=== FORS+C grinding margin — C10 ===")
    print(f"N={N} H={H} D={D} K={K} A={A}  ->  t=2^{A}={T} leaves/tree, "
          f"{2**H} FORS instances")
    print(f"removed (forced-zero) tree size t_last = {T_LAST}\n")

    # ---- Guardrail 1: the removed tree must not be smaller than the others.
    if T_LAST < T:
        failures.append(
            f"t_last ({T_LAST}) < t ({T}): FORS+C is STRICTLY WEAKER than plain "
            f"FORS. The paper's inequality (DS^(k-1))/t_last <= DS^k requires "
            f"t_last >= t."
        )
    print(f"[guardrail 1] t_last >= t : {'OK' if T_LAST >= T else 'FAIL'} "
          f"(C10 sits on the EQUALITY boundary t_last == t)")

    # ---- Guardrail 2: ratio <= 1 for every realistic gamma.
    print("\n{:>6} {:>13} {:>15} {:>17} {:>13} {:>12}".format(
        "gamma", "DS_g", "p_FORS", "p_FORS+C", "ratio", "bits gained"))
    worst_g, worst_ratio = None, -1.0
    for g in [1, 2, 3, 4, 5, 8, 16, 32, 64, 128, 256]:
        ds, pf, pfc = darkside(g), p_plain_fors(g), p_forsc(g)
        ratio = pfc / pf
        bits = -math.log2(ratio) if ratio > 0 else float("inf")
        if ratio > worst_ratio:
            worst_g, worst_ratio = g, ratio
        print(f"{g:>6} {ds:>13.4e} {pf:>15.4e} {pfc:>17.4e} "
              f"{ratio:>13.6f} {bits:>12.2f}")

    if worst_ratio > 1.0 + 1e-12:
        failures.append(
            f"ratio > 1 at gamma={worst_g} ({worst_ratio:.6f}): FORS+C weaker "
            f"than plain FORS."
        )
    print(f"\n[guardrail 2] max ratio over gamma = {worst_ratio:.6f} at "
          f"gamma={worst_g} : {'OK (<= 1)' if worst_ratio <= 1 + 1e-12 else 'FAIL'}")

    # ---- Guardrail 3: DS_g >= 1/t for all gamma (the inequality's engine).
    bad = [g for g in range(1, 2001) if darkside(g) < 1.0 / T - 1e-18]
    if bad:
        failures.append(f"DS_g < 1/t at gamma in {bad[:5]}")
    print(f"[guardrail 3] DS_g >= 1/t for gamma in 1..2000 : "
          f"{'OK' if not bad else 'FAIL'}")

    # ---- Absolute margin at the worst case gamma = 1.
    p1 = p_forsc(1)
    bits1 = -math.log2(p1)
    print(f"\nAbsolute per-query forgery probability at gamma=1 (worst case):")
    print(f"  p_FORS+C = {p1:.4e} = 2^-{bits1:.1f}   (= 2^-(A*K) = 2^-{A*K})")
    print(f"  p_FORS   = {p_plain_fors(1):.4e} = 2^-{-math.log2(p_plain_fors(1)):.1f}")
    print(f"  -> identical at gamma=1; FORS+C strictly better for gamma > 1.")

    if abs(bits1 - A * K) > 0.5:
        failures.append(f"per-query bits {bits1:.1f} != A*K = {A*K}")

    print("\n" + "=" * 68)
    if failures:
        print("FAIL — FORS+C margin guardrails violated:")
        for f in failures:
            print("  - " + f)
        return 1
    print("OK — for C10's parameters FORS+C is NEVER weaker than plain FORS")
    print("     (equal at gamma=1, better by ~log2(gamma) bits beyond).")
    print("\nNOTE: this is a COMPUTED MARGIN, not a reduction. The literature has no")
    print("FORS+C security theorem; A5-ITSR remains cited-tcb. See AXIOM_STATUS.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
