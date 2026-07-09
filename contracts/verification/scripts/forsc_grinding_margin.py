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

WHY A BLACK-BOX REDUCTION TO PLAIN ITSR IS A DEAD END (computed 2026-07-09)
--------------------------------------------------------------------------
The obvious way to justify A5-ITSR's citation would be to reduce ITSR(+C) to MM45's
plain ITSR. For C10 (which grinds the KEY `R`, not a counter) such a reduction EXISTS
and is sound: simulate the +C oracle — whose `R` is conditioned on `predC` — by
REJECTION SAMPLING on plain ITSR's uniform-key oracle. Coverage transfers (the
reduction's target list is a superset, and coverage is monotone in it); freshness
transfers (rejected targets have `¬predC`, the forgery has `predC`, so they can never
collide).

But it is quantitatively useless. Rejection sampling registers ~`t = 2^11` targets per
real query, so the reduction's game has `qs*t = 2^27` targets over `2^18` FORS
instances — a max per-instance load of ~625 instead of ~5. The resulting bound is
**~25 bits**, versus **~113 bits** from the paper's direct DarkSide argument:
**88 bits lost**. So the axiom cannot be discharged black-box; it needs the DIRECT
(tight, non-black-box) combinatorial argument mechanized. `itsr_report()` recomputes
this, so the conclusion cannot rot.

STATUS: this is a COMPUTED MARGIN, not a kernel theorem and not a reduction. It does
not discharge A5-ITSR. It bounds the blast radius of the literature gap for OUR
parameters.

GUARDRAILS (exit 0 iff all hold; `--self-test` proves each can fire):
  1. t_last >= t             — else FORS+C is strictly weaker than plain FORS
  2. ratio <= 1 for all gamma
  3. DS_gamma >= 1/t          — the engine of (2)
  4. ITSR term at qs = 2^16 >= 96-bit floor — RAISING MAX_SLOT_USES DEGRADES FORS
                                 few-time security (this is what the cap buys us)
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

# Per-chain signature cap (MAX_SLOT_USES / MAX_BOOTSTRAP_USES, see CLAUDE.md).
QS_CAP = 2 ** 16
# Project security floor (Crypto/Quantitative.lean's multi-term floor).
FLOOR_BITS = 96


def darkside(gamma: int, t: int = T) -> float:
    """Pr[a given FORS index is already revealed] after `gamma` signatures."""
    return 1.0 - (1.0 - 1.0 / t) ** gamma


def p_plain_fors(gamma: int) -> float:
    return darkside(gamma) ** K


def p_forsc(gamma: int) -> float:
    return darkside(gamma) ** (K - 1) / T_LAST


def maxload(q: int, bins: int) -> float:
    """High-probability max balls-in-bins load (the adversary grinds to pick the
    heaviest FORS instance, so `gamma` is a MAX, not an average)."""
    m = q / bins
    if m >= 1.0:
        return m + math.sqrt(2.0 * m * math.log(bins))
    lb = math.log(bins)
    return max(1.0, lb / math.log(lb))


def itsr_bits(gamma: float) -> float:
    """Security bits of the ITSR term: work ~ 1/(DS_gamma ** K)."""
    return -math.log2(darkside_f(gamma) ** K)


def darkside_f(gamma: float) -> float:
    return 1.0 - (1.0 - 1.0 / T) ** gamma


def itsr_report(qs: int, floor_bits: int) -> tuple[float, float, list[str]]:
    """ITSR-term security at the usage cap, and the loss a GENERIC black-box
    reduction to plain ITSR would incur. Returns (real_bits, reduction_bits, failures)."""
    failures: list[str] = []
    bins = 2 ** H  # one FORS instance per hypertree leaf

    g_real = maxload(qs, bins)
    real_bits = itsr_bits(g_real)

    # A reduction that simulates the +C oracle (whose key R is CONDITIONED on
    # predC) using plain ITSR's UNIFORM-key oracle must rejection-sample: it
    # registers ~T targets per real query. Those extra targets raise the
    # per-instance load, and coverage is monotone in the target list.
    q_red = qs * T
    g_red = maxload(q_red, bins)
    red_bits = itsr_bits(g_red)

    print(f"\n=== ITSR term at the usage cap (qs = 2^{int(math.log2(qs))}, "
          f"{bins} FORS instances) ===")
    print(f"  direct (paper's DarkSide) argument : gamma_max ~ {g_real:.2f}"
          f"  ->  {real_bits:6.1f} bits")
    print(f"  generic reduction to plain ITSR    : gamma_max ~ {g_red:.1f}"
          f"  ->  {red_bits:6.1f} bits   (registers qs*t = 2^{math.log2(q_red):.0f} targets)")
    print(f"  cost of going black-box            : {real_bits - red_bits:.1f} bits LOST")

    # ---- Guardrail 4: the usage cap must keep the ITSR term above the project floor.
    if real_bits < floor_bits:
        failures.append(
            f"ITSR term at qs=2^{int(math.log2(qs))} is {real_bits:.1f} bits "
            f"< the {floor_bits}-bit floor. Raising MAX_SLOT_USES degrades FORS "
            f"few-time security."
        )
    print(f"[guardrail 4] ITSR bits ({real_bits:.1f}) >= {floor_bits}-bit floor : "
          f"{'OK' if real_bits >= floor_bits else 'FAIL'}")
    return real_bits, red_bits, failures


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
    finally:
        T_LAST = saved

    # negative control #2: blow up the usage cap -> ITSR floor guardrail must fire
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _, _, fails = itsr_report(2 ** 26, FLOOR_BITS)
    if not fails:
        print("  self-test FAIL: raising the usage cap to 2^26 did NOT trip the "
              "ITSR floor guardrail -> the gate is vacuous")
        return 1
    print("  ok: raising MAX_SLOT_USES to 2^26 is caught (ITSR term < 96-bit floor)")
    print("=== self-test PASS ===")
    return 0


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

    # ---- ITSR term at the cap + the cost of a generic black-box reduction.
    real_bits, red_bits, itsr_fail = itsr_report(QS_CAP, FLOOR_BITS)
    failures.extend(itsr_fail)

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
