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
instances. The resulting bound is **~28.1 bits**, versus **~130.6 bits** for FORS+C
by the direct argument: **~102 bits lost**. So the axiom cannot be discharged
black-box; it needs the DIRECT (tight, non-black-box) combinatorial argument.
`itsr_report()` recomputes all of this, so the conclusion cannot rot.

METHOD CORRECTION (2026-07-10, after an external adversarial review by a second
frontier model). The first version of this script evaluated `DS` at a
high-probability MAXIMUM per-instance load ("typical max ~5") and reported ~113
bits. That is **not a cryptographic bound**: the tail that *some* one of 2^18 bins
is heavier is not negligible, and a maximum is the wrong object anyway — the
adversary cannot choose which instance its candidate lands in, since the digest
decides. The correct object is the **binomial mixture** over a fresh candidate's own
instance load, `G ~ Bin(qs, 1/N)`, with a `(q_h + 1)` union bound over the
adversary's hash queries:

    Pr[win] <= (q_h + 1) * (1/t_last) * E_G[ DS_G^(k-1) ]

The old method UNDER-stated security by ~15 bits (safe direction, wrong method).
Corrected figures at `qs = 2^16`: FORS+C **130.6 bits**, plain FORS **128.5 bits**
(so FORS+C is genuinely the stronger of the two, by 2.1 bits, not merely "never
weaker"). The 96-bit floor is first crossed at `qs = 2^22`, not `2^26`.

STATUS: this is a COMPUTED MARGIN, not a kernel theorem and not a reduction. It does
not discharge A5-ITSR. It bounds the blast radius of the literature gap for OUR
parameters.

GUARDRAILS (exit 0 iff all hold; `--self-test` proves each can fire):
  1. t_last >= t             — else FORS+C is strictly weaker than plain FORS
  2. ratio <= 1 for all gamma
  3. DS_gamma >= 1/t          — the engine of (2)
  4. ITSR WORK FACTOR at qs = 2^16 >= 96 bits of hash queries — RAISING
                                 MAX_SLOT_USES DEGRADES FORS few-time security
                                 (this is what the cap buys us)
  5. `_mixture` really is an UPPER bound (self-test widens the window and checks
                                 the exact partial sum does not exceed it)

TWO CORRECTIONS, 2026-07-10b (adversarial review, findings F3 + F4)
-------------------------------------------------------------------
F3. `-log2(B)` is a WORK FACTOR (hash queries needed), NOT an advantage. The old
    guardrail compared it to a floor named after `Crypto/Quantitative.lean`, whose
    convention puts the query count INSIDE the term
    (`queryTerm_le_of_le : q * 2^t <= 2^SecurityBits`). Two different objects. The
    docstring stated `Pr[win] <= (q_h+1)*B` while the code never applied the
    multiplier. Now the floor is explicitly a QUERY-WORK floor and the report
    PRINTS the advantage at representative q_h. There is no operational cap on
    offline hashing, so no `Q_H_CAP` is asserted. Read the printed advantage line
    before quoting "130.6 bits" as a security level.
F4. `_mixture` truncated the binomial support and so UNDER-estimated the
    expectation, making `-log2` OVERSTATE security. It now adds a rigorous
    geometric tail bound (see its docstring).
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

N_INST = 2 ** H     # one FORS instance per hypertree leaf

# Per-chain signature cap (MAX_SLOT_USES / MAX_BOOTSTRAP_USES, see CLAUDE.md).
QS_CAP = 2 ** 16
# QUERY-WORK floor, in bits of adversary HASH QUERIES.
#
# F3 FIX (2026-07-10b, adversarial review). This is NOT `Crypto/Quantitative.lean`'s
# floor. That one bounds an ADVANTAGE and has the query count INSIDE the term
# (`queryTerm_le_of_le : q * 2^t <= 2^SecurityBits`). This script's `-log2(B)` is a
# per-candidate probability, i.e. a WORK FACTOR: the number of hash queries an
# adversary needs. Comparing a work factor to an advantage floor conflates two
# different objects -- the previous version did exactly that while its own docstring
# stated `Pr[win] <= (q_h+1)*B`, a formula the code never applied.
#
# So: guardrail 4 now asserts a WORK floor (>= 2^96 hash queries), and the report
# prints the ADVANTAGE `(q_h+1)*B` at representative q_h so nobody has to infer it.
# There is no operational cap on offline hashing, so no `Q_H_CAP` is asserted.
WORK_FLOOR_BITS = 96

def darkside(gamma: int, t: int = T) -> float:
    """Pr[a given FORS index is already revealed] after `gamma` signatures."""
    return 1.0 - (1.0 - 1.0 / t) ** gamma


def p_plain_fors(gamma: int) -> float:
    return darkside(gamma) ** K


def p_forsc(gamma: int) -> float:
    return darkside(gamma) ** (K - 1) / T_LAST


def _lbinom(n: int, g: int, p: float) -> float:
    """log of the Binomial(n, p) pmf at g, via lgamma (n can be huge)."""
    return (math.lgamma(n + 1) - math.lgamma(g + 1) - math.lgamma(n - g + 1)
            + g * math.log(p) + (n - g) * math.log1p(-p))


def darkside_f(gamma: float) -> float:
    return 1.0 - (1.0 - 1.0 / T) ** gamma


def _mixture(qs: int, exponent: int, prefactor: float) -> float:
    """UPPER BOUND on prefactor * E_G[ DS_G ** exponent ],  G ~ Bin(qs, 1/N_INST).

    A FRESH candidate's FORS instance is uniform over the 2^H instances (its
    index is read off the digest), so the number of signatures already made on
    THAT instance is Binomial(qs, 1/N) -- NOT a worst-case maximum load.

    F4 FIX (2026-07-10b, adversarial review). The previous version summed only to
    `mean + 10*sqrt(mean+1) + 40` and silently DROPPED the rest of the support.
    Every dropped term is non-negative, so it returned a LOWER approximation to
    the expectation -- and `-log2` of it therefore OVERSTATED security. Wrong
    direction for something presented as a cryptographic bound (at qs = 2^16 the
    loop stopped at g = 51 while the support runs to 65536).

    Now: an exact partial sum, PLUS a rigorous upper bound on the omitted tail.
    Since `P[G=g+1]/P[G=g] = ((n-g)/(g+1)) * p/(1-p) <= mu' / (g+1)` with
    `mu' = n*p/(1-p)`, choosing `hi >= 4*mu'` gives ratio <= 1/4 beyond `hi`, so
        sum_{g>hi} P[G=g] * DS_g^e  <=  sum_{g>hi} P[G=g]  <=  P[G=hi+1]/(1-r)
    using `DS_g^e <= 1`. The result is a genuine upper bound.
    """
    mean = qs / N_INST
    mu_p = mean / (1.0 - 1.0 / N_INST)          # n*p/(1-p)
    hi = max(int(4.0 * mu_p) + 1, int(mean + 10.0 * math.sqrt(mean + 1.0)) + 40)
    hi = min(hi, qs)

    acc = 0.0
    for g in range(0, hi + 1):
        d = darkside_f(g)
        if d <= 0.0:            # g = 0: nothing revealed on that instance
            continue
        acc += math.exp(_lbinom(qs, g, 1.0 / N_INST) + exponent * math.log(d))

    tail = 0.0
    if hi < qs:
        r = mu_p / (hi + 2.0)
        assert r < 1.0, "geometric tail bound requires ratio < 1"
        tail = math.exp(_lbinom(qs, hi + 1, 1.0 / N_INST)) / (1.0 - r)

    return prefactor * (acc + tail)


def b_forsc(qs: int) -> float:
    """FORS+C per-candidate coverage: (1/t_last) * E[DS_G^(k-1)].
    The last tree's leaf 0 is revealed by every signature, but the digest must
    still HIT it -- costing the 1/t_last factor."""
    return _mixture(qs, K - 1, 1.0 / T_LAST)


def b_plain(qs: int) -> float:
    """plain FORS per-candidate coverage: E[DS_G^k]."""
    return _mixture(qs, K, 1.0)


def itsr_report(qs: int, work_floor_bits: int) -> tuple[float, float, list[str]]:
    """ITSR-term security at the usage cap, and the cost of a black-box reduction.

    METHOD NOTE (corrected 2026-07-10 after an external adversarial review).  An
    earlier version used a high-probability MAX per-instance load ("typical max
    ~5") and evaluated DS at that fixed gamma.  That is NOT a cryptographic
    bound -- the tail that some one of 2^18 bins is heavier is not negligible,
    and a maximum is the wrong object anyway: the adversary cannot choose which
    instance its candidate lands in (the digest decides).  The correct object is
    the BINOMIAL MIXTURE over a fresh candidate's own instance load, with a
    (q_h + 1) union bound over its hash queries:

        Pr[win] <= (q_h + 1) * (1/t_last) * E_G[ DS_G^(k-1) ],  G ~ Bin(qs, 1/N)

    The old method UNDER-stated security by ~15 bits (safe direction, wrong method).
    """
    failures: list[str] = []

    bd, bp = b_forsc(qs), b_plain(qs)
    real_bits, plain_bits = -math.log2(bd), -math.log2(bp)

    # A reduction simulating the +C oracle (conditioned key) on plain ITSR's
    # UNIFORM-key oracle must rejection-sample: ~T targets per real query.
    q_red = qs * T
    red_bits = -math.log2(b_plain(q_red))

    print(f"\n=== ITSR term at the usage cap (qs = 2^{int(math.log2(qs))}, "
          f"{N_INST} FORS instances) ===")
    print(f"  FORS+C work factor (binom. mixture): {real_bits:6.1f} bits")
    print(f"  plain FORS, same method            : {plain_bits:6.1f} bits"
          f"   (FORS+C stronger by {real_bits - plain_bits:.1f})")
    print(f"  generic reduction to plain ITSR    : {red_bits:6.1f} bits"
          f"   (registers qs*t = 2^{math.log2(q_red):.0f} targets)")
    print(f"  cost of going black-box            : {real_bits - red_bits:.1f} bits LOST")

    # ---- F3: make the (q_h + 1) union bound VISIBLE. `real_bits` is a WORK
    # factor (queries needed), not an advantage. Print the advantage explicitly.
    print("  advantage Pr[win] <= (q_h + 1) * B, at representative q_h:")
    for qh_bits in (64, 96, 128):
        adv = min(1.0, (2.0 ** qh_bits + 1.0) * bd)
        print(f"      q_h = 2^{qh_bits:<3d} ->  Pr[win] <= 2^{math.log2(adv):.1f}")

    if real_bits < work_floor_bits:
        failures.append(
            f"ITSR WORK factor at qs=2^{int(math.log2(qs))} is {real_bits:.1f} bits "
            f"< the {work_floor_bits}-bit query-work floor. Raising MAX_SLOT_USES "
            f"degrades FORS few-time security."
        )
    print(f"[guardrail 4] ITSR work factor ({real_bits:.1f} bits of hash queries) "
          f">= {work_floor_bits}-bit floor : "
          f"{'OK' if real_bits >= work_floor_bits else 'FAIL'}")
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
        _, _, fails = itsr_report(2 ** 22, WORK_FLOOR_BITS)
    if not fails:
        print("  self-test FAIL: raising the usage cap to 2^22 did NOT trip the "
              "ITSR floor guardrail -> the gate is vacuous")
        return 1
    print("  ok: raising MAX_SLOT_USES to 2^22 is caught (ITSR term < 96-bit floor)")

    # negative control #3 (F4): the mixture must be an UPPER bound. Widen the
    # summation window and check the exact partial sum never exceeds what we return.
    qs = QS_CAP
    reported = b_forsc(qs)
    exact_partial = 0.0
    for g in range(0, 4000):
        d = darkside_f(g)
        if d <= 0.0:
            continue
        exact_partial += math.exp(_lbinom(qs, g, 1.0 / N_INST) + (K - 1) * math.log(d))
    exact_partial /= T_LAST
    if exact_partial > reported * (1.0 + 1e-12):
        print(f"  self-test FAIL: mixture {reported:.6e} is BELOW a wider exact "
              f"partial sum {exact_partial:.6e} -- not an upper bound")
        return 1
    print(f"  ok: mixture is an upper bound (wide partial {exact_partial:.4e} "
          f"<= reported {reported:.4e})")
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
    real_bits, red_bits, itsr_fail = itsr_report(QS_CAP, WORK_FLOOR_BITS)
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
