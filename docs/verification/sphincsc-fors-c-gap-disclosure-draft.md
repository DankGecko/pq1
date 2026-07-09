# DRAFT — disclosure note to the SPHINCS+C authors (NOT SENT)

**Status: draft for review. Nothing has been sent to anyone.** Decide whether/when to send,
and to whom (suggested: Andreas Hülsing, Mikhail Kudinov, Eyal Ronen, Eylon Yogev).

**This is not a vulnerability report.** No attack is claimed. It reports a *proof gap* — a
component of a published scheme whose security is asserted informally and, as far as we can
determine, has never been reduced. We think it is worth closing; we do not think it is broken.

---

## Context

We are mechanizing the EUF-CMA security of SPHINCS+C (specifically a `C10` parameter set:
`n=16, h=18, d=2, a=11, k=13, w=8`) in EasyCrypt, on top of the
`MM45/FV-SPHINCSPLUS-EC` artifact accompanying *"A Tight Security Proof for SPHINCS+,
Formally Verified"* (Barbosa, Dupressoir, Hülsing, Meijers, Strub — ePrint 2024/910,
ASIACRYPT 2024).

We have machine-checked the **WOTS+C** leg: multi-instance `d-EU-naCMA` for WOTS+C reduces to
`S-TCR(+C)` plus MM45's actual WOTS-TW `M_EUF_GCMA_WOTSTWESNPRF` game, with no admits and no
free parameters. This matches your Theorem C.2 and the Appendix-D sketch, and we found no
problem with it.

## The gap

Working the **FORS+C** leg, we could not find a security reduction for FORS+C anywhere — in the
NIST PQC-2022 version, or in the final IEEE S&P 2023 version (DOI 10.1109/SP46215.2023.10179381).

Concretely, in the S&P version:

- The paper contains exactly two numbered theorems: **Thm 5.2** (the SPHINCS+C bound) and
  **Thm C.2** (WOTS+C one-time EU-naCMA).
- **Thm 5.2's preamble** derives the bound purely from the WOTS substitution: *"By obtaining a
  d−EU-naCMA security proof for **WOTS+C** one can just substitute WOTS-TW with our
  modification. This results in adding a S-TCR(+C) term to the security of SPHINCS+."* Its
  message-hash term remains the **plain** `InSec^itsr(Hmsg)`.
- **§IV.1 ("Security")** treats FORS+C in one paragraph: *"The security analysis is the same as
  the security analysis of FORS… There is no degradation in security for the tree,"* concluding
  *"Hence, we can use the previous ITSR analysis to bound the security of FORS+C."*
- **§V** states *"The usage of FORS+C is straightforward, but WOTS+C in SPHINCS+ requires some
  work to obtain a tight security proof."*

So FORS+C's security rests on a combinatorial `DarkSide_γ` argument
(`(DarkSide_γ)^(k−1) · 1/t' ≤ (DarkSide_γ)^k` when `t' ≥ t`), not on a reduction, and Thm 5.2 —
though labelled `InSec^EU-CMA(SPHINCS+C)` — never analyses FORS+C's effect on the ITSR term.

## Why we think it deserves a reduction

1. **The ITSR game changes shape.** FORS+C grinds a randomizer/counter until the last FORS index
   is zero, then omits that tree's authentication path. A verifier must therefore accept *any*
   randomizer satisfying the predicate — not only the one the honest signer found. Plain ITSR
   does not model that predicate, and the win condition is no longer "all `k` indices covered."

2. **A natural formalization of it is unsound.** When we first modelled FORS+C's message hash as
   a *deterministic* fold (folding the signer's counter into the message, `in_t = msg`), we got a
   game that misses a forger which supplies a **different, non-canonical but still valid**
   counter against the permissive verifier. We had to replace it with a bespoke *free-counter*
   `ITSR(+C)` game. That an obvious formalization is unsound is, to us, evidence that the
   informal "same analysis" step is doing more work than it appears to.

3. **The inequality is parameter-sensitive at the boundary.** `(DarkSide_γ)^(k−1)/t' ≤
   (DarkSide_γ)^k` requires `t' ≥ t`. The paper explicitly floats making the removed tree
   *larger* (`b' > b`) for extra compression — that direction is safe. But the inequality
   **inverts** if the removed tree is ever made smaller, and nothing in the text flags that as a
   hard constraint rather than a tuning knob. (Our own parameter set sits exactly on the
   equality boundary, `t' = t = 2^11`; we now gate on `t' ≥ t` in CI.)

To be explicit: for our parameters we computed that FORS+C is **never weaker** than plain FORS
(equal at `γ = 1`, better by `≈ log2 γ` bits beyond), which is consistent with your claim. Our
concern is the absence of a reduction, not a belief that the claim is false.

## What we are asking

1. Is there a FORS+C security reduction we have missed — in a later revision, a full version, or
   unpublished notes?
2. If not: would you agree that Thm 5.2, as stated, covers SPHINCS+ with WOTS-TW → WOTS+C
   substituted, and that the FORS+C substitution's effect on the `InSec^itsr(Hmsg)` term is
   argued only informally?
3. Is the constraint `t' ≥ t` intended as a hard security requirement?

We are happy to share our EasyCrypt development (WOTS+C leg complete and admit-free; FORS+C
`ITSR(+C)` hop proven, tree layer and composition open) if useful.

---

### Internal notes (strip before sending)

- Our evidence lives in `docs/verification/easycrypt-euf-cma-port-feasibility-2026-07.md`
  (§UPDATE 2026-07-09) and `~/repos/c10-eufcma-port`.
- The `t' ≥ t` guardrail is `make -C contracts/verification verify-forsc-margin`.
- Do **not** frame this as a vulnerability disclosure; it is a proof-gap report. There is no
  known attack, and our own numbers support the paper's qualitative claim.
- Sending is a judgement call for the maintainer. It is outward-facing and, once sent, not
  retractable.
