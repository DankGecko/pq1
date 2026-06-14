/-
Cryptographic assumptions used by the SPHINCS+C10 security argument.

This file is the **TCB declaration** for everything cryptographic. Each
`axiom` corresponds to a real, peer-reviewed cryptographic assumption
about SHA-256. Every axiom in this file is reflected in
`docs/AXIOMS.md` with a citation.

The Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT 2024 paper
"A Tight Security Proof for SPHINCS+, Formally Verified"
proves EUF-CMA for SPHINCS+ in EasyCrypt under:

  * `SM-DT-TCR` on F (single-function multi-target distinct-tweak
    target-collision resistance), the chain-step tweakable hash.
  * `ITSR` (Interleaved Target Subset Resilience) on the FORS-roots
    compression hash.
  * `H_msg` modelled as a random oracle.

For **SPHINCS+C** (Hülsing et al. PQC2022) the same modular structure
applies; the WOTS+C and FORS+C variants change only how digit-search /
forced-zero is performed *outside* the hash-collision argument.
Extending the Barbosa et al. development from SPHINCS+ to SPHINCS+C is
the rigorous-but-multi-month path; we take the pragmatic path and
axiomatise the resulting bound with citations.

## Formalisation strategy

Lean 4 + mathlib does not (yet) have a production-grade game-based
cryptography library comparable to EasyCrypt's `pRHL` and `phl`
modules. Rather than introduce a probability theory backbone, we treat
each cryptographic assumption as an OPAQUE proposition (2026-06-14
reconciliation): the three hardness shapes (`SM_DT_TCR_F_Shape` etc.)
are `opaque Prop`s witnessed by their axioms, and the operative
assumptions are stated as REDUCTIONS to the opaque `BreaksHash` token
(an EUF-CMA forgery ⇒ `BreaksHash`; a same-length SHA-256 collision ⇒
`BreaksHash`). This is consistent — no `∀_,True` placeholders, no
literally-false injectivity — and `BreaksHash` is never assumed false. A
future EasyCrypt-style port would replace these with `Pr[Game(A)] ≤
ε(A)` real-valued inequalities.

The downstream chain in `Crypto/EUFCMA.lean` is:

  `EUF_CMA_SPHINCSplusC` takes the three primitives as preconditions
  and yields a "no forgery" conclusion in deterministic-adversary form.
  `cannot_forge_without_breaking_SHA256` applies it. The dep closure of
  the latter contains all four crypto axioms by reference.
-/

import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Params

namespace SphincsCVerify.Crypto

open SphincsCVerify.Spec
open ByteVec

/-! ## A. Behavioural axioms about `sha256`. -/

/-- SHA-256 is deterministic: same input → same output. This is true by
    `def` (the opaque is a single-valued function); we restate it for
    documentation. -/
theorem sha256_deterministic (xs : List ByteSeg) :
    sha256 xs = sha256 xs := rfl

/-! ## B. Cryptographic-hardness axioms.

The probability spaces here are over the random coins of a probabilistic
polynomial-time (PPT) adversary `A` and over the SHA-256 random oracle.
We do not formalise probability theory in this file; the spec form is
"A has negligible advantage" treated as a `Prop` argument. A future
EasyCrypt-style port would replace these with `Pr[Game(A)] ≤ ε(A)`
real-valued inequalities. -/

/-- The bound is "negligible" — for our purposes, a function of the
    security parameter `n = 128` (bits) that we treat as the constant
    `2^-128`-class quantity. Production deployments inherit this from
    Hülsing PQC2022 Table 2 (SPHINCS+-128f / 128s analogues). -/
def negligible : Nat := 1 <<< 128  -- ≥ 2^128, the inverse of the bound

/-- **Opaque SHA-256 hardness-break token.** The shared conclusion of every
    cryptographic reduction in this development (an EUF-CMA forgery, or a
    SHA-256 same-length collision): "one of the cited SHA-256 hardness
    assumptions was broken." Opaque — concludable, never refutable.
    **INVARIANT: never assume `¬ BreaksHash`** (that re-introduces the
    inconsistency the 2026-06-14 reconciliation fixed). Lives here (rather than
    in `EUFCMA.lean`) so the EUF-CMA reduction and the collision-resistance
    axiom share one token. -/
opaque BreaksHash : Prop

/-! ### Spec-level signature shapes for the three primitives.

These type aliases pin the call shape of the three SHA-256 assumptions.
Downstream consumers (notably `EUF_CMA_SPHINCSplusC`) take them as
preconditions so the axioms are threaded into the dependency closure
of any theorem that uses EUF-CMA. -/

/-- The functional type of an SM-DT-TCR-F witness: a Prop-valued
    statement parametric in the SHA-256 inputs the assumption ranges
    over. The witness is the axiom `SM_DT_TCR_F` below; downstream
    consumers take values of this type as preconditions. -/
opaque SM_DT_TCR_F_Shape : Prop

/-- Functional type of an ITSR-F witness. -/
opaque ITSR_F_Shape : Prop

/-- Functional type of an `H_msg`-RO witness. -/
opaque hMsg_RO_Shape : Prop

/-- **SM-DT-TCR on F (the chain step tweakable hash).**

    For any PPT adversary `A` and any positive number of targets `q`,
    the probability of producing a distinct-tweak target collision on
    `F(pkSeed, ADRS, x) = sha256(pkSeed ‖ ADRS ‖ x)[0..N]` is bounded
    by `q * 2^-n + q^2 / 2^n` (the multi-target generic-attack bound)
    plus a negligible adversary advantage `ε_TCR(A)`.

    In Lean we state the property as an axiom witness over the
    parametric Prop `SM_DT_TCR_F_Shape`. A full game-based treatment
    would replace `True` with the probability inequality.

    Cited from Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT 2024
    (IACR ePrint 2024/910) §§ 4-5, Theorem 1. -/
axiom SM_DT_TCR_F : SM_DT_TCR_F_Shape

/-- **ITSR (Interleaved Target Subset Resilience) on the FORS-roots
    compression hash.**

    Central to the tight SPHINCS+ bound. Given access to a polynomial
    number of FORS public keys, no PPT adversary can construct a
    message `m*` whose `H_msg`-derived FORS leaf indices have been
    collectively covered by prior queries — except with negligible
    probability.

    Cited from Barbosa et al. ASIACRYPT 2024 § 6, Theorem 2. -/
axiom ITSR_F : ITSR_F_Shape

/-- **Random-oracle behaviour of `H_msg`.**

    For the security argument, `hMsg seed root R message` is modelled
    as a fresh uniform 32-byte string for each new input. The Barbosa
    et al. proof shows this assumption is necessary for the tight
    bound (it can be relaxed to "indistinguishable from random" but
    the bound loosens).

    Cited from Barbosa et al. ASIACRYPT 2024 § 7. -/
axiom hMsg_random_oracle : hMsg_RO_Shape

/-! ## C. Named corollaries used by wallet-level theorems. -/

/-- **SHA-256 collision-resistance (reduction form).**

    For any two segment lists whose flattened byte arrays have the same
    length, if their SHA-256 digests match then EITHER the flattened arrays
    are equal OR a SHA-256 hardness assumption was broken (`BreaksHash`).

    This is the honest, CONSISTENT rendering (2026-06-14): literal injectivity
    (`… → flatten segs1 = flatten segs2`) is mathematically FALSE — by
    pigeonhole, two distinct same-length inputs longer than 32 bytes must
    collide. So an unconditional "equal digests ⟹ equal preimages" axiom is a
    false proposition (latent-inconsistent; it would detonate under mathlib's
    pigeonhole). The reduction form is true: a distinct-same-length collision
    IS a collision-resistance break, so it lands in the `BreaksHash` disjunct;
    when no collision occurs, the equal-preimage disjunct holds. `BreaksHash`
    is the cited-infeasible branch (Barbosa et al. 2024 SM-DT-TCR, empty-ADRS
    unkeyed collision-resistance), never assumed false.

    Claim 1's `sphincsDigest_field_binding` propagates the disjunct: equal
    `sphincsDigest(op)` digests imply equal preimages — unless SHA-256 is
    broken. -/
axiom sha256_collision_resistance :
    ∀ (segs1 segs2 : List ByteSeg),
      (ByteSeg.flatten segs1).size = (ByteSeg.flatten segs2).size →
      sha256 segs1 = sha256 segs2 →
      ByteSeg.flatten segs1 = ByteSeg.flatten segs2 ∨ BreaksHash

end SphincsCVerify.Crypto
