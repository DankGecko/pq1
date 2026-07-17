/-
Combinatorial core of the dual-SE XOR seed split (invariant #1, secrecy layer).

## What this proves — and, just as importantly, what it does NOT

CLAUDE.md invariant #1 ("Dual-chip seed split") XOR-splits the 32-byte BIP-39
entropy into `half_O` (OPTIGA Trust M, a fresh mask) and `half_E` (SE050,
`entropy XOR half_O`), so `entropy = half_O XOR half_E` (`secure/src/dual_se.rs`,
`xor_32`). The architectural claim is "neither chip alone reveals any bit of the
seed" (`dual_se.rs:5`). This file formalises the SOUND, kernel-checkable part of
that claim — the one-time-pad **combinatorial core** — and is scrupulous about
the parts it does not reach.

### What IS proven (kernel-clean, mathlib-free, unconditional `BitVec` algebra)

* `reconstruct` — `half_O XOR half_E = entropy` (faithfulness anchor: the model's
  split inverts to the firmware's `unlock` reconstruction).
* `halfE_unique_mask` / `halfO_unique_mask` — over the FULL mask space, exactly
  one mask explains any observed half value, for EVERY entropy: the
  exactly-one-key counting structure underlying perfect secrecy.
* `halfE_pushforward_bijective` / `halfO_pushforward_bijective` — the mask ↦ half
  map is a bijection, so a *uniform* mask pushes forward to a *uniform* half.
* `halfE_deployed_consistent` / `halfE_deployed_excludes_self` — the FAITHFUL
  firmware statement (the deployed mask is nonzero, see §Caveats): an observed
  `half_E = v` is consistent with every entropy EXCEPT `v`, and excludes exactly
  `v`. So the deployed leak is the single bit "entropy ≠ v" — statistical secrecy
  with distinguishing advantage ≤ 2⁻²⁵⁶.
* `joint_determines_entropy` / `dual_split_2of2_structure` — both halves together
  pin the entropy uniquely (the share is genuinely 2-of-2, not a collapse).

### Scope and assumptions — what is NOT proven here (read before citing)

1. **The mask must be UNIFORM and INDEPENDENT of the entropy.** Perfect (Shannon)
   secrecy of a one-time pad needs (a) the exactly-one-key/bijection facts proven
   here AND (b) the key (mask) drawn uniformly, independent of the secret. This
   file proves ONLY (a) — unconditional combinatorial facts over the *set* of
   masks; it says nothing about the mask *distribution*. With a broken constant
   mask (`mask = 0`) the SE050 half equals the entropy verbatim, yet every lemma
   below still holds. So these lemmas are NECESSARY-not-sufficient for secrecy;
   (b) is discharged by the firmware TRNG (`generate_split_half`, the 3-source
   STM32⊕OPTIGA⊕SE050 mix) and is a HARDWARE assumption, not a theorem here.
   ("marginally uniform *iff* mask uniform+independent" — fv-soundness-roadmap.)
   A measure-theoretic / mathlib probability proof of (b) is deliberately out of
   scope for this mathlib-free file.

2. **Caveat — the deployed mask is NONZERO, so halfE secrecy is STATISTICAL, not
   exact.** `generate_split_half` fails closed on the all-zero mask
   (`dual_se.rs:130`, an FI countermeasure preventing the degenerate
   `half_E = entropy`). So the deployed mask is uniform over the 2²⁵⁶−1 nonzero
   values, NOT the full space. The `*_unique_mask` lemmas state the idealised
   FULL-space (exact) version; the `halfE_deployed_*` lemmas state the faithful
   firmware version, whose leak is exactly one excluded entropy (Δ ≤ 2⁻²⁵⁶). The
   halfO side (`halfO = mask`) carries zero entropy information regardless of the
   nonzero constraint, so it is exact either way.

3. **Out of scope — `master_secret` co-residence.** Each chip ALSO stores
   `master_secret = KDF("sphincs-master", entropy)` (`dual_se.rs:11-16`,
   `provision` lines 180/185), encrypted under its own per-SE PIN / AES-GCM.
   Since `master_secret` is a deterministic image of the FULL entropy, absolute
   single-chip secrecy against an unbounded extraction adversary rests ALSO on
   the COMPUTATIONAL confidentiality of `master_secret` (SHA-256 preimage
   resistance + the per-SE encryption / PIN gate) — NOT on this information-
   theoretic split alone. This file covers the XOR *half* only.

This is the information-theoretic (and therefore SOUND) counterpart to any
symbolic Dolev-Yao XOR model: computationally-sound symbolic XOR is provably
impossible (Unruh, IACR ePrint 2010/389), so the secrecy of an XOR split must be
argued by counting at the layer that owns it — which is what this file does.

### Faithfulness to the firmware

The firmware XORs two 32-byte arrays byte-by-byte (`dual_se.rs::xor_32`); modeled
as `BitVec 256` (bitwise XOR of one 256-bit word = byte-wise XOR of the 32-byte
representation; the byte grouping is a pure bijective re-indexing, no endianness
dependence). That `[u8;32] ↔ BitVec 256` correspondence is a documented modeling
boundary (sound, not separately mechanised here). `∃!`/`Bijective` are spelled
out (`UniqueMask`/`Bij`) — the project is mathlib-free and the explicit forms are
clearer. The single `by decide` (in `halfE_nondegenerate`) is over the literal
constants `0`/`1`, NOT over any secret/mask variable; everything else is core
`BitVec` XOR algebra (no solver, no `bv_decide`, kernel reduction only).
-/

namespace SphincsCVerify.Crypto.SplitSecrecy

/-- Entropy / mask / half width: the 256-bit (32-byte) BIP-39 entropy. -/
abbrev Half := BitVec 256

/-- OPTIGA-side half = the fresh mask (`half_O`). -/
def halfO (mask : Half) : Half := mask

/-- SE050-side half = `entropy XOR half_O` (`half_E`, `dual_se.rs:9`). -/
def halfE (entropy mask : Half) : Half := entropy ^^^ mask

/-- Exactly one mask satisfies `P` (mathlib-free `∃!`). -/
def UniqueMask (P : Half → Prop) : Prop := ∃ m, P m ∧ ∀ m', P m' → m' = m

/-- `f` is a bijection on masks (mathlib-free `Function.Bijective`):
    injective and surjective. -/
def Bij (f : Half → Half) : Prop :=
  (∀ a b, f a = f b → a = b) ∧ (∀ v, ∃ a, f a = v)

/-! ## Core XOR algebra (the only facts the proofs use) -/

/-- `a ^^^ (a ^^^ b) = b`. The self-inverse identity every statement below rests
    on; proved from core `BitVec` lemmas (no solver, no `decide`). -/
private theorem xor_cancel_left (a b : Half) : a ^^^ (a ^^^ b) = b := by
  rw [← BitVec.xor_assoc, BitVec.xor_self, BitVec.zero_xor]

/-- `a ^^^ b = 0 → a = b` (XOR is its own inverse). Used to show `e ^^^ v ≠ 0`
    from `e ≠ v` in the deployed (nonzero-mask) secrecy lemmas. -/
private theorem xor_eq_zero_imp_eq (a b : Half) (h : a ^^^ b = 0) : a = b := by
  have hc : a ^^^ (a ^^^ b) = b := xor_cancel_left a b
  rw [h] at hc
  simpa using hc

/-! ## Reconstruction (faithfulness anchor) -/

/-- **Reconstruction correctness.** Both halves together recover the entropy
    exactly — `half_O XOR half_E = entropy` (`dual_se.rs:9`, the `unlock`
    reconstruction `xor_32(half_o, half_e)`). Anchors the model to the firmware. -/
theorem reconstruct (entropy mask : Half) :
    halfO mask ^^^ halfE entropy mask = entropy := by
  unfold halfO halfE
  rw [BitVec.xor_comm entropy mask, xor_cancel_left]

/-! ## Combinatorial core: exactly-one-mask (idealised full mask space)

These are the counting facts underlying one-time-pad secrecy. They hold over the
FULL mask space; the security reading ("leaks no bit") additionally needs the
mask uniform+independent (Scope §1) — these lemmas do NOT establish that, only
the exactly-one-key structure it builds on. -/

/-- **Exactly one mask explains an observed `half_E`, for every entropy** (full
    mask space). For every entropy `e` and observed `v` there is a unique mask
    (`e ^^^ v`). Equinumerous across entropies ⇒ the counting precondition for
    perfect secrecy — but ONLY perfect secrecy once the mask is uniform (Scope
    §1), and only over the full space (the deployed mask is nonzero, Scope §2). -/
theorem halfE_unique_mask (e v : Half) : UniqueMask (fun m => halfE e m = v) := by
  refine ⟨e ^^^ v, ?_, ?_⟩
  · show e ^^^ (e ^^^ v) = v
    exact xor_cancel_left e v
  · intro m hm
    show m = e ^^^ v
    rw [← (show e ^^^ m = v from hm)]
    exact (xor_cancel_left e m).symm

/-- **Exactly one mask explains an observed `half_O`.** `half_O` is the mask
    itself, so the observation determines the mask (`v`); the entropy `_e` does
    not occur. NOTE: this expresses mask-determinability, not directly entropy
    secrecy — `half_O` leaks no entropy bit because the *other* half is
    unobserved and the mask is independent of the entropy (Scope §1), neither of
    which this lemma states. -/
theorem halfO_unique_mask (_e v : Half) : UniqueMask (fun m => halfO m = v) := by
  refine ⟨v, rfl, ?_⟩
  intro m hm
  exact hm

/-- **Equiconsistency across entropies** (full mask space). Any two candidate
    entropies are each explained by exactly one mask — the *equal-count* counting
    precondition for secrecy. This is NOT a posterior/Shannon claim: equal counts
    yield equal posteriors only once the mask is uniform (Scope §1); this lemma
    has no probabilistic content. -/
theorem halfE_equiconsistent (e1 e2 v : Half) :
    UniqueMask (fun m => halfE e1 m = v) ∧ UniqueMask (fun m => halfE e2 m = v) :=
  ⟨halfE_unique_mask e1 v, halfE_unique_mask e2 v⟩

/-! ## Distributional form: uniform mask ⇒ uniform half -/

/-- The mask ↦ `half_E` map is a bijection for every fixed entropy, so a uniform
    mask pushes forward to a uniform `half_E` independent of the entropy (the
    distributional one-time-pad statement — given a uniform mask, Scope §1). -/
theorem halfE_pushforward_bijective (e : Half) : Bij (halfE e) := by
  refine ⟨?_, ?_⟩
  · intro m1 m2 h
    have h2 : e ^^^ (e ^^^ m1) = e ^^^ (e ^^^ m2) := by
      show e ^^^ halfE e m1 = e ^^^ halfE e m2
      rw [h]
    rwa [xor_cancel_left, xor_cancel_left] at h2
  · intro v
    exact ⟨e ^^^ v, xor_cancel_left e v⟩

/-- `half_O` is the identity on the mask, hence a bijection. -/
theorem halfO_pushforward_bijective : Bij halfO := by
  refine ⟨?_, ?_⟩
  · intro m1 m2 h; exact h
  · intro v; exact ⟨v, rfl⟩

/-! ## Faithful deployed statement: the firmware mask is NONZERO

`generate_split_half` rejects the all-zero mask (`dual_se.rs:130`). The two
lemmas below characterise the deployed leak EXACTLY: an observed `half_E = v` is
consistent with every entropy except `v`, and `v` is the unique excluded one. So
a single-chip `half_E` observation reveals exactly the one bit "entropy ≠ v" — a
statistical distinguishing advantage of ≤ 2⁻²⁵⁶ (one value out of 2²⁵⁶), not the
exact zero of the idealised full-space lemmas. -/

/-- **Deployed: every entropy other than `v` stays consistent.** For `e ≠ v`
    there is a NONZERO mask (`e ^^^ v`) with `half_E = v` — so the deployed
    observation does not rule out any entropy except possibly `v`. -/
theorem halfE_deployed_consistent (e v : Half) (hev : e ≠ v) :
    ∃ m, m ≠ 0 ∧ halfE e m = v := by
  refine ⟨e ^^^ v, ?_, xor_cancel_left e v⟩
  intro h0
  exact hev (xor_eq_zero_imp_eq e v h0)

/-- **Deployed: `entropy = v` is excluded.** `half_E = v` under entropy `v`
    forces the mask to be all-zero — which the firmware never emits. So observing
    `half_E = v` rules out exactly the single entropy `v` (and no other). -/
theorem halfE_deployed_excludes_self (v : Half) :
    ∀ m, halfE v m = v → m = 0 := by
  intro m hm
  have hvm : v ^^^ (v ^^^ m) = v ^^^ v := by
    show v ^^^ halfE v m = v ^^^ v
    rw [hm]
  rwa [xor_cancel_left, BitVec.xor_self] at hvm

/-! ## Framing guards: 2-of-2, and non-degeneracy -/

/-- **The share is genuinely 2-of-2.** Both halves together pin the entropy
    uniquely (`halfE` is injective in the entropy for a fixed mask) — the
    single-chip secrecy above is complemented by full recovery from the pair. -/
theorem joint_determines_entropy (e1 e2 mask : Half)
    (h : halfE e1 mask = halfE e2 mask) : e1 = e2 := by
  have h1 : mask ^^^ halfE e1 mask = mask ^^^ halfE e2 mask := by rw [h]
  unfold halfE at h1
  rw [BitVec.xor_comm e1 mask, BitVec.xor_comm e2 mask,
      xor_cancel_left, xor_cancel_left] at h1
  exact h1

/-- **Non-degeneracy guard (entropy axis).** `half_E` genuinely depends on the
    entropy — it is not constant in its first argument — so `reconstruct`,
    `joint_determines_entropy`, and the 2-of-2 framing are about a real XOR split,
    not a degenerate map. (This guards the ENTROPY axis only; it says nothing
    about mask quality/uniformity — Scope §1. The secrecy lemmas' non-triviality
    is instead witnessed by mask-bijectivity, `halfE_pushforward_bijective`.)
    Witness: `half_E 0 0 = 0 ≠ 1 = half_E 1 0`. -/
theorem halfE_nondegenerate :
    ∃ e1 e2 mask : Half, halfE e1 mask ≠ halfE e2 mask :=
  ⟨0, 1, 0, by decide⟩

/-- **Invariant #1 combinatorial core, packaged.** Both halves recover the
    entropy, and each half alone admits exactly one mask per observation (the
    counting core of single-chip secrecy — see Scope §1–3 for the assumptions
    that turn this into a security statement). -/
theorem dual_split_2of2_structure (entropy mask : Half) :
    halfO mask ^^^ halfE entropy mask = entropy
    ∧ (∀ v, UniqueMask (fun m => halfE entropy m = v))
    ∧ (∀ v, UniqueMask (fun m => halfO m = v)) :=
  ⟨reconstruct entropy mask,
   fun v => halfE_unique_mask entropy v,
   fun v => halfO_unique_mask entropy v⟩

/-! ## Quantitative deployed-leak bound (F10): single-chip advantage ≤ 2⁻²⁵⁶

The `halfE_deployed_*` lemmas above characterise the deployed single-chip leak
combinatorially. This section (a) PACKAGES them into the excluded-set cardinality
— an observed `half_E = v` excludes exactly the singleton entropy `{v}` — and (b)
turns the prose "Δ ≤ 2⁻²⁵⁶" (lines 27/52/194) into an explicit kernel-pinned
quantity, mirroring the cross-function-separation floor in `Crypto/Quantitative.lean`.
It COMPOSES with — does not replace — the CryptoVerif full-space uniform-pad ideal
(exact 0 advantage over the FULL 2²⁵⁶ mask space): the deployed nonzero-mask rule
is that ideal MINUS one excluded point, and this is the exact statistical transfer
distance. Still an information-theoretic counting statement; the mask-uniformity
premise (Scope §1) stays a hardware assumption. -/

/-- **Deployed excluded-set characterisation (F10).** For an observed `half_E = v`,
    an entropy `e` is EXCLUDED (no NONZERO mask explains the observation) IFF
    `e = v`. Packages `halfE_deployed_excludes_self` (v is excluded — its only mask
    is the forbidden `0`) with `halfE_deployed_consistent` (every `e ≠ v` stays
    consistent via a nonzero mask) into one statement: the excluded set is EXACTLY
    the singleton `{v}`, cardinality 1. This is the load-bearing combinatorial fact
    the 2⁻²⁵⁶ floor below rests on. -/
theorem halfE_deployed_excluded_iff (e v : Half) :
    (∀ m, m ≠ 0 → halfE e m ≠ v) ↔ e = v := by
  constructor
  · intro hexcl
    -- The mask `e ^^^ v` produces the observation `v`; if it were nonzero, `hexcl`
    -- would forbid it — so it is the (rejected) zero mask, i.e. `e = v`.
    have hobs : halfE e (e ^^^ v) = v := xor_cancel_left e v
    have hz : e ^^^ v = 0 := by
      by_cases h : e ^^^ v = 0
      · exact h
      · exact absurd hobs (hexcl (e ^^^ v) h)
    exact xor_eq_zero_imp_eq e v hz
  · intro hev m hm0 hmv
    subst hev
    exact hm0 (halfE_deployed_excludes_self e m hmv)

/-- The number of entropies the deployed single-chip `half_E` observation excludes:
    exactly ONE (the singleton `{v}`, `halfE_deployed_excluded_iff`). -/
def SplitLeakExcludedCount : Nat := 1

/-- The entropy-space cardinality — `2²⁵⁶` (a 256-bit / 32-byte BIP-39 seed). -/
def SplitEntropySpace : Nat := 2 ^ 256

/-- **Deployed single-chip statistical distinguishing-advantage floor (F10).** The
    leak is `|excluded| / |space| = 1 / 2²⁵⁶`, i.e. bounded by `2⁻²⁵⁶`. In the
    log-domain encoding `excludedCount · 2^t ≤ space  ⟺  distance ≤ 2⁻ᵗ`, this is
    the exact `t = 256` floor. Kernel-pinned counterpart to the prose bound;
    composes the CryptoVerif full-space ideal (exact 0) with the one-excluded-point
    deployed rule. -/
theorem splitLeak_advantage_floor :
    SplitLeakExcludedCount * 2 ^ 256 ≤ SplitEntropySpace := by
  unfold SplitLeakExcludedCount SplitEntropySpace; decide

/-- **Anti-vacuity: the floor is TIGHT at the true excluded count.** With the
    actual `|excluded| = 1` the bound holds with equality; a leak of even ONE more
    excluded value (`2`) would VIOLATE the 2⁻²⁵⁶ floor (`2 · 2²⁵⁶ > 2²⁵⁶`). So the
    singleton cardinality from `halfE_deployed_excluded_iff` is load-bearing — the
    floor is not an accidentally-true `≥ 0`. -/
theorem splitLeak_floor_tight :
    ¬ (2 * 2 ^ 256 ≤ SplitEntropySpace) := by
  unfold SplitEntropySpace; decide

/-- **How the count binds to the cardinality (honest wiring).** The two floor
    theorems above are `Nat` arithmetic over the literal `SplitLeakExcludedCount = 1`;
    this mathlib-free file has no `Finset.card` object to MECHANICALLY equate the
    excluded-set cardinality to the `def`, so the count → distance step is
    human-mediated: `halfE_deployed_excluded_iff` PROVES the deployed excluded set is
    exactly `{v}` (an `e` is excluded iff `e = v`), and `SplitLeakExcludedCount = 1`
    records that singleton cardinality as the distance numerator. The proof content
    lives in `halfE_deployed_excluded_iff`; the floor theorems package its consequence. -/
theorem splitLeak_count_matches_singleton (e v : Half) :
    (∀ m, m ≠ 0 → halfE e m ≠ v) ↔ (e = v) :=
  halfE_deployed_excluded_iff e v

end SphincsCVerify.Crypto.SplitSecrecy
