# FV pilot — seed-split single-chip leak, quantitative bound (F10) — 2026-07-17

> **Scope, first (F9).** A kernel-checked quantitative refinement of the deployed
> single-chip leak in the dual-SE XOR seed split (invariant #1). It packages the
> existing combinatorial lemmas into the excluded-set cardinality and turns the
> prose "Δ ≤ 2⁻²⁵⁶" into an explicit pinned quantity. It stays information-theoretic
> counting; the mask-uniformity premise (Scope §1 of `SplitSecrecy.lean`) remains a
> hardware assumption, and `master_secret` co-residence (Scope §3) is out of frame.

## The question (F10 / SIMPLIFY)

`Crypto/SplitSecrecy.lean` already proves the exact combinatorial content of the
deployed single-chip leak — an observed `half_E = v` is consistent with every
entropy `e ≠ v` via a nonzero mask (`halfE_deployed_consistent`) and excludes `v`
because its only explaining mask is the firmware-rejected all-zero one
(`halfE_deployed_excludes_self`). But the security reading "distinguishing
advantage ≤ 2⁻²⁵⁶" lived only in PROSE (comments, lines 27/52/194). The review
asked: add an explicit Lean lemma bounding the statistical distance by 2⁻²⁵⁶ and
cite it from the CryptoVerif full-space ideal — the same honest-quantification the
OC2 cross-hash pilot did.

## Correctness check first (the load-bearing fact)

The 2⁻²⁵⁶ bound rests on the deployed code actually rejecting the all-zero mask (so
the excluded set is the singleton `{v}`, not larger). Confirmed: `dual_se.rs:131`
`if acc == 0 { … "half_o stuck at zero — FI suspected" … }` fails closed on an
all-zero `half_O` mask. So the deployed mask is uniform over the `2²⁵⁶ − 1` nonzero
values, and exactly one entropy (`v`) is excluded per observation. ✓

## The refinement (`Crypto/SplitSecrecy.lean`, new § Quantitative deployed-leak bound)

1. **`halfE_deployed_excluded_iff`** — packages the two existing deployed lemmas
   into one statement: for an observed `half_E = v`, an entropy `e` is EXCLUDED (no
   nonzero mask explains it) IFF `e = v`. So the excluded set is EXACTLY the
   singleton `{v}`, cardinality 1. (Kernel-only `[propext, Quot.sound]`; proved
   with core tactics only — this project is mathlib-free, so `by_contra`/`obtain`
   are unavailable; used `by_cases` + `absurd` + `subst` + the existing private XOR
   lemmas `xor_cancel_left` / `xor_eq_zero_imp_eq`.)
2. **The quantitative floor** — `SplitLeakExcludedCount = 1`,
   `SplitEntropySpace = 2²⁵⁶`, and `splitLeak_advantage_floor :
   SplitLeakExcludedCount · 2²⁵⁶ ≤ SplitEntropySpace` — the log-domain encoding of
   `distance = |excluded| / |space| = 1 / 2²⁵⁶ ≤ 2⁻²⁵⁶` (`excludedCount · 2^t ≤
   space  ⟺  distance ≤ 2⁻ᵗ`, exact at `t = 256`). No axioms.
3. **Anti-vacuity** — `splitLeak_floor_tight : ¬ (2 · 2²⁵⁶ ≤ 2²⁵⁶)`: a leak of even
   one MORE excluded value would violate the floor, so the singleton cardinality
   from lemma 1 is load-bearing (not an accidentally-true `≥ 0`). No axioms.

## What this establishes (and its honest ceiling)

- **The deployed leak is now a pinned quantity**, not prose: exactly 1 of 2²⁵⁶
  entropies excluded ⟹ statistical distinguishing advantage ≤ 2⁻²⁵⁶. It COMPOSES
  with the CryptoVerif full-space uniform-pad ideal (exact 0 advantage over the full
  2²⁵⁶ mask space): the deployed nonzero-mask rule is that ideal MINUS one excluded
  point, and 2⁻²⁵⁶ is the exact statistical transfer distance.
- **Ceiling (unchanged, stated honestly).** This is information-theoretic COUNTING
  over the excluded *set*; it does not establish the mask is drawn uniformly and
  independently (Scope §1 — a hardware TRNG assumption), and it does not cover the
  `master_secret` computational co-residence (Scope §3). The `[u8;32] ↔ BitVec 256`
  modeling boundary is unchanged.

## Closure hygiene

New theorems reference NO named axioms (`halfE_deployed_excluded_iff`
`[propext, Quot.sound]`; both floor theorems: none). No existing theorem touched.
`lake build SphincsCVerify` clean; `make -C contracts/verification
verify-ledger-consistency` passes (18 closures / 17 axioms unchanged — the new
symbols enter no tracked closure).

## Files

- `contracts/verification/lean/SphincsCVerify/Crypto/SplitSecrecy.lean` — new
  § Quantitative deployed-leak bound (`halfE_deployed_excluded_iff`,
  `SplitLeakExcludedCount`, `SplitEntropySpace`, `splitLeak_advantage_floor`,
  `splitLeak_floor_tight`).
