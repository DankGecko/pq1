/-
Quantitative security margin of the SPHINCS+C10 usage caps.

## What this file adds

The headline theorem `theft_free` (and the `Crypto/` block it rests on) is
*qualitative*: a balance-decreasing UserOp implies a verifying C10 signature,
and any EUF-CMA forgery implies `BreaksHash` (the opaque "a cited SHA-256
hardness assumption was broken" token). It says nothing numeric about *how
hard* `BreaksHash` is at the parameters and usage caps PQSigner OS actually
ships.

This module formalises that missing quantitative layer — the arithmetic that
justifies why `MAX_SLOT_USES = MAX_BOOTSTRAP_USES = 2^16` is a safe cap — by
turning the two bounds the project ALREADY cites in prose into Lean-kernel-
checked `Nat` inequalities.

It is deliberately **mathlib-free** and **kernel-clean** (`decide` only, no
`native_decide`, so no `ofReduceBool`/compiler trust enters the ledger). A full
real-valued / probability-monad treatment (`Pr[Game(A)] ≤ ε`) is the standing
EasyCrypt-style follow-up noted in `Crypto/Assumptions.lean`; what is done here
is the *log-domain* skeleton of that bound — exact for the query- and
parameter-dependent (information-theoretic, generic-attack) terms, which are
precisely the terms a usage cap controls. The residual `ε(A)` adversary-advantage term stays
the cited cryptographic-hardness assumption (`BreaksHash`), unquantified by
design.

## The two cited bounds (both already in-repo)

1. **EUF-CMA query term** — `docs/AXIOMS.md` (`Crypto.EUF_CMA_SPHINCSplusC`):
       Adv_EUF-CMA(A) ≤ ε(A) + Q · 2^-128         (Q = signing queries / key)
   Here `Q` is unambiguously the number of signatures produced under one key —
   exactly the quantity invariant #9's combined cap bounds by `MAX_SLOT_USES`.

2. **SM-DT-TCR generic multi-target term** — `Crypto/Assumptions.lean` (the
   `SM_DT_TCR_F` doc-comment, lines 113-115):
       Adv_SM-DT-TCR(A) ≤ ε_TCR(A) + q · 2^-n + q^2 · 2^-n,     n = 8·N bits
   the generic (birthday) part being `(q + q^2) · 2^-n`.

## Log-domain encoding

For a target floor `2^-t`, the predicate `term ≤ 2^-t` is, after multiplying
through by `2^n`, the `Nat` inequality `(numerator) · 2^t ≤ 2^n`. So:

   `Q · 2^-128 ≤ 2^-t`            ⟺  `Q · 2^t ≤ 2^128`
   `(q + q^2) · 2^-128 ≤ 2^-t`    ⟺  `(q + q^2) · 2^t ≤ 2^128`

These are closed `Nat` facts the kernel decides directly.

## Margin table (proved below)

| usage `q`                     | EUF-CMA `Q·2⁻¹²⁸`   | generic `(q+q²)·2⁻¹²⁸` |
|-------------------------------|---------------------|------------------------|
| per-slot cap  `2^16`          | ≤ 2⁻¹¹²             | ≤ 2⁻⁹⁵  (q² term ≤2⁻⁹⁶)|
| bootstrap cap `2^16`          | ≤ 2⁻¹¹²             | ≤ 2⁻⁹⁵                 |
| lifetime per-chain `2^32`     | ≤ 2⁻⁹⁶              | ≤ 2⁻⁶³                 |

The operative single-key bound is the EUF-CMA `≤ 2⁻¹¹²` at `q = 2^16`; the
`2^32` row is the aggregate per-chain transaction budget (CLAUDE.md
"≈2^32 txns/chain") across *independently-capped* keys, shown for completeness.
-/

import SphincsCVerify.Spec.Params

namespace SphincsCVerify.Crypto.Quantitative

open SphincsCVerify.Spec

/-! ## Security parameter, in bits -/

/-- The truncated-hash security parameter `n`, in **bits**: the spec truncates
    every tweakable hash to `N = 16` bytes, i.e. `8 · N = 128` bits. This is the
    `n` in the SM-DT-TCR generic bound `q·2⁻ⁿ + q²·2⁻ⁿ`. -/
def SecurityBits : Nat := 8 * Spec.N

theorem securityBits_eq : SecurityBits = 128 := by decide

/-- The lifetime per-chain transaction budget (CLAUDE.md: "≈ 2^32 txns/chain,
    well inside the C10 birthday margin"). Not a single-key count — it is the
    aggregate across all independently-`MAX_SLOT_USES`-capped slot keys. -/
def LifetimeBudgetPerChain : Nat := 1 <<< 32

theorem lifetimeBudget_eq : LifetimeBudgetPerChain = 4294967296 := by decide

/-! ## General monotone margin lemmas

A usage cap `C` is useful precisely because it bounds *every* admissible query
count `q ≤ C`. These two lemmas carry a margin proved at the cap down to any
`q` under it. The cap itself is enforced AT RUNTIME by the deployed bytecode
(Solidity-0.8 checked arithmetic on `slotUses[i] + offchainSigCount[i]`,
reverting on overflow); the monotonicity building blocks
(`MultiOwnable.bumpSlot_monotonic`, the P3 cross-counter preservation lemmas) +
the per-step `combinedCap_inductive` are kernel facts, but a full
`Reachable → q ≤ C` Lean theorem is not yet assembled (its reachability is
currently backed by the Foundry invariant fuzz test — see P1 note on
`theft_free_bytecode`). So the floor below holds for every state SATISFYING the
cap; "for all reachable states" rests on the runtime cap, not (yet) a single
kernel reachable-state theorem. -/

/-- **EUF-CMA query-term margin is monotone in the cap.** If the linear query
    term meets the `2⁻ᵗ` floor at cap `C` (`C · 2ᵗ ≤ 2ⁿ`), it meets it for every
    `q ≤ C`. -/
theorem queryTerm_le_of_le {q C t : Nat} (hq : q ≤ C)
    (hC : C * 2 ^ t ≤ 2 ^ SecurityBits) :
    q * 2 ^ t ≤ 2 ^ SecurityBits :=
  Nat.le_trans (Nat.mul_le_mul hq (Nat.le_refl (2 ^ t))) hC

/-- **SM-DT-TCR generic-term margin is monotone in the cap.** The generic
    multi-target numerator `q + q²` is monotone in `q`, so a floor met at cap
    `C` holds for every `q ≤ C`. -/
theorem genericTerm_le_of_le {q C t : Nat} (hq : q ≤ C)
    (hC : (C + C * C) * 2 ^ t ≤ 2 ^ SecurityBits) :
    (q + q * q) * 2 ^ t ≤ 2 ^ SecurityBits :=
  Nat.le_trans
    (Nat.mul_le_mul (Nat.add_le_add hq (Nat.mul_le_mul hq hq)) (Nat.le_refl (2 ^ t)))
    hC

/-! ## Margins at the production caps (closed `Nat` facts) -/

/-- Per-slot cap: the EUF-CMA query term `Q·2⁻¹²⁸` is ≤ `2⁻¹¹²` at `Q = 2^16`
    (`2^16 · 2^112 = 2^128`). 112-bit floor from the cap alone. -/
theorem eufcma_term_at_slot_cap :
    MaxSlotUses * 2 ^ 112 ≤ 2 ^ SecurityBits := by decide

/-- Bootstrap cap: identical 112-bit floor (`MAX_BOOTSTRAP_USES = 2^16`). -/
theorem eufcma_term_at_bootstrap_cap :
    MaxBootstrapUses * 2 ^ 112 ≤ 2 ^ SecurityBits := by decide

/-- Per-slot cap: the SM-DT-TCR generic multi-target term `(q+q²)·2⁻¹²⁸` is
    ≤ `2⁻⁹⁵` at `q = 2^16`. (At `t = 96` the linear `q` summand tips it over
    `2^128`, so 95 is the exact integer floor for the combined term.) -/
theorem generic_term_at_slot_cap :
    (MaxSlotUses + MaxSlotUses * MaxSlotUses) * 2 ^ 95 ≤ 2 ^ SecurityBits := by
  decide

/-- The dominant birthday summand `q²·2⁻¹²⁸` alone clears `2⁻⁹⁶` at `q = 2^16`
    (`(2^16)² · 2^96 = 2^128`). -/
theorem birthday_term_at_slot_cap :
    (MaxSlotUses * MaxSlotUses) * 2 ^ 96 ≤ 2 ^ SecurityBits := by decide

/-- Lifetime per-chain budget (`2^32`): EUF-CMA query term ≤ `2⁻⁹⁶`. -/
theorem eufcma_term_at_lifetime_budget :
    LifetimeBudgetPerChain * 2 ^ 96 ≤ 2 ^ SecurityBits := by decide

/-- Lifetime per-chain budget (`2^32`): generic multi-target term ≤ `2⁻⁶³`
    (the birthday summand `(2^32)²·2⁻¹²⁸ = 2⁻⁶⁴` dominates; the extra linear
    summand drops the integer floor to 63). -/
theorem generic_term_at_lifetime_budget :
    (LifetimeBudgetPerChain + LifetimeBudgetPerChain * LifetimeBudgetPerChain)
      * 2 ^ 63 ≤ 2 ^ SecurityBits := by decide

/-! ## Headline: the cap enforces the floor for every reachable usage

Invariant #9's combined cap (`slotUses[i] + offchainSigCount[i] < MAX_SLOT_USES`)
keeps the per-key signing count `q` below `MAX_SLOT_USES`. That cap is enforced
at runtime by the deployed contract; the Lean `Invariants.combinedCap_inductive`
proves the `validateSignature`-step preservation (a building block toward, but
not yet, a full reachable-state theorem — see the P1 note). Composing the cap
with the monotone margin lemmas: at *every* state under the cap both cited
advantage terms sit below their
floors — the EUF-CMA query term below `2⁻¹¹²` and the generic multi-target term
below `2⁻⁹⁵` — with no appeal to the (cited, unquantified) adversary advantage
`ε(A)`. This is the quantitative companion to `theft_free`'s qualitative
"forgery ⇒ BreaksHash": it bounds the generic feasibility of the `BreaksHash`
event at PQSigner OS's shipped parameters and caps. -/
theorem advantage_floors_within_slot_cap {q : Nat} (hq : q ≤ MaxSlotUses) :
    q * 2 ^ 112 ≤ 2 ^ SecurityBits
    ∧ (q + q * q) * 2 ^ 95 ≤ 2 ^ SecurityBits :=
  ⟨queryTerm_le_of_le hq eufcma_term_at_slot_cap,
   genericTerm_le_of_le hq generic_term_at_slot_cap⟩

/-- Same headline anchored at the bootstrap cap (Type-1 registration key).

    **P14 (cross-chain caveat).** `MaxBootstrapUses` is enforced PER CHAIN, but
    the bootstrap key is chain-INDEPENDENT (invariant #6 requires it for
    cross-chain address stability — the same key registers slot 0 on every
    chain). So a single bootstrap key's true EUF-CMA query budget across `C`
    chains is `C · MaxBootstrapUses`, not `MaxBootstrapUses`. This per-chain
    theorem therefore bounds only the single-chain term; the cross-chain bound
    is `advantage_floor_within_bootstrap_cap_crosschain` below, which shows the
    floor degrades by `⌈log₂ C⌉` bits yet stays ≥ 96 bits for any realistic
    deployment (it would take `C > 2^16` chains to erode below the operative
    slot-generic floor). Mirrors the per-chain-vs-lifetime caveat the slot
    aggregate already carries. -/
theorem advantage_floor_within_bootstrap_cap {q : Nat} (hq : q ≤ MaxBootstrapUses) :
    q * 2 ^ 112 ≤ 2 ^ SecurityBits :=
  queryTerm_le_of_le hq eufcma_term_at_bootstrap_cap

/-- **Cross-chain bootstrap-key floor (P14).** A bootstrap key signing across
    `C` chains has total query budget `q ≤ C · MaxBootstrapUses`. For any
    deployment spanning `C ≤ 2^16` chains the (weaker, generic-multi-target)
    floor stays ≥ 96 bits: `q · 2^96 ≤ 2^SecurityBits = 2^128`. This is an
    explicit CONDITIONAL honest bound — there is no on-chain cap on the number
    of chains, so this does not assert `C ≤ 2^16` is enforced anywhere; it shows
    that even a 65536-chain deployment keeps the bootstrap floor at the same
    96-bit level as the operative per-slot generic term, so the per-key
    cross-chain aggregation never becomes the binding floor in practice. -/
theorem advantage_floor_within_bootstrap_cap_crosschain
    {q C : Nat} (hq : q ≤ C * MaxBootstrapUses) (hC : C ≤ 2 ^ 16) :
    q * 2 ^ 96 ≤ 2 ^ SecurityBits :=
  Nat.le_trans (Nat.mul_le_mul hq (Nat.le_refl (2 ^ 96)))
    (Nat.le_trans
      (Nat.mul_le_mul (Nat.mul_le_mul hC (Nat.le_refl MaxBootstrapUses))
        (Nat.le_refl (2 ^ 96)))
      (by decide))

/-! ## Multi-term bit-security floor (the faithful full bound)

The two terms above are the cited *single* terms. The full EUF-CMA bound is the
WEAKEST of three independent attack modalities (the security level is their
`min`). Encoded here in the **bit-security (log) domain** so the whole bound is a
closed `Nat` fact the kernel decides. Term provenance — the upstream SPHINCS-
security analysis (repo `SPHINCS-`, which is C10's origin):

* **FORS+C subset-resilience** — `docs/SECURITY-ANALYSIS.md §2.3` ("Avenue A"
  work estimate): `(k-1)` message-dependent FORS trees of height `a` plus the
  forced-zero tree's `a` bits ⇒ `(k-1)·a + a` bits. SCHEME-INHERENT
  (query-independent). For C10 `(a=11, k=13)` this is `12·11 + 11 = 143`.
* **Birthday / `ht_idx` term** — `§4.1`: H_msg leaf-index collisions after
  `q = 2^qBits` signatures over an `n`-bit hash ⇒ `n - qBits` bits.
* **Generic multi-target term** — the SM-DT-TCR `(q+q²)·2⁻ⁿ` part
  (`Crypto/Assumptions.lean` doc, `n = 8·N`) ⇒ `n - 2·qBits` bits.

NOTE on faithfulness: C10 is *archived / not formally verified* in the upstream
repo (its `sec_20 ≈ 104.5` bit). These term formulas are the upstream analyst's
accounting, imported here as cited claims — not re-derived. The operative,
in-repo-cryptographic content stays the `theft_free` qualitative reduction; this
section quantifies the generic feasibility at PQSigner's shipped params + cap. -/

/-- FORS+C subset-resilience work, in bits (upstream `SECURITY-ANALYSIS.md §2.3`). -/
def forsCBits (a k : Nat) : Nat := (k - 1) * a + a

-- NAMING FIX 2026-07-02 (finding birthdayBits-naming-inverted): the two terms below
-- were named the WRONG way round vs convention — `birthdayBits` held the LINEAR `n − qBits`
-- and `multiTargetBits` held the QUADRATIC `n − 2·qBits`. A birthday bound is quadratic in q
-- (q² collisions ⇒ floor `n − 2·qBits`), so the names are now: `queryBits` = the linear
-- EUF-CMA query term, `birthdayBits` = the quadratic birthday / multi-target term. Bodies
-- unchanged (only the names moved); `securityFloorBits`'s `Nat.min` is symmetric so the 96-bit
-- floor is unaffected — this is a labeling fix, zero soundness effect.

/-- Linear EUF-CMA query term `q·2⁻ⁿ`, in bits, after `2^qBits` signatures (`n − qBits`). -/
def queryBits (n qBits : Nat) : Nat := n - qBits

/-- Birthday / multi-target term `q²·2⁻ⁿ` (`ht_idx` collision), in bits, after `2^qBits`
    signatures (`n − 2·qBits`) — quadratic in q, hence the usual binding modality. -/
def birthdayBits (n qBits : Nat) : Nat := n - 2 * qBits

/-- Overall EUF-CMA bit-security floor: the weakest of the three modalities. -/
def securityFloorBits (n qBits a k : Nat) : Nat :=
  Nat.min (forsCBits a k) (Nat.min (queryBits n qBits) (birthdayBits n qBits))

/-- The production per-slot cap is `2^16`. -/
theorem maxSlotUses_eq_two_pow_16 : MaxSlotUses = 2 ^ 16 := by decide

/-- **C10 at the per-slot cap (`q = 2^16`) holds a 96-bit EUF-CMA floor.**
    `min(143, 112, 96) = 96` — the quadratic birthday term (`n − 2·qBits`) is the binding one. -/
theorem c10_security_floor_at_slot_cap :
    securityFloorBits SecurityBits 16 Spec.A Spec.K = 96 := by decide

/-- Each of the three modalities is independently ≥ 96 bits at the cap (so their
    `min` is ≥ 96), spelled out term-by-term for auditability. -/
theorem c10_modalities_ge_96_at_cap :
    96 ≤ forsCBits Spec.A Spec.K
    ∧ 96 ≤ queryBits SecurityBits 16
    ∧ 96 ≤ birthdayBits SecurityBits 16 := by decide

/-- **The 2^16 cap is load-bearing.** At C10's native `2^18` leaf space the floor
    would fall to 92 bits; the shipped `2^16` cap holds it at 96 (a +4-bit margin
    bought purely by the cap — invariant #7's unresettable monotone cap). -/
theorem c10_cap_is_load_bearing :
    securityFloorBits SecurityBits 18 Spec.A Spec.K = 92
    ∧ securityFloorBits SecurityBits 16 Spec.A Spec.K = 96 := by decide

/-- The floor is monotone non-increasing in the (log) query budget: more
    signatures never *increase* security. So the cap `q ≤ 2^16` lower-bounds the
    floor for every reachable usage, not just at the boundary. -/
theorem securityFloor_antitone_in_qBits {n a k q1 q2 : Nat} (h : q1 ≤ q2) :
    securityFloorBits n q2 a k ≤ securityFloorBits n q1 a k := by
  unfold securityFloorBits queryBits birthdayBits
  exact Nat.le_min.mpr
    ⟨Nat.min_le_left _ _,
     Nat.le_min.mpr
       ⟨Nat.le_trans (Nat.min_le_right _ _)
          (Nat.le_trans (Nat.min_le_left _ _) (Nat.sub_le_sub_left h n)),
        Nat.le_trans (Nat.min_le_right _ _)
          (Nat.le_trans (Nat.min_le_right _ _) (Nat.sub_le_sub_left (by omega) n))⟩⟩

/-! ## Cross-function separation floor (OC2 — off-chain/on-chain domain separation)

The `Wallet/OffchainBinding.keccak_sha256_cross_separation` axiom is the
QUALITATIVE reduction (`keccak256 x = sha256 y ⟹ BreaksHash`) that grounds the
RAW32 UserOp-forgery-oracle defense: the off-chain-signed value (`replaySafeHash`,
a keccak-256 image) is never equal to any UserOp `sphincsDigest` (a SHA-256 image)
unless a hash-hardness assumption is broken. This section adds the missing
QUANTITATIVE layer for that `BreaksHash` disjunct — the explicit search-game floor
— exactly as the sections above quantify the EUF-CMA / SM-DT-TCR BreaksHash events.
It stays a bound on the FEASIBILITY of the disjunct; it does NOT discharge the
axiom (which remains `cited-tcb`).

**The honest point (finding OC2): the floor is NOT automatically `2⁻²⁵⁶`.** It
depends on whether the attacker's target is FIXED or BOTH messages vary, because
the two hashes share the same 256-bit codomain (`ByteVec 32` on both sides —
type-guaranteed, independent of the `N = 16` truncation INSIDE the tweakable
hashes, which is not applied to these outer digests):

* **Both-messages-vary (claw / birthday)** — find ANY `(x, y)` with
  `keccak256 x = sha256 y`. Two independent 256-bit-codomain functions ⇒ birthday
  advantage `q² · 2⁻²⁵⁶` ⇒ floor `256 − 2·qBits`, break at `q ≈ 2¹²⁸`.
* **Fixed-target (preimage)** — hit one specific `sphincsDigest = T` with
  `keccak256 x = T` ⇒ `q · 2⁻²⁵⁶` ⇒ floor `256 − qBits`.

**The claw is the OPERATIVE regime for the RAW32 defense**, and it is genuinely
available: the attacker varies the off-chain `rawHash` freely (full 2²⁵⁶ image via
`replaySafeHash`) AND the draining UserOp (its `nonce` alone spans 256 bits, plus
the gas fields), so it can search for a cross-image collision, not just a preimage.
Take the attacker-favorable minimum = the claw. So the honest headline floor is
**128 bits — C10's Cat-1 design level**: the RAW32 cross-separation holds at the
SAME birthday strength the whole wallet already lives at. The naive `2⁻²⁵⁶` was the
wrong yardstick (that is the fixed-target preimage number); the right one is the
128-bit both-vary claw. This is a precision/honesty fix, not a downgrade. -/

/-- Output width of BOTH cross-separation images — the off-chain `replaySafeHash`
    (a keccak-256 `ByteVec 32`) and the on-chain `sphincsDigest` (a SHA-256
    `ByteVec 32`): 32 bytes = 256 bits. Type-guaranteed by `ByteVec 32` on both
    sides; the `N = 16` truncation inside the tweakable hashes does not touch these
    outer digests. -/
def CrossOutputBits : Nat := 8 * 32

theorem crossOutputBits_eq : CrossOutputBits = 256 := by decide

/-- **Both-messages-vary (claw / birthday) floor**, in bits, at adversary offline
    work `2^qBits`: finding ANY `(x, y)` with `keccak256 x = sha256 y` is a claw
    between two independent 256-bit-codomain functions ⇒ `q² · 2⁻²⁵⁶` ⇒
    `256 − 2·qBits`. The OPERATIVE regime for the RAW32-oracle defense. -/
def crossClawBits (qBits : Nat) : Nat := CrossOutputBits - 2 * qBits

/-- **Fixed-target (preimage) floor**, in bits: hitting a FIXED `sphincsDigest = T`
    with `keccak256 x = T` is a preimage search ⇒ `q · 2⁻²⁵⁶` ⇒ `256 − qBits`. The
    stronger regime — only applies if the attacker cannot also vary the UserOp. -/
def crossPreimageBits (qBits : Nat) : Nat := CrossOutputBits - qBits

/-- **Anti-vacuity (exact value, not `≥ 0`).** The operative claw floor at a
    generous `2⁶⁴` offline-work budget is EXACTLY 128 bits = C10's Cat-1 design
    level. Pinned exactly so a wrong arithmetic (or Nat-subtraction truncation)
    would flip it — mirrors `c10_security_floor_at_slot_cap : … = 96`. -/
theorem crossClaw_at_2pow64 : crossClawBits 64 = 128 := by decide

/-- **The claw break-point (exact).** At `2¹²⁸` work the birthday floor reaches 0
    (a cross-image collision is expected) — the exact 256-bit-codomain birthday
    bound, pinned so the formula cannot silently truncate to an accidentally-true
    `≥ 0` past the break. -/
theorem crossClaw_breakpoint : crossClawBits 128 = 0 := by decide

/-- Fixed-target preimage floor is 192 bits at `2⁶⁴` work and 128 bits at `2¹²⁸`
    — strictly above the claw floor, confirming the claw is the binding regime. -/
theorem crossPreimage_at_2pow64 : crossPreimageBits 64 = 192 := by decide
theorem crossPreimage_at_2pow128 : crossPreimageBits 128 = 128 := by decide

/-- **The claw is the attacker-favorable (weaker) regime at every work budget**:
    `256 − 2·qBits ≤ 256 − qBits`. So headlining the claw floor is conservative —
    the reported 128-bit strength is a lower bound on both regimes. -/
theorem crossClaw_le_preimage (qBits : Nat) :
    crossClawBits qBits ≤ crossPreimageBits qBits := by
  unfold crossClawBits crossPreimageBits
  exact Nat.sub_le_sub_left (by omega) CrossOutputBits

/-- The claw floor is monotone non-increasing in the (log) offline-work budget:
    more work never *increases* the separation strength. -/
theorem crossClaw_antitone {q1 q2 : Nat} (h : q1 ≤ q2) :
    crossClawBits q2 ≤ crossClawBits q1 := by
  unfold crossClawBits
  exact Nat.sub_le_sub_left (by omega) CrossOutputBits

end SphincsCVerify.Crypto.Quantitative
