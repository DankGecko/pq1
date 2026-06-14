# EUF-CMA axiom inconsistency — `theft_free` is currently vacuous

**Status:** 🛑 **OPEN (found 2026-06-14).** A deep adversarial audit found, and
two independent reproductions (including a hand-written one) confirmed
**kernel-checked, `sorryAx`-free**, that the `lean/` (SphincsCVerify) crypto
axiom set is **logically inconsistent** — `False` is derivable. The headline
theorem `theft_free` depends on that axiom set, so it is **vacuously true and
proves nothing about wallet safety** until the axiom is restated.

This is **not an on-chain vulnerability** — the deployed contracts are
unchanged. It is a defect in the *Lean security argument*: the top-level claim
is currently unsupported.

---

## 1. The inconsistency

```lean
-- Crypto/EUFCMA.lean:103
def isForgery (vk : VerifyingKey) (transcript : Transcript)
    (msgStar : ByteVec 32) (sigStar : Hypertree.Signature) : Prop :=
  Hypertree.verify vk.pkSeed vk.pkRoot msgStar sigStar = true
  ∧ ¬ transcriptHasMsg transcript msgStar

-- Crypto/EUFCMA.lean:135  (gated by three `∀_,True` shape axioms)
axiom EUF_CMA_SPHINCSplusC :
  SM_DT_TCR_F_Shape → ITSR_F_Shape → hMsg_RO_Shape →
  ∀ vk transcript msgStar sigStar, isForgery vk transcript msgStar sigStar → False
```

At `transcript = []`, `¬ transcriptHasMsg [] m` is trivially true, so the axiom
degenerates to: **"the verifier accepts NO signature for any key."** But commit
`5055d66` (2026-06-13, the A3.1 functional-faithfulness fix) made
`Spec.Signature.verify` *executably accept* the 4 valid KAT vectors
(`verify-test-vectors` full-verify 10/10). Feeding a genuine valid KAT
signature as the `isForgery` witness at the empty transcript derives `False`.

### Reproduction (kernel-checked, no `sorryAx`)

```lean
def v : KatVector := vectors.head!                       -- valid-1
def myVk  : Signature.VerifyingKey := ⟨pkSeed16, pkRoot16⟩
def sigStar : Hypertree.Signature := Signature.deserialise sigBV

theorem forgery_witness : isForgery myVk [] msgBV sigStar :=
  ⟨by native_decide, by rintro ⟨s, h⟩; cases h⟩
theorem boom : False :=
  cannot_forge_without_breaking_SHA256 myVk [] msgBV sigStar forgery_witness
#print axioms boom
-- [propext, Classical.choice, Lean.ofReduceBool, Quot.sound,
--  EUF_CMA_SPHINCSplusC, ITSR_F, SM_DT_TCR_F, hMsg_random_oracle]   -- NO sorryAx
```

`native_decide`/`Lean.ofReduceBool` here is **not** a cheat: it proves
`verify = true` on the project's *own* valid-1 vector — a fact independently
confirmed true by `lake exe verify-test-vectors` (10/10), which runs the same
compiled `verify`. The inconsistency is in the **axiom**, not the tactic; the
logical point (the axiom asserts "verify accepts nothing", contradicted by a
verifier that accepts valid sigs) holds regardless of how `verify = true` is
proved.

## 2. Root cause — a whack-a-mole between A3.1 and A5

| Before `5055d66` | After `5055d66` (current) |
|---|---|
| `verify` rejected everything | `verify` accepts valid sigs (A3.1 faithful, full-verify 10/10) |
| A3.1 (`solidityVerifier_compiles_correctly`) was a **FALSE** axiom (Lean said false, bytecode said true) | A3.1 is now faithful ✓ |
| A5 (`EUF_CMA`) was **vacuously consistent** (no-forgery-at-[] matched a verifier accepting nothing) | A5 is now **INCONSISTENT** (a real sig at [] is a forgery) |

The A3.1 fix relocated the inconsistency from A3.1 to A5 without anyone noticing.

## 3. Why this is non-reconcilable as a *proof refinement* (but reconcilable as a *model*)

For any honestly-generated `pk` and any message, a valid signature **exists**
(the honest signer can produce one). So `isForgery` (`verify ∧ m∉transcript`)
is **satisfiable for every finite transcript**. Therefore **any** unconditional
axiom that "rules out forgeries" — `→ False`, or `→ HashBreak` with `¬HashBreak`
assumed — detonates the same way. You cannot refine the *proof* out of a *false
axiom*.

EUF-CMA is inherently **computational**: forgeries exist as mathematical
objects; they are merely *infeasible to compute without `sk`*. The only
**faithful AND consistent** renderings model the computationally-bounded
adversary so a hand-supplied valid sig is not "an adversary's output":

- **(a) Game/probability-based** — `Pr[A wins] ≤ negligible` over a bounded
  probabilistic adversary (the EasyCrypt/SSProve/CryptHOL shape). Most
  faithful; needs a probability monad (mathlib `PMF`); SPHINCS+ security stays
  a *cited* assumption (Barbosa et al. ASIACRYPT 2024), not an in-Lean proof.
- **(b) Reduction** — `forgery ⇒ break(hardness)` with `break` an *opaque*
  predicate that is **not** assumed false unconditionally (so theft_free
  concludes "drain ⇒ hash break", honestly weaker).
- **(c) Abstract bounded-adversary** — an opaque `Adversary` type whose `run`
  (given only `pk` + oracle) cannot be inhabited by a hand-decoded KAT;
  consistency hinges on that non-inhabitation.
- **(d) Demote + explicit hypothesis** — make `EUF_CMA` inert/cited-TCB and
  have `theft_free` take a *consistent* unforgeability hypothesis as an
  explicit argument (smallest change; honest conditional theorem).

Whichever is chosen, SPHINCS+ unforgeability remains **cited-TCB** (same status
as A1 SHA-256=FIPS, A2 EntryPoint-honest) — the bug was that A5 was stated in a
*self-contradictory* way rather than as a clean cited assumption. The shape is
under active design + adversarial testing (workflow `eufcma-reconcile`).

## 4. Scope (what is damaged vs intact)

- **Vacuous now** (depend on the inconsistent crypto axioms): `theft_free`,
  `theft_free_bytecode`, `cannot_forge_without_breaking_SHA256`,
  `theft_free_with_calldata_binding`.
- **Still valid** (`#print axioms` closes over only `propext`/`Classical.choice`/`Quot.sound`,
  i.e. NOT the crypto axioms): the wallet-model invariants
  (`combinedCap_inductive`, `bootstrap_unremovable`, `eip1271_forbids_bootstrap`,
  `factory_requires_bootstrap_sig`, `create2_*`, `validateSignature_only_via_verify`,
  …), the §33 Aeneas-extracted functional proofs (only `keccak256_pure`), the
  Halmos bytecode-equivalence discharges (A3.*), and the A3.1 verifier KAT.
- **Secondary / latent:** `sha256_injective_on_fixed_length` (Assumptions.lean:158)
  is mathematically false (pigeonhole at length > 32 B) but currently
  non-detonatable because `lean/` is **mathlib-free** (no `Finite`/pigeonhole).
  ⚠️ Adding mathlib detonates it — restate it as collision-resistance BEFORE
  importing mathlib.

## 5. Required fixes (before theft-freedom can be re-claimed)

1. Restate `EUF_CMA_SPHINCSplusC` to a consistent, faithful shape (design TBD —
   see §3). Re-derive `theft_free`.
2. Re-run `#print axioms theft_free`; write a **regression probe** that the old
   `boom : False` no longer type-checks.
3. Restate `sha256_injective_on_fixed_length` as collision-resistance (and only
   then consider mathlib).
4. Reinstate the claims in `THE_CLAIM.md` / `AXIOM_STATUS.json` once 1–3 land.

History: this was missed by two earlier audit passes (which checked the
`verify_signs` route — gated by the unproven `consistent` hypothesis — but
overlooked that `Hypertree.verify` is *computable*, so a concrete KAT can be
`native_decide`d to `true`). `#print axioms` (the `sorryAx`/`ofReduceBool`
ledger) is the gate that makes the inconsistency visible.
