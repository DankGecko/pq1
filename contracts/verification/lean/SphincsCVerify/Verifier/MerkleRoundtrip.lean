/- Group-V round-trip foundation — Merkle auth-path round-trip.

   `Spec.Hypertree.verifyAuthPath` (the verifier-side XMSS subtree climb) is the
   one piece every hypertree/FORS root reconstruction relies on. Here we define
   the HONEST signer-side Merkle tree (`mtNode`) + its auth path (`mtAuthPath`)
   and prove `merkle_roundtrip`: climbing an honestly-built auth path from a leaf
   reconstructs the tree root. This is the first of the four `verify_signs`
   sub-lemmas (`merkle_roundtrip`); it is signer-independent (abstract over the
   leaf function `lf`) so the FORS and hypertree legs both reuse it.

   Built on the `htAcc`/`htStep` fold form of `verifyAuthPath`
   (`Interpreter/HypertreePhase.lean`); the proof is a clean loop invariant by
   induction on the climb height via `htAcc_succ`. -/
import SphincsCVerify.Interpreter.HypertreePhase

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify SphincsCVerify.Spec

/-- Sibling index at climb level `h` for the leaf `leafIdx`: the index `p`'s
    sibling in the Merkle tree, where `p = leafIdx / 2^h` is the ancestor index
    at that level. -/
def sibIdx (leafIdx h : Nat) : Nat :=
  let p := leafIdx / 2 ^ h
  if p % 2 = 0 then p + 1 else p - 1

/-- The honest signer-side Merkle tree node at `(level, idx)` over leaves `lf`,
    using the exact `Adrs.treeNode` + `thPair` shape `htStep` reconstructs with. -/
def mtNode (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (lf : Nat → ByteVec 16) :
    Nat → Nat → ByteVec 16
  | 0, idx => lf idx
  | (ℓ + 1), idx =>
      Spec.thPair seed (Spec.Adrs.treeNode layer tree (UInt32.ofNat (ℓ + 1)) (UInt32.ofNat idx))
        (ByteVec.pad16 (mtNode seed layer tree lf ℓ (2 * idx)))
        (ByteVec.pad16 (mtNode seed layer tree lf ℓ (2 * idx + 1)))

/-- The honest auth path for `leafIdx`: the sibling node at each climb level. -/
def mtAuthPath (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (lf : Nat → ByteVec 16)
    (leafIdx : Nat) : Array (ByteVec 16) :=
  Array.ofFn (n := Spec.SubtreeH) fun h => mtNode seed layer tree lf h.val (sibIdx leafIdx h.val)

/-- The honest auth path at any climb level `< SubtreeH` is the sibling node. -/
theorem mtAuthPath_getD (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (lf : Nat → ByteVec 16) (leafIdx c : Nat) (hcs : c < Spec.SubtreeH) :
    (mtAuthPath seed layer tree lf leafIdx).getD c (ByteVec.zero 16)
      = mtNode seed layer tree lf c (sibIdx leafIdx c) := by
  simp [mtAuthPath, hcs]

/-- **Merkle climb invariant.** After `c ≤ SubtreeH` climb levels from the leaf,
    the accumulator is `⟨leafIdx / 2^c, mtNode c (leafIdx / 2^c)⟩` — the ancestor
    index and node at that level. By induction via `htAcc_succ`. -/
theorem htAcc_climbs (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (lf : Nat → ByteVec 16) (leafIdx : Nat) :
    ∀ c, c ≤ Spec.SubtreeH →
      htAcc seed layer tree (lf leafIdx) leafIdx (mtAuthPath seed layer tree lf leafIdx) c
        = ⟨leafIdx / 2 ^ c, mtNode seed layer tree lf c (leafIdx / 2 ^ c)⟩ := by
  intro c
  induction c with
  | zero => intro _; rw [htAcc_zero]; simp [mtNode]
  | succ c ih =>
      intro hc
      have hcs : c < Spec.SubtreeH := Nat.lt_of_succ_le hc
      rw [htAcc_succ, ih (Nat.le_of_succ_le hc)]
      have hdd : leafIdx / 2 ^ c / 2 = leafIdx / 2 ^ (c + 1) := by
        rw [Nat.div_div_eq_div_mul, ← Nat.pow_succ]
      unfold htStep
      rw [mtAuthPath_getD seed layer tree lf leafIdx c hcs]
      simp only [beq_iff_eq]
      rw [hdd]
      split
      · rename_i hpar
        have he1 : leafIdx / 2 ^ c = 2 * (leafIdx / 2 ^ (c + 1)) := by omega
        have he2 : sibIdx leafIdx c = 2 * (leafIdx / 2 ^ (c + 1)) + 1 := by
          simp only [sibIdx]; rw [if_pos hpar]; omega
        rw [he1, he2]
        simp only [mtNode]
      · rename_i hpar
        have he1 : leafIdx / 2 ^ c = 2 * (leafIdx / 2 ^ (c + 1)) + 1 := by omega
        have he2 : sibIdx leafIdx c = 2 * (leafIdx / 2 ^ (c + 1)) := by
          simp only [sibIdx]; rw [if_neg hpar]; omega
        rw [he1, he2]
        simp only [mtNode]

/-- **`merkle_roundtrip`.** Climbing the honest auth path for `leafIdx` from the
    leaf `lf leafIdx` reconstructs the tree root `mtNode SubtreeH 0`, for any
    `leafIdx < 2^SubtreeH`. (The first of the four `verify_signs` sub-lemmas.) -/
theorem merkle_roundtrip (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (lf : Nat → ByteVec 16) (leafIdx : Nat) (hlt : leafIdx < 2 ^ Spec.SubtreeH) :
    Spec.Hypertree.verifyAuthPath seed layer tree (lf leafIdx) leafIdx
        (mtAuthPath seed layer tree lf leafIdx)
      = mtNode seed layer tree lf Spec.SubtreeH 0 := by
  rw [verifyAuthPath_eq_htAcc,
    htAcc_climbs seed layer tree lf leafIdx Spec.SubtreeH (Nat.le_refl _)]
  simp [Nat.div_eq_of_lt hlt]

end SphincsCVerify.Interpreter.C10
