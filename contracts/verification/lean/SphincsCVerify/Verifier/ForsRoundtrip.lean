/- Group-V round-trip — FORS tree round-trip (verify_signs sub-lemma 3/4).

   `Fors.reconstructRoot` (the verifier-side FORS Merkle climb, `Adrs.forsNode`)
   is the FORS analogue of `verifyAuthPath`. This mirrors `merkle_roundtrip`:
   define the honest FORS tree `forsMtNode` (leaf = `th` of the secret) + auth
   path `forsMtAuthPath`, and prove climbing an honest path reconstructs the
   tree root. Built on the existing `forsAcc`/`forsAcc_succ` fold machinery
   (`Interpreter/Phases.lean`); reuses `sibIdx` from `MerkleRoundtrip`. The one
   delta vs the Merkle leg: the leaf index is a `UInt32`, so the index tracking
   needs the `UInt32`-roundtrip `(UInt32.ofNat n).toNat = n` (n < 2^32). -/
import SphincsCVerify.Verifier.MerkleRoundtrip
import SphincsCVerify.Interpreter.Phases

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify SphincsCVerify.Spec

/-- The honest FORS Merkle tree node at `(level, idx)`: level-0 leaf is `th` of
    the secret `lf idx`; internal nodes are `thPair`, all under `Adrs.forsNode`
    — matching `forsStep`'s reconstruction shape exactly. -/
def forsMtNode (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32) (lf : Nat → ByteVec 16) :
    Nat → Nat → ByteVec 16
  | 0, idx =>
      Spec.th seed (Spec.Adrs.forsNode htIdx treeIdx 0 (UInt32.ofNat idx)) (ByteVec.pad16 (lf idx))
  | (ℓ + 1), idx =>
      Spec.thPair seed (Spec.Adrs.forsNode htIdx treeIdx (UInt32.ofNat (ℓ + 1)) (UInt32.ofNat idx))
        (ByteVec.pad16 (forsMtNode seed htIdx treeIdx lf ℓ (2 * idx)))
        (ByteVec.pad16 (forsMtNode seed htIdx treeIdx lf ℓ (2 * idx + 1)))

/-- The honest FORS auth path for `leafIdx`: the sibling node at each level. -/
def forsMtAuthPath (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32) (lf : Nat → ByteVec 16)
    (leafIdx : Nat) : Array (ByteVec 16) :=
  Array.ofFn (n := Spec.A) fun h => forsMtNode seed htIdx treeIdx lf h.val (sibIdx leafIdx h.val)

theorem forsMtAuthPath_getD (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32)
    (lf : Nat → ByteVec 16) (leafIdx c : Nat) (hcs : c < Spec.A) :
    (forsMtAuthPath seed htIdx treeIdx lf leafIdx).getD c (ByteVec.zero 16)
      = forsMtNode seed htIdx treeIdx lf c (sibIdx leafIdx c) := by
  simp [forsMtAuthPath, hcs]

/-- `reconstructRoot` is the node component (`.fst`) of `forsAcc` at level `A`. -/
theorem reconstructRoot_eq_forsAcc (seed : ByteVec 32) (htIdx : UInt64) (treeIdx leafIdx : UInt32)
    (secret : ByteVec 16) (authPath : Array (ByteVec 16)) :
    Spec.Fors.reconstructRoot seed htIdx treeIdx leafIdx secret authPath
      = (forsAcc seed htIdx treeIdx leafIdx secret authPath Spec.A).fst := by
  rw [reconstructRoot_eq_foldl]; rfl

/-- **FORS climb invariant.** After `c ≤ A` levels, the accumulator is
    `⟨forsMtNode c (leafIdx/2^c), leafIdx/2^c⟩` (node fst, idx snd). -/
theorem forsAcc_climbs (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32)
    (lf : Nat → ByteVec 16) (leafIdx : Nat) (h32 : (UInt32.ofNat leafIdx).toNat = leafIdx) :
    ∀ c, c ≤ Spec.A →
      forsAcc seed htIdx treeIdx (UInt32.ofNat leafIdx) (lf leafIdx)
          (forsMtAuthPath seed htIdx treeIdx lf leafIdx) c
        = ⟨forsMtNode seed htIdx treeIdx lf c (leafIdx / 2 ^ c), leafIdx / 2 ^ c⟩ := by
  intro c
  induction c with
  | zero => intro _; rw [forsAcc_zero]; simp [forsAccInit, forsMtNode, h32]
  | succ c ih =>
      intro hc
      have hcs : c < Spec.A := Nat.lt_of_succ_le hc
      rw [forsAcc_succ, ih (Nat.le_of_succ_le hc)]
      have hdd : leafIdx / 2 ^ c / 2 = leafIdx / 2 ^ (c + 1) := by
        rw [Nat.div_div_eq_div_mul, ← Nat.pow_succ]
      unfold forsStep
      rw [forsMtAuthPath_getD seed htIdx treeIdx lf leafIdx c hcs]
      simp only [beq_iff_eq]
      rw [hdd]
      split
      · rename_i hpar
        have he1 : leafIdx / 2 ^ c = 2 * (leafIdx / 2 ^ (c + 1)) := by omega
        have he2 : sibIdx leafIdx c = 2 * (leafIdx / 2 ^ (c + 1)) + 1 := by
          simp only [sibIdx]; rw [if_pos hpar]; omega
        rw [he1, he2]
        simp only [forsMtNode]
      · rename_i hpar
        have he1 : leafIdx / 2 ^ c = 2 * (leafIdx / 2 ^ (c + 1)) + 1 := by omega
        have he2 : sibIdx leafIdx c = 2 * (leafIdx / 2 ^ (c + 1)) := by
          simp only [sibIdx]; rw [if_neg hpar]; omega
        rw [he1, he2]
        simp only [forsMtNode]

/-- **`fors_roundtrip`.** Climbing the honest FORS auth path for `leafIdx` from
    the secret-leaf reconstructs the FORS tree root `forsMtNode A 0`, for any
    `leafIdx < 2^A`. (The third of the four `verify_signs` sub-lemmas.) -/
theorem fors_roundtrip (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32)
    (lf : Nat → ByteVec 16) (leafIdx : Nat) (hlt : leafIdx < 2 ^ Spec.A) :
    Spec.Fors.reconstructRoot seed htIdx treeIdx (UInt32.ofNat leafIdx) (lf leafIdx)
        (forsMtAuthPath seed htIdx treeIdx lf leafIdx)
      = forsMtNode seed htIdx treeIdx lf Spec.A 0 := by
  have h32 : (UInt32.ofNat leafIdx).toNat = leafIdx := by
    apply UInt32.toNat_ofNat_of_lt'
    have hb : (2 : Nat) ^ Spec.A < UInt32.size := by decide
    omega
  rw [reconstructRoot_eq_forsAcc,
    forsAcc_climbs seed htIdx treeIdx lf leafIdx h32 Spec.A (Nat.le_refl _)]
  simp [Nat.div_eq_of_lt hlt]

end SphincsCVerify.Interpreter.C10
