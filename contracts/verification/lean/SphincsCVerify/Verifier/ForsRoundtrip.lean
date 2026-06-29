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

-- `forsMtNode`, `forsMtAuthPath` (the honest FORS tree) now live in
-- `Spec.Treehash` (reused by the reference signer); `sibIdx` likewise.
-- Referenced here via `open SphincsCVerify.Spec`.

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

open SphincsCVerify.Util in
/-- **`fors_pk_roundtrip`.** The FORS public-key aggregate: an honest FORS+C
    signature (each of the `K-1` normal trees carries the honest secret-leaf +
    subtree auth path under leaf function `lf t`, and the forced-zero last index
    holds) reconstructs to the honest FORS public key — the `computeForsPk`
    (`thMulti`) compression of the `K-1` reconstructed tree roots plus the
    leaf-only last-tree root. Each normal tree round-trips by `fors_roundtrip`;
    the aggregate by `Array.ofFn` congruence. The forced-zero gate is discharged
    by `hzero`; the leaf-index bounds by `hbound` (each `< 2^A`, itself a
    consequence of `readBitsLe_lt`). -/
theorem fors_pk_roundtrip (seed digest : ByteVec 32) (sig : Spec.Fors.ForsSig)
    (lf : Nat → Nat → ByteVec 16)
    (hzero : (extractForsIndices digest).getD (Spec.K - 1) 0 = 0)
    (hbound : ∀ t, t < Spec.K - 1 → (extractForsIndices digest).getD t 0 < 2 ^ Spec.A)
    (hsec : ∀ t, t < Spec.K - 1 →
      sig.secrets.getD t (ByteVec.zero 16) = lf t ((extractForsIndices digest).getD t 0))
    (hpath : ∀ t, t < Spec.K - 1 →
      sig.authPaths.getD t #[]
        = forsMtAuthPath seed (UInt64.ofNat (extractHtIndex digest)) (UInt32.ofNat t) (lf t)
            ((extractForsIndices digest).getD t 0)) :
    Spec.Fors.reconstructForsPk seed digest sig
      = some (Spec.Fors.computeForsPk seed (UInt64.ofNat (extractHtIndex digest))
          ((Array.ofFn (n := Spec.K - 1) fun t : Fin (Spec.K - 1) =>
              forsMtNode seed (UInt64.ofNat (extractHtIndex digest)) (UInt32.ofNat t.val) (lf t.val)
                Spec.A 0).push
            (Spec.th seed
              (Spec.Adrs.forsNode (UInt64.ofNat (extractHtIndex digest)) (UInt32.ofNat (Spec.K - 1)) 0 0)
              (ByteVec.pad16 (sig.secrets.getD (Spec.K - 1) (ByteVec.zero 16)))))) := by
  have hofn :
      (Array.ofFn (n := Spec.K - 1) fun t : Fin (Spec.K - 1) =>
          Spec.Fors.reconstructRoot seed (UInt64.ofNat (extractHtIndex digest)) (UInt32.ofNat t.val)
            (UInt32.ofNat ((extractForsIndices digest).getD t.val 0))
            (sig.secrets.getD t.val (ByteVec.zero 16)) (sig.authPaths.getD t.val #[]))
        = (Array.ofFn (n := Spec.K - 1) fun t : Fin (Spec.K - 1) =>
            forsMtNode seed (UInt64.ofNat (extractHtIndex digest)) (UInt32.ofNat t.val) (lf t.val)
              Spec.A 0) := by
    congr 1
    funext t
    rw [hsec t.val t.isLt, hpath t.val t.isLt]
    exact fors_roundtrip seed (UInt64.ofNat (extractHtIndex digest)) (UInt32.ofNat t.val) (lf t.val)
      ((extractForsIndices digest).getD t.val 0) (hbound t.val t.isLt)
  simp only [Spec.Fors.reconstructForsPk]
  rw [if_neg (not_not_intro hzero), hofn]

end SphincsCVerify.Interpreter.C10
