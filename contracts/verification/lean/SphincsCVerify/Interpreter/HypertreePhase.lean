/-
SphincsCVerify.Interpreter.HypertreePhase — the hypertree (XMSS) phase of the
interpreter-refinement, in a separate file so it recompiles fast against the cached
`Phases` olean (Phases.lean is ~5340 lines / 8-min builds).

This phase refines the deployed `SPHINCsC10Asm.sol` hypertree walk
(`-- L144-226`, the `for layer in [:D=2]` loop) against `Spec.Hypertree.verifyHypertree`:
per layer, WOTS+C recovers the public key (`wots_pkfromsig`, in `Phases`), then the
XMSS Merkle auth path climbs to the subtree root (`verifyAuthPath`); after `D=2`
layers the result is compared against `pk_root`.

The Merkle climb here is the FORS climb (`fors_climb` in `Phases`) MINUS the leaf
hash: it starts from the WOTS public key directly, uses `Adrs.treeNode` ADRS, and
runs `SubtreeH = 9` levels. So `htStep`/`verifyAuthPath_eq_foldl` mirror
`forsStep`/`reconstructRoot_eq_foldl` — with one difference: the `do`-elaboration of
`verifyAuthPath` packs the mutable accumulator as `⟨idx, node⟩` (`.fst` = path index,
`.snd` = node), the opposite field order from `reconstructRoot`'s `⟨node, pathIdx⟩`.
-/

import SphincsCVerify.Interpreter.Phases

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify.Interpreter
open SphincsCVerify.Spec (ByteVec)

/-! ### The spec Merkle auth-path climb as a fold -/

/-- One XMSS Merkle auth-path step (`Adrs.treeNode` ADRS). Accumulator is
    `⟨pathIdx, node⟩` (`.fst` = idx, `.snd` = node) — the order `verifyAuthPath`'s
    `do`-block elaborates to. -/
def htStep (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (authPath : Array (ByteVec 16)) (acc : MProd Nat (ByteVec 16)) (h : Nat) :
    MProd Nat (ByteVec 16) :=
  let pathIdx := acc.fst
  let node := acc.snd
  let parentIdx := pathIdx / 2
  let adrs := Spec.Adrs.treeNode layer tree (UInt32.ofNat (h + 1)) (UInt32.ofNat parentIdx)
  let sibling := authPath.getD h (ByteVec.zero 16)
  if pathIdx % 2 == 0 then
    ⟨parentIdx, Spec.thPair seed adrs (ByteVec.pad16 node) (ByteVec.pad16 sibling)⟩
  else
    ⟨parentIdx, Spec.thPair seed adrs (ByteVec.pad16 sibling) (ByteVec.pad16 node)⟩

/-- **`verifyAuthPath` as a fold.** The spec XMSS subtree-root reconstruction is the
    second component (`.snd` = node) of folding `htStep` over `[0, SubtreeH)` from
    `⟨leafIdx, leafNode⟩` (the WOTS public key as the leaf). Same `forIn → foldl`
    collapse as `reconstructRoot_eq_foldl`. -/
theorem verifyAuthPath_eq_foldl
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (leafNode : ByteVec 16) (leafIdx : Nat) (authPath : Array (ByteVec 16)) :
    Spec.Hypertree.verifyAuthPath seed layer tree leafNode leafIdx authPath
      = ((List.range' 0 Spec.SubtreeH).foldl (htStep seed layer tree authPath)
          ⟨leafIdx, leafNode⟩).snd := by
  rw [Spec.Hypertree.verifyAuthPath]
  set_option linter.deprecated false in
  simp only [Std.Range.forIn_eq_forIn_range', Std.Range.size, Nat.sub_zero, Nat.add_sub_cancel,
    Nat.div_one, Id.run, Id.bind_eq, Id.pure_eq]
  rw [show (fun (h : Nat) (r : MProd Nat (ByteVec 16)) =>
        (if (r.fst % 2 == 0) = true then
            ForInStep.yield (⟨r.fst / 2, Spec.thPair seed (Spec.Adrs.treeNode layer tree
                  (UInt32.ofNat (h + 1)) (UInt32.ofNat (r.fst / 2))) r.snd.pad16
                  (authPath.getD h (ByteVec.zero 16)).pad16⟩ : MProd Nat (ByteVec 16))
          else
            ForInStep.yield ⟨r.fst / 2, Spec.thPair seed (Spec.Adrs.treeNode layer tree
                  (UInt32.ofNat (h + 1)) (UInt32.ofNat (r.fst / 2)))
                  (authPath.getD h (ByteVec.zero 16)).pad16 r.snd.pad16⟩))
      = (fun (h : Nat) (r : MProd Nat (ByteVec 16)) =>
          pure (f := Id) (ForInStep.yield (htStep seed layer tree authPath r h))) from by
        funext h r
        show _ = ForInStep.yield (htStep seed layer tree authPath r h)
        unfold htStep
        rw [apply_ite ForInStep.yield]]
  rw [List.forIn_pure_yield_eq_foldl]
  rfl

/-- The Merkle-climb accumulator after `c` levels (fold of `htStep` from the leaf
    `⟨leafIdx, leafNode⟩`). The `ht_climb` loop invariant tracks this. -/
def htAcc (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (leafNode : ByteVec 16) (leafIdx : Nat) (authPath : Array (ByteVec 16)) (c : Nat) :
    MProd Nat (ByteVec 16) :=
  (List.range' 0 c).foldl (htStep seed layer tree authPath) ⟨leafIdx, leafNode⟩

theorem htAcc_zero (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (leafNode : ByteVec 16) (leafIdx : Nat) (authPath : Array (ByteVec 16)) :
    htAcc seed layer tree leafNode leafIdx authPath 0 = ⟨leafIdx, leafNode⟩ := rfl

/-- **`htAcc` recursion.** One more climb level is one more `htStep`. -/
theorem htAcc_succ (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (leafNode : ByteVec 16) (leafIdx : Nat) (authPath : Array (ByteVec 16)) (c : Nat) :
    htAcc seed layer tree leafNode leafIdx authPath (c + 1)
      = htStep seed layer tree authPath (htAcc seed layer tree leafNode leafIdx authPath c) c := by
  unfold htAcc
  rw [List.range'_1_concat, List.foldl_append, Nat.zero_add]
  rfl

/-- `verifyAuthPath` is the node component (`.snd`) of `htAcc` at `SubtreeH`. The
    form `ht_climb`'s loop drive lands on. -/
theorem verifyAuthPath_eq_htAcc
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (leafNode : ByteVec 16) (leafIdx : Nat) (authPath : Array (ByteVec 16)) :
    Spec.Hypertree.verifyAuthPath seed layer tree leafNode leafIdx authPath
      = (htAcc seed layer tree leafNode leafIdx authPath Spec.SubtreeH).snd := by
  rw [verifyAuthPath_eq_foldl]; rfl

end SphincsCVerify.Interpreter.C10
