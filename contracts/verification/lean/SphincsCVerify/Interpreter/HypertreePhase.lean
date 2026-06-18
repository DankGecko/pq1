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
import SphincsCVerify.Interpreter.EnvFrame

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

/-! ### The interpreter HT Merkle-climb body -/

/-- The hypertree XMSS Merkle-climb inner body (`SPHINCsC10Asm.sol` L209-222),
    written with raw constructors so it is defeq to the corresponding slice of
    `c10Program`'s inner `forRange "h" (lit 9)` (the `TREEADRS_MASK` literal is
    `0xFFFF…FF` top-fields, low 8 bytes zero — inlined here since C10Program's
    `TREEADRS_MASK` def is private; defeq to `lit TREEADRS_MASK`). One auth-path
    level: load+mask sibling, halve `mIdx`, store the `treeNode` ADRS at `0x20`
    (mask `treeAdrs` then OR height+parentIdx), branchless-swap node/sibling into
    `0x40`/`0x60`, hash the 4-segment pair, mask the digest back, recurse. -/
def htClimbBody : List Stmt :=
  [ .letv "sibling" (.bin .band (.calldataload (.bin .add (.var "merklePtr")
        (.bin .shl (.lit 4) (.var "h")))) (.var "N_MASK"))
  , .letv "parentIdx" (.bin .shr (.lit 1) (.var "mIdx"))
  , .mstore (.lit 0x20)
      (.bin .bor (.bin .band (.var "treeAdrs")
            (.lit 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000))
        (.bin .bor (.bin .shl (.lit 32) (.bin .add (.var "h") (.lit 1))) (.var "parentIdx")))
  , .letv "s" (.bin .shl (.lit 5) (.bin .band (.var "mIdx") (.lit 1)))
  , .mstore (.bin .bxor (.lit 0x40) (.var "s")) (.var "merkleNode")
  , .mstore (.bin .bxor (.lit 0x60) (.var "s")) (.var "sibling")
  , .sha256 (.lit 0x00) (.lit 0x80) (.var "OUT")
  , .setv "merkleNode" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))
  , .setv "mIdx" (.var "parentIdx") ]

/-- `(p &&& 1) <<< 5 % W` is `0` when `p` even, `32` when `p` odd (the branchless-swap
    parity). Local copy of Phases' private `s_value`. -/
private theorem s_value (p : Nat) :
    (p &&& 1) <<< 5 % W = if p % 2 == 0 then 0 else 32 := by
  rw [Nat.and_one_is_mod]
  have h2 : p % 2 = 0 ∨ p % 2 = 1 := Nat.mod_two_eq_zero_or_one p
  rcases h2 with h | h
  · rw [h]; rfl
  · rw [h]; rfl

/-! ### One HT Merkle-climb level (clone of `fors_climb_step`)

Same structure as `fors_climb_step` (branchless swap, `climbMem_thPair`, masked
read-back), with `treeNode` ADRS (the `treeAdrs &&& TREEADRS_MASK` form), and the
accumulator field order SWAPPED — `htAcc`/`htStep` are `⟨pathIdx, node⟩` (`.fst` =
idx, `.snd` = node), the order `verifyAuthPath`'s `do`-block elaborates to. -/
set_option maxHeartbeats 4000000 in
set_option maxRecDepth 4000 in
theorem ht_climb_step
    (sig : ByteVec Spec.SignatureLen)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (leafNode : ByteVec 16) (leafIdx : Nat) (authPath : Array (ByteVec 16)) (tBase mptr : Nat)
    (H_adrs : ∀ h, h < Spec.SubtreeH → ∀ p, p < 2 ^ 32 →
        (tBase &&& 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000)
          ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
        = wordOf (Spec.Adrs.treeNode layer tree (UInt32.ofNat (h + 1)) (UInt32.ofNat (p / 2))))
    (H_sib : ∀ h, h < Spec.SubtreeH → calldataload sig ((mptr + h <<< 4 % W) % W) &&& NMASK
        = wordOf (ByteVec.pad16 (authPath.getD h (ByteVec.zero 16))))
    (cur : Nat) (hcur : cur < Spec.SubtreeH) (w : VM)
    (hR : w.env "merkleNode"
            = wordOf (ByteVec.pad16 (htAcc seed layer tree leafNode leafIdx authPath cur).snd)
          ∧ w.env "mIdx" = (htAcc seed layer tree leafNode leafIdx authPath cur).fst
          ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600
          ∧ w.env "treeAdrs" = tBase ∧ w.env "merklePtr" = mptr
          ∧ (∀ i, i < 32 → w.mem (0 + i) = seed.data.getD i 0)
          ∧ (htAcc seed layer tree leafNode leafIdx authPath cur).fst < 2 ^ 32) :
    (execList c10Oracle sig htClimbBody { w with env := setVar w.env "h" cur }).2 = none
    ∧ ((execList c10Oracle sig htClimbBody { w with env := setVar w.env "h" cur }).1.env "merkleNode"
          = wordOf (ByteVec.pad16 (htAcc seed layer tree leafNode leafIdx authPath (cur + 1)).snd)
        ∧ (execList c10Oracle sig htClimbBody { w with env := setVar w.env "h" cur }).1.env "mIdx"
            = (htAcc seed layer tree leafNode leafIdx authPath (cur + 1)).fst
        ∧ (execList c10Oracle sig htClimbBody { w with env := setVar w.env "h" cur }).1.env "N_MASK"
            = NMASK
        ∧ (execList c10Oracle sig htClimbBody { w with env := setVar w.env "h" cur }).1.env "OUT"
            = 0x600
        ∧ (execList c10Oracle sig htClimbBody { w with env := setVar w.env "h" cur }).1.env "treeAdrs"
            = tBase
        ∧ (execList c10Oracle sig htClimbBody { w with env := setVar w.env "h" cur }).1.env "merklePtr"
            = mptr
        ∧ (∀ i, i < 32 →
            (execList c10Oracle sig htClimbBody { w with env := setVar w.env "h" cur }).1.mem (0 + i)
              = seed.data.getD i 0)
        ∧ (htAcc seed layer tree leafNode leafIdx authPath (cur + 1)).fst < 2 ^ 32) := by
  obtain ⟨hRnode, hRpath, hRN, hROUT, hRtA, hRmptr, hRseed, hRbound⟩ := hR
  unfold htClimbBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  refine ⟨rfl, ?_⟩
  simp only [execStmt, eval, setVar, ite_true, ite_false, String.reduceEq,
    hRN, hROUT, hRtA, hRmptr, hRnode, hRpath]
  rw [htAcc_succ]
  rw [H_adrs cur hcur (htAcc seed layer tree leafNode leafIdx authPath cur).fst hRbound,
      H_sib cur hcur]
  rw [s_value]
  refine ⟨?node, ?path, trivial, trivial, trivial, trivial, ?mem, ?bound⟩
  · by_cases hpar : (htAcc seed layer tree leafNode leafIdx authPath cur).fst % 2 == 0
    · rw [if_pos hpar]
      simp only [show (64 : Nat) ^^^ 0 = 64 from rfl, show (96 : Nat) ^^^ 0 = 96 from rfl]
      rw [climbMem_thPair w.mem seed _ _ _ hRseed]
      show _ = wordOf (ByteVec.pad16 (htStep seed layer tree authPath
        (htAcc seed layer tree leafNode leafIdx authPath cur) cur).snd)
      unfold htStep
      rw [if_pos hpar]
    · rw [if_neg hpar]
      simp only [show (64 : Nat) ^^^ 32 = 96 from rfl, show (96 : Nat) ^^^ 32 = 64 from rfl]
      rw [mstore32_comm _ 96 64 _ _ (by omega)]
      rw [climbMem_thPair w.mem seed _ _ _ hRseed]
      show _ = wordOf (ByteVec.pad16 (htStep seed layer tree authPath
        (htAcc seed layer tree leafNode leafIdx authPath cur) cur).snd)
      unfold htStep
      rw [if_neg hpar]
  · show ((htAcc seed layer tree leafNode leafIdx authPath cur).fst >>> 1)
      = (htStep seed layer tree authPath
          (htAcc seed layer tree leafNode leafIdx authPath cur) cur).fst
    unfold htStep
    rw [Nat.shiftRight_eq_div_pow, Nat.pow_one]
    simp only []
    split <;> rfl
  · intro i hi
    rw [writeRegion_frame _ _ _ (0 + i) (by omega)]
    by_cases hpar : (htAcc seed layer tree leafNode leafIdx authPath cur).fst % 2 == 0
    · rw [if_pos hpar]
      simp only [show (64 : Nat) ^^^ 0 = 64 from rfl, show (96 : Nat) ^^^ 0 = 96 from rfl]
      rw [mstore32_frame _ 96 _ (0 + i) (by omega), mstore32_frame _ 64 _ (0 + i) (by omega),
          mstore32_frame _ 32 _ (0 + i) (by omega)]
      exact hRseed i hi
    · rw [if_neg hpar]
      simp only [show (64 : Nat) ^^^ 32 = 96 from rfl, show (96 : Nat) ^^^ 32 = 64 from rfl]
      rw [mstore32_frame _ 64 _ (0 + i) (by omega), mstore32_frame _ 96 _ (0 + i) (by omega),
          mstore32_frame _ 32 _ (0 + i) (by omega)]
      exact hRseed i hi
  · show (htStep seed layer tree authPath
        (htAcc seed layer tree leafNode leafIdx authPath cur) cur).fst < 2 ^ 32
    have hfst : (htStep seed layer tree authPath
        (htAcc seed layer tree leafNode leafIdx authPath cur) cur).fst
        = (htAcc seed layer tree leafNode leafIdx authPath cur).fst / 2 := by
      unfold htStep
      by_cases hp : (htAcc seed layer tree leafNode leafIdx authPath cur).fst % 2 == 0
      · rw [if_pos hp]
      · rw [if_neg hp]
    rw [hfst]
    exact Nat.lt_of_le_of_lt (Nat.div_le_self _ 2) hRbound

/-! ### The HT Merkle climb (clone of `fors_climb`) -/

set_option maxHeartbeats 2000000 in
set_option maxRecDepth 4000 in
/-- **Hypertree XMSS Merkle climb.** Running the `SubtreeH=9`-level inner Merkle
    climb (`htClimbBody`) from a VM whose env supplies the leaf node word
    `merkleNode = wordOf (pad16 leafNode)` (the WOTS public key), leaf index
    `mIdx = leafIdx`, the persisting consts, and `seed` in scratch `[0,0x20)`, falls
    through (`.2 = none`) and binds `"merkleNode"` to
    `wordOf (pad16 (verifyAuthPath seed layer tree leafNode leafIdx authPath))`.
    Clone of `fors_climb` (no leaf hash; `treeNode` ADRS; `htAcc`'s swapped fields).
    `hleaf : leafIdx < 2^32` seeds the running-pathIdx bound (free downstream: the
    leaf index is `idxLeaf = idxTree &&& 0x1FF < 512`). -/
theorem ht_climb
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (leafNode : ByteVec 16) (leafIdx : Nat) (authPath : Array (ByteVec 16))
    (tBase mptr : Nat) (hleaf : leafIdx < 2 ^ 32)
    (hNMASK : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (htA : vm.env "treeAdrs" = tBase)
    (hmptr : vm.env "merklePtr" = mptr)
    (hnode : vm.env "merkleNode" = wordOf (ByteVec.pad16 leafNode))
    (hpath : vm.env "mIdx" = leafIdx)
    (hseed : ∀ i, i < 32 → vm.mem (0 + i) = seed.data.getD i 0)
    (H_adrs : ∀ h, h < Spec.SubtreeH → ∀ p, p < 2 ^ 32 →
        (tBase &&& 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000)
          ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
        = wordOf (Spec.Adrs.treeNode layer tree (UInt32.ofNat (h + 1)) (UInt32.ofNat (p / 2))))
    (H_sib : ∀ h, h < Spec.SubtreeH → calldataload sig ((mptr + h <<< 4 % W) % W) &&& NMASK
        = wordOf (ByteVec.pad16 (authPath.getD h (ByteVec.zero 16)))) :
    (execFor c10Oracle sig "h" htClimbBody Spec.SubtreeH 0 vm).2 = none
    ∧ ((execFor c10Oracle sig "h" htClimbBody Spec.SubtreeH 0 vm).1).env "merkleNode"
        = wordOf (ByteVec.pad16
            (Spec.Hypertree.verifyAuthPath seed layer tree leafNode leafIdx authPath))
    ∧ (∀ i, i < 32 → ((execFor c10Oracle sig "h" htClimbBody Spec.SubtreeH 0 vm).1).mem (0 + i)
        = seed.data.getD i 0) := by
  let R : Nat → VM → Prop := fun c w =>
    w.env "merkleNode" = wordOf (ByteVec.pad16 (htAcc seed layer tree leafNode leafIdx authPath c).snd)
    ∧ w.env "mIdx" = (htAcc seed layer tree leafNode leafIdx authPath c).fst
    ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600
    ∧ w.env "treeAdrs" = tBase ∧ w.env "merklePtr" = mptr
    ∧ (∀ i, i < 32 → w.mem (0 + i) = seed.data.getD i 0)
    ∧ (htAcc seed layer tree leafNode leafIdx authPath c).fst < 2 ^ 32
  have hstep : ∀ cur w, cur < Spec.SubtreeH → R cur w →
      (execList c10Oracle sig htClimbBody { w with env := setVar w.env "h" cur }).2 = none ∧
      R (cur + 1) (execList c10Oracle sig htClimbBody { w with env := setVar w.env "h" cur }).1 :=
    fun cur w hcur hRcw =>
      ht_climb_step sig seed layer tree leafNode leafIdx authPath tBase mptr
        H_adrs H_sib cur hcur w hRcw
  have hR0 : R 0 vm := by
    refine ⟨?_, ?_, hNMASK, hOUT, htA, hmptr, hseed, ?_⟩
    · rw [hnode, htAcc_zero]
    · rw [hpath, htAcc_zero]
    · rw [htAcc_zero]; exact hleaf
  have hloop := execFor_invariant_lt c10Oracle sig "h" htClimbBody Spec.SubtreeH R hstep vm hR0
  obtain ⟨hn, _, _, _, _, _, hmemfinal, _⟩ := hloop.2
  refine ⟨hloop.1, ?_, hmemfinal⟩
  rw [hn]
  show wordOf (ByteVec.pad16 (htAcc seed layer tree leafNode leafIdx authPath Spec.SubtreeH).snd) = _
  rw [verifyAuthPath_eq_htAcc]

/-! ### The interpreter per-layer body

`htLayerBody` is one hypertree layer (`SPHINCsC10Asm.sol` L149-228, the body of
`c10Program`'s `forRange "layer" (lit 2)`), built as `setup ++ wotsBody ++ setup2
++ [the Merkle forRange] ++ finalize`. The big WOTS and Merkle parts reuse the
already-defined `wotsBody` (Phases) and `htClimbBody` — so this is defeq to
c10Program's inline layer body (`List.append` of literals flattens; `wotsBody`/
`htClimbBody` unfold to the same statements). `ht_layer` (next) composes
`wots_pkfromsig` and `ht_climb` over it = one `Spec.Hypertree.verifyHypertree` step. -/
def htLayerBody : List Stmt :=
  -- setup (L161-167): idxLeaf, idxTree>>=9, wotsAdrs, countOff, count
  [ .letv "idxLeaf" (.bin .band (.var "idxTree") (.lit 0x1FF))
  , .setv "idxTree" (.bin .shr (.lit 9) (.var "idxTree"))
  , .letv "wotsAdrs"
      (.bin .bor (.bin .shl (.lit 224) (.var "layer"))
        (.bin .bor (.bin .shl (.lit 160) (.var "idxTree")) (.bin .shl (.lit 96) (.var "idxLeaf"))))
  , .letv "countOff" (.bin .add (.var "sigOff") (.lit 688))
  , .letv "count" (.bin .shr (.lit 224) (.calldataload (.bin .add (.var "sigBase") (.var "countOff")))) ]
  -- the WOTS+C fragment (digit hash, digit-sum gate, chains, PK compress → "wotsPk")
  ++ wotsBody
  -- setup2 (L207-213): authOff, treeAdrs, merkleNode := wotsPk, mIdx := idxLeaf, merklePtr
  ++ [ .letv "authOff" (.bin .add (.var "countOff") (.lit 4))
     , .letv "treeAdrs"
         (.bin .bor (.bin .shl (.lit 224) (.var "layer"))
           (.bin .bor (.bin .shl (.lit 160) (.var "idxTree")) (.bin .shl (.lit 128) (.lit 2))))
     , .letv "merkleNode" (.var "wotsPk")
     , .letv "mIdx" (.var "idxLeaf")
     , .letv "merklePtr" (.bin .add (.var "sigBase") (.var "authOff")) ]
  -- the XMSS Merkle auth-path climb (9 levels)
  ++ [ .forRange "h" (.lit 9) htClimbBody ]
  -- finalize (L227-228): currentNode := merkleNode, sigOff := authOff + 144
  ++ [ .setv "currentNode" (.var "merkleNode")
     , .setv "sigOff" (.bin .add (.var "authOff") (.lit 144)) ]

/-! ### `verifyHypertree` as a fold

Same `forIn → foldl` collapse as `verifyAuthPath_eq_foldl`, but the loop body has
a 3-field mutable accumulator `⟨bad, currentNode, idxTree⟩` and an inner
`pkFromSig` match. `vhStep` is one layer of that fold; once `bad` is set it is the
identity (mirrors `if bad then pure ()`). -/
-- Seal the heavy spec calls so the `forIn → foldl` `simp` does not try to whnf
-- through the WOTS chain / SHA-256 (those seals in `Phases` are file-`local`, so
-- they do not reach here — `verifyAuthPath_eq_foldl` only survived above because
-- its body has no `pkFromSig`). Stays in force for `ht_layer`/`verifyHypertree_refine` too.
attribute [local irreducible] Spec.Wots.pkFromSig Spec.Hypertree.verifyAuthPath
  Spec.wotsDigest Spec.chainHash SphincsCVerify.Util.digitSum SphincsCVerify.Util.extractDigits
  Spec.Adrs.wots Spec.Adrs.treeNode

/-- **Pointwise `forIn → foldl` bridge.** Like `List.forIn_pure_yield_eq_foldl`, but the
    body need only *equal* `pure ∘ yield ∘ f` pointwise (`h`) rather than be syntactically
    in that form — so a body with an inner `match` (whose auxiliary differs from a
    transcribed copy) is matched by unification on the bound `body`, sidestepping the
    `match`-aux syntactic mismatch that defeats `rw`/`simp` on the lambda directly. -/
theorem forIn_yield_eq_foldl_pointwise {α β : Type _} (l : List α) (init : β)
    (body : α → β → ForInStep β) (f : α → β → β)
    (h : ∀ a b, body a b = ForInStep.yield (f a b)) :
    forIn (m := Id) l init body = List.foldl (fun b a => f a b) init l := by
  induction l generalizing init with
  | nil => rfl
  | cons a l ih =>
    rw [List.forIn_cons, h a init]
    exact ih (f a init)

def vhStep (seed : ByteVec 32) (layers : Array Spec.Hypertree.LayerSig)
    (acc : MProd Bool (MProd (ByteVec 16) Nat)) (layer : Nat) :
    MProd Bool (MProd (ByteVec 16) Nat) :=
  if acc.fst then acc
  else
    let idxLeaf := acc.snd.snd &&& ((1 <<< Spec.SubtreeH) - 1)
    let idxTree' := acc.snd.snd >>> Spec.SubtreeH
    let layerSig := layers.getD layer Spec.Hypertree.defaultLayerSig
    match Spec.Wots.pkFromSig seed (UInt32.ofNat layer) (UInt64.ofNat idxTree')
            (UInt32.ofNat idxLeaf) acc.snd.fst layerSig.wots with
    | none => ⟨true, acc.snd.fst, idxTree'⟩
    | some wotsPk =>
      ⟨false, Spec.Hypertree.verifyAuthPath seed (UInt32.ofNat layer) (UInt64.ofNat idxTree')
          wotsPk idxLeaf layerSig.authPath, idxTree'⟩

theorem verifyHypertree_eq_foldl
    (seed : ByteVec 32) (forsPk : ByteVec 16) (htIdx : Nat)
    (layers : Array Spec.Hypertree.LayerSig) :
    Spec.Hypertree.verifyHypertree seed forsPk htIdx layers
      = (let r := (List.range' 0 Spec.D).foldl (vhStep seed layers)
            (⟨false, forsPk, htIdx⟩ : MProd Bool (MProd (ByteVec 16) Nat))
         if r.fst then none else some r.snd.fst) := by
  rw [Spec.Hypertree.verifyHypertree]
  set_option linter.deprecated false in
  simp only [Std.Range.forIn_eq_forIn_range', Std.Range.size, Nat.sub_zero, Nat.add_sub_cancel,
    Nat.div_one, Id.run, Id.bind_eq, Id.pure_eq]
  rw [forIn_yield_eq_foldl_pointwise (f := fun layer r => vhStep seed layers r layer) (h := ?hpt)]
  case hpt =>
    intro layer r
    show _ = ForInStep.yield (vhStep seed layers r layer)
    simp only [vhStep]
    by_cases hr : r.fst = true
    · rw [if_pos hr, if_pos hr]
    · rw [if_neg hr, if_neg hr]
      simp only [Bool.not_eq_true] at hr
      cases Spec.Wots.pkFromSig seed (UInt32.ofNat layer) (UInt64.ofNat (r.snd.snd >>> Spec.SubtreeH))
          (UInt32.ofNat (r.snd.snd &&& 1 <<< Spec.SubtreeH - 1)) r.snd.fst
          (layers.getD layer Spec.Hypertree.defaultLayerSig).wots with
      | none => rfl
      | some wotsPk => rw [hr]

/-! ### One hypertree layer — `ht_layer_step`

`execList htLayerBody` over a VM holding a layer's entry state refines one `vhStep`:
the WOTS+C digit-sum gate failing makes the layer revert (↔ `pkFromSig = none` ↔
`vhStep` sets `bad`); otherwise it yields `currentNode = wordOf(pad16(verifyAuthPath
… wotsPk …))`, `idxTree >>>= SubtreeH`, `sigOff += 836`. Composes `wots_pkfromsig`
(WOTS fragment) and `ht_climb` (XMSS Merkle climb) across the `setup ++ wotsBody ++
setup2 ++ [Merkle] ++ finalize` split. The sig-byte relationships (`hsig`, `hcount`,
`H_sib`) and the treeNode ADRS layout (`H_adrs`) thread to the sub-lemmas; the grand
composition discharges them from `deserialise`. -/
theorem ht_layer_step
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (layer : UInt32) (idxTreeIn : Nat) (cnode : ByteVec 16)
    (sigOffIn : Nat) (sigma : Spec.Wots.Sigma) (authPath : Array (ByteVec 16))
    (hwp : sigOffIn < 4096)
    (hidxbnd : idxTreeIn < 2 ^ 64)   -- htIdx is a u64; needed so `idxTreeIn >>> 9 < 2^64`
                                     -- (the `tree`-field round-trip in `H_adrs` / `wordOf_treeNode`)
    (hpathSize : authPath.size = Spec.SubtreeH)
    -- entry env
    (hlayer : vm.env "layer" = layer.toNat)
    (hidxTree : vm.env "idxTree" = idxTreeIn)
    (hsigoff : vm.env "sigOff" = sigOffIn)
    (hcn : vm.env "currentNode" = wordOf (ByteVec.pad16 cnode))
    (hseedw : vm.env "seed" = wordOf seed)
    (hsigbase : vm.env "sigBase" = 0)
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hseedmem : ∀ i, i < 32 → vm.mem (0 + i) = seed.data.getD i 0)
    -- the layer's WOTS sig + auth-path bytes (forwarded to the sub-lemmas)
    (hsig : ∀ i (h : i < sigma.chains.size),
        sigma.chains[i] = ByteVec.loadValue16 sig (sigOffIn + 16 * i))
    (hcount : calldataload sig (sigOffIn + 688) >>> 224
        = wordOf (ByteVec.u32ToB32 sigma.count))
    -- the treeNode ADRS layout for the Merkle climb's `tBase`
    (H_adrs : ∀ h, h < Spec.SubtreeH → ∀ p, p < 2 ^ 32 →
        ((layer.toNat <<< 224 ||| (idxTreeIn >>> 9) <<< 160 ||| 2 <<< 128)
            &&& 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000)
          ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
        = wordOf (Spec.Adrs.treeNode layer (UInt64.ofNat (idxTreeIn >>> 9))
            (UInt32.ofNat (h + 1)) (UInt32.ofNat (p / 2))))
    (H_sib : ∀ h, h < Spec.SubtreeH →
        calldataload sig (((sigOffIn + 692) + h <<< 4 % W) % W) &&& NMASK
        = wordOf (ByteVec.pad16 (authPath.getD h (ByteVec.zero 16)))) :
    (if SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits
          (Spec.wotsDigest seed (Spec.Adrs.wots layer (UInt64.ofNat (idxTreeIn >>> 9))
            (UInt32.ofNat (idxTreeIn &&& 0x1FF))) (ByteVec.pad16 cnode) sigma.count))
          ≠ Spec.TargetSum then
        (execList c10Oracle sig htLayerBody vm).2 = some Halt.reverted
      else
        (execList c10Oracle sig htLayerBody vm).2 = none
        ∧ ∃ wotsPk, Spec.Wots.pkFromSig seed layer (UInt64.ofNat (idxTreeIn >>> 9))
              (UInt32.ofNat (idxTreeIn &&& 0x1FF)) cnode sigma = some wotsPk
          ∧ (execList c10Oracle sig htLayerBody vm).1.env "currentNode"
              = wordOf (ByteVec.pad16 (Spec.Hypertree.verifyAuthPath seed layer
                  (UInt64.ofNat (idxTreeIn >>> 9)) wotsPk (idxTreeIn &&& 0x1FF) authPath))
          ∧ (execList c10Oracle sig htLayerBody vm).1.env "idxTree" = idxTreeIn >>> 9
          ∧ (execList c10Oracle sig htLayerBody vm).1.env "sigOff" = sigOffIn + 836
          ∧ (execList c10Oracle sig htLayerBody vm).1.env "seed" = wordOf seed
          ∧ (execList c10Oracle sig htLayerBody vm).1.env "sigBase" = 0
          ∧ (execList c10Oracle sig htLayerBody vm).1.env "N_MASK" = NMASK
          ∧ (execList c10Oracle sig htLayerBody vm).1.env "OUT" = 0x600
          ∧ (∀ i, i < 32 → (execList c10Oracle sig htLayerBody vm).1.mem (0 + i)
              = seed.data.getD i 0)) := by
  -- PROOF PLAN (mathlib-free → no `set`; mirror `fors_phase_zero` 3099+):
  --   by_cases hgate on the digit-sum gate (so each branch fixes it), then in each branch
  --   step the layer body in the MAIN flow via `execList_cons_none`/`execList_append`
  --   (`obtain ⟨vK, hvK⟩ : ∃ vK, (execStmt … sK …).1 = vK := ⟨_, rfl⟩; rw [hvK]`), discharging
  --   each `vK.env` fact by `rw [← hvK]; simp only [execStmt, eval, setVar, String.reduceEq,
  --   ite_false]; exact …`. setup(5) → establish `wots_pkfromsig`'s 15 preconds (wotsAdrs via
  --   `wordOf_wots` + `%W` identity via `Nat.mod_eq_of_lt`; count via `hcount`); apply
  --   `wots_pkfromsig`; gate-fail → `execList_append` short-circuits to `some reverted`; gate-pass
  --   → setup2(5) → `ht_climb` (forward `H_adrs`/`H_sib`; needs de-privatized
  --   `shl_lt_two_pow_256`/`lt_W_of_lt` only at `verifyHypertree_refine`'s discharge, not here)
  --   → finalize(2). Verify chunks with `lean_diagnostic_messages severity error` (the conclusion
  --   inlines `execList … htLayerBody vm` ~10×, so `lean_goal` dumps are huge — avoid).
  by_cases hgate : SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits
        (Spec.wotsDigest seed (Spec.Adrs.wots layer (UInt64.ofNat (idxTreeIn >>> 9))
          (UInt32.ofNat (idxTreeIn &&& 0x1FF))) (ByteVec.pad16 cnode) sigma.count))
        ≠ Spec.TargetSum
  · rw [if_pos hgate]
    rw [htLayerBody]
    simp only [List.cons_append, List.nil_append, List.append_assoc]
    -- s1: idxLeaf := idxTree &&& 0x1FF
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    obtain ⟨v1, hv1⟩ : ∃ v1, (execStmt c10Oracle sig
        (.letv "idxLeaf" (.bin .band (.var "idxTree") (.lit 0x1FF))) vm).1 = v1 := ⟨_, rfl⟩
    rw [hv1]
    -- s2: idxTree := idxTree >>> 9
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    obtain ⟨v2, hv2⟩ : ∃ v2, (execStmt c10Oracle sig
        (.setv "idxTree" (.bin .shr (.lit 9) (.var "idxTree"))) v1).1 = v2 := ⟨_, rfl⟩
    rw [hv2]
    -- s3: wotsAdrs
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    obtain ⟨v3, hv3⟩ : ∃ v3, (execStmt c10Oracle sig
        (.letv "wotsAdrs" (.bin .bor (.bin .shl (.lit 224) (.var "layer"))
          (.bin .bor (.bin .shl (.lit 160) (.var "idxTree")) (.bin .shl (.lit 96) (.var "idxLeaf"))))) v2).1
        = v3 := ⟨_, rfl⟩
    rw [hv3]
    -- s4: countOff := sigOff + 688
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    obtain ⟨v4, hv4⟩ : ∃ v4, (execStmt c10Oracle sig
        (.letv "countOff" (.bin .add (.var "sigOff") (.lit 688))) v3).1 = v4 := ⟨_, rfl⟩
    rw [hv4]
    -- s5: count := shr 224 (calldataload (sigBase + countOff))
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    obtain ⟨v5, hv5⟩ : ∃ v5, (execStmt c10Oracle sig
        (.letv "count" (.bin .shr (.lit 224)
          (.calldataload (.bin .add (.var "sigBase") (.var "countOff"))))) v4).1 = v5 := ⟨_, rfl⟩
    rw [hv5]
    rw [execList_append]
    -- v5 env facts (propagated unchanged through the 5 setup setVars)
    have hv5seed : v5.env "seed" = wordOf seed := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hseedw
    have hv5sb : v5.env "sigBase" = 0 := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hsigbase
    have hv5so : v5.env "sigOff" = sigOffIn := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hsigoff
    have hv5layer : v5.env "layer" = layer.toNat := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hlayer
    have hv5N : v5.env "N_MASK" = NMASK := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hN
    have hv5OUT : v5.env "OUT" = 0x600 := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hOUT
    have hv5cn : v5.env "currentNode" = wordOf (ByteVec.pad16 cnode) := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hcn
    have hv5mem : ∀ i, i < 32 → v5.mem (0 + i) = seed.data.getD i 0 := by
      intro i hi; rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval]; exact hseedmem i hi
    -- computed: idxLeaf = idxTree &&& 0x1FF, idxTree updated to idxTree >>> 9 (round-trips)
    have hv5idxLeaf : v5.env "idxLeaf" = (UInt32.ofNat (idxTreeIn &&& 0x1FF)).toNat := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
      rw [hidxTree, UInt32.toNat_ofNat_of_lt' (Nat.lt_of_le_of_lt Nat.and_le_right (by decide))]
    have hv5idxTree : v5.env "idxTree" = (UInt64.ofNat (idxTreeIn >>> 9)).toNat := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
      rw [hidxTree, UInt64.toNat_ofNat_of_lt'
        (by rw [Nat.shiftRight_eq_div_pow]; exact Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hidxbnd)]
    -- count = shr 224 (calldataload (sigBase + countOff)); the double %W collapses (sigOff+688 < W)
    have hv5count : v5.env "count" = wordOf (ByteVec.u32ToB32 sigma.count) := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
      rw [hsigbase, hsigoff, Nat.zero_add, Nat.mod_mod]
      have hb : sigOffIn + 688 < W := by
        show sigOffIn + 688 < 2 ^ 256
        exact Nat.lt_of_lt_of_le (show sigOffIn + 688 < 2 ^ 13 by omega)
          (Nat.pow_le_pow_right (by decide) (by decide))
      rw [Nat.mod_eq_of_lt hb]
      exact hcount
    -- wotsAdrs = layer<<<224 | idxTree<<<160 | idxLeaf<<<96  (= wordOf (Adrs.wots …), ADRS_WOTS=0)
    have hv5wa : v5.env "wotsAdrs"
        = wordOf (Spec.Adrs.wots layer (UInt64.ofNat (idxTreeIn >>> 9))
            (UInt32.ofNat (idxTreeIn &&& 0x1FF))) := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
      -- %W drops stated as `% W` haves (defeq to `% 2^256`) so `rw` matches the goal's `W`
      have hwL : layer.toNat <<< 224 % W = layer.toNat <<< 224 :=
        Nat.mod_eq_of_lt (shl_lt_two_pow_256 layer.toNat 32 224 layer.toNat_lt (by decide))
      have hidx9 : idxTreeIn >>> 9 < 2 ^ 64 := by
        rw [Nat.shiftRight_eq_div_pow]; exact Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hidxbnd
      have hwT : (idxTreeIn >>> 9) <<< 160 % W = (idxTreeIn >>> 9) <<< 160 :=
        Nat.mod_eq_of_lt (shl_lt_two_pow_256 (idxTreeIn >>> 9) 64 160 hidx9 (by decide))
      have hand : idxTreeIn &&& 0x1FF < 2 ^ 9 := Nat.lt_of_le_of_lt Nat.and_le_right (by decide)
      have hwLf : (idxTreeIn &&& 0x1FF) <<< 96 % W = (idxTreeIn &&& 0x1FF) <<< 96 :=
        Nat.mod_eq_of_lt (shl_lt_two_pow_256 (idxTreeIn &&& 0x1FF) 9 96 hand (by decide))
      rw [hlayer, hidxTree, wordOf_wots, hwL, hwT, hwLf,
        UInt64.toNat_ofNat_of_lt' hidx9,
        UInt32.toNat_ofNat_of_lt' (Nat.lt_of_le_of_lt Nat.and_le_right (by decide)),
        (by decide : (UInt32.ofNat Spec.ADRS_WOTS).toNat = 0),
        Nat.zero_shiftLeft, Nat.or_zero, Nat.or_assoc]
    -- apply wots_pkfromsig; gate-fail → wotsBody reverts → execList_append short-circuits
    have hw := wots_pkfromsig sig v5 seed layer (UInt64.ofNat (idxTreeIn >>> 9))
      (UInt32.ofNat (idxTreeIn &&& 0x1FF)) cnode sigma sigOffIn hwp hsig
      hv5seed hv5wa hv5cn hv5count hv5sb hv5so hv5layer hv5idxTree hv5idxLeaf hv5N hv5OUT
    rw [if_pos hgate] at hw
    cases hwex : execList c10Oracle sig wotsBody v5 with
    | mk w' o => rw [hwex] at hw; simp only at hw; subst hw; rfl
  · rw [if_neg hgate]
    rw [htLayerBody]
    simp only [List.cons_append, List.nil_append, List.append_assoc]
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    obtain ⟨v1, hv1⟩ : ∃ v1, (execStmt c10Oracle sig
        (.letv "idxLeaf" (.bin .band (.var "idxTree") (.lit 0x1FF))) vm).1 = v1 := ⟨_, rfl⟩
    rw [hv1]
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    obtain ⟨v2, hv2⟩ : ∃ v2, (execStmt c10Oracle sig
        (.setv "idxTree" (.bin .shr (.lit 9) (.var "idxTree"))) v1).1 = v2 := ⟨_, rfl⟩
    rw [hv2]
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    obtain ⟨v3, hv3⟩ : ∃ v3, (execStmt c10Oracle sig
        (.letv "wotsAdrs" (.bin .bor (.bin .shl (.lit 224) (.var "layer"))
          (.bin .bor (.bin .shl (.lit 160) (.var "idxTree")) (.bin .shl (.lit 96) (.var "idxLeaf"))))) v2).1
        = v3 := ⟨_, rfl⟩
    rw [hv3]
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    obtain ⟨v4, hv4⟩ : ∃ v4, (execStmt c10Oracle sig
        (.letv "countOff" (.bin .add (.var "sigOff") (.lit 688))) v3).1 = v4 := ⟨_, rfl⟩
    rw [hv4]
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    obtain ⟨v5, hv5⟩ : ∃ v5, (execStmt c10Oracle sig
        (.letv "count" (.bin .shr (.lit 224)
          (.calldataload (.bin .add (.var "sigBase") (.var "countOff"))))) v4).1 = v5 := ⟨_, rfl⟩
    rw [hv5]
    rw [execList_append]
    have hv5seed : v5.env "seed" = wordOf seed := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hseedw
    have hv5sb : v5.env "sigBase" = 0 := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hsigbase
    have hv5so : v5.env "sigOff" = sigOffIn := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hsigoff
    have hv5layer : v5.env "layer" = layer.toNat := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hlayer
    have hv5N : v5.env "N_MASK" = NMASK := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hN
    have hv5OUT : v5.env "OUT" = 0x600 := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hOUT
    have hv5cn : v5.env "currentNode" = wordOf (ByteVec.pad16 cnode) := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hcn
    have hv5mem : ∀ i, i < 32 → v5.mem (0 + i) = seed.data.getD i 0 := by
      intro i hi; rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval]; exact hseedmem i hi
    have hv5idxLeaf : v5.env "idxLeaf" = (UInt32.ofNat (idxTreeIn &&& 0x1FF)).toNat := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
      rw [hidxTree, UInt32.toNat_ofNat_of_lt' (Nat.lt_of_le_of_lt Nat.and_le_right (by decide))]
    have hv5idxTree : v5.env "idxTree" = (UInt64.ofNat (idxTreeIn >>> 9)).toNat := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
      rw [hidxTree, UInt64.toNat_ofNat_of_lt'
        (by rw [Nat.shiftRight_eq_div_pow]; exact Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hidxbnd)]
    have hv5count : v5.env "count" = wordOf (ByteVec.u32ToB32 sigma.count) := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
      rw [hsigbase, hsigoff, Nat.zero_add, Nat.mod_mod]
      have hb : sigOffIn + 688 < W := by
        show sigOffIn + 688 < 2 ^ 256
        exact Nat.lt_of_lt_of_le (show sigOffIn + 688 < 2 ^ 13 by omega)
          (Nat.pow_le_pow_right (by decide) (by decide))
      rw [Nat.mod_eq_of_lt hb]
      exact hcount
    have hv5wa : v5.env "wotsAdrs"
        = wordOf (Spec.Adrs.wots layer (UInt64.ofNat (idxTreeIn >>> 9))
            (UInt32.ofNat (idxTreeIn &&& 0x1FF))) := by
      rw [← hv5, ← hv4, ← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
      have hwL : layer.toNat <<< 224 % W = layer.toNat <<< 224 :=
        Nat.mod_eq_of_lt (shl_lt_two_pow_256 layer.toNat 32 224 layer.toNat_lt (by decide))
      have hidx9 : idxTreeIn >>> 9 < 2 ^ 64 := by
        rw [Nat.shiftRight_eq_div_pow]; exact Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hidxbnd
      have hwT : (idxTreeIn >>> 9) <<< 160 % W = (idxTreeIn >>> 9) <<< 160 :=
        Nat.mod_eq_of_lt (shl_lt_two_pow_256 (idxTreeIn >>> 9) 64 160 hidx9 (by decide))
      have hand : idxTreeIn &&& 0x1FF < 2 ^ 9 := Nat.lt_of_le_of_lt Nat.and_le_right (by decide)
      have hwLf : (idxTreeIn &&& 0x1FF) <<< 96 % W = (idxTreeIn &&& 0x1FF) <<< 96 :=
        Nat.mod_eq_of_lt (shl_lt_two_pow_256 (idxTreeIn &&& 0x1FF) 9 96 hand (by decide))
      rw [hlayer, hidxTree, wordOf_wots, hwL, hwT, hwLf,
        UInt64.toNat_ofNat_of_lt' hidx9,
        UInt32.toNat_ofNat_of_lt' (Nat.lt_of_le_of_lt Nat.and_le_right (by decide)),
        (by decide : (UInt32.ofNat Spec.ADRS_WOTS).toNat = 0),
        Nat.zero_shiftLeft, Nat.or_zero, Nat.or_assoc]
    -- countOff = sigOff + 688 (bound at s4, preserved through s5; %W collapses)
    have hv5countOff : v5.env "countOff" = sigOffIn + 688 := by
      rw [← hv5, ← hv4]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
      rw [← hv3, ← hv2, ← hv1]
      simp only [execStmt, eval, setVar, String.reduceEq, ite_false]
      rw [hsigoff]
      exact Nat.mod_eq_of_lt (show sigOffIn + 688 < 2 ^ 256 from
        Nat.lt_of_lt_of_le (show sigOffIn + 688 < 2 ^ 13 by omega)
          (Nat.pow_le_pow_right (by decide) (by decide)))
    have hw := wots_pkfromsig sig v5 seed layer (UInt64.ofNat (idxTreeIn >>> 9))
      (UInt32.ofNat (idxTreeIn &&& 0x1FF)) cnode sigma sigOffIn hwp hsig
      hv5seed hv5wa hv5cn hv5count hv5sb hv5so hv5layer hv5idxTree hv5idxLeaf hv5N hv5OUT
    rw [if_neg hgate] at hw
    obtain ⟨hwnone, wpk, hpk, hwpk⟩ := hw
    -- hwnone : (execList wotsBody v5).2 = none ; hwpk : (execList wotsBody v5).1.env "wotsPk" = wordOf (pad16 wpk)
    -- resolve the wots match: execList wotsBody v5 = (v6, none) → match → execList (setup2++merkle++finalize) v6
    cases hwe : execList c10Oracle sig wotsBody v5 with
    | mk v6 o =>
      rw [hwe] at hwnone hwpk
      simp only at hwnone hwpk
      subst hwnone
      simp only [hwe]
      -- v6 = (execList wotsBody v5).1.  The WOTS loops touch only d/digitSum/ii/wotsPtr/i/chain
      -- scratch/pkAdrs/wotsPk — NOT idxLeaf/layer/idxTree/sigBase/countOff/sigOff/N_MASK/OUT/seed —
      -- so the generic env-frame (`execList_env_frame`, `assignsVarList wotsBody x = false` by decide)
      -- carries every entry var through.  Only the scratch window [0,0x20) (which `wotsBody` re-lays
      -- = seed) needs the dedicated `wotsBody_seed_mem` (Phases) — stubbed here, landed next.
      have hv6e : (execList c10Oracle sig wotsBody v5).1 = v6 := by rw [hwe]
      have hframe : ∀ x, assignsVarList wotsBody x = false → v6.env x = v5.env x := fun x hx => by
        rw [← hv6e]; exact execList_env_frame c10Oracle sig wotsBody x v5 hx
      have hv6layer : v6.env "layer" = layer.toNat := by rw [hframe "layer" (by decide)]; exact hv5layer
      have hv6idxTree : v6.env "idxTree" = (UInt64.ofNat (idxTreeIn >>> 9)).toNat := by
        rw [hframe "idxTree" (by decide)]; exact hv5idxTree
      have hv6idxLeaf : v6.env "idxLeaf" = (UInt32.ofNat (idxTreeIn &&& 0x1FF)).toNat := by
        rw [hframe "idxLeaf" (by decide)]; exact hv5idxLeaf
      have hv6sb : v6.env "sigBase" = 0 := by rw [hframe "sigBase" (by decide)]; exact hv5sb
      have hv6countOff : v6.env "countOff" = sigOffIn + 688 := by
        rw [hframe "countOff" (by decide)]; exact hv5countOff
      have hv6N : v6.env "N_MASK" = NMASK := by rw [hframe "N_MASK" (by decide)]; exact hv5N
      have hv6OUT : v6.env "OUT" = 0x600 := by rw [hframe "OUT" (by decide)]; exact hv5OUT
      have hv6seed : v6.env "seed" = wordOf seed := by rw [hframe "seed" (by decide)]; exact hv5seed
      -- seed-mem preserved by `wotsBody` (`wotsBody_seed_mem`, Phases): the digit hash re-lays
      -- the seed into scratch [0,0x20) and every later WOTS write is at ≥ 0x20.
      have hv6mem : ∀ i, i < 32 → v6.mem (0 + i) = seed.data.getD i 0 := by
        intro i hi; rw [← hv6e]; exact wotsBody_seed_mem sig v5 seed hv5seed hv5OUT i hi
      -- ===== setup2 (5 letvs): authOff, treeAdrs, merkleNode := wotsPk, mIdx := idxLeaf, merklePtr.
      rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
      obtain ⟨v7, hv7⟩ : ∃ v7, (execStmt c10Oracle sig
          (.letv "authOff" (.bin .add (.var "countOff") (.lit 4))) v6).1 = v7 := ⟨_, rfl⟩
      rw [hv7]
      rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
      obtain ⟨v8, hv8⟩ : ∃ v8, (execStmt c10Oracle sig
          (.letv "treeAdrs" (.bin .bor (.bin .shl (.lit 224) (.var "layer"))
            (.bin .bor (.bin .shl (.lit 160) (.var "idxTree")) (.bin .shl (.lit 128) (.lit 2))))) v7).1
          = v8 := ⟨_, rfl⟩
      rw [hv8]
      rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
      obtain ⟨v9, hv9⟩ : ∃ v9, (execStmt c10Oracle sig
          (.letv "merkleNode" (.var "wotsPk")) v8).1 = v9 := ⟨_, rfl⟩
      rw [hv9]
      rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
      obtain ⟨v10, hv10⟩ : ∃ v10, (execStmt c10Oracle sig
          (.letv "mIdx" (.var "idxLeaf")) v9).1 = v10 := ⟨_, rfl⟩
      rw [hv10]
      rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
      obtain ⟨v11, hv11⟩ : ∃ v11, (execStmt c10Oracle sig
          (.letv "merklePtr" (.bin .add (.var "sigBase") (.var "authOff"))) v10).1 = v11 := ⟨_, rfl⟩
      rw [hv11]
      -- %W collapse helpers (idxTreeIn >>> 9 < 2^64 etc.)
      have hidx9 : idxTreeIn >>> 9 < 2 ^ 64 := by
        rw [Nat.shiftRight_eq_div_pow]; exact Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hidxbnd
      have hwL : layer.toNat <<< 224 % W = layer.toNat <<< 224 :=
        Nat.mod_eq_of_lt (shl_lt_two_pow_256 layer.toNat 32 224 layer.toNat_lt (by decide))
      have hwT : (idxTreeIn >>> 9) <<< 160 % W = (idxTreeIn >>> 9) <<< 160 :=
        Nat.mod_eq_of_lt (shl_lt_two_pow_256 (idxTreeIn >>> 9) 64 160 hidx9 (by decide))
      have hw2 : (2 : Nat) <<< 128 % W = 2 <<< 128 :=
        Nat.mod_eq_of_lt (shl_lt_two_pow_256 2 2 128 (by decide) (by decide))
      -- treeAdrs = tBase := layer<<<224 ||| (idxTree>>>9)<<<160 ||| 2<<<128 (bound at v8).
      have hv8tA : v8.env "treeAdrs"
          = layer.toNat <<< 224 ||| (idxTreeIn >>> 9) <<< 160 ||| 2 <<< 128 := by
        rw [← hv8]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
        rw [← hv7]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]
        rw [hv6layer, hv6idxTree, UInt64.toNat_ofNat_of_lt' hidx9, hwL, hwT, hw2, Nat.or_assoc]
      -- authOff = sigOff + 692 (bound at v7).
      have hv7authOff : v7.env "authOff" = sigOffIn + 692 := by
        rw [← hv7]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
        rw [hv6countOff]
        exact Nat.mod_eq_of_lt (show sigOffIn + 688 + 4 < 2 ^ 256 from
          Nat.lt_of_lt_of_le (show sigOffIn + 688 + 4 < 2 ^ 13 by omega)
            (Nat.pow_le_pow_right (by decide) (by decide)))
      -- v11-level facts (step back through the 5 setup2 letvs; idxLeaf/mIdx round-trip).
      have hv11tA : v11.env "treeAdrs"
          = layer.toNat <<< 224 ||| (idxTreeIn >>> 9) <<< 160 ||| 2 <<< 128 := by
        rw [← hv11, ← hv10, ← hv9]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv8tA
      have hv11authOff : v11.env "authOff" = sigOffIn + 692 := by
        rw [← hv11, ← hv10, ← hv9, ← hv8]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv7authOff
      have hv11node : v11.env "merkleNode" = wordOf (ByteVec.pad16 wpk) := by
        rw [← hv11, ← hv10]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]
        rw [← hv9]
        simp only [execStmt, eval, setVar, String.reduceEq, if_true]
        -- merkleNode := wotsPk ; wotsPk preserved v6 → v8 (authOff/treeAdrs ≠ wotsPk)
        rw [← hv8, ← hv7]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]
        exact hwpk
      have hv11mIdx : v11.env "mIdx" = idxTreeIn &&& 0x1FF := by
        rw [← hv11]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]
        rw [← hv10]
        simp only [execStmt, eval, setVar, String.reduceEq, if_true]
        rw [← hv9, ← hv8, ← hv7]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]
        rw [hv6idxLeaf, UInt32.toNat_ofNat_of_lt' (Nat.lt_of_le_of_lt Nat.and_le_right (by decide))]
      have hv11mptr : v11.env "merklePtr" = sigOffIn + 692 := by
        rw [← hv11]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
        -- merklePtr := sigBase + authOff ; both at v10
        rw [show v10.env "sigBase" = 0 from by
              rw [← hv10, ← hv9, ← hv8, ← hv7]
              simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv6sb,
            show v10.env "authOff" = sigOffIn + 692 from by
              rw [← hv10, ← hv9, ← hv8]
              simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv7authOff]
        rw [Nat.zero_add]
        exact Nat.mod_eq_of_lt (show sigOffIn + 692 < 2 ^ 256 from
          Nat.lt_of_lt_of_le (show sigOffIn + 692 < 2 ^ 13 by omega)
            (Nat.pow_le_pow_right (by decide) (by decide)))
      have hv11N : v11.env "N_MASK" = NMASK := by
        rw [← hv11, ← hv10, ← hv9, ← hv8, ← hv7]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv6N
      have hv11OUT : v11.env "OUT" = 0x600 := by
        rw [← hv11, ← hv10, ← hv9, ← hv8, ← hv7]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv6OUT
      have hv11layer : v11.env "layer" = layer.toNat := by
        rw [← hv11, ← hv10, ← hv9, ← hv8, ← hv7]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv6layer
      have hv11idxTree : v11.env "idxTree" = (UInt64.ofNat (idxTreeIn >>> 9)).toNat := by
        rw [← hv11, ← hv10, ← hv9, ← hv8, ← hv7]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv6idxTree
      have hv11seed : v11.env "seed" = wordOf seed := by
        rw [← hv11, ← hv10, ← hv9, ← hv8, ← hv7]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv6seed
      have hv11sb : v11.env "sigBase" = 0 := by
        rw [← hv11, ← hv10, ← hv9, ← hv8, ← hv7]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv6sb
      have hv11mem : ∀ i, i < 32 → v11.mem (0 + i) = seed.data.getD i 0 := by
        intro i hi
        rw [← hv11, ← hv10, ← hv9, ← hv8, ← hv7]
        simp only [execStmt, eval]; exact hv6mem i hi
      -- ===== the Merkle climb (forRange "h" 9 htClimbBody) via ht_climb.
      have hmerkleStmt : execStmt c10Oracle sig (.forRange "h" (.lit 9) htClimbBody) v11
          = execFor c10Oracle sig "h" htClimbBody 9 0 v11 := by simp only [execStmt, eval]
      obtain ⟨hcl_none, hcl_node, hcl_mem⟩ := ht_climb sig v11 seed layer
        (UInt64.ofNat (idxTreeIn >>> 9)) wpk (idxTreeIn &&& 0x1FF) authPath
        (layer.toNat <<< 224 ||| (idxTreeIn >>> 9) <<< 160 ||| 2 <<< 128) (sigOffIn + 692)
        (Nat.lt_of_le_of_lt Nat.and_le_right (by decide))
        hv11N hv11OUT hv11tA hv11mptr hv11node hv11mIdx hv11mem H_adrs H_sib
      rw [execList_cons_none c10Oracle sig _ _ _ (by rw [hmerkleStmt]; exact hcl_none), hmerkleStmt]
      obtain ⟨v12, hv12⟩ : ∃ v12, (execFor c10Oracle sig "h" htClimbBody 9 0 v11).1 = v12 := ⟨_, rfl⟩
      rw [hv12]
      have hv12node : v12.env "merkleNode"
          = wordOf (ByteVec.pad16 (Spec.Hypertree.verifyAuthPath seed layer
              (UInt64.ofNat (idxTreeIn >>> 9)) wpk (idxTreeIn &&& 0x1FF) authPath)) := by
        rw [← hv12]; exact hcl_node
      have hv12authOff : v12.env "authOff" = sigOffIn + 692 := by
        rw [← hv12, execFor_env_frame c10Oracle sig "h" htClimbBody "authOff" (by decide) (by decide)
          9 0 v11]; exact hv11authOff
      have hv12idxTree : v12.env "idxTree" = (UInt64.ofNat (idxTreeIn >>> 9)).toNat := by
        rw [← hv12, execFor_env_frame c10Oracle sig "h" htClimbBody "idxTree" (by decide) (by decide)
          9 0 v11]; exact hv11idxTree
      have hv12seed : v12.env "seed" = wordOf seed := by
        rw [← hv12, execFor_env_frame c10Oracle sig "h" htClimbBody "seed" (by decide) (by decide)
          9 0 v11]; exact hv11seed
      have hv12sb : v12.env "sigBase" = 0 := by
        rw [← hv12, execFor_env_frame c10Oracle sig "h" htClimbBody "sigBase" (by decide) (by decide)
          9 0 v11]; exact hv11sb
      have hv12N : v12.env "N_MASK" = NMASK := by
        rw [← hv12, execFor_env_frame c10Oracle sig "h" htClimbBody "N_MASK" (by decide) (by decide)
          9 0 v11]; exact hv11N
      have hv12OUT : v12.env "OUT" = 0x600 := by
        rw [← hv12, execFor_env_frame c10Oracle sig "h" htClimbBody "OUT" (by decide) (by decide)
          9 0 v11]; exact hv11OUT
      have hv12mem : ∀ i, i < 32 → v12.mem (0 + i) = seed.data.getD i 0 := by
        intro i hi; rw [← hv12]; exact hcl_mem i hi
      -- ===== finalize (2 setvs): currentNode := merkleNode, sigOff := authOff + 144.
      rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
      obtain ⟨v13, hv13⟩ : ∃ v13, (execStmt c10Oracle sig
          (.setv "currentNode" (.var "merkleNode")) v12).1 = v13 := ⟨_, rfl⟩
      rw [hv13]
      rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
      obtain ⟨v14, hv14⟩ : ∃ v14, (execStmt c10Oracle sig
          (.setv "sigOff" (.bin .add (.var "authOff") (.lit 144))) v13).1 = v14 := ⟨_, rfl⟩
      rw [hv14, execList]
      -- ===== assemble the 11-component conjunction.
      refine ⟨rfl, wpk, hpk, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · -- currentNode = wordOf (pad16 (verifyAuthPath …))
        rw [← hv14]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]
        rw [← hv13]
        simp only [execStmt, eval, setVar, String.reduceEq, if_true]
        exact hv12node
      · -- idxTree = idxTreeIn >>> 9
        rw [← hv14, ← hv13]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]
        rw [hv12idxTree, UInt64.toNat_ofNat_of_lt' hidx9]
      · -- sigOff = sigOffIn + 836
        rw [← hv14]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false, if_true]
        rw [show v13.env "authOff" = sigOffIn + 692 from by
              rw [← hv13]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]
              exact hv12authOff]
        exact Nat.mod_eq_of_lt (show sigOffIn + 692 + 144 < 2 ^ 256 from
          Nat.lt_of_lt_of_le (show sigOffIn + 692 + 144 < 2 ^ 13 by omega)
            (Nat.pow_le_pow_right (by decide) (by decide)))
      · -- seed = wordOf seed
        rw [← hv14, ← hv13]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv12seed
      · -- sigBase = 0
        rw [← hv14, ← hv13]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv12sb
      · -- N_MASK
        rw [← hv14, ← hv13]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv12N
      · -- OUT
        rw [← hv14, ← hv13]
        simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv12OUT
      · -- seed-mem
        intro i hi
        rw [← hv14, ← hv13]
        simp only [execStmt, eval]; exact hv12mem i hi

/-! ### The hypertree layer loop refinement — `verifyHypertree_refine`

Drives `ht_layer_step` over the `D = 2` `forRange "layer"` loop = one
`Spec.Hypertree.verifyHypertree`.  The two `_Hadrs`/`_Hsib` per-layer hypotheses of
`ht_layer_step` are discharged here: `H_adrs` purely (the treeNode ADRS word, masked
base + `wordOf_treeNode`), `H_sib`/`hsig`/`hcount` from the per-layer sig bindings the
grand composition feeds from `deserialise`. -/

/-- One `execFor` iteration whose body falls through: continue from the body's result. -/
theorem execFor_cont {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (v : String) (body : List Stmt) (rem cur : Nat) (vm : VM)
    (h : (execList sha sig body { vm with env := setVar vm.env v cur }).2 = none) :
    execFor sha sig v body (rem + 1) cur vm
      = execFor sha sig v body rem (cur + 1) (execList sha sig body { vm with env := setVar vm.env v cur }).1 := by
  rw [execFor]
  rcases hp : execList sha sig body { vm with env := setVar vm.env v cur } with ⟨v', o⟩
  rw [hp] at h; simp only at h; subst h; simp only [hp]

/-- One `execFor` iteration whose body halts: the loop returns the body's result. -/
theorem execFor_halt {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (v : String) (body : List Stmt) (rem cur : Nat) (vm : VM) (hh : Halt)
    (h : (execList sha sig body { vm with env := setVar vm.env v cur }).2 = some hh) :
    execFor sha sig v body (rem + 1) cur vm = execList sha sig body { vm with env := setVar vm.env v cur } := by
  rw [execFor]
  rcases hp : execList sha sig body { vm with env := setVar vm.env v cur } with ⟨v', o⟩
  rw [hp] at h; simp only at h; subst h; simp only [hp]

/-- `verifyHypertree` unrolled to its two `vhStep` applications (D = 2). -/
theorem verifyHypertree_unroll (seed : ByteVec 32) (forsPk : ByteVec 16) (htIdx : Nat)
    (layers : Array Spec.Hypertree.LayerSig) :
    Spec.Hypertree.verifyHypertree seed forsPk htIdx layers
      = (if (vhStep seed layers (vhStep seed layers ⟨false, forsPk, htIdx⟩ 0) 1).fst then none
         else some (vhStep seed layers (vhStep seed layers ⟨false, forsPk, htIdx⟩ 0) 1).snd.fst) := by
  rw [verifyHypertree_eq_foldl, show (List.range' 0 Spec.D) = ([0, 1] : List Nat) from rfl,
      List.foldl_cons, List.foldl_cons, List.foldl_nil]

/-- `vhStep` when `bad` already set: identity. -/
theorem vhStep_bad (seed : ByteVec 32) (layers : Array Spec.Hypertree.LayerSig)
    (acc : MProd Bool (MProd (ByteVec 16) Nat)) (layer : Nat) (hbad : acc.fst = true) :
    vhStep seed layers acc layer = acc := by unfold vhStep; rw [if_pos hbad]

/-- `vhStep` when not bad and the WOTS+C check fails (`pkFromSig = none`): sets `bad`. -/
theorem vhStep_none (seed : ByteVec 32) (layers : Array Spec.Hypertree.LayerSig)
    (acc : MProd Bool (MProd (ByteVec 16) Nat)) (layer : Nat) (hbad : acc.fst = false)
    (hpk : Spec.Wots.pkFromSig seed (UInt32.ofNat layer) (UInt64.ofNat (acc.snd.snd >>> Spec.SubtreeH))
        (UInt32.ofNat (acc.snd.snd &&& (1 <<< Spec.SubtreeH - 1))) acc.snd.fst
        (layers.getD layer Spec.Hypertree.defaultLayerSig).wots = none) :
    vhStep seed layers acc layer = ⟨true, acc.snd.fst, acc.snd.snd >>> Spec.SubtreeH⟩ := by
  unfold vhStep; rw [if_neg (by rw [hbad]; decide)]; simp only [hpk]

/-- `vhStep` when not bad and `pkFromSig = some wpk`: climbs the layer's auth path. -/
theorem vhStep_some (seed : ByteVec 32) (layers : Array Spec.Hypertree.LayerSig)
    (acc : MProd Bool (MProd (ByteVec 16) Nat)) (layer : Nat) (hbad : acc.fst = false) (wpk : ByteVec 16)
    (hpk : Spec.Wots.pkFromSig seed (UInt32.ofNat layer) (UInt64.ofNat (acc.snd.snd >>> Spec.SubtreeH))
        (UInt32.ofNat (acc.snd.snd &&& (1 <<< Spec.SubtreeH - 1))) acc.snd.fst
        (layers.getD layer Spec.Hypertree.defaultLayerSig).wots = some wpk) :
    vhStep seed layers acc layer = ⟨false, Spec.Hypertree.verifyAuthPath seed (UInt32.ofNat layer)
        (UInt64.ofNat (acc.snd.snd >>> Spec.SubtreeH)) wpk (acc.snd.snd &&& (1 <<< Spec.SubtreeH - 1))
        (layers.getD layer Spec.Hypertree.defaultLayerSig).authPath, acc.snd.snd >>> Spec.SubtreeH⟩ := by
  unfold vhStep; rw [if_neg (by rw [hbad]; decide)]; simp only [hpk]

/-- **`H_adrs` discharge** — the masked treeNode-base ADRS word equals
    `wordOf (treeNode layer idxTree (h+1) (p/2))`.  The base `layer<<<224 |
    idxTree<<<160 | 2<<<128` has bits only `≥ 128`, so `&&& MASK` (clear low 64) is the
    identity; then `wordOf_treeNode` recombines.  (Treelike `H_leafAdrs_dischargeable`,
    plus the in-place base mask the climb performs.) -/
theorem treeNode_Hadrs (layer : UInt32) (idxTree : Nat) (hidx : idxTree < 2 ^ 64) :
    ∀ h, h < Spec.SubtreeH → ∀ p, p < 2 ^ 32 →
      ((layer.toNat <<< 224 ||| idxTree <<< 160 ||| 2 <<< 128)
          &&& 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000)
        ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
      = wordOf (Spec.Adrs.treeNode layer (UInt64.ofNat idxTree) (UInt32.ofNat (h + 1))
          (UInt32.ofNat (p / 2))) := by
  intro h hh p hp
  have hh9 : h < 9 := hh
  have hmaskid : (layer.toNat <<< 224 ||| idxTree <<< 160 ||| 2 <<< 128)
      &&& 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000
    = layer.toNat <<< 224 ||| idxTree <<< 160 ||| 2 <<< 128 := by
    have hshl : ∀ (x kk nn : Nat), x < 2 ^ nn → x <<< kk < 2 ^ (nn + kk) := by
      intro x kk nn hx; rw [Nat.shiftLeft_eq, Nat.pow_add]
      exact (Nat.mul_lt_mul_right (Nat.two_pow_pos kk)).mpr hx
    have hfactor : layer.toNat <<< 224 ||| idxTree <<< 160 ||| 2 <<< 128
        = (layer.toNat <<< 160 ||| idxTree <<< 96 ||| 2 <<< 64) <<< 64 := by
      rw [Nat.shiftLeft_or_distrib, Nat.shiftLeft_or_distrib,
          ← Nat.shiftLeft_add, ← Nat.shiftLeft_add, ← Nat.shiftLeft_add]
    have hM : layer.toNat <<< 160 ||| idxTree <<< 96 ||| 2 <<< 64 < 2 ^ 192 := by
      refine Nat.or_lt_two_pow (Nat.or_lt_two_pow ?_ ?_) ?_
      · exact hshl layer.toNat 160 32 layer.toNat_lt
      · exact Nat.lt_trans (hshl idxTree 96 64 hidx) (Nat.pow_lt_pow_right (by decide) (by decide))
      · exact Nat.lt_trans (hshl 2 64 2 (by decide)) (Nat.pow_lt_pow_right (by decide) (by decide))
    rw [hfactor, show (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000 : Nat)
          = (2 ^ 192 - 1) <<< 64 from by decide,
        ← Nat.shiftLeft_and_distrib, Nat.and_two_pow_sub_one_eq_mod, Nat.mod_eq_of_lt hM]
  rw [hmaskid, wordOf_treeNode]
  have hh1 : (h + 1) % W = h + 1 := Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  have hh1s : (h + 1) <<< 32 % W = (h + 1) <<< 32 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 (h + 1) 4 32 (by omega) (by decide))
  have hp2 : p >>> 1 = p / 2 := by rw [Nat.shiftRight_eq_div_pow, Nat.pow_one]
  rw [hh1, hh1s, hp2, UInt64.toNat_ofNat_of_lt' hidx,
      UInt32.toNat_ofNat_of_lt' (show h + 1 < UInt32.size from
        Nat.lt_of_lt_of_le (show h + 1 < 4096 by omega) (by decide)),
      UInt32.toNat_ofNat_of_lt' (show p / 2 < UInt32.size from
        Nat.lt_of_le_of_lt (Nat.div_le_self _ _) (Nat.lt_of_lt_of_le hp (by decide))),
      (by decide : (UInt32.ofNat Spec.ADRS_TREE).toNat = 2), ← Nat.or_assoc]

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 4000 in
/-- **The hypertree layer loop refines `verifyHypertree`.** Running the `D = 2`
    `forRange "layer"` loop from the post-FORS entry VM (`currentNode = forsPk`,
    `idxTree = htIdx`, `sigOff = 2336`, seed/consts/seed-mem) reverts exactly when
    `verifyHypertree = none`, else binds `currentNode` to the hypertree root.  Unrolls
    both sides (D = 2) and applies `ht_layer_step` per layer, mapping the digit-sum
    gate to `pkFromSig` (`pkFromSig_eq`/`pkFromSig_none`) ↔ `vhStep`'s branches.  The
    per-layer sig bindings (`Hbind`) are discharged from `deserialise` by the caller. -/
theorem verifyHypertree_refine
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (forsPk : ByteVec 16) (htIdx : Nat)
    (layers : Array Spec.Hypertree.LayerSig)
    (hidxbnd : htIdx < 2 ^ 64)
    (hidxTree : vm.env "idxTree" = htIdx)
    (hsigoff : vm.env "sigOff" = 2336)
    (hcn : vm.env "currentNode" = wordOf (ByteVec.pad16 forsPk))
    (hseedw : vm.env "seed" = wordOf seed)
    (hsigbase : vm.env "sigBase" = 0)
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hseedmem : ∀ i, i < 32 → vm.mem (0 + i) = seed.data.getD i 0)
    (Hbind : ∀ k, k < 2 →
      (∀ i (h : i < ((layers.getD k Spec.Hypertree.defaultLayerSig).wots).chains.size),
          ((layers.getD k Spec.Hypertree.defaultLayerSig).wots).chains[i]
            = ByteVec.loadValue16 sig (2336 + 836 * k + 16 * i))
      ∧ (calldataload sig (2336 + 836 * k + 688) >>> 224
          = wordOf (ByteVec.u32ToB32 ((layers.getD k Spec.Hypertree.defaultLayerSig).wots).count))
      ∧ (∀ hh, hh < Spec.SubtreeH →
          calldataload sig (((2336 + 836 * k + 692) + hh <<< 4 % W) % W) &&& NMASK
            = wordOf (ByteVec.pad16 (((layers.getD k Spec.Hypertree.defaultLayerSig).authPath).getD hh
                (ByteVec.zero 16))))
      ∧ ((layers.getD k Spec.Hypertree.defaultLayerSig).authPath.size = Spec.SubtreeH)) :
    (Spec.Hypertree.verifyHypertree seed forsPk htIdx layers = none
        → (execFor c10Oracle sig "layer" htLayerBody 2 0 vm).2 = some Halt.reverted)
    ∧ (∀ finalNode, Spec.Hypertree.verifyHypertree seed forsPk htIdx layers = some finalNode →
        (execFor c10Oracle sig "layer" htLayerBody 2 0 vm).2 = none
        ∧ (execFor c10Oracle sig "layer" htLayerBody 2 0 vm).1.env "currentNode"
            = wordOf (ByteVec.pad16 finalNode)
        ∧ (execFor c10Oracle sig "layer" htLayerBody 2 0 vm).1.env "seed" = wordOf seed
        ∧ (execFor c10Oracle sig "layer" htLayerBody 2 0 vm).1.env "sigBase" = 0
        ∧ (execFor c10Oracle sig "layer" htLayerBody 2 0 vm).1.env "N_MASK" = NMASK
        ∧ (execFor c10Oracle sig "layer" htLayerBody 2 0 vm).1.env "OUT" = 0x600
        ∧ (∀ i, i < 32 → (execFor c10Oracle sig "layer" htLayerBody 2 0 vm).1.mem (0 + i)
            = seed.data.getD i 0)) := by
  obtain ⟨h0sig, h0count, h0sib, h0size⟩ := Hbind 0 (by decide)
  obtain ⟨h1sig, h1count, h1sib, h1size⟩ := Hbind 1 (by decide)
  -- ===== LAYER 0 entry VM vm0 = {vm with layer := 0}; apply ht_layer_step.
  obtain ⟨vm0, hvm0⟩ : ∃ vm0, ({ vm with env := setVar vm.env "layer" 0 } : VM) = vm0 := ⟨_, rfl⟩
  have hvm0env : vm0.env = setVar vm.env "layer" 0 := by rw [← hvm0]
  have hvm0mem : vm0.mem = vm.mem := by rw [← hvm0]
  have e0layer : vm0.env "layer" = (UInt32.ofNat 0).toNat := by rw [hvm0env]; rfl
  have e0idx : vm0.env "idxTree" = htIdx := by rw [hvm0env, setVar_get_ne _ _ _ _ (by decide)]; exact hidxTree
  have e0so : vm0.env "sigOff" = 2336 := by rw [hvm0env, setVar_get_ne _ _ _ _ (by decide)]; exact hsigoff
  have e0cn : vm0.env "currentNode" = wordOf (ByteVec.pad16 forsPk) := by
    rw [hvm0env, setVar_get_ne _ _ _ _ (by decide)]; exact hcn
  have e0seed : vm0.env "seed" = wordOf seed := by rw [hvm0env, setVar_get_ne _ _ _ _ (by decide)]; exact hseedw
  have e0sb : vm0.env "sigBase" = 0 := by rw [hvm0env, setVar_get_ne _ _ _ _ (by decide)]; exact hsigbase
  have e0N : vm0.env "N_MASK" = NMASK := by rw [hvm0env, setVar_get_ne _ _ _ _ (by decide)]; exact hN
  have e0OUT : vm0.env "OUT" = 0x600 := by rw [hvm0env, setVar_get_ne _ _ _ _ (by decide)]; exact hOUT
  have e0mem : ∀ i, i < 32 → vm0.mem (0 + i) = seed.data.getD i 0 := by
    intro i hi; rw [hvm0mem]; exact hseedmem i hi
  have hstep0 := ht_layer_step sig vm0 seed (UInt32.ofNat 0) htIdx forsPk 2336
    ((layers.getD 0 Spec.Hypertree.defaultLayerSig).wots)
    ((layers.getD 0 Spec.Hypertree.defaultLayerSig).authPath)
    (by decide) hidxbnd h0size e0layer e0idx e0so e0cn e0seed e0sb e0N e0OUT e0mem h0sig h0count
    (treeNode_Hadrs (UInt32.ofNat 0) (htIdx >>> 9) (by
      rw [Nat.shiftRight_eq_div_pow]; exact Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hidxbnd))
    h0sib
  obtain ⟨va0, o0, hpair0⟩ : ∃ va0 o0, execList c10Oracle sig htLayerBody vm0 = (va0, o0) := ⟨_, _, rfl⟩
  by_cases hg0 : SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits
        (Spec.wotsDigest seed (Spec.Adrs.wots (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> 9))
          (UInt32.ofNat (htIdx &&& 0x1FF))) (ByteVec.pad16 forsPk)
          ((layers.getD 0 Spec.Hypertree.defaultLayerSig).wots).count)) ≠ Spec.TargetSum
  · -- LAYER-0 REVERT.
    rw [if_pos hg0] at hstep0
    rw [hpair0] at hstep0; simp only at hstep0; subst hstep0
    have hpk0none : Spec.Wots.pkFromSig seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> Spec.SubtreeH))
        (UInt32.ofNat (htIdx &&& (1 <<< Spec.SubtreeH - 1))) forsPk
        (layers.getD 0 Spec.Hypertree.defaultLayerSig).wots = none :=
      pkFromSig_none seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> 9))
        (UInt32.ofNat (htIdx &&& 0x1FF)) forsPk _ hg0
    have hVH : Spec.Hypertree.verifyHypertree seed forsPk htIdx layers = none := by
      rw [verifyHypertree_unroll,
          vhStep_none seed layers ⟨false, forsPk, htIdx⟩ 0 rfl hpk0none,
          vhStep_bad seed layers ⟨true, forsPk, htIdx >>> Spec.SubtreeH⟩ 1 rfl]
      rfl
    have hloop : execFor c10Oracle sig "layer" htLayerBody 2 0 vm = (va0, some Halt.reverted) := by
      rw [execFor, hvm0, hpair0]
    exact ⟨fun _ => by rw [hloop], fun fn hs => by rw [hVH] at hs; exact Option.noConfusion hs⟩
  · -- LAYER-0 PASS.
    rw [if_neg hg0] at hstep0
    obtain ⟨h0none, wpk0, hpk0, hcn1, hidx1, hso1, hseed1, hsb1, hN1, hOUT1, hmem1⟩ := hstep0
    rw [hpair0] at h0none hcn1 hidx1 hso1 hseed1 hsb1 hN1 hOUT1 hmem1
    simp only at h0none hcn1 hidx1 hso1 hseed1 hsb1 hN1 hOUT1 hmem1
    subst h0none
    have hpk0some : Spec.Wots.pkFromSig seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> Spec.SubtreeH))
        (UInt32.ofNat (htIdx &&& (1 <<< Spec.SubtreeH - 1))) forsPk
        (layers.getD 0 Spec.Hypertree.defaultLayerSig).wots = some wpk0 := hpk0
    -- ===== LAYER 1 entry VM vm1 = {va0 with layer := 1}; apply ht_layer_step.
    obtain ⟨vm1, hvm1⟩ : ∃ vm1, ({ va0 with env := setVar va0.env "layer" 1 } : VM) = vm1 := ⟨_, rfl⟩
    have hvm1env : vm1.env = setVar va0.env "layer" 1 := by rw [← hvm1]
    have hvm1mem : vm1.mem = va0.mem := by rw [← hvm1]
    have e1layer : vm1.env "layer" = (UInt32.ofNat 1).toNat := by rw [hvm1env]; rfl
    have e1idx : vm1.env "idxTree" = htIdx >>> 9 := by
      rw [hvm1env, setVar_get_ne _ _ _ _ (by decide)]; exact hidx1
    have e1so : vm1.env "sigOff" = 2336 + 836 := by
      rw [hvm1env, setVar_get_ne _ _ _ _ (by decide)]; exact hso1
    have e1cn : vm1.env "currentNode"
        = wordOf (ByteVec.pad16 (Spec.Hypertree.verifyAuthPath seed (UInt32.ofNat 0)
            (UInt64.ofNat (htIdx >>> 9)) wpk0 (htIdx &&& 0x1FF)
            (layers.getD 0 Spec.Hypertree.defaultLayerSig).authPath)) := by
      rw [hvm1env, setVar_get_ne _ _ _ _ (by decide)]; exact hcn1
    have e1seed : vm1.env "seed" = wordOf seed := by
      rw [hvm1env, setVar_get_ne _ _ _ _ (by decide)]; exact hseed1
    have e1sb : vm1.env "sigBase" = 0 := by rw [hvm1env, setVar_get_ne _ _ _ _ (by decide)]; exact hsb1
    have e1N : vm1.env "N_MASK" = NMASK := by rw [hvm1env, setVar_get_ne _ _ _ _ (by decide)]; exact hN1
    have e1OUT : vm1.env "OUT" = 0x600 := by rw [hvm1env, setVar_get_ne _ _ _ _ (by decide)]; exact hOUT1
    have e1mem : ∀ i, i < 32 → vm1.mem (0 + i) = seed.data.getD i 0 := by
      intro i hi; rw [hvm1mem]; exact hmem1 i hi
    have hidx1bnd : htIdx >>> 9 < 2 ^ 64 := by
      rw [Nat.shiftRight_eq_div_pow]; exact Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hidxbnd
    have hstep1 := ht_layer_step sig vm1 seed (UInt32.ofNat 1) (htIdx >>> 9)
      (Spec.Hypertree.verifyAuthPath seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> 9)) wpk0
        (htIdx &&& 0x1FF) (layers.getD 0 Spec.Hypertree.defaultLayerSig).authPath)
      (2336 + 836)
      ((layers.getD 1 Spec.Hypertree.defaultLayerSig).wots)
      ((layers.getD 1 Spec.Hypertree.defaultLayerSig).authPath)
      (by decide) hidx1bnd h1size e1layer e1idx e1so e1cn e1seed e1sb e1N e1OUT e1mem h1sig h1count
      (treeNode_Hadrs (UInt32.ofNat 1) ((htIdx >>> 9) >>> 9) (by
        rw [Nat.shiftRight_eq_div_pow]; exact Nat.lt_of_le_of_lt (Nat.div_le_self _ _) hidx1bnd))
      h1sib
    obtain ⟨va1, o1, hpair1⟩ : ∃ va1 o1, execList c10Oracle sig htLayerBody vm1 = (va1, o1) := ⟨_, _, rfl⟩
    -- the explicit layer-0 vhStep result (so layer-1 rewrites are SYNTACTIC, not metavar+defeq).
    by_cases hg1 : SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits
          (Spec.wotsDigest seed (Spec.Adrs.wots (UInt32.ofNat 1) (UInt64.ofNat ((htIdx >>> 9) >>> 9))
            (UInt32.ofNat ((htIdx >>> 9) &&& 0x1FF)))
            (ByteVec.pad16 (Spec.Hypertree.verifyAuthPath seed (UInt32.ofNat 0)
              (UInt64.ofNat (htIdx >>> 9)) wpk0 (htIdx &&& 0x1FF)
              (layers.getD 0 Spec.Hypertree.defaultLayerSig).authPath))
            ((layers.getD 1 Spec.Hypertree.defaultLayerSig).wots).count)) ≠ Spec.TargetSum
    · -- LAYER-1 REVERT.
      rw [if_pos hg1] at hstep1
      rw [hpair1] at hstep1; simp only at hstep1; subst hstep1
      have hpk1none : Spec.Wots.pkFromSig seed (UInt32.ofNat 1)
          (UInt64.ofNat ((htIdx >>> Spec.SubtreeH) >>> Spec.SubtreeH))
          (UInt32.ofNat ((htIdx >>> Spec.SubtreeH) &&& (1 <<< Spec.SubtreeH - 1)))
          (Spec.Hypertree.verifyAuthPath seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> Spec.SubtreeH)) wpk0
            (htIdx &&& (1 <<< Spec.SubtreeH - 1)) (layers.getD 0 Spec.Hypertree.defaultLayerSig).authPath)
          (layers.getD 1 Spec.Hypertree.defaultLayerSig).wots = none :=
        pkFromSig_none _ _ _ _ _ _ hg1
      have hVH : Spec.Hypertree.verifyHypertree seed forsPk htIdx layers = none := by
        rw [verifyHypertree_unroll, vhStep_some seed layers ⟨false, forsPk, htIdx⟩ 0 rfl wpk0 hpk0some,
            vhStep_none seed layers
              ⟨false, Spec.Hypertree.verifyAuthPath seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> Spec.SubtreeH))
                wpk0 (htIdx &&& (1 <<< Spec.SubtreeH - 1)) (layers.getD 0 Spec.Hypertree.defaultLayerSig).authPath,
                htIdx >>> Spec.SubtreeH⟩ 1 rfl hpk1none]
        rfl
      have hloop : execFor c10Oracle sig "layer" htLayerBody 2 0 vm = (va1, some Halt.reverted) := by
        rw [execFor, hvm0, hpair0]; simp only []; rw [execFor, hvm1, hpair1]
      exact ⟨fun _ => by rw [hloop], fun fn hs => by rw [hVH] at hs; exact Option.noConfusion hs⟩
    · -- LAYER-1 PASS.
      rw [if_neg hg1] at hstep1
      obtain ⟨h1none, wpk1, hpk1, hcn2, hidx2, hso2, hseed2, hsb2, hN2, hOUT2, hmem2⟩ := hstep1
      rw [hpair1] at h1none hcn2 hseed2 hsb2 hN2 hOUT2 hmem2
      simp only at h1none hcn2 hseed2 hsb2 hN2 hOUT2 hmem2
      subst h1none
      have hpk1some : Spec.Wots.pkFromSig seed (UInt32.ofNat 1)
          (UInt64.ofNat ((htIdx >>> Spec.SubtreeH) >>> Spec.SubtreeH))
          (UInt32.ofNat ((htIdx >>> Spec.SubtreeH) &&& (1 <<< Spec.SubtreeH - 1)))
          (Spec.Hypertree.verifyAuthPath seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> Spec.SubtreeH)) wpk0
            (htIdx &&& (1 <<< Spec.SubtreeH - 1)) (layers.getD 0 Spec.Hypertree.defaultLayerSig).authPath)
          (layers.getD 1 Spec.Hypertree.defaultLayerSig).wots = some wpk1 := hpk1
      have hVH : Spec.Hypertree.verifyHypertree seed forsPk htIdx layers
          = some (Spec.Hypertree.verifyAuthPath seed (UInt32.ofNat 1)
              (UInt64.ofNat ((htIdx >>> Spec.SubtreeH) >>> Spec.SubtreeH)) wpk1
              ((htIdx >>> Spec.SubtreeH) &&& (1 <<< Spec.SubtreeH - 1))
              (layers.getD 1 Spec.Hypertree.defaultLayerSig).authPath) := by
        rw [verifyHypertree_unroll, vhStep_some seed layers ⟨false, forsPk, htIdx⟩ 0 rfl wpk0 hpk0some,
            vhStep_some seed layers
              ⟨false, Spec.Hypertree.verifyAuthPath seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> Spec.SubtreeH))
                wpk0 (htIdx &&& (1 <<< Spec.SubtreeH - 1)) (layers.getD 0 Spec.Hypertree.defaultLayerSig).authPath,
                htIdx >>> Spec.SubtreeH⟩ 1 rfl wpk1 hpk1some]
        rfl
      have hloop : execFor c10Oracle sig "layer" htLayerBody 2 0 vm = (va1, none) := by
        rw [execFor, hvm0, hpair0]; simp only []; rw [execFor, hvm1, hpair1]; simp only []; rw [execFor]
      refine ⟨fun hn => by rw [hVH] at hn; exact Option.noConfusion hn, fun fn hs => ?_⟩
      rw [hVH] at hs
      obtain rfl := Option.some.inj hs
      rw [hloop]
      exact ⟨rfl, hcn2, hseed2, hsb2, hN2, hOUT2, hmem2⟩

end SphincsCVerify.Interpreter.C10
