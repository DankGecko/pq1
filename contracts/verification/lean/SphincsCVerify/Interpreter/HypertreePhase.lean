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

end SphincsCVerify.Interpreter.C10
