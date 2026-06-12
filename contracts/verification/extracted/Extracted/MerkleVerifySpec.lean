/- §33 rank 6 — merkle::verify_auth_path: FUNCTIONAL spec (statement only).

   The XMSS auth-path walk: from a leaf and its index, fold the 9 siblings
   upward — parent ADRS at height h+1 and index idx>>1, left/right operand
   order selected by idx&1, node = th_pair(seed, adrs, l, r). The index walk
   and operand order ARE the security-relevant content (a swapped operand or
   a wrong parent index verifies a different tree); th_pair itself is the
   uninterpreted boundary (th_pair_pure, Merkle/FunsExternal.lean).

   The ADRS bytes are pinned via specMakeAdrs (AdrsEquiv.lean), which is
   already proven equal to BOTH the extracted make_adrs (make_adrs_spec) and
   the vendored on-chain spec (firmware_make_adrs_matches_vendored) — so this
   statement composes into the SpecBridge chain.

   Proof plan: loop.spec_decr_nat with invariant
     state after k steps = (authFold (auth.take k) leaf idx 0 unrolled k times,
                            idx >>> k)
   i.e. node_k = authFold seed layer tree (auth.val.take k) leaf_node idx.val 0
   and idx_k.val = leaf_idx.val >>> k; each step: make_adrs_spec gives the
   adrs bytes = specMakeAdrs (lift to adrsBytes via map_val_mk-style argument:
   entries < 256 so BitVec.ofNat is injective on them), pad16 step* gives the
   pure pad, the &&&1 / >>>1 selections match %2 / /2 by scalar_tac. -/
import Extracted.Merkle.Funs
import Extracted.AdrsEquiv

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open sphincs_c10

/-- Pure `pad16`: the 16-byte node left-justified in a zero 32-byte block. -/
def pad16p (v : Std.Array Std.U8 16#usize) : Std.Array Std.U8 32#usize :=
  ⟨v.val ++ List.replicate 16 0#u8, by have := v.property; simp_all⟩

/-- Pure tree-ADRS at height `h+1`, parent index `pidx` — the exact
    `specMakeAdrs` bytes (ADRS_TREE = 2, kp = ci = 0), lifted to `U8`s.
    Entries are < 256 by construction so `BitVec.ofNat` loses nothing. -/
def treeAdrs (layer : Std.U32) (tree : Std.U64) (h : Nat) (pidx : Nat) :
    Std.Array Std.U8 32#usize :=
  ⟨(specMakeAdrs layer.val tree.val 2 0 0 (h + 1) pidx).map
      (fun n => (⟨BitVec.ofNat 8 n⟩ : Std.U8)), by
    simp [specMakeAdrs, u32be, u64be]⟩

/-- The pure auth-path fold mirroring the Rust loop step-for-step. -/
noncomputable def authFold (seed : Std.Array Std.U8 32#usize) (layer : Std.U32) (tree : Std.U64) :
    List (Std.Array Std.U8 16#usize) → Std.Array Std.U8 16#usize → Nat → Nat →
    Std.Array Std.U8 16#usize
  | [], node, _, _ => node
  | sib :: rest, node, idx, h =>
      let adrs := treeAdrs layer tree h (idx / 2)
      let next :=
        if idx % 2 = 0 then th_pair_pure seed adrs (pad16p node) (pad16p sib)
        else th_pair_pure seed adrs (pad16p sib) (pad16p node)
      authFold seed layer tree rest next (idx / 2) (h + 1)

/-- **Functional spec**: `verify_auth_path` computes exactly the 9-step fold —
    every parent index, height tweak, and left/right operand order pinned. -/
theorem verify_auth_path_spec (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf_node : Std.Array Std.U8 16#usize)
    (leaf_idx : Std.U32) (auth_path : Std.Array (Std.Array Std.U8 16#usize) 9#usize) :
    merkle.verify_auth_path seed layer tree leaf_node leaf_idx auth_path
      ⦃ r => r = authFold seed layer tree auth_path.val leaf_node leaf_idx.val 0 ⦄ := by
  sorry

end Extracted.Equiv
