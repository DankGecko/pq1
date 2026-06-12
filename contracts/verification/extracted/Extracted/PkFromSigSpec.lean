/- §33 rank 5 — wots::pk_from_sig: FUNCTIONAL spec (statement only).

   The verifier-side WOTS+C recovery — the campaign's hardest target. The
   security-relevant content pinned here:
     1. the digit-sum GATE is exact equality (Σ digits = TARGET_SUM = 205,
        not a range check) — fail returns the all-zero pubkey;
     2. each chain advances exactly (W-1) - digit[i] steps from digit[i] —
        the unsigned subtraction CANNOT wrap because digit < 8 = W
        (rank 4's extract_digits_spec closed form, used definitionally);
     3. every ADRS (wots base, per-chain, pk-compress) is the exact
        specMakeAdrs byte layout (bridged on-chain via SpecBridge);
     4. chain order: pk_elements[j] uses sigma[j] (no permutation).
   wots_digest / chain_hash / th_multi are the uninterpreted hash boundaries
   (PkFromSig/FunsExternal.lean).

   Proof plan: step* through the prefix (pad16/make_adrs via make_adrs_spec,
   wots_digest_pure); rank 4's extract_digits_spec gives digits[j] =
   (digestWord d >>> j*3) % 8; loop0 (digit sum) is a fold invariant
   sum_k = Σ_{j<k} digit j; the gate if-split; loop1 invariant
   pk_elements[j] = chain_hash_pure … for j < k (List.set_getElem! bookkeeping
   like rank 2/4); set_chain_index bridges via specSetChainIndex =
   specMakeAdrs-with-ci (take/append identity). The (W-1)-digit subtraction:
   U32 sub side-condition discharged by digit < 8 ≤ W. -/
import Extracted.PkFromSig.Funs
import Extracted.MerkleVerifySpec
import Extracted.ForsExtract

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open sphincs_c10

/-- General pure ADRS: the `specMakeAdrs` bytes lifted to a `U8` array.
    (`treeAdrs` in MerkleVerifySpec is the `atype = 2` specialization.) -/
def adrsArr (layer : Std.U32) (tree : Std.U64) (atype kp ci cp ha : Nat) :
    Std.Array Std.U8 32#usize :=
  ⟨(specMakeAdrs layer.val tree.val atype kp ci cp ha).map
      (fun n => (⟨BitVec.ofNat 8 n⟩ : Std.U8)), by
    simp [specMakeAdrs, u32be, u64be]⟩

/-- WOTS digit `j` of the count-tweaked digest — rank 4's proven closed form,
    used here definitionally. Always < 8. -/
noncomputable def wotsDigit (d : Std.Array Std.U8 32#usize) (j : Nat) : Nat :=
  (digestWord d >>> (j * 3)) % 8

/-- The L = 43 recovered chain ends, in chain order. -/
noncomputable def pkChains (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize)
    (d : Std.Array Std.U8 32#usize) : List (Std.Array Std.U8 16#usize) :=
  (List.range 43).map fun j =>
    chain_hash_pure seed (adrsArr layer tree 0 kp.val j 0 0) (sigma.val[j]!)
      (⟨BitVec.ofNat 32 (wotsDigit d j)⟩ : Std.U32)
      (⟨BitVec.ofNat 32 (7 - wotsDigit d j)⟩ : Std.U32)

/-- **Functional spec**: digit-sum gate (exact 205) + per-chain advance
    (start = digit, steps = 7 - digit, sigma in chain order) + th_multi
    compress, with every ADRS byte-pinned. -/
theorem pk_from_sig_spec (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (msg_hash : Std.Array Std.U8 16#usize)
    (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize) (count : Std.U32) :
    wots.pk_from_sig seed layer tree kp msg_hash sigma count
      ⦃ r =>
        let d := wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0)
                   (pad16p msg_hash) count
        if ((List.range 43).map (wotsDigit d)).sum = 205 then
          r = th_multi_pure seed (adrsArr layer tree 1 kp.val 0 0 0)
                ⟨pkChains seed layer tree kp sigma d, by
                  simp [pkChains]; scalar_tac⟩
        else
          r.val = List.replicate 16 0#u8 ⦄ := by
  sorry

end Extracted.Equiv
