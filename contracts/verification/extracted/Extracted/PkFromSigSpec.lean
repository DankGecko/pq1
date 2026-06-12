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
import Extracted.WotsDigits

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

/-- Digits are 3-bit windows, hence < 8. -/
theorem wotsDigit_lt (d : Std.Array Std.U8 32#usize) (j : Nat) : wotsDigit d j < 8 :=
  Nat.mod_lt _ (by norm_num)

/-- A `U32` equals the `BitVec.ofNat` lift of any small Nat it values to. -/
theorem u32_eq_ofNat {x : Std.U32} {n : Nat} (hn : n < 2 ^ 32) (h : x.val = n) :
    x = (⟨BitVec.ofNat 32 n⟩ : Std.U32) := by
  apply UScalar.eq_of_val_eq
  show x.val = (BitVec.ofNat 32 n).toNat
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt hn, h]

/-- General `adrsArr` bridge (the `treeAdrs_eq_of_map_val` method). -/
theorem adrsArr_eq_of_map_val (a : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (atype kp ci cp ha : Nat)
    (hmap : a.val.map (·.val) = specMakeAdrs layer.val tree.val atype kp ci cp ha) :
    adrsArr layer tree atype kp ci cp ha = a := by
  apply Subtype.ext
  show (specMakeAdrs layer.val tree.val atype kp ci cp ha).map
      (fun n => (⟨BitVec.ofNat 8 n⟩ : Std.U8)) = a.val
  rw [← hmap, List.map_map]
  conv_rhs => rw [← List.map_id a.val]
  apply List.map_congr_left
  intro x _
  exact U8.mk_ofNat_val x

/-- Setting the chain index on a fresh WOTS ADRS = building it with that index. -/
theorem specSetChainIndex_fresh (l t a k i : Nat) :
    specSetChainIndex (specMakeAdrs l t a k 0 0 0) i = specMakeAdrs l t a k i 0 0 := by
  simp [specSetChainIndex, specMakeAdrs, u32be, u64be]

set_option maxHeartbeats 8000000 in
/-- Digit-sum loop: accumulates `Σ_{j<start} digits[j]`. -/
theorem pk_loop0_value (digits : Std.Array Std.U8 43#usize)
    (iter : core.ops.range.Range Std.Usize) (sum : Std.Usize)
    (d : Std.Array Std.U8 32#usize)
    (hdig : ∀ j, j < 43 → (digits.val[j]!).val = wotsDigit d j)
    (hend : iter.«end».val = 43) (hle : iter.start.val ≤ 43)
    (hsum : sum.val = ((List.range iter.start.val).map (wotsDigit d)).sum) :
    wots.pk_from_sig_loop0 iter digits sum
      ⦃ r => r.val = ((List.range 43).map (wotsDigit d)).sum ⦄ := by
  unfold wots.pk_from_sig_loop0
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × Std.Usize) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × Std.Usize) =>
       s.1.«end».val = 43 ∧ s.1.start.val ≤ 43 ∧
       s.2.val = ((List.range s.1.start.val).map (wotsDigit d)).sum)
  · rintro ⟨it, sm⟩ ⟨hbnd, hsle, hs⟩
    simp only at hbnd hsle hs
    unfold wots.pk_from_sig_loop0.body
    simp only [lift]
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      rw [hs, show it.start.val = 43 from by omega]
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hjv : j.val = it.start.val := by rw [hj]
      have hj42 : j.val ≤ 42 := by omega
      -- bound: every partial sum ≤ 7·43
      have hsb : sm.val ≤ 7 * 43 := by
        rw [hs]
        calc ((List.range it.start.val).map (wotsDigit d)).sum
            ≤ ((List.range it.start.val).map (fun _ => 7)).sum := by
              apply List.sum_le_sum
              intro i _
              have := wotsDigit_lt d i
              omega
          _ = 7 * it.start.val := by
              simp [List.map_const', List.sum_replicate, smul_eq_mul, List.length_range]
              ring
          _ ≤ 7 * 43 := by omega
      have hdj : (digits.val[j.val]!).val = wotsDigit d j.val := hdig j.val (by omega)
      have hdlt : (digits.val[j.val]!).val < 8 := by rw [hdj]; exact wotsDigit_lt d j.val
      have hdiglen : digits.val.length = 43 := by
        have := digits.property; simpa using this
      step* <;> first | scalar_tac | skip
      refine ⟨by rw [hend']; exact hbnd, by omega, ?_, by rw [hend']; omega⟩
      rw [show (↑iter1.start : Nat) = ↑j + 1 from by omega, List.range_succ, List.map_append,
          List.sum_append]
      simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
      have hi1v : i1 = digits.val[j.val]! := by
        rw [i1_post, ← getElem!_pos _ _ (by rw [hdiglen]; omega)]
      rw [sum1_post, UScalar.cast_val_eq, hi1v, hdj]
      have hmod : wotsDigit d j.val % 2 ^ UScalarTy.Usize.numBits = wotsDigit d j.val := by
        apply Nat.mod_eq_of_lt
        have := wotsDigit_lt d j.val
        have h32 : (8:Nat) ≤ 2 ^ UScalarTy.Usize.numBits := by
          rcases System.Platform.numBits_eq with hnb | hnb <;>
            simp [UScalarTy.numBits, hnb] <;> norm_num
        omega
      rw [hmod, hjv, hs]
      omega
  · exact ⟨hend, hle, hsum⟩

set_option maxHeartbeats 16000000 in
/-- Chain loop: fills `pk_elements[j]` with the recovered chain ends. -/
theorem pk_loop1_value (seed : Std.Array Std.U8 32#usize)
    (sigma : Std.Array (Std.Array Std.U8 16#usize) 43#usize)
    (digits : Std.Array Std.U8 43#usize) (base_adrs : Std.Array Std.U8 32#usize)
    (iter : core.ops.range.Range Std.Usize)
    (pk_elements : Std.Array (Std.Array Std.U8 16#usize) 43#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (d : Std.Array Std.U8 32#usize)
    (hbase : base_adrs.val.map (·.val) = specMakeAdrs layer.val tree.val 0 kp.val 0 0 0)
    (hdig : ∀ j, j < 43 → (digits.val[j]!).val = wotsDigit d j)
    (hend : iter.«end».val = 43) (hle : iter.start.val ≤ 43)
    (hpk : ∀ j, j < iter.start.val →
      pk_elements.val[j]! = chain_hash_pure seed (adrsArr layer tree 0 kp.val j 0 0)
        (sigma.val[j]!) (⟨BitVec.ofNat 32 (wotsDigit d j)⟩ : Std.U32)
        (⟨BitVec.ofNat 32 (7 - wotsDigit d j)⟩ : Std.U32)) :
    wots.pk_from_sig_loop1 iter seed sigma digits base_adrs pk_elements
      ⦃ r => ∀ j, j < 43 →
        r.val[j]! = chain_hash_pure seed (adrsArr layer tree 0 kp.val j 0 0)
          (sigma.val[j]!) (⟨BitVec.ofNat 32 (wotsDigit d j)⟩ : Std.U32)
          (⟨BitVec.ofNat 32 (7 - wotsDigit d j)⟩ : Std.U32) ⦄ := by
  unfold wots.pk_from_sig_loop1
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize ×
                      Std.Array (Std.Array Std.U8 16#usize) 43#usize) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize ×
                     Std.Array (Std.Array Std.U8 16#usize) 43#usize) =>
       s.1.«end».val = 43 ∧ s.1.start.val ≤ 43 ∧
       ∀ j, j < s.1.start.val →
         s.2.val[j]! = chain_hash_pure seed (adrsArr layer tree 0 kp.val j 0 0)
           (sigma.val[j]!) (⟨BitVec.ofNat 32 (wotsDigit d j)⟩ : Std.U32)
           (⟨BitVec.ofNat 32 (7 - wotsDigit d j)⟩ : Std.U32))
  · rintro ⟨it, pk⟩ ⟨hbnd, hsle, hinv⟩
    simp only at hbnd hsle hinv
    unfold wots.pk_from_sig_loop1.body
    simp only [lift, params.W]
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      exact fun j hj => hinv j (by omega)
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hjv : j.val = it.start.val := by rw [hj]
      have hj42 : j.val ≤ 42 := by omega
      have hdiglen : digits.val.length = 43 := by
        have := digits.property; simpa using this
      have hdj : (digits.val[j.val]!).val = wotsDigit d j.val := hdig j.val (by omega)
      have hdlt : (digits.val[j.val]!).val < 8 := by rw [hdj]; exact wotsDigit_lt d j.val
      let* ⟨chain_adrs, hchain⟩ ← set_chain_index_spec base_adrs
            (UScalar.cast UScalarTy.U32 j)
      have hcastj : (UScalar.cast UScalarTy.U32 j).val = j.val := by
        rw [UScalar.cast_val_eq]
        exact Nat.mod_eq_of_lt (by
          calc j.val ≤ 42 := hj42
            _ < 2 ^ UScalarTy.U32.numBits := by norm_num)
      rw [hbase, hcastj, specSetChainIndex_fresh] at hchain
      have hchain_eq : adrsArr layer tree 0 kp.val j.val 0 0 = chain_adrs :=
        adrsArr_eq_of_map_val _ _ _ _ _ _ _ _ hchain
      step* <;> first | scalar_tac | skip
      · -- the (W-1)-digit subtraction: no underflow (digit < 8)
        have h8 : i4.val < 8 := by
          rw [i4_post, ← getElem!_pos digits.val j.val (by rw [hdiglen]; omega)]
          exact hdlt
        simp only [UScalar.cast_val_eq, show UScalarTy.U32.numBits = 32 from rfl]
        omega
      have hi4v : i4 = digits.val[j.val]! := by
        rw [i4_post, ← getElem!_pos _ _ (by rw [hdiglen]; omega)]
      have hav : a = sigma.val[j.val]! := by
        rw [a_post, ← getElem!_pos _ _ (by
          have := sigma.property; simp_all; omega)]
      have hi4val : i4.val = wotsDigit d j.val := by rw [hi4v, hdj]
      have hc4 : (UScalar.cast UScalarTy.U32 i4).val = wotsDigit d j.val := by
        rw [UScalar.cast_val_eq, hi4val,
            show UScalarTy.U32.numBits = 32 from rfl,
            Nat.mod_eq_of_lt (by have := wotsDigit_lt d j.val; omega)]
      have hcastStart : (UScalar.cast UScalarTy.U32 i4)
          = (⟨BitVec.ofNat 32 (wotsDigit d j.val)⟩ : Std.U32) :=
        u32_eq_ofNat (by have := wotsDigit_lt d j.val; omega) hc4
      have hremv : remaining.val = 7 - wotsDigit d j.val := by
        rw [remaining_post1, hc4]
        have hc7 : (UScalar.cast UScalarTy.U32 i2).val = 7 := by
          rw [UScalar.cast_val_eq, i2_post1,
              show UScalarTy.U32.numBits = 32 from rfl]; norm_num
        rw [hc7]
      have hcastRem : remaining = (⟨BitVec.ofNat 32 (7 - wotsDigit d j.val)⟩ : Std.U32) :=
        u32_eq_ofNat (by have := wotsDigit_lt d j.val; omega) hremv
      refine ⟨by rw [hend']; exact hbnd, by omega, ?_, by rw [hend']; omega⟩
      intro jj hjj
      rw [a2_post, Array.set_val_eq]
      have hpklen : pk.val.length = 43 := by have := pk.property; simpa using this
      by_cases hjb : jj = j.val
      · subst hjb
        rw [List.set_getElem!_eq _ _ _ _ ⟨by omega, rfl⟩, a1_post, ← hchain_eq, hav,
            hcastStart, hcastRem]
      · rw [List.set_getElem!_ne _ _ _ _ (by simp only [Nat.not_eq]; omega)]
        apply hinv jj
        rw [hstart'] at hjj
        omega
  · exact ⟨hend, hle, hpk⟩

set_option maxHeartbeats 4000000 in
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
  unfold wots.pk_from_sig
  simp only [params.ADRS_WOTS, params.ADRS_WOTS_PK, params.L, params.TARGET_SUM]
  let* ⟨padded, hpadded⟩ ← pad16_spec
  let* ⟨wots_adrs, hwadrs⟩ ← make_adrs_spec
  have hwadrs_eq : adrsArr layer tree 0 kp.val 0 0 0 = wots_adrs :=
    adrsArr_eq_of_map_val _ _ _ _ _ _ _ _ (by simpa using hwadrs)
  step*
  -- the extracted digest equals the spec's digest
  have hd : d = wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0)
              (pad16p msg_hash) count := by
    rw [d_post, ← hwadrs_eq, hpadded]
  rw [← hd]
  -- digits = the closed-form WOTS digits of `d`
  let* ⟨digits, hdigits⟩ ← extract_digits_spec
  have hdig : ∀ j, j < 43 → (digits.val[j]!).val = wotsDigit d j := by
    intro j hj; rw [wotsDigit]; exact hdigits j hj
  -- digit-sum loop
  let* ⟨sum, hsum⟩ ← pk_loop0_value digits { start := 0#usize, «end» := 43#usize } 0#usize d
    hdig (by simp) (by simp) (by simp)
  -- gate on Σ digits = 205
  by_cases hg : sum = 205#usize
  · -- gate passes → else branch builds the chains + compresses
    subst hg
    rw [if_neg (by simp)]
    let* ⟨base_adrs, hbase⟩ ← make_adrs_spec
    let* ⟨pk_elements1, hpk1⟩ ← pk_loop1_value seed sigma digits base_adrs
      { start := 0#usize, «end» := 43#usize }
      (Array.repeat 43#usize (Array.repeat 16#usize 0#u8)) layer tree kp d
      (by simpa using hbase) hdig (by simp) (by simp) (by simp)
    let* ⟨pk_adrs, hpkadrs⟩ ← make_adrs_spec
    simp only [lift]
    step*
    have h205 : ((List.range 43).map (wotsDigit d)).sum = 205 := by simpa using hsum.symm
    rw [r_post, if_pos h205]
    -- pk_adrs = adrsArr layer tree 1 …
    have hpkadrs_eq : adrsArr layer tree 1 kp.val 0 0 0 = pk_adrs :=
      adrsArr_eq_of_map_val _ _ _ _ _ _ _ _ (by simpa using hpkadrs)
    -- chain ends = pkChains
    have hpk1eq : pk_elements1.val = pkChains seed layer tree kp sigma d := by
      apply List.ext_getElem
      · simp only [pkChains, List.length_map, List.length_range]
        simpa using pk_elements1.property
      intro n h1 h2
      have hn43 : n < 43 := by simpa using h1
      rw [← getElem!_pos pk_elements1.val n h1, hpk1 n hn43]
      simp only [pkChains, List.getElem_map, List.getElem_range]
    rw [hpkadrs_eq]
    exact congrArg (th_multi_pure seed pk_adrs)
      (Subtype.ext (by simpa [Array.to_slice] using hpk1eq))
  · -- gate fails → then branch returns the all-zero element
    rw [if_pos (by simp [bne_iff_ne, hg])]
    simp only [WP.spec_ok]
    have hne : ((List.range 43).map (wotsDigit d)).sum ≠ 205 := by
      rw [← hsum]; intro hc; exact hg (UScalar.eq_of_val_eq (by rw [hc]; rfl))
    rw [if_neg hne]
    simp [Array.repeat]

end Extracted.Equiv
