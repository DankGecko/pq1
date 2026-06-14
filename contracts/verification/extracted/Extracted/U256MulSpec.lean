/- §33 rank 10 — U256::saturating_mul_u64: FUNCTIONAL spec (statement only).

   The fee-budget multiply (`max_fee * gas_limit`) rendered on the trusted
   display. Exact saturation semantics: the product is correct iff it fits in
   256 bits, else clamps to U256::MAX with the overflow flag raised — the flag
   must NEVER be wrong in either direction (a silent wrap would show the user
   a tiny fee for a huge one).

   Proof plan: loop invariant over the indexed LS-first carry multiply —
   after j steps (bytes 31 down to 32-j processed),
     beValue (out.drop (32-j)) + carry * 256^j = beValue (self.drop (32-j)) * rhs
   with carry < 2^64 (u128 product of u8*u64 + carry never overflows).
   Final: drop 0 = whole array; overflow ⟺ carry ≠ 0 ⟺ product ≥ 2^256.
   Reuses beValue from RlpIntSpec.lean. -/
import Extracted.U256Mul.Funs
import Extracted.RlpIntSpec

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_tx_core

/-- Horner fold with an arbitrary accumulator splits as `acc·256^len + value`. -/
theorem beValue_foldl_acc (l : List Std.U8) :
    ∀ acc, l.foldl (fun a b => a * 256 + b.val) acc = acc * 256 ^ l.length + beValue l := by
  induction l with
  | nil => intro acc; simp [beValue]
  | cons b tl ih =>
    intro acc
    simp only [List.foldl_cons, List.length_cons]
    have hb : beValue (b :: tl) = b.val * 256 ^ tl.length + beValue tl := by
      show tl.foldl _ (0 * 256 + b.val) = _
      rw [show (0 * 256 + b.val) = b.val by omega, ih]
    rw [ih (acc * 256 + b.val), hb, pow_succ]
    ring

/-- BE value of a cons: the head sits at weight `256^(rest length)`. -/
theorem beValue_cons (b : Std.U8) (l : List Std.U8) :
    beValue (b :: l) = b.val * 256 ^ l.length + beValue l := by
  show l.foldl _ (0 * 256 + b.val) = _
  rw [show (0 * 256 + b.val) = b.val by omega, beValue_foldl_acc]

set_option maxHeartbeats 8000000 in
/-- The LS-first carry-multiply loop invariant: after processing `j = start`
    bytes (indices 31 down to 32-j), the written suffix plus the carry at
    weight `256^j` equals the product of the processed suffix of `self`. -/
theorem saturating_mul_u64_loop_value
    (iter : core.ops.range.Range Std.Usize) (self : eip1559.U256) (rhs : Std.U64)
    (out : Std.Array Std.U8 32#usize) (carry : Std.U128)
    (hend : iter.«end».val = 32) (hle : iter.start.val ≤ 32)
    (hc : carry.val < 2 ^ 64)
    (hinv : beValue (out.val.drop (32 - iter.start.val)) + carry.val * 256 ^ iter.start.val
            = beValue (self.val.drop (32 - iter.start.val)) * rhs.val) :
    eip1559.U256.saturating_mul_u64_loop iter self rhs out carry
      ⦃ p => beValue p.1.val + p.2.val * 2 ^ 256 = beValue self.val * rhs.val ∧
             p.2.val < 2 ^ 64 ⦄ := by
  unfold eip1559.U256.saturating_mul_u64_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize × eip1559.U256 ×
                       Std.Array Std.U8 32#usize × Std.U128) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize × eip1559.U256 ×
                     Std.Array Std.U8 32#usize × Std.U128) =>
       s.1.«end».val = 32 ∧ s.1.start.val ≤ 32 ∧ s.2.1 = self ∧
       s.2.2.2.val < 2 ^ 64 ∧
       beValue (s.2.2.1.val.drop (32 - s.1.start.val)) + s.2.2.2.val * 256 ^ s.1.start.val
         = beValue (self.val.drop (32 - s.1.start.val)) * rhs.val)
  · rintro ⟨it, slf, o, c⟩ ⟨hbnd, hsle, hself, hcb, hval⟩
    simp only at hbnd hsle hself hcb hval
    subst hself
    unfold eip1559.U256.saturating_mul_u64_loop.body
    simp only [lift]
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨j, it', heq, hj, hlt, hend', hstart'⟩
    · subst ho
      simp only [WP.spec_ok]
      have h0 : it.start.val = 32 := by omega
      rw [h0] at hval
      simp only [Nat.sub_self, List.drop_zero] at hval
      refine ⟨?_, hcb⟩
      rw [show (2:Nat) ^ 256 = 256 ^ 32 by norm_num]
      exact hval
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hjv : j.val = it.start.val := by rw [hj]
      have hj31 : j.val ≤ 31 := by omega
      have hlen : (slf : Std.Array Std.U8 32#usize).val.length = 32 := by
        have := (slf : Std.Array Std.U8 32#usize).property; simpa using this
      have hlolen : (o : Std.Array Std.U8 32#usize).val.length = 32 := by
        have := (o : Std.Array Std.U8 32#usize).property; simpa using this
      step* <;> first | scalar_tac | skip
      -- value facts
      have hcast1 : (UScalar.cast UScalarTy.U128 i1).val = i1.val := by scalar_tac
      have hcast2 : (UScalar.cast UScalarTy.U128 rhs).val = rhs.val := by scalar_tac
      have hi1lt : i1.val < 256 := by
        have := i1.hBounds; simp only [Std.U8.size] at this; omega
      have hrhslt : rhs.val < 2 ^ 64 := by
        have := rhs.hBounds; simp only [Std.U64.size] at this; omega
      have hbyte : i1.val = ((slf : Std.Array Std.U8 32#usize).val[31 - j.val]!).val := by
        rw [i1_post, ← getElem!_pos _ _ (by rw [hlen]; omega)]
        congr 1
        rw [i_post1]
      have hprodv : prod.val = i1.val * rhs.val + c.val := by
        rw [prod_post, i4_post, hcast1, hcast2]
      have hprodlt : prod.val < 2 ^ 72 := by
        rw [hprodv]
        calc i1.val * rhs.val + c.val
            ≤ 255 * (2 ^ 64 - 1) + c.val := by
              exact Nat.add_le_add_right
                (Nat.mul_le_mul (by omega) (by omega)) _
          _ < 2 ^ 72 := by omega
      have hc1v : carry1.val = prod.val / 256 := by
        rw [carry1_post1, Nat.shiftRight_eq_div_pow]
      have hc1lt : carry1.val < 2 ^ 64 := by rw [hc1v]; omega
      have hvv : (UScalar.cast UScalarTy.U8 prod).val = prod.val % 256 := by
        rw [UScalar.cast_val_eq]
        norm_num
      -- structural rewrites: index arithmetic, set/drop/cons
      have hidx1 : 32 - iter1.start.val = 31 - j.val := by omega
      have hidx2 : 31 - j.val + 1 = 32 - j.val := by omega
      have hsetlen : ((o : Std.Array Std.U8 32#usize).val.set i.val
          (UScalar.cast UScalarTy.U8 prod)).length = 32 := by
        simp [List.length_set, hlolen]
      have hhead : (((o : Std.Array Std.U8 32#usize).val.set i.val
            (UScalar.cast UScalarTy.U8 prod))[31 - j.val]'(by rw [hsetlen]; omega))
          = UScalar.cast UScalarTy.U8 prod := by
        have hieq : i.val = 31 - j.val := i_post1
        rw [← getElem!_pos _ _ (by rw [hsetlen]; omega), ← hieq,
            List.set_getElem!_eq _ _ _ _ ⟨by rw [hlolen]; omega, rfl⟩]
      have htail : List.drop (32 - j.val)
            ((o : Std.Array Std.U8 32#usize).val.set i.val (UScalar.cast UScalarTy.U8 prod))
          = List.drop (32 - j.val) (o : Std.Array Std.U8 32#usize).val := by
        apply List.drop_set_of_lt
        rw [i_post1]; omega
      have hlendrop : (List.drop (32 - j.val) (o : Std.Array Std.U8 32#usize).val).length
          = j.val := by
        rw [List.length_drop, hlolen]; omega
      have hlendrop2 : (List.drop (32 - j.val) (slf : Std.Array Std.U8 32#usize).val).length
          = j.val := by
        rw [List.length_drop, hlen]; omega
      refine ⟨by rw [hend', hbnd], by omega, hc1lt, ?_, by rw [hend']; omega⟩
      rw [hidx1, a_post, Array.set_val_eq]
      rw [← List.cons_getElem_drop_succ (n := 31 - j.val) (h := by rw [hsetlen]; omega)]
      rw [beValue_cons, hidx2, hhead, hvv, htail, hlendrop]
      rw [← List.cons_getElem_drop_succ (l := (slf : Std.Array Std.U8 32#usize).val)
            (n := 31 - j.val) (h := by rw [hlen]; omega)]
      rw [beValue_cons, hidx2, hlendrop2]
      rw [show (32 - (↑it.start : Nat)) = 32 - j.val from by omega] at hval
      rw [show (((slf : Std.Array Std.U8 32#usize).val)[31 - j.val]'(by rw [hlen]; omega))
            = ((slf : Std.Array Std.U8 32#usize).val[31 - j.val]!) from by
          rw [← getElem!_pos _ _ (by rw [hlen]; omega)]]
      rw [show (↑iter1.start : Nat) = j.val + 1 from by omega, hc1v]
      have hsplit : prod.val % 256 * 256 ^ j.val + prod.val / 256 * 256 ^ (j.val + 1)
          = prod.val * 256 ^ j.val := by
        have hdm : prod.val % 256 + (prod.val / 256) * 256 = prod.val := by omega
        calc prod.val % 256 * 256 ^ j.val + prod.val / 256 * 256 ^ (j.val + 1)
            = (prod.val % 256 + (prod.val / 256) * 256) * 256 ^ j.val := by ring
          _ = prod.val * 256 ^ j.val := by rw [hdm]
      rw [hbyte] at hprodv
      calc (↑prod : Nat) % 256 * 256 ^ j.val + beValue (List.drop (32 - j.val) (o : Std.Array Std.U8 32#usize).val)
            + ↑prod / 256 * 256 ^ (j.val + 1)
          = beValue (List.drop (32 - j.val) (o : Std.Array Std.U8 32#usize).val) + ↑prod * 256 ^ j.val := by
            rw [← hsplit]; ring
        _ = ((slf : Std.Array Std.U8 32#usize).val[31 - j.val]!).val * 256 ^ j.val * rhs.val
              + (beValue (List.drop (32 - j.val) (o : Std.Array Std.U8 32#usize).val)
                 + c.val * 256 ^ j.val) := by
            rw [hprodv]; ring
        _ = ((slf : Std.Array Std.U8 32#usize).val[31 - j.val]!).val * 256 ^ j.val * rhs.val
              + beValue (List.drop (32 - j.val) (slf : Std.Array Std.U8 32#usize).val) * rhs.val := by
            rw [show (↑it.start : Nat) = j.val from by omega] at hval
            rw [hval]
        _ = (((slf : Std.Array Std.U8 32#usize).val[31 - j.val]!).val * 256 ^ j.val
              + beValue (List.drop (32 - j.val) (slf : Std.Array Std.U8 32#usize).val)) * rhs.val := by
            ring
  · exact ⟨hend, hle, rfl, hc, hinv⟩

/-- **Functional spec**: exact product + exact saturation, both directions. -/
theorem saturating_mul_u64_spec (self : eip1559.U256) (rhs : Std.U64) :
    eip1559.U256.saturating_mul_u64 self rhs
      ⦃ p =>
        (p.2 = false →
          beValue p.1.val = beValue self.val * rhs.val ∧
          beValue self.val * rhs.val < 2 ^ 256) ∧
        (p.2 = true →
          p.1.val = List.replicate 32 255#u8 ∧
          2 ^ 256 ≤ beValue self.val * rhs.val) ⦄ := by
  unfold eip1559.U256.saturating_mul_u64
  let* ⟨p, hp1, hp2⟩ ← saturating_mul_u64_loop_value
        { start := 0#usize, «end» := 32#usize } self rhs (Array.repeat 32#usize 0#u8) 0#u128
        rfl (by simp) (by simp)
        (by simp [Array.repeat_val, beValue, List.drop_of_length_le])
  step* <;> first | scalar_tac | skip
  all_goals first
  | (-- carry = 0 branch: exact product, fits
     rename_i hz
     have hz0 : hp1.val = 0 := by
       simp only [bne_iff_ne, ne_eq, not_not] at hz
       rw [hz]
       rfl
     have hplen : (p : Std.Array Std.U8 32#usize).val.length = 32 := by
       have := (p : Std.Array Std.U8 32#usize).property; simpa using this
     have hfit : beValue (p : Std.Array Std.U8 32#usize).val < 2 ^ 256 := by
       have h := beValue_lt (p : Std.Array Std.U8 32#usize).val
       rw [hplen] at h
       calc beValue (p : Std.Array Std.U8 32#usize).val < 256 ^ 32 := h
         _ = 2 ^ 256 := by norm_num
     have heq : beValue (p : Std.Array Std.U8 32#usize).val = beValue self.val * rhs.val := by
       rw [← hp2, hz0]
       ring
     exact ⟨fun _ => ⟨heq, heq ▸ hfit⟩, fun hff => absurd hff (by simp)⟩)
  | (-- carry ≠ 0 branch: saturated, product ≥ 2^256
     rename_i hnz
     have hnz0 : hp1.val ≠ 0 := by
       simp only [bne_iff_ne, ne_eq] at hnz
       intro h0
       apply hnz
       apply UScalar.eq_of_val_eq
       simpa using h0
     have hge : 2 ^ 256 ≤ beValue self.val * rhs.val := by
       rw [← hp2]
       have h1 : 1 ≤ hp1.val := by omega
       have h2 : 2 ^ 256 ≤ hp1.val * 2 ^ 256 := by
         calc (2:Nat) ^ 256 = 1 * 2 ^ 256 := by ring
           _ ≤ hp1.val * 2 ^ 256 := Nat.mul_le_mul_right _ h1
       omega
     exact ⟨fun htf => absurd htf (by simp), fun _ => ⟨by simp [Array.repeat_val], hge⟩⟩)
  | skip

end Extracted.Equiv
