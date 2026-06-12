/- §33 rank 11 — tx::erc20::merkle::verify_proof: FUNCTIONAL spec (statement
   only). This ONE function underpins all four trust-bundle verifiers
   (erc20 / names / selectors / erc7730).

   Pinned content: (1) the exact-length gate `proof_bytes.len = depth * 32` —
   if the gate and the walk ever disagreed, a proof with trailing or missing
   siblings could be accepted; (2) the index walk (sibling order by idx&1,
   idx>>=1) — rank 6's walk restated for the sha256 domain-separated scheme;
   (3) acceptance ⟺ the fold collapses exactly to the expected root.

   Proof plan: rank-6 method. loop.spec_decr_nat, invariant
   (h_k, idx_k) = (merkleFold (chunks.take k) leafHash idx, idx >>> k);
   the try_from Ok branch is total under the length gate (slice index
   [l*32, l*32+32) in bounds, chunk pad empty); PartialEqArray.eq at the
   `none` exit gives the root comparison; the iff's ← direction needs the
   gate to force the Err branch unreachable. -/
import Extracted.TxMerkle.Funs
import Extracted.ForsLoop

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_tx

/-- The 32-byte sibling at chunk `l` of the proof blob (zero-padded if short —
    the length gate makes the pad empty in every reachable case). -/
def chunk32 (bytes : List Std.U8) (l : Nat) : Std.Array Std.U8 32#usize :=
  ⟨((bytes.drop (l * 32)).take 32)
      ++ List.replicate (32 - ((bytes.drop (l * 32)).take 32).length) 0#u8, by
    simp [List.length_take, List.length_drop]⟩

/-- The pure index walk: fold the siblings upward, order by idx parity. -/
noncomputable def merkleFold :
    List (Std.Array Std.U8 32#usize) → Std.Array Std.U8 32#usize → Nat →
    Std.Array Std.U8 32#usize
  | [], h, _ => h
  | sib :: rest, h, idx =>
      merkleFold rest
        (if idx % 2 = 0 then node_hash_pure h sib else node_hash_pure sib h)
        (idx / 2)

/-- `List.allM` of a pure predicate is `ok` of `List.all`. -/
theorem allM_ok {α : Type} (f : α → Bool) (l : List α) :
    List.allM (m := Result) (fun x => ok (f x)) l = ok (l.all f) := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.allM, List.all_cons]
    cases hf : f x <;> simp [hf, ih, List.allM] <;> rfl

/-- Pairwise equality over a zip of equal-length lists is list equality. -/
theorem all_zip_eq_iff (l0 : List Std.U8) :
    ∀ l1 : List Std.U8, l0.length = l1.length →
      (((l0.zip l1).all fun p => p.1 = p.2) = true ↔ l0 = l1) := by
  induction l0 with
  | nil =>
    intro l1 hlen
    cases l1
    · simp
    · simp at hlen
  | cons x xs ih =>
    intro l1 hlen
    cases l1 with
    | nil => simp at hlen
    | cons y ys =>
      simp only [List.zip_cons_cons, List.all_cons, Bool.and_eq_true, decide_eq_true_iff,
                 List.cons.injEq]
      rw [ih ys (by simpa using hlen)]

/-- Array equality test returns exactly propositional equality. -/
theorem partialEqArray_u8_spec {N : Std.Usize} (a0 a1 : Std.Array Std.U8 N) :
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 a0 a1
      ⦃ b => (b = true) ↔ a0 = a1 ⦄ := by
  unfold core.array.equality.PartialEqArray.eq
  have hl0 : a0.length = a1.length := by scalar_tac
  rw [if_pos hl0]
  have : (List.allM (m := Result) (fun (p : Std.U8 × Std.U8) => ok (decide (p.1 = p.2)))
      (a0.val.zip a1.val)) = ok ((a0.val.zip a1.val).all fun p => decide (p.1 = p.2)) :=
    allM_ok _ _
  rw [show (fun (p : Std.U8 × Std.U8) => core.cmp.PartialEqU8.eq p.1 p.2)
        = (fun (p : Std.U8 × Std.U8) => ok (decide (p.1 = p.2))) from rfl] at *
  rw [this]
  simp only [WP.spec_ok]
  rw [all_zip_eq_iff _ _ (by scalar_tac)]
  exact ⟨fun h => Subtype.ext h, fun h => by rw [h]⟩

set_option maxHeartbeats 16000000 in
/-- Loop lemma (continuation form): the result Bool is `true` iff the total
    fold hits the root — given the carried fold-equality invariant. -/
theorem verify_proof_loop_value
    (iter : core.ops.range.Range Std.Usize) (proof_bytes : Slice Std.U8)
    (expected_root : Std.Array Std.U8 32#usize)
    (node : Std.Array Std.U8 32#usize) (idx : Std.Usize)
    (total : Std.Array Std.U8 32#usize) (D : Nat)
    (hD : iter.«end».val = D) (hle : iter.start.val ≤ D)
    (hlen : proof_bytes.val.length = D * 32)
    (hcont : merkleFold (((List.range D).map (chunk32 proof_bytes.val)).drop iter.start.val)
               node idx.val = total) :
    erc20.merkle.verify_proof_loop iter proof_bytes expected_root node idx
      ⦃ b => (b = true) ↔ (total = expected_root) ⦄ := by
  unfold erc20.merkle.verify_proof_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.ops.range.Range Std.Usize ×
                      Std.Array Std.U8 32#usize × Std.Usize) =>
       s.1.«end».val - s.1.start.val)
    (inv := fun (s : core.ops.range.Range Std.Usize ×
                     Std.Array Std.U8 32#usize × Std.Usize) =>
       s.1.«end».val = D ∧ s.1.start.val ≤ D ∧
       merkleFold (((List.range D).map (chunk32 proof_bytes.val)).drop s.1.start.val)
         s.2.1 s.2.2.val = total)
  · rintro ⟨it, nd, ix⟩ ⟨hbnd, hsle, hfold⟩
    simp only at hbnd hsle hfold
    unfold erc20.merkle.verify_proof_loop.body
    simp only [lift]
    let* ⟨ob, iter1, hpost⟩ ← next_usize_spec it
    rcases hpost with ⟨ho, hge⟩ | ⟨lvl, it', heq, hlv, hlt, hend', hstart'⟩
    · subst ho
      have h9 : it.start.val = D := by omega
      rw [h9, List.drop_of_length_le (by simp)] at hfold
      simp only [merkleFold] at hfold
      let* ⟨b, hb⟩ ← partialEqArray_u8_spec nd expected_root
      rw [← hfold]
      exact hb
    · simp only [Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl⟩ := heq
      have hlvlv : lvl.val = it.start.val := by rw [hlv]
      have hlvD : lvl.val < D := by omega
      step* <;> first | scalar_tac | skip
      -- the 32-byte window exists exactly (length gate)
      have hslen32 : s.len = 32#usize := by
        apply UScalar.eq_of_val_eq
        rw [Slice.len_val]
        scalar_tac
      unfold core.array.TryFromSharedArraySlice.try_from
      rw [dif_pos hslen32]
      simp only [bind_tc_ok]
      -- the produced array IS this level's chunk
      have hcv : (chunk32 proof_bytes.val lvl.val).val = s.val := by
        show ((proof_bytes.val.drop (lvl.val * 32)).take 32)
            ++ List.replicate (32 - ((proof_bytes.val.drop (lvl.val * 32)).take 32).length) 0#u8
            = s.val
        have htl : ((proof_bytes.val.drop (lvl.val * 32)).take 32).length = 32 := by
          rw [List.length_take, List.length_drop, hlen]
          omega
        rw [htl, Nat.sub_self, List.replicate_zero, List.append_nil,
            s_post1, List.slice, sib_off_post, i_post, sib_off_post,
            show lvl.val * 32 + 32 - lvl.val * 32 = 32 from by omega]
      have hchunk : chunk32 proof_bytes.val lvl.val
          = (⟨s.val, by scalar_tac⟩ : Std.Array Std.U8 32#usize) := by
        apply Subtype.ext
        exact hcv
      -- peel hfold one step
      rw [show (↑it.start : Nat) = ↑lvl from hlvlv.symm] at hfold
      rw [← List.cons_getElem_drop_succ (n := lvl.val)
            (h := by simp only [List.length_map, List.length_range]; omega)] at hfold
      rw [show ((List.map (chunk32 ↑proof_bytes) (List.range D))[lvl.val]'(by
            simp only [List.length_map, List.length_range]; omega))
          = chunk32 proof_bytes.val lvl.val from by
            simp] at hfold
      simp only [merkleFold] at hfold
      rw [hchunk] at hfold
      split
      · -- even level: node ‖ sibling
        rename_i hcond
        have hmod : ix.val % 2 = 0 := by
          have hv := congrArg UScalar.val hcond
          rw [UScalar.val_and, show ((1#usize) : Std.Usize).val = 1 from rfl,
              show ((0#usize) : Std.Usize).val = 0 from rfl,
              show (1:Nat) = 2 ^ 1 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod] at hv
          simpa using hv
        rw [if_pos hmod] at hfold
        step* <;>
          first
          | scalar_tac
          | (rcases System.Platform.numBits_eq with hnb | hnb <;> simp [hnb])
          | skip
        refine ⟨by rw [hend', hbnd], by omega, ?_, by rw [hend']; omega⟩
        rw [show (↑iter1.start : Nat) = ↑lvl + 1 from by omega, h1_post,
            show (↑idx1 : Nat) = ↑ix / 2 from by
              rw [idx1_post1, Nat.shiftRight_eq_div_pow, pow_one]]
        exact hfold
      · -- odd level: sibling ‖ node
        rename_i hcond
        have hmod : ¬ ix.val % 2 = 0 := by
          intro h0
          apply hcond
          apply UScalar.eq_of_val_eq
          rw [UScalar.val_and, show ((1#usize) : Std.Usize).val = 1 from rfl,
              show ((0#usize) : Std.Usize).val = 0 from rfl,
              show (1:Nat) = 2 ^ 1 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]
          simpa using h0
        rw [if_neg hmod] at hfold
        step* <;>
          first
          | scalar_tac
          | (rcases System.Platform.numBits_eq with hnb | hnb <;> simp [hnb])
          | skip
        refine ⟨by rw [hend', hbnd], by omega, ?_, by rw [hend']; omega⟩
        rw [show (↑iter1.start : Nat) = ↑lvl + 1 from by omega, h1_post,
            show (↑idx1 : Nat) = ↑ix / 2 from by
              rw [idx1_post1, Nat.shiftRight_eq_div_pow, pow_one]]
        exact hfold
  · exact ⟨hD, hle, hcont⟩

/-- **Functional spec**: accepts ⟺ the blob is exactly `depth` siblings AND
    the domain-separated fold from `leaf_hash(canonical)` at `leaf_index`
    collapses to `expected_root`.

    The `hdepth` precondition is forced by the EXTRACTED code: the Rust
    computes `proof_depth * 32` BEFORE the length comparison, so a depth that
    overflows `usize` panics rather than returning false. Callers pass bundle
    depths ≤ ~40. -/
theorem verify_proof_spec (canonical : Slice Std.U8) (leaf_index : Std.Usize)
    (proof_bytes : Slice Std.U8) (proof_depth : Std.Usize)
    (expected_root : Std.Array Std.U8 32#usize)
    (hdepth : proof_depth.val * 32 ≤ Std.Usize.max) :
    erc20.merkle.verify_proof canonical leaf_index proof_bytes proof_depth
        expected_root
      ⦃ b => b = true ↔
        (proof_bytes.val.length = proof_depth.val * 32 ∧
         merkleFold ((List.range proof_depth.val).map (chunk32 proof_bytes.val))
             (leaf_hash_pure canonical) leaf_index.val
           = expected_root) ⦄ := by
  unfold erc20.merkle.verify_proof
  step* <;> first | scalar_tac | skip
  have hne : ¬ (proof_bytes.len != i1) = true := ‹_›
  have hgate : proof_bytes.val.length = proof_depth.val * 32 := by
    simp only [bne_iff_ne, ne_eq, not_not] at hne
    have hv := congrArg UScalar.val hne
    rw [Slice.len_val, i1_post] at hv
    exact hv
  apply WP.spec_mono (verify_proof_loop_value
    { start := 0#usize, «end» := proof_depth } proof_bytes expected_root h leaf_index
    (merkleFold (List.map (chunk32 proof_bytes.val) (List.range proof_depth.val))
      (leaf_hash_pure canonical) leaf_index.val)
    proof_depth.val rfl (by simp) hgate
    (by
      rw [h_post]
      show merkleFold ((List.map (chunk32 proof_bytes.val) (List.range proof_depth.val)).drop 0)
          (leaf_hash_pure canonical) leaf_index.val = _
      rw [List.drop_zero]))
  intro b hb
  rw [hb]
  exact ⟨fun hr => ⟨hgate, hr⟩, fun ⟨_, hr⟩ => hr⟩

end Extracted.Equiv
