/- §33 rank 8 — rlp::decode_item: FUNCTIONAL spec — PROVEN 2026-06-12.

   The canonical-RLP boundary: every length threshold and leading-zero rule is
   where historical RLP bugs live, and `used` (bytes consumed) drives the list
   walk — a wrong `used` desyncs every subsequent field.

   The reference `decodeRef` below is an INDEPENDENT transcription of the RLP
   grammar (5-way first-byte split + the 6 canonical-form checks), returning
   `(isList, used)` on accept and `none` on reject. It was #eval-validated
   byte-for-byte against the real tx-core/tests/rlp_decoder.rs vectors (8
   positive + 7 negative — single byte / empty / short & long string & list /
   the 0x81,0x00 & 0x81,0x7f NonCanonical / 0x83,0x11,0x22 & 0xb9,0x10
   Truncated / long-form-≤55) BEFORE being stated, so the spec itself is
   ground-truth-checked, not just plausible.

   Proof shape: unfold decode_item; the former extraction axioms
   (core::{Option.ok_or, Try.branch, FromResidual, Slice.first}) are now DEFs
   in Extracted/Decode/FunsExternal.lean (into_iter pattern), so
   `#print axioms decode_item_spec` = [propext, Classical.choice, Quot.sound].
   `step*` splits the ≤0x7f/≤0xb7/≤0xbf/≤0xf7/else ladder into 11 goals;
   decode_length_be gets its own loop spec (rank-7 bytes_to_u64 template with
   checked ops); each leaf rewrites the post's `decodeRef` scrutinee via the
   per-arm evaluation lemmas. Grind note: scalar_tac recursion-loops once the
   ∀-quantified decode_length_be post is in context — the long arms `clear` it
   and use clean-context UScalar→val converter lemmas + plain omega.

   Rust finding (FIXED 2026-06-12, found by this proof): the original
   accumulator used `acc.checked_shl(8)`, but rustc's `usize::checked_shl`
   returns None only when the SHIFT AMOUNT ≥ BITS — overflowing VALUE bits
   are silently discarded. On a 32-bit usize (thumbv8m, the STM32U585!),
   decode_length_be WRAPPED for len_of_len ≥ 5 (e.g. length bytes
   01 00 00 01 00 claim 2^32+256, wrap to 256, and a 262-byte buffer was
   ACCEPTED where canonical RLP demands rejection) — the spec was provable
   only against a deliberately-stricter model. tx-core/src/rlp.rs now uses
   `acc.checked_mul(256)` (extracts to Aeneas stdlib `Usize.checked_mul`, no
   hand model at all); regression test
   `negative_length_field_exceeding_usize_errors_not_wraps` pins it. -/
import Extracted.Decode.Funs
import Extracted.RlpIntSpec

set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false
set_option linter.unreachableTactic false

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_tx_core

/-- Independent canonical-RLP reference: `(isList, used)` on accept, `none` on
    reject. #eval-validated against the rlp_decoder.rs vectors (see header). -/
def decodeRef (input : List Nat) : Option (Bool × Nat) :=
  match input with
  | [] => none
  | first :: _ =>
    if first ≤ 0x7f then some (false, 1)
    else if first ≤ 0xb7 then
      let len := first - 0x80
      let total := 1 + len
      if input.length < total then none
      else if len = 1 ∧ (input.getD 1 0) ≤ 0x7f then none
      else some (false, total)
    else if first ≤ 0xbf then
      let lol := first - 0xb7
      if lol = 0 ∨ lol > 8 then none
      else if input.length < 1 + lol then none
      else match (input.drop 1).take lol with
        | [] => none
        | b0 :: tl =>
          if b0 = 0 then none
          else let len := (b0 :: tl).foldl (fun a b => a * 256 + b) 0
               if len ≤ 55 then none
               else let total := 1 + lol + len
                    if input.length < total then none else some (false, total)
    else if first ≤ 0xf7 then
      let len := first - 0xc0
      let total := 1 + len
      if input.length < total then none else some (true, total)
    else
      let lol := first - 0xf7
      if lol = 0 ∨ lol > 8 then none
      else if input.length < 1 + lol then none
      else match (input.drop 1).take lol with
        | [] => none
        | b0 :: tl =>
          if b0 = 0 then none
          else let len := (b0 :: tl).foldl (fun a b => a * 256 + b) 0
               if len ≤ 55 then none
               else let total := 1 + lol + len
                    if input.length < total then none else some (true, total)

/-- True iff the decoded item is a list — matched against `decodeRef`'s flag. -/
def itemIsList : rlp.Item → Bool
  | .Bytes _ => false
  | .List _ => true

/-! ### Leaf lemmas — `beValue` accumulator algebra (extends RlpIntSpec's) -/

theorem beValue_foldl_acc (l : List Std.U8) (acc : Nat) :
    l.foldl (fun a b => a * 256 + b.val) acc = acc * 256 ^ l.length + beValue l := by
  induction l generalizing acc with
  | nil => simp [beValue]
  | cons b tl ih =>
    simp only [List.foldl_cons, List.length_cons]
    rw [ih (acc * 256 + b.val)]
    have hb : beValue (b :: tl) = b.val * 256 ^ tl.length + beValue tl := by
      simp only [beValue, List.foldl_cons]
      rw [show tl.foldl (fun a b => a * 256 + b.val) (0 * 256 + b.val)
            = tl.foldl (fun a b => a * 256 + b.val) b.val from by norm_num]
      rw [ih b.val]
      simp [beValue]
    rw [hb, pow_succ]
    ring

theorem beValue_take_le (l : List Std.U8) (m : Nat) :
    beValue (l.take m) ≤ beValue l := by
  have hl : beValue l
      = beValue (l.take m) * 256 ^ (l.drop m).length + beValue (l.drop m) := by
    conv_lhs => rw [← List.take_append_drop m l]
    simp only [beValue, List.foldl_append]
    exact beValue_foldl_acc (l.drop m) _
  rw [hl]
  calc beValue (l.take m)
      ≤ beValue (l.take m) * 256 ^ (l.drop m).length :=
        Nat.le_mul_of_pos_right _ (pow_pos (by norm_num) _)
    _ ≤ _ := Nat.le_add_right _ _

/-- The mapped-`Nat` Horner fold in `decodeRef` is exactly `beValue`. -/
theorem beValue_eq_foldl_map (l : List Std.U8) :
    (l.map (·.val)).foldl (fun a b => a * 256 + b) 0 = beValue l := by
  rw [List.foldl_map]; rfl

/-! ### `decode_length_be` — the BE accumulator (rank-7 loop template, checked ops) -/

open pqsigner_tx_core in
set_option maxHeartbeats 8000000 in
/-- The checked BE accumulator loop: returns `Ok (beValue slice)` when the
    value fits in `usize`, `Err LengthOverflow` otherwise. -/
theorem decode_length_be_loop_spec
    (it : core.slice.iter.Iter Std.U8) (acc : Std.Usize)
    (hik : it.i ≤ it.slice.val.length)
    (hacc : acc.val = beValue (it.slice.val.take it.i)) :
    rlp.decode_length_be_loop it acc
      ⦃ r =>
        (beValue it.slice.val < Usize.size →
          ∃ v, r = core.result.Result.Ok v ∧ v.val = beValue it.slice.val) ∧
        (Usize.size ≤ beValue it.slice.val →
          r = core.result.Result.Err rlp.RlpError.LengthOverflow) ⦄ := by
  unfold rlp.decode_length_be_loop
  apply Aeneas.Std.loop.spec_decr_nat
    (measure := fun (s : core.slice.iter.Iter Std.U8 × Std.Usize) =>
       s.1.slice.val.length - s.1.i)
    (inv := fun (s : core.slice.iter.Iter Std.U8 × Std.Usize) =>
       s.1.slice = it.slice ∧ s.1.i ≤ it.slice.val.length ∧
       s.2.val = beValue (it.slice.val.take s.1.i))
  · rintro ⟨jt, a⟩ ⟨hsl, hji, hjacc⟩
    simp only at hsl hji hjacc
    unfold rlp.decode_length_be_loop.body
    simp only [lift]
    let* ⟨o, iter1, hpost⟩ ← sliceIter_next_spec
    rcases hpost with ⟨hdone, ho, hit⟩ | ⟨hlt, ⟨hb, ho⟩, hit⟩
    · -- exhausted: take i = whole list, acc < size by construction
      subst ho
      simp only [WP.spec_ok]
      rw [hsl] at hdone
      have hge : it.slice.val.length ≤ jt.i := by omega
      have hfull : a.val = beValue it.slice.val := by
        rw [hjacc, List.take_of_length_le hge]
      refine ⟨fun _ => ⟨a, rfl, hfull⟩, fun hbig => ?_⟩
      exfalso
      scalar_tac
    · -- one more byte
      subst ho
      simp only []
      have hja : a.val = beValue (jt.slice.val.take jt.i) := by rw [hjacc, hsl]
      set b := (jt.slice.val)[jt.i]'hb with hbdef
      have hstep : beValue (jt.slice.val.take (jt.i + 1)) = a.val * 256 + b.val := by
        rw [List.take_succ_eq_append_getElem hb, beValue_append_byte, ← hja]
      have hmono : beValue (jt.slice.val.take (jt.i + 1)) ≤ beValue jt.slice.val :=
        beValue_take_le _ _
      have hslv : beValue jt.slice.val = beValue it.slice.val := by rw [hsl]
      have hbb : b.val < 256 := by
        have := b.hBounds
        simp only [Std.U8.size] at this
        omega
      have h256 : (256#usize).val = 256 := by scalar_tac
      have hmulspec := Std.Usize.checked_mul_bv_spec a 256#usize
      cases hmul : Std.Usize.checked_mul a 256#usize with
      | some z =>
        rw [hmul] at hmulspec
        simp only at hmulspec
        have hzval : z.val = a.val * 256 := by
          have := hmulspec.2.1; rwa [h256] at this
        have hcast : (UScalar.cast .Usize b).val = b.val := Std.U8.cast_Usize_val_eq b
        simp only [core.option.Option.ok_or,
                   core.result.Result.Insts.CoreOpsTry_traitTry.branch,
                   bind_tc_ok, bind_ok]
        cases hadd : Std.Usize.checked_add z (UScalar.cast .Usize b) with
        | none =>
          -- add overflow ⇒ the full value can't fit
          have hspec := Std.Usize.checked_add_bv_spec z (UScalar.cast .Usize b)
          rw [hadd] at hspec
          simp only at hspec
          rw [hzval, hcast] at hspec
          simp only [core.option.Option.ok_or,
                     core.result.Result.Insts.CoreOpsTry_traitTry.branch,
                     core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
                     core.convert.FromSame, core.convert.FromSame.from_,
                     bind_tc_ok, bind_ok, WP.spec_ok]
          have hms : Usize.max + 1 = Usize.size := by scalar_tac
          have hbig : Usize.size ≤ beValue it.slice.val := by
            rw [← hslv]; omega
          refine ⟨fun hcontra => absurd hcontra (by omega),
                  by first
                    | exact fun _ => True.intro
                    | exact fun _ => rfl
                    | trivial⟩
        | some z1 =>
          have hspec := Std.Usize.checked_add_bv_spec z (UScalar.cast .Usize b)
          rw [hadd] at hspec
          simp only at hspec
          have hz : z1.val = a.val * 256 + b.val := by
            rw [← hzval, ← hcast]; exact hspec.2.1
          simp only [core.option.Option.ok_or,
                     core.result.Result.Insts.CoreOpsTry_traitTry.branch,
                     bind_tc_ok, bind_ok, WP.spec_ok]
          have hi1 : iter1.i = jt.i + 1 := by rw [hit]
          have hs1 : iter1.slice = jt.slice := by rw [hit]
          refine ⟨by rw [hs1]; exact hsl,
                  by rw [hi1]; rw [← hsl]; omega,
                  ?_,
                  by rw [hi1, hs1]; omega⟩
          rw [hi1, ← hsl, hstep]
          exact hz
      | none =>
        -- multiply overflows usize ⇒ the full value can't fit
        rw [hmul] at hmulspec
        simp only at hmulspec
        rw [h256] at hmulspec
        simp only [core.option.Option.ok_or,
                   core.result.Result.Insts.CoreOpsTry_traitTry.branch,
                   core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
                   core.convert.FromSame, core.convert.FromSame.from_,
                   bind_tc_ok, bind_ok, WP.spec_ok]
        have hms : Usize.max + 1 = Usize.size := by scalar_tac
        have hbig : Usize.size ≤ beValue it.slice.val := by
          rw [← hslv]; omega
        refine ⟨fun hcontra => absurd hcontra (by omega),
                  by first
                    | exact fun _ => True.intro
                    | exact fun _ => rfl
                    | trivial⟩
  · exact ⟨rfl, hik, hacc⟩

open pqsigner_tx_core in
set_option maxHeartbeats 8000000 in
/-- **Functional spec** for `decode_length_be`: NonCanonical on empty,
    LeadingZero on a 0 first byte, otherwise `Ok (beValue bytes)` when it fits
    in `usize` and `Err LengthOverflow` when it doesn't. -/
theorem decode_length_be_spec (bytes : Slice Std.U8) :
    rlp.decode_length_be bytes
      ⦃ r =>
        (bytes.val = [] → r = core.result.Result.Err rlp.RlpError.NonCanonical) ∧
        (∀ b0 tl, bytes.val = b0 :: tl → b0.val = 0 →
          r = core.result.Result.Err rlp.RlpError.LeadingZero) ∧
        (∀ b0 tl, bytes.val = b0 :: tl → b0.val ≠ 0 →
          (beValue bytes.val < Usize.size →
            ∃ v, r = core.result.Result.Ok v ∧ v.val = beValue bytes.val) ∧
          (Usize.size ≤ beValue bytes.val →
            r = core.result.Result.Err rlp.RlpError.LengthOverflow)) ⦄ := by
  unfold rlp.decode_length_be
  simp only [SharedASlice.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter,
             core.slice.Slice.is_empty, bind_tc_ok, bind_ok, decide_eq_true_eq]
  split
  · -- empty
    rename_i hempty
    simp only [WP.spec_ok]
    have hnil : bytes.val = [] := by
      have h0 : bytes.val.length = 0 := by simpa using hempty
      exact List.length_eq_zero_iff.mp h0
    refine ⟨by first
              | exact fun _ => True.intro
              | exact fun _ => rfl,
            fun b0 tl heq _ => ?_, fun b0 tl heq _ => ?_⟩
    · rw [heq] at hnil; simp at hnil
    · rw [heq] at hnil; simp at hnil
  · rename_i hnempty
    have hnnil : bytes.val ≠ [] := by
      intro hnil
      apply hnempty
      simp [hnil]
    have hpos : 0 < bytes.val.length := List.length_pos_of_ne_nil hnnil
    step* <;> first | scalar_tac | skip
    · -- first byte is zero
      rename_i hz
      try simp only [WP.spec_ok]
      obtain ⟨b0, tl, heq⟩ := List.exists_cons_of_ne_nil hnnil
      refine ⟨fun h => absurd h hnnil,
              by first
                | exact fun c0 ctl heq' _ => True.intro
                | exact fun c0 ctl heq' _ => rfl,
              fun c0 ctl heq' hnz => ?_⟩
      exfalso
      apply hnz
      have : i = c0 := by
        rw [i_post, ← getElem!_pos _ _ (by rw [heq']; simp), heq',
            List.getElem!_cons_zero]
      rw [← this, hz]
      rfl
    · -- nonzero first byte: run the loop
      rename_i hnz
      let* ⟨r, hr1, hr2⟩ ← decode_length_be_loop_spec ⟨bytes, 0⟩ 0#usize
        (by simp) (by simp [beValue])
      try simp only [WP.spec_ok]
      try simp only at hr1 hr2
      refine ⟨fun h => absurd h hnnil, fun c0 ctl heq' hc0 => ?_,
              fun c0 ctl heq' _ => ⟨hr1, hr2⟩⟩
      exfalso
      apply hnz
      have : i = c0 := by
        rw [i_post, ← getElem!_pos _ _ (by rw [heq']; simp), heq',
            List.getElem!_cons_zero]
      rw [this]
      apply UScalar.eq_of_val_eq
      simpa using hc0

/-! ### `decodeRef` arm-evaluation lemmas (pure `Nat`, one per grammar arm) -/

/-- `getD 0` of a mapped non-empty list. -/
theorem mapval_getD (l : List Std.U8) (h : l ≠ []) :
    (l.map (·.val)).getD 0 0 = (l[0]!).val := by
  cases l with
  | nil => exact absurd rfl h
  | cons x xs => simp

theorem decodeRef_single (f : Nat) (t : List Nat) (h : f ≤ 0x7f) :
    decodeRef (f :: t) = some (false, 1) := by
  simp [decodeRef, h]

theorem decodeRef_short_str_trunc (f : Nat) (t : List Nat)
    (h1 : 0x7f < f) (h2 : f ≤ 0xb7)
    (h3 : (f :: t).length < 1 + (f - 0x80)) :
    decodeRef (f :: t) = none := by
  simp only [decodeRef]
  rw [if_neg (by omega), if_pos (by omega), if_pos h3]

theorem decodeRef_short_str_noncanon (f : Nat) (t : List Nat)
    (h1 : 0x7f < f) (h2 : f ≤ 0xb7)
    (h3 : ¬ (f :: t).length < 1 + (f - 0x80))
    (hl1 : f - 0x80 = 1) (hb : t.getD 0 0 ≤ 0x7f) :
    decodeRef (f :: t) = none := by
  simp only [decodeRef]
  rw [if_neg (by omega), if_pos (by omega), if_neg h3,
      if_pos ⟨hl1, by simpa using hb⟩]

theorem decodeRef_short_str_ok (f : Nat) (t : List Nat)
    (h1 : 0x7f < f) (h2 : f ≤ 0xb7)
    (h3 : ¬ (f :: t).length < 1 + (f - 0x80))
    (hcanon : ¬ (f - 0x80 = 1 ∧ t.getD 0 0 ≤ 0x7f)) :
    decodeRef (f :: t) = some (false, 1 + (f - 0x80)) := by
  simp only [decodeRef]
  rw [if_neg (by omega), if_pos (by omega), if_neg h3,
      if_neg (by simpa using hcanon)]

theorem decodeRef_short_list_trunc (f : Nat) (t : List Nat)
    (h1 : 0xbf < f) (h2 : f ≤ 0xf7)
    (h3 : (f :: t).length < 1 + (f - 0xc0)) :
    decodeRef (f :: t) = none := by
  simp only [decodeRef]
  rw [if_neg (by omega), if_neg (by omega), if_neg (by omega),
      if_pos (by omega), if_pos h3]

theorem decodeRef_short_list_ok (f : Nat) (t : List Nat)
    (h1 : 0xbf < f) (h2 : f ≤ 0xf7)
    (h3 : ¬ (f :: t).length < 1 + (f - 0xc0)) :
    decodeRef (f :: t) = some (true, 1 + (f - 0xc0)) := by
  simp only [decodeRef]
  rw [if_neg (by omega), if_neg (by omega), if_neg (by omega),
      if_pos (by omega), if_neg h3]

/-- Long-form arms (string `0xb8..0xbf` / list `0xf8..0xff`) share their whole
    body shape; `isStr` selects which bounds/flag apply. -/
theorem decodeRef_long_trunc_hdr (f : Nat) (t : List Nat) (lol : Nat)
    (hf : (0xb7 < f ∧ f ≤ 0xbf ∧ lol = f - 0xb7) ∨
          (0xf7 < f ∧ f ≤ 0xff ∧ lol = f - 0xf7))
    (h3 : (f :: t).length < 1 + lol) :
    decodeRef (f :: t) = none := by
  simp only [decodeRef]
  rcases hf with ⟨h1, h2, hlol⟩ | ⟨h1, h2, hlol⟩
  · rw [if_neg (by omega), if_neg (by omega), if_pos (by omega),
        if_neg (by omega), if_pos (by omega)]
  · rw [if_neg (by omega), if_neg (by omega), if_neg (by omega),
        if_neg (by omega), if_neg (by omega), if_pos (by omega)]

theorem decodeRef_long_body (f : Nat) (t : List Nat) (lol : Nat)
    (b0 : Nat) (tl : List Nat) (isList : Bool)
    (hf : (0xb7 < f ∧ f ≤ 0xbf ∧ lol = f - 0xb7 ∧ isList = false) ∨
          (0xf7 < f ∧ f ≤ 0xff ∧ lol = f - 0xf7 ∧ isList = true))
    (h3 : ¬ (f :: t).length < 1 + lol)
    (ht : t.take lol = b0 :: tl) :
    decodeRef (f :: t) =
      (if b0 = 0 then none
       else
         let len := (b0 :: tl).foldl (fun a b => a * 256 + b) 0
         if len ≤ 55 then none
         else if (f :: t).length < 1 + lol + len then none
              else some (isList, 1 + lol + len)) := by
  simp only [decodeRef]
  rcases hf with ⟨h1, h2, hlol, hflag⟩ | ⟨h1, h2, hlol, hflag⟩
  · rw [if_neg (by omega), if_neg (by omega), if_pos (by omega),
        if_neg (by omega), if_neg (by omega)]
    rw [show (f :: t).drop 1 = t from rfl, ← hlol, ht, hflag]
  · rw [if_neg (by omega), if_neg (by omega), if_neg (by omega),
        if_neg (by omega), if_neg (by omega), if_neg (by omega)]
    rw [show (f :: t).drop 1 = t from rfl, ← hlol, ht, hflag]

/-! Clean-context UScalar→`val` converters: `scalar_tac` recursion-loops when
    the `∀`-quantified `decode_length_be_spec` post is in context, so the long
    arms convert their branch conditions through these and use plain `omega`. -/

private theorem usize_le55_val {v : Std.Usize} (h : v ≤ 55#usize) :
    v.val ≤ 55 := by scalar_tac

private theorem usize_gt55_val {v : Std.Usize} (h : ¬ v ≤ 55#usize) :
    55 < v.val := by scalar_tac

private theorem slice_len_lt_val {α} {s : Slice α} {y : Std.Usize}
    (h : Slice.len s < y) : s.val.length < y.val := by scalar_tac

private theorem slice_len_not_lt_val {α} {s : Slice α} {y : Std.Usize}
    (h : ¬ Slice.len s < y) : y.val ≤ s.val.length := by scalar_tac

/-- **Functional spec**: `decode_item` accepts exactly the canonical inputs
    `decodeRef` accepts, returns the matching `used`, and the item kind agrees.
    (The payload-slice identity `input[header..used]` is a follow-on refinement
    once the accept/used/kind core is closed.) -/
theorem decode_item_spec (input : Slice Std.U8) :
    rlp.decode_item input
      ⦃ r =>
        match decodeRef (input.val.map (·.val)) with
        | none => ∃ e, r = core.result.Result.Err e
        | some (isList, used) =>
            ∃ item u, r = core.result.Result.Ok (item, u) ∧
              u.val = used ∧ itemIsList item = isList ⦄ := by
  unfold rlp.decode_item
  simp only [core.slice.Slice.first, lift, bind_tc_ok, bind_ok]
  cases hv : input.val with
  | nil =>
    simp only [List.head?_nil, List.map_nil, core.option.Option.ok_or,
               core.result.Result.Insts.CoreOpsTry_traitTry.branch,
               core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
               core.convert.FromSame, core.convert.FromSame.from_,
               bind_tc_ok, bind_ok, WP.spec_ok, decodeRef]
    exact ⟨_, rfl⟩
  | cons b0 rest =>
    simp only [List.head?_cons, List.map_cons, core.option.Option.ok_or,
               core.result.Result.Insts.CoreOpsTry_traitTry.branch,
               bind_tc_ok, bind_ok]
    have hlen : input.val.length = rest.length + 1 := by rw [hv]; rfl
    have hb0lt : b0.val < 256 := by
      have := b0.hBounds
      simp only [Std.U8.size] at this
      omega
    step* <;> first | scalar_tac | skip
    · -- A: single byte (≤ 0x7f)
      rw [decodeRef_single _ _ (by scalar_tac)]
      exact ⟨_, 1#usize, rfl, by scalar_tac, rfl⟩
    · -- B: short string, truncated
      rw [decodeRef_short_str_trunc _ _ (by scalar_tac) (by scalar_tac)
        (by simp only [List.length_cons, List.length_map]; scalar_tac)]
      exact ⟨_, rfl⟩
    · -- B: short string, len = 1, payload ≤ 0x7f — NonCanonical
      have hrest : rest ≠ [] := by
        intro h
        rw [h] at hlen
        simp at hlen
        scalar_tac
      have hi2 : i2 = rest[0]! := by
        rw [i2_post, ← getElem!_pos _ _ (by scalar_tac), hv]
        simp
      have hgetD : (List.map (fun x => x.val) rest).getD 0 0 = i2.val := by
        rw [mapval_getD rest hrest, hi2]
      rw [decodeRef_short_str_noncanon _ _ (by scalar_tac) (by scalar_tac)
        (by simp only [List.length_cons, List.length_map]; scalar_tac)
        (by scalar_tac) (by rw [hgetD]; scalar_tac)]
      exact ⟨_, rfl⟩
    · -- B: short string, len = 1, payload > 0x7f — Ok
      have hrest : rest ≠ [] := by
        intro h
        rw [h] at hlen
        simp at hlen
        scalar_tac
      have hi2 : i2 = rest[0]! := by
        rw [i2_post, ← getElem!_pos _ _ (by scalar_tac), hv]
        simp
      have hgetD : (List.map (fun x => x.val) rest).getD 0 0 = i2.val := by
        rw [mapval_getD rest hrest, hi2]
      rw [decodeRef_short_str_ok _ _ (by scalar_tac) (by scalar_tac)
        (by simp only [List.length_cons, List.length_map]; scalar_tac)
        (by rintro ⟨-, hle⟩; rw [hgetD] at hle; scalar_tac)]
      exact ⟨_, total, rfl, by scalar_tac, rfl⟩
    · -- B: short string, len ≠ 1 — Ok
      rw [decodeRef_short_str_ok _ _ (by scalar_tac) (by scalar_tac)
        (by simp only [List.length_cons, List.length_map]; scalar_tac)
        (by rintro ⟨h1, -⟩; scalar_tac)]
      exact ⟨_, total, rfl, by scalar_tac, rfl⟩
    · -- C: long string, truncated header
      rw [decodeRef_long_trunc_hdr _ _ (i.val)
        (Or.inl ⟨by scalar_tac, by scalar_tac, by scalar_tac⟩)
        (by simp only [List.length_cons, List.length_map]; scalar_tac)]
      exact ⟨_, rfl⟩
    · -- C: long string body (decode_length_be onward)
      have hlol1 : 1 ≤ i.val := by scalar_tac
      have hlol8 : i.val ≤ 8 := by scalar_tac
      have hi2v : i2.val = 1 + i.val := by scalar_tac
      have hfit : i2.val ≤ rest.length + 1 := by scalar_tac
      have hsval : s.val = rest.take i.val := by
        rw [s_post1, hv]
        show List.slice 1 i2.val (b0 :: rest) = _
        unfold List.slice
        rw [show (b0 :: rest).drop 1 = rest from rfl]
        congr 1
        omega
      have hslen : s.val.length = i.val := by
        rw [hsval, List.length_take]
        omega
      have hsnnil : s.val ≠ [] := by
        intro h
        rw [h] at hslen
        simp at hslen
        omega
      obtain ⟨c0, ctl, hcons⟩ := List.exists_cons_of_ne_nil hsnnil
      have htake : (List.map (fun x => x.val) rest).take i.val
          = c0.val :: List.map (fun x => x.val) ctl := by
        rw [← List.map_take, ← hsval, hcons, List.map_cons]
      have hfold : (c0.val :: List.map (fun x => x.val) ctl).foldl
          (fun a b => a * 256 + b) 0 = beValue s.val := by
        rw [← List.map_cons, beValue_eq_foldl_map, ← hcons]
      have hbody := decodeRef_long_body b0.val (List.map (fun x => x.val) rest)
        i.val c0.val (List.map (fun x => x.val) ctl) false
        (Or.inl ⟨by scalar_tac, by scalar_tac, by scalar_tac, rfl⟩)
        (by simp only [List.length_cons, List.length_map]; scalar_tac)
        htake
      have h55size : (55:Nat) < Usize.size := by scalar_tac
      have hinmax : input.val.length ≤ Usize.max := Slice.length_ineq input
      have hms : Usize.max + 1 = Usize.size := by scalar_tac
      let* ⟨r1, hr1, hr2, hr3⟩ ← decode_length_be_spec
      have hLZ := hr2 c0 ctl hcons
      have hOKOF := hr3 c0 ctl hcons
      clear hr1 hr2 hr3
      by_cases hc0 : c0.val = 0
      · -- LeadingZero from the length bytes
        rw [hLZ hc0]
        simp only [core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
                   core.convert.FromSame, core.convert.FromSame.from_,
                   bind_tc_ok, bind_ok, WP.spec_ok]
        rw [if_pos hc0] at hbody
        rw [hbody]
        exact ⟨_, rfl⟩
      · rw [if_neg hc0] at hbody
        simp only [hfold] at hbody
        have hcases := hOKOF hc0
        clear hOKOF hLZ
        by_cases hsize : beValue s.val < Usize.size
        · obtain ⟨v, hv1, hv2⟩ := hcases.1 hsize
          clear hcases
          rw [hv1]
          simp only [bind_tc_ok, bind_ok]
          split
          · -- len ≤ 55 — NonCanonical
            have h55v : v.val ≤ 55 := usize_le55_val ‹_›
            rw [if_pos (by omega)] at hbody
            try simp only [WP.spec_ok]
            rw [hbody]
            exact ⟨_, rfl⟩
          · -- len > 55
            have h55v : 55 < v.val := usize_gt55_val ‹_›
            rw [if_neg (by omega)] at hbody
            cases hadd : Std.Usize.checked_add i2 v with
            | none =>
              have hspec := Std.Usize.checked_add_bv_spec i2 v
              rw [hadd] at hspec
              simp only at hspec
              simp only [bind_tc_ok, bind_ok, WP.spec_ok]
              rw [if_pos (by
                simp only [List.length_cons, List.length_map]
                omega)] at hbody
              rw [hbody]
              exact ⟨_, rfl⟩
            | some val2 =>
              have hspec := Std.Usize.checked_add_bv_spec i2 v
              rw [hadd] at hspec
              simp only at hspec
              have hval2 : val2.val = i2.val + v.val := hspec.2.1
              simp only [bind_tc_ok, bind_ok]
              split
              · -- input too short — LengthOverflow
                have hltv : input.val.length < val2.val := slice_len_lt_val ‹_›
                rw [if_pos (by
                  simp only [List.length_cons, List.length_map]
                  omega)] at hbody
                try simp only [WP.spec_ok]
                rw [hbody]
                exact ⟨_, rfl⟩
              · -- accept
                have hgev : val2.val ≤ input.val.length := slice_len_not_lt_val ‹_›
                rw [if_neg (by
                  simp only [List.length_cons, List.length_map]
                  omega)] at hbody
                let* ⟨s1, hs1a, hs1b⟩ ←
                  core.slice.index.SliceIndexRangeUsizeSlice.index.step_spec
                    ⟨i2, val2⟩ input
                    (by show i2 ≤ val2; rw [UScalar.le_equiv]; omega)
                    (by show val2.val ≤ input.val.length; omega)
                try simp only [WP.spec_ok]
                rw [hbody]
                exact ⟨_, val2, rfl, by omega, rfl⟩
        · -- length value overflows usize — LengthOverflow
          rw [hcases.2 (by omega)]
          simp only [core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
                     core.convert.FromSame, core.convert.FromSame.from_,
                     bind_tc_ok, bind_ok, WP.spec_ok]
          rw [if_neg (by omega)] at hbody
          rw [if_pos (by
            simp only [List.length_cons, List.length_map]
            omega)] at hbody
          rw [hbody]
          exact ⟨_, rfl⟩
    · -- D: short list, truncated
      rw [decodeRef_short_list_trunc _ _ (by scalar_tac) (by scalar_tac)
        (by simp only [List.length_cons, List.length_map]; scalar_tac)]
      exact ⟨_, rfl⟩
    · -- D: short list — Ok
      rw [decodeRef_short_list_ok _ _ (by scalar_tac) (by scalar_tac)
        (by simp only [List.length_cons, List.length_map]; scalar_tac)]
      exact ⟨_, total, rfl, by scalar_tac, rfl⟩
    · -- E: long list, truncated header
      rw [decodeRef_long_trunc_hdr _ _ (i.val)
        (Or.inr ⟨by scalar_tac, by scalar_tac, by scalar_tac⟩)
        (by simp only [List.length_cons, List.length_map]; scalar_tac)]
      exact ⟨_, rfl⟩
    · -- E: long list body (decode_length_be onward)
      have hlol1 : 1 ≤ i.val := by scalar_tac
      have hlol8 : i.val ≤ 8 := by scalar_tac
      have hi2v : i2.val = 1 + i.val := by scalar_tac
      have hfit : i2.val ≤ rest.length + 1 := by scalar_tac
      have hsval : s.val = rest.take i.val := by
        rw [s_post1, hv]
        show List.slice 1 i2.val (b0 :: rest) = _
        unfold List.slice
        rw [show (b0 :: rest).drop 1 = rest from rfl]
        congr 1
        omega
      have hslen : s.val.length = i.val := by
        rw [hsval, List.length_take]
        omega
      have hsnnil : s.val ≠ [] := by
        intro h
        rw [h] at hslen
        simp at hslen
        omega
      obtain ⟨c0, ctl, hcons⟩ := List.exists_cons_of_ne_nil hsnnil
      have htake : (List.map (fun x => x.val) rest).take i.val
          = c0.val :: List.map (fun x => x.val) ctl := by
        rw [← List.map_take, ← hsval, hcons, List.map_cons]
      have hfold : (c0.val :: List.map (fun x => x.val) ctl).foldl
          (fun a b => a * 256 + b) 0 = beValue s.val := by
        rw [← List.map_cons, beValue_eq_foldl_map, ← hcons]
      have hbody := decodeRef_long_body b0.val (List.map (fun x => x.val) rest)
        i.val c0.val (List.map (fun x => x.val) ctl) true
        (Or.inr ⟨by scalar_tac, by scalar_tac, by scalar_tac, rfl⟩)
        (by simp only [List.length_cons, List.length_map]; scalar_tac)
        htake
      have h55size : (55:Nat) < Usize.size := by scalar_tac
      have hinmax : input.val.length ≤ Usize.max := Slice.length_ineq input
      have hms : Usize.max + 1 = Usize.size := by scalar_tac
      let* ⟨r1, hr1, hr2, hr3⟩ ← decode_length_be_spec
      have hLZ := hr2 c0 ctl hcons
      have hOKOF := hr3 c0 ctl hcons
      clear hr1 hr2 hr3
      by_cases hc0 : c0.val = 0
      · -- LeadingZero from the length bytes
        rw [hLZ hc0]
        simp only [core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
                   core.convert.FromSame, core.convert.FromSame.from_,
                   bind_tc_ok, bind_ok, WP.spec_ok]
        rw [if_pos hc0] at hbody
        rw [hbody]
        exact ⟨_, rfl⟩
      · rw [if_neg hc0] at hbody
        simp only [hfold] at hbody
        have hcases := hOKOF hc0
        clear hOKOF hLZ
        by_cases hsize : beValue s.val < Usize.size
        · obtain ⟨v, hv1, hv2⟩ := hcases.1 hsize
          clear hcases
          rw [hv1]
          simp only [bind_tc_ok, bind_ok]
          split
          · -- len ≤ 55 — NonCanonical
            have h55v : v.val ≤ 55 := usize_le55_val ‹_›
            rw [if_pos (by omega)] at hbody
            try simp only [WP.spec_ok]
            rw [hbody]
            exact ⟨_, rfl⟩
          · -- len > 55
            have h55v : 55 < v.val := usize_gt55_val ‹_›
            rw [if_neg (by omega)] at hbody
            cases hadd : Std.Usize.checked_add i2 v with
            | none =>
              have hspec := Std.Usize.checked_add_bv_spec i2 v
              rw [hadd] at hspec
              simp only at hspec
              simp only [bind_tc_ok, bind_ok, WP.spec_ok]
              rw [if_pos (by
                simp only [List.length_cons, List.length_map]
                omega)] at hbody
              rw [hbody]
              exact ⟨_, rfl⟩
            | some val2 =>
              have hspec := Std.Usize.checked_add_bv_spec i2 v
              rw [hadd] at hspec
              simp only at hspec
              have hval2 : val2.val = i2.val + v.val := hspec.2.1
              simp only [bind_tc_ok, bind_ok]
              split
              · -- input too short — LengthOverflow
                have hltv : input.val.length < val2.val := slice_len_lt_val ‹_›
                rw [if_pos (by
                  simp only [List.length_cons, List.length_map]
                  omega)] at hbody
                try simp only [WP.spec_ok]
                rw [hbody]
                exact ⟨_, rfl⟩
              · -- accept
                have hgev : val2.val ≤ input.val.length := slice_len_not_lt_val ‹_›
                rw [if_neg (by
                  simp only [List.length_cons, List.length_map]
                  omega)] at hbody
                let* ⟨s1, hs1a, hs1b⟩ ←
                  core.slice.index.SliceIndexRangeUsizeSlice.index.step_spec
                    ⟨i2, val2⟩ input
                    (by show i2 ≤ val2; rw [UScalar.le_equiv]; omega)
                    (by show val2.val ≤ input.val.length; omega)
                try simp only [WP.spec_ok]
                rw [hbody]
                exact ⟨_, val2, rfl, by omega, rfl⟩
        · -- length value overflows usize — LengthOverflow
          rw [hcases.2 (by omega)]
          simp only [core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
                     core.convert.FromSame, core.convert.FromSame.from_,
                     bind_tc_ok, bind_ok, WP.spec_ok]
          rw [if_neg (by omega)] at hbody
          rw [if_pos (by
            simp only [List.length_cons, List.length_map]
            omega)] at hbody
          rw [hbody]
          exact ⟨_, rfl⟩

end Extracted.Equiv
