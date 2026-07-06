/- §33 — format_decimal Track-1 M7: END-TO-END WYSIWYS composition —
   `u256_format_decimal` functional correctness over the committed Aeneas
   extraction (`Extracted/FormatDecimal/Funs.lean`).

   THE RESULT (`format_decimal_spec` / `u256_format_decimal_spec`): for
   EVERY 256-bit value `v`, decimals `D`, fractional precision `F ≤ 255`,
   trim flag and output slice, with `V = beValue v` and the SPEC-SIDE
   quantities (defined purely from `V`,`D`,`F`,`trim` — no internal
   firmware state):

     roundedScaled V D F = if F < D then (V + 5·10^(D-F-1)) / 10^(D-F)
                           else V · 10^(F-D)
       — the round-half-up rendering of V/10^D at F fractional digits,
         as the integer (displayed number)·10^F;
     specFracCount    — F when not trimming; when trimming, the largest
                        pos ≤ F whose pos-th fractional digit of
                        roundedScaled is nonzero (0 when the fraction is
                        all zeros);
     specWidth        — numDigits10(roundedScaled/10^F) integer digits
                        + ('.' + specFracCount) when specFracCount ≠ 0,

   the call returns
     (1) `(none, out)` — out LITERALLY unchanged — iff
         `out.length < specWidth` (see `FormatPost` + `FormatPost.none_iff`);
     (2) otherwise `(some w, out')` with `w = specWidth`, only `out'[0,w)`
         rewritten (drop-frame + length preserved), and the rendered
         string `s = out'.take w`:
         (2a) WELL-FORMED (`wellFormedRender`): nonempty; every byte an
              ASCII digit or '.'; the dot appears EXACTLY at distance
              specFracCount+1 from the end and only when specFracCount ≠ 0;
              byte 0 is a digit; a leading '0' happens only in the "0" /
              "0.xxx" shapes (no spurious leading zero);
         (2b) VALUE-EXACT (the WYSIWYS headline):
                parsedScaled s · 10^(F - specFracCount) = roundedScaled V D F
              where `parsedScaled` re-parses the digit bytes (dot skipped)
              — the string the user sees IS the round-half-up rendering of
              the 256-bit value, machine-checked end-to-end (this is where
              the M-6 digit-aliasing and F14#3 nonzero-collapse HIGH-class
              display bugs lived);
         (2c) TRIM SEMANTICS: trim=false renders exactly F fractional
              digits (specFracCount = F definitionally); trim=true renders
              specFracCount ≤ F digits with the SAME parsed value (2b) and
              MINIMALLY — when specFracCount ≠ 0 the last rendered digit
              is nonzero (`parsedScaled s % 10 ≠ 0`), so no further digit
              could be trimmed without changing the value.

   All four phase specs (M4 extract / M5 round / M6 trim / M6b emit) are
   composed with every intermediate-state hypothesis DISCHARGED: the M5
   digits-≤9 + zero-tail hypotheses come from the M4 post on the fresh
   zeroed [0u8;80] buffer, the M6b digit bounds from the M5 `carryPost`
   (or the M4 post in the no-round case), and `frac_emit ≤ 255` from the
   caller-facing `hF255` precondition (see caveats).

   Key pure bridges (all in this file):
     • `getElem!_eq_digit`      — a ≤9-digit buffer IS the base-10 digit
                                  string of its `decValue` (positionwise);
     • `parsedScaled_emitBytes` — re-parsing the emitted bytes yields
                                  exactly decValue/10^(td-fe) (fe ≤ td)
                                  resp. decValue·10^(fe-td);
     • `round_half_up_div`      — (V + 5·10^(k-1))/10^k = V/10^k +
                                  (1 iff digit_(k-1)(V) ≥ 5): the
                                  `fmt_round_half_up` +10^rid carry IS
                                  round-half-up division;
     • `trim_value_preserving`  — stripping structurally-zero fractional
                                  positions preserves the parsed value;
     • `intEmitN_eq_numDigits`  — the emitted integer width is the decimal
                                  digit count of roundedScaled/10^F.

   HONEST CAVEATS (no silent weakening):
   1. `hF255 : frac_digits.val ≤ 255` is a genuine precondition inherited
      from M6b `emit_spec` (headroom for the checked `need` width adds).
      It matches `frac_digits`' provenance at every firmware call site
      (token decimals are u8-scale); a >255-fractional-digit render is
      out of scope.
   2. `decimals` is unconstrained (D up to 2^32-1 is covered — huge D
      simply renders "0.000…0").
   3. The None-iff is stated as the two directions inside `FormatPost`
      (no-fit → literally `(none, out)`, fit → `some` with the full
      render contract); `FormatPost.none_iff` derives the ↔ form.

   NOTE (axiom discipline): no `bv_tac` (`bv_decide` would inject a
   native-computation axiom the §33 gate rejects) — closure is exactly
   [propext, Classical.choice, Quot.sound].

   Sixth and FINAL milestone of the format_decimal Track-1 WYSIWYS spec
   (work-todo FV frontier): "the emitted string parses back to
   round-half-up(v/10^d, f)" is now a kernel-checked theorem. -/
import Aeneas
import Extracted.FormatDecimal.Funs
import Extracted.FormatDecimal.Div10Spec
import Extracted.FormatDecimal.ExtractDigitsSpec
import Extracted.FormatDecimal.RoundCarrySpec
import Extracted.FormatDecimal.TrimFracSpec
import Extracted.FormatDecimal.EmitSpec
import Mathlib.Data.Nat.Log
import Mathlib.Data.Nat.Find
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.unusedVariables false
set_option maxHeartbeats 1000000

namespace FormatDecimalSpec

open Extracted.Equiv    -- beValue + lemmas (RlpIntSpec / U256MulSpec)
open pqsigner_tx_core
open Div10Spec          -- take_succ_getElem!
open ExtractDigitsSpec  -- decValue + lemmas, extract_digits_spec
open RoundCarrySpec     -- dropDigitVal, carryPost, round_carry_spec
open TrimFracSpec       -- fracDigitVal, trim_frac_spec
open EmitSpec           -- emitBytes + corollaries, emit_spec

theorem ten_pow_pos (k : Nat) : 0 < 10 ^ k := Nat.pow_pos (by norm_num)

/-! ### decValue toolkit (extends the M4/M5 kit) -/

theorem decValue_append (a b : List Std.U8) :
    decValue (a ++ b) = decValue a + 10 ^ a.length * decValue b := by
  induction a with
  | nil => simp
  | cons x a ih =>
    rw [List.cons_append, decValue_cons, decValue_cons, ih, List.length_cons,
        pow_succ]
    ring

theorem decValue_lt (l : List Std.U8)
    (h : ∀ i, i < l.length → (l[i]!).val ≤ 9) :
    decValue l < 10 ^ l.length := by
  induction l with
  | nil => simp [decValue]
  | cons b tl ih =>
    rw [decValue_cons, List.length_cons, pow_succ]
    have hb : b.val ≤ 9 := by
      have := h 0 (by simp); simpa using this
    have htl : decValue tl < 10 ^ tl.length := by
      apply ih
      intro i hi
      have := h (i + 1) (by simpa using Nat.succ_lt_succ hi)
      simpa using this
    omega

theorem decValue_zero_of_all_zero (l : List Std.U8)
    (h : ∀ i, i < l.length → l[i]! = 0#u8) : decValue l = 0 := by
  induction l with
  | nil => rfl
  | cons b tl ih =>
    rw [decValue_cons]
    have hb : b = 0#u8 := by
      have := h 0 (by simp); simpa using this
    have htl : decValue tl = 0 := by
      apply ih
      intro i hi
      have := h (i + 1) (by simpa using Nat.succ_lt_succ hi)
      simpa using this
    simp [htl, hb]

/-- Zero tail: the value is carried entirely by the prefix. -/
theorem decValue_take_of_zero_tail (l : List Std.U8) (n : Nat)
    (h : ∀ i, n ≤ i → i < l.length → l[i]! = 0#u8) :
    decValue l = decValue (l.take n) := by
  have hdz : decValue (l.drop n) = 0 := by
    apply decValue_zero_of_all_zero
    intro i hi
    rw [List.getElem!_drop]
    have hilen : i < l.length - n := by simpa using hi
    exact h (n + i) (by omega) (by omega)
  conv_lhs => rw [← List.take_append_drop n l]
  rw [decValue_append, hdz, Nat.mul_zero, Nat.add_zero]

/-- With a zero tail above `n` and real digits below, the value is < 10^n. -/
theorem decValue_lt_pow_of_zero_tail (l : List Std.U8) (n : Nat)
    (hn : n ≤ l.length)
    (hdig : ∀ i, i < l.length → (l[i]!).val ≤ 9)
    (hzero : ∀ i, n ≤ i → i < l.length → l[i]! = 0#u8) :
    decValue l < 10 ^ n := by
  rw [decValue_take_of_zero_tail l n hzero]
  have hlt : (l.take n).length = n := by
    rw [List.length_take]; omega
  have := decValue_lt (l.take n) (fun i hi => by
    rw [hlt] at hi
    rw [List.getElem!_take_of_lt _ _ _ hi]
    exact hdig i (by omega))
  rwa [hlt] at this

/-- Every stored digit contributes a lower bound: `l[i]·10^i ≤ decValue l`. -/
theorem le_decValue_of_getElem! (l : List Std.U8) (i : Nat)
    (hi : i < l.length) :
    (l[i]!).val * 10 ^ i ≤ decValue l := by
  have h1 : decValue l
      = decValue (l.take (i + 1)) + 10 ^ (i + 1) * decValue (l.drop (i + 1)) := by
    conv_lhs => rw [← List.take_append_drop (i + 1) l]
    rw [decValue_append, List.length_take, Nat.min_eq_left (by omega)]
  have h2 : decValue (l.take (i + 1))
      = decValue (l.take i) + (l[i]!).val * 10 ^ i := by
    rw [take_succ_getElem! l i hi, decValue_append_digit, List.length_take,
        Nat.min_eq_left (by omega)]
  omega

/-- Digit extraction: a buffer of ≤9-digits IS the base-10 digit string of
    its `decValue` — the stored byte at index `i` is the i-th digit. -/
theorem getElem!_eq_digit (l : List Std.U8)
    (h : ∀ i, i < l.length → (l[i]!).val ≤ 9) (i : Nat) (hi : i < l.length) :
    (l[i]!).val = (decValue l / 10 ^ i) % 10 := by
  induction l generalizing i with
  | nil => simp at hi
  | cons b tl ih =>
    cases i with
    | zero =>
      rw [List.getElem!_cons_zero, decValue_cons, pow_zero, Nat.div_one]
      have hb : b.val ≤ 9 := by
        have := h 0 (by simp); simpa using this
      omega
    | succ j =>
      rw [List.getElem!_cons_succ, decValue_cons]
      have hj : j < tl.length := by simpa using hi
      have htl : ∀ k, k < tl.length → (tl[k]!).val ≤ 9 := by
        intro k hk
        have := h (k + 1) (by simpa using Nat.succ_lt_succ hk)
        simpa using this
      rw [ih htl j hj]
      congr 1
      have hb : b.val ≤ 9 := by
        have := h 0 (by simp); simpa using this
      have h1 : (decValue tl * 10 + b.val) / 10 = decValue tl := by omega
      rw [pow_succ, Nat.mul_comm ((10:Nat) ^ j) 10, ← Nat.div_div_eq_div_mul,
          h1]

/-- One digit-shift of a floor division: `(X/10^(k+1))·10 + digit_k = X/10^k`. -/
theorem div_pow_succ_digit (X k : Nat) :
    (X / 10 ^ (k + 1)) * 10 + (X / 10 ^ k) % 10 = X / 10 ^ k := by
  rw [pow_succ, ← Nat.div_div_eq_div_mul]
  omega

/-! ### Spec-side parser: `parsedScaled` and the emitBytes re-parse -/

/-- Parsed value of a rendered decimal string, ignoring the dot: MS-first
    digit fold over the ASCII bytes ('.' bytes are skipped). Applied to a
    well-formed render, this is (displayed number)·10^(frac digit count). -/
def parsedScaled (s : List Std.U8) : Nat :=
  s.foldl (fun acc b => if b.val = 46 then acc else acc * 10 + (b.val - 48)) 0

/-- MS-first accumulator value of the digit prefix `f 0 … f (m-1)`. -/
def msVal (f : Nat → Nat) : Nat → Nat
  | 0 => 0
  | m + 1 => msVal f m * 10 + f m

/-- Folding the parser over an ASCII-digit block appends its `msVal` below
    the accumulator. -/
theorem foldl_digits (f : Nat → Nat) (m : Nat) (acc : Nat)
    (hf : ∀ j, j < m → f j ≤ 9) :
    ((List.range m).map (fun j => asciiByte (f j))).foldl
        (fun acc b => if b.val = 46 then acc else acc * 10 + (b.val - 48)) acc
      = acc * 10 ^ m + msVal f m := by
  induction m with
  | zero => simp [msVal]
  | succ k ih =>
    rw [List.range_succ, List.map_append, List.foldl_append,
        ih (fun j hj => hf j (by omega))]
    simp only [List.map_cons, List.map_nil, List.foldl_cons, List.foldl_nil]
    rw [if_neg (by rw [asciiByte_val]; omega),
        asciiByte_val_of_le (hf k (by omega))]
    simp only [msVal]
    have hc : 48 + f k - 48 = f k := by omega
    rw [hc, pow_succ]
    ring

/-- The stored fractional digit read agrees with the arithmetic fractional
    digit of the buffer value (structural zeros included). -/
theorem fracDigitVal_arith (l : List Std.U8) (n td pos : Nat)
    (hlen : l.length = 80) (hn : n ≤ 80)
    (hdig : ∀ i, i < 80 → (l[i]!).val ≤ 9)
    (hWlt : decValue l < 10 ^ n) :
    fracDigitVal l n td pos
      = if pos ≤ td then (decValue l / 10 ^ (td - pos)) % 10 else 0 := by
  unfold fracDigitVal
  by_cases hpt : pos ≤ td
  · rw [if_pos hpt]
    by_cases hin : td - pos < n
    · rw [if_pos ⟨hpt, hin⟩]
      exact getElem!_eq_digit l (fun i hi => hdig i (by omega)) (td - pos)
        (by omega)
    · rw [if_neg (by tauto)]
      have hz : decValue l / 10 ^ (td - pos) = 0 :=
        Nat.div_eq_of_lt (lt_of_lt_of_le hWlt
          (Nat.pow_le_pow_right (by norm_num) (by omega)))
      simp [hz]
  · rw [if_neg (by tauto), if_neg hpt]

/-- The drop-digit read agrees with the arithmetic digit of the value. -/
theorem dropDigitVal_arith (l : List Std.U8) (n rid : Nat)
    (hlen : l.length = 80) (hn : n ≤ 80)
    (hdig : ∀ i, i < 80 → (l[i]!).val ≤ 9)
    (hWlt : decValue l < 10 ^ n) :
    dropDigitVal l n rid = (decValue l / 10 ^ (rid - 1)) % 10 := by
  unfold dropDigitVal
  by_cases hin : rid - 1 < n
  · rw [if_pos hin]
    exact getElem!_eq_digit l (fun i hi => hdig i (by omega)) (rid - 1)
      (by omega)
  · rw [if_neg hin]
    have hz : decValue l / 10 ^ (rid - 1) = 0 :=
      Nat.div_eq_of_lt (lt_of_lt_of_le hWlt
        (Nat.pow_le_pow_right (by norm_num) (by omega)))
    simp [hz]

/-- Integer-part digit accumulator: the MS-first prefix of `l[td..n)`
    (read from the top) accumulates to the scaled-down integer value. -/
theorem msVal_int (l : List Std.U8) (n : Nat)
    (hlen : l.length = 80) (hn : n ≤ 80)
    (hdig : ∀ i, i < 80 → (l[i]!).val ≤ 9)
    (hWlt : decValue l < 10 ^ n) :
    ∀ m, m ≤ n →
      msVal (fun j => (l[n - 1 - j]!).val) m = decValue l / 10 ^ (n - m) := by
  intro m
  induction m with
  | zero =>
    intro _
    simp only [msVal, Nat.sub_zero]
    exact (Nat.div_eq_of_lt hWlt).symm
  | succ k ih =>
    intro hm
    simp only [msVal]
    rw [ih (by omega)]
    have hidx : (l[n - 1 - k]!).val = (decValue l / 10 ^ (n - 1 - k)) % 10 :=
      getElem!_eq_digit l (fun i hi => hdig i (by omega)) (n - 1 - k)
        (by omega)
    rw [hidx]
    have h1 : n - k = (n - 1 - k) + 1 := by omega
    have h2 : n - (k + 1) = n - 1 - k := by omega
    rw [h1, h2]
    exact div_pow_succ_digit (decValue l) (n - 1 - k)

/-- Combined int·10^fe + frac accumulator: the exact scaled parse value. -/
theorem scaled_G (l : List Std.U8) (n td : Nat)
    (hlen : l.length = 80) (hn : n ≤ 80)
    (hdig : ∀ i, i < 80 → (l[i]!).val ≤ 9)
    (hWlt : decValue l < 10 ^ n) :
    ∀ fe, (decValue l / 10 ^ td) * 10 ^ fe
            + msVal (fun p => fracDigitVal l n td (p + 1)) fe
      = if fe ≤ td then decValue l / 10 ^ (td - fe)
        else decValue l * 10 ^ (fe - td) := by
  intro fe
  induction fe with
  | zero =>
    simp only [msVal, pow_zero, Nat.mul_one, Nat.add_zero]
    rw [if_pos (Nat.zero_le td), Nat.sub_zero]
  | succ k ih =>
    simp only [msVal]
    have hstep : (decValue l / 10 ^ td) * 10 ^ (k + 1)
          + (msVal (fun p => fracDigitVal l n td (p + 1)) k * 10
             + fracDigitVal l n td (k + 1))
        = ((decValue l / 10 ^ td) * 10 ^ k
           + msVal (fun p => fracDigitVal l n td (p + 1)) k) * 10
          + fracDigitVal l n td (k + 1) := by
      rw [pow_succ]; ring
    rw [hstep, ih, fracDigitVal_arith l n td (k + 1) hlen hn hdig hWlt]
    by_cases hk1 : k + 1 ≤ td
    · have hk : k ≤ td := by omega
      simp only [if_pos hk1, if_pos hk]
      have h1 : td - k = (td - (k + 1)) + 1 := by omega
      rw [h1]
      exact div_pow_succ_digit (decValue l) (td - (k + 1))
    · simp only [if_neg hk1]
      by_cases hk : k ≤ td
      · have hktd : k = td := by omega
        subst hktd
        simp only [if_pos (Nat.le_refl k), Nat.sub_self, pow_zero,
                   Nat.div_one]
        have h1 : k + 1 - k = 1 := by omega
        rw [h1, pow_one]
        omega
      · simp only [if_neg hk]
        have h1 : k + 1 - td = (k - td) + 1 := by omega
        rw [h1, pow_succ]
        ring

/-- **Re-parse identity**: parsing the emitted byte string back (dot
    skipped) yields exactly the value scaled to the emitted precision. -/
theorem parsedScaled_emitBytes (l : List Std.U8) (n td fe : Nat)
    (hlen : l.length = 80) (hn : n ≤ 80)
    (hdig : ∀ i, i < 80 → (l[i]!).val ≤ 9)
    (hzero : ∀ i, n ≤ i → i < 80 → l[i]! = 0#u8) :
    parsedScaled (emitBytes l n td fe)
      = if fe ≤ td then decValue l / 10 ^ (td - fe)
        else decValue l * 10 ^ (fe - td) := by
  have hWlt : decValue l < 10 ^ n :=
    decValue_lt_pow_of_zero_tail l n (by omega)
      (fun i hi => hdig i (by omega)) (fun i h1 h2 => hzero i h1 (by omega))
  have hint : (intBytes l n td).foldl
      (fun acc b => if b.val = 46 then acc else acc * 10 + (b.val - 48)) 0
      = decValue l / 10 ^ td := by
    unfold intBytes
    split
    · rename_i hle
      simp only [List.foldl_cons, List.foldl_nil, asciiByte_val]
      rw [if_neg (by omega)]
      have hz : decValue l / 10 ^ td = 0 :=
        Nat.div_eq_of_lt (lt_of_lt_of_le hWlt
          (Nat.pow_le_pow_right (by norm_num) hle))
      omega
    · rename_i hgt
      rw [foldl_digits (fun j => (l[n - 1 - j]!).val) (n - td) 0
            (fun j hj => hdig (n - 1 - j) (by omega)),
          msVal_int l n hlen hn hdig hWlt (n - td) (by omega)]
      have h1 : n - (n - td) = td := by omega
      rw [h1]
      omega
  unfold emitBytes parsedScaled
  by_cases hfe0 : fe = 0
  · subst hfe0
    rw [if_pos rfl, List.append_nil, hint, if_pos (Nat.zero_le td),
        Nat.sub_zero]
  · rw [if_neg hfe0, List.foldl_append, hint, List.foldl_cons,
        if_pos (by simp)]
    unfold fracBytes
    rw [foldl_digits (fun p => fracDigitVal l n td (p + 1)) fe _
          (fun p hp => by
            simp only [fracDigitVal]
            split
            · rename_i hcond
              exact hdig (td - (p + 1)) (by omega)
            · omega)]
    exact scaled_G l n td hlen hn hdig hWlt fe

/-! ### Round-half-up arithmetic bridge -/

/-- Adding half an ulp and flooring IS "+1 iff the dropped digit ≥ 5" —
    the bridge between `fmt_round_half_up`'s carry and true rounding. -/
theorem round_half_up_div (V k : Nat) (hk : 1 ≤ k) :
    (V + 5 * 10 ^ (k - 1)) / 10 ^ k
      = V / 10 ^ k + (if 5 ≤ (V / 10 ^ (k - 1)) % 10 then 1 else 0) := by
  obtain ⟨k', rfl⟩ : ∃ k', k = k' + 1 := ⟨k - 1, by omega⟩
  rw [Nat.add_sub_cancel, pow_succ, ← Nat.div_div_eq_div_mul,
      ← Nat.div_div_eq_div_mul,
      Nat.add_mul_div_right V 5 (ten_pow_pos k')]
  have h10 : (V / 10 ^ k') % 10 < 10 := Nat.mod_lt _ (by norm_num)
  split <;> omega

/-! ### Scaled-value algebra (division shifts, trim preservation) -/

/-- Dividing the F-scaled value by 10^F recovers the integer part. -/
theorem scaled_div_pow (W td F : Nat) :
    (if F ≤ td then W / 10 ^ (td - F) else W * 10 ^ (F - td)) / 10 ^ F
      = W / 10 ^ td := by
  split
  · rename_i h
    rw [Nat.div_div_eq_div_mul, ← pow_add,
        show td - F + F = td from by omega]
  · rename_i h
    have hsplit : (10:Nat) ^ F = 10 ^ (F - td) * 10 ^ td := by
      rw [← pow_add, show F - td + td = F from by omega]
    rw [hsplit, ← Nat.div_div_eq_div_mul, Nat.mul_comm W ((10:Nat) ^ (F - td)),
        Nat.mul_div_cancel_left W (ten_pow_pos _)]

/-- All-zero low digits force divisibility:
    `(∀ j<m, digit_j Y = 0) → 10^m ∣ Y`. -/
theorem pow_dvd_of_digits_zero (Y m : Nat)
    (h : ∀ j, j < m → (Y / 10 ^ j) % 10 = 0) : 10 ^ m ∣ Y := by
  induction m with
  | zero => simp
  | succ k ih =>
    obtain ⟨q, rfl⟩ := ih (fun j hj => h j (by omega))
    have hd : (10 ^ k * q / 10 ^ k) % 10 = 0 := h k (by omega)
    rw [Nat.mul_div_cancel_left q (ten_pow_pos k)] at hd
    obtain ⟨r, rfl⟩ := Nat.dvd_of_mod_eq_zero hd
    exact ⟨r, by ring⟩

/-- Trimming structurally-zero fractional positions preserves the scaled
    value: `scaled(f)·10^(F-f) = scaled(F)` when positions (f, F] are 0. -/
theorem trim_value_preserving (W td F f : Nat)
    (hfF : f ≤ F)
    (hz : ∀ pos, f < pos → pos ≤ F →
       (if pos ≤ td then (W / 10 ^ (td - pos)) % 10 else 0) = 0) :
    (if f ≤ td then W / 10 ^ (td - f) else W * 10 ^ (f - td)) * 10 ^ (F - f)
      = if F ≤ td then W / 10 ^ (td - F) else W * 10 ^ (F - td) := by
  by_cases hFtd : F ≤ td
  · -- digits of X := W/10^(td-F) at [0, F-f) are zero
    rw [if_pos hFtd, if_pos (show f ≤ td by omega)]
    have hdvd : 10 ^ (F - f) ∣ W / 10 ^ (td - F) := by
      apply pow_dvd_of_digits_zero
      intro j hj
      have hdd : W / 10 ^ (td - F) / 10 ^ j = W / 10 ^ (td - (F - j)) := by
        rw [Nat.div_div_eq_div_mul, ← pow_add,
            show td - F + j = td - (F - j) from by omega]
      rw [hdd]
      have := hz (F - j) (by omega) (by omega)
      rwa [if_pos (by omega)] at this
    obtain ⟨q, hq⟩ := hdvd
    have hqval : q = W / 10 ^ (td - f) := by
      have hd1 : W / 10 ^ (td - F) / 10 ^ (F - f) = W / 10 ^ (td - f) := by
        rw [Nat.div_div_eq_div_mul, ← pow_add,
            show td - F + (F - f) = td - f from by omega]
      rw [← hd1, hq, Nat.mul_div_cancel_left q (ten_pow_pos _)]
    rw [hq, hqval]
    ring
  · by_cases hftd : f ≤ td
    · -- digits of W at [0, td-f) are zero
      rw [if_pos hftd, if_neg hFtd]
      have hdvd : 10 ^ (td - f) ∣ W := by
        apply pow_dvd_of_digits_zero
        intro j hj
        have := hz (td - j) (by omega) (by omega)
        rwa [if_pos (by omega),
             show td - (td - j) = j from by omega] at this
      obtain ⟨q, hq⟩ := hdvd
      have hdivq : W / 10 ^ (td - f) = q := by
        rw [hq, Nat.mul_div_cancel_left q (ten_pow_pos _)]
      rw [hdivq, hq,
          show F - f = (td - f) + (F - td) from by omega, pow_add]
      ring
    · rw [if_neg hftd, if_neg hFtd, Nat.mul_assoc, ← pow_add,
          show f - td + (F - f) = F - td from by omega]

/-- Fractional digit `pos` of the F-scaled value = fractional digit `pos`
    of the underlying value (structural zero past position td). -/
theorem scaled_frac_digit (W td F pos : Nat) (h1 : 1 ≤ pos) (hpF : pos ≤ F) :
    ((if F ≤ td then W / 10 ^ (td - F) else W * 10 ^ (F - td))
        / 10 ^ (F - pos)) % 10
      = if pos ≤ td then (W / 10 ^ (td - pos)) % 10 else 0 := by
  by_cases hFtd : F ≤ td
  · rw [if_pos hFtd, if_pos (by omega), Nat.div_div_eq_div_mul, ← pow_add,
        show td - F + (F - pos) = td - pos from by omega]
  · rw [if_neg hFtd]
    by_cases hpt : pos ≤ td
    · rw [if_pos hpt]
      have hsplit : (10:Nat) ^ (F - pos) = 10 ^ (F - td) * 10 ^ (td - pos) := by
        rw [← pow_add, show F - td + (td - pos) = F - pos from by omega]
      rw [hsplit, ← Nat.div_div_eq_div_mul,
          Nat.mul_comm W ((10:Nat) ^ (F - td)),
          Nat.mul_div_cancel_left W (ten_pow_pos _)]
    · rw [if_neg hpt]
      have hsplit : (10:Nat) ^ (F - td) = 10 ^ (pos - td) * 10 ^ (F - pos) := by
        rw [← pow_add, show pos - td + (F - pos) = F - td from by omega]
      rw [hsplit, ← Nat.mul_assoc,
          Nat.mul_comm (W * 10 ^ (pos - td)) ((10:Nat) ^ (F - pos)),
          Nat.mul_div_cancel_left _ (ten_pow_pos _)]
      have hdvd : (10:Nat) ∣ W * 10 ^ (pos - td) :=
        Dvd.dvd.mul_left (dvd_pow_self 10 (by omega : pos - td ≠ 0)) W
      obtain ⟨q, hq⟩ := hdvd
      rw [hq, Nat.mul_mod_right]

/-! ### Spec-side quantities: the rounded value, its width, the trim count -/

/-- Round-half-up rendering of `V/10^D` at `F` fractional digits, as the
    integer (displayed number)·10^F. Exact (no rounding) when F ≥ D. -/
def roundedScaled (V D F : Nat) : Nat :=
  if F < D then (V + 5 * 10 ^ (D - F - 1)) / 10 ^ (D - F)
  else V * 10 ^ (F - D)

/-- Emitted fractional-digit count: `F` when not trimming; when trimming,
    the largest position ≤ F whose fractional digit of `roundedScaled` is
    nonzero (0 when the displayed fraction is all zeros). -/
def specFracCount (V D F : Nat) (trim : Bool) : Nat :=
  if trim then
    Nat.findGreatest
      (fun pos => (roundedScaled V D F / 10 ^ (F - pos)) % 10 ≠ 0) F
  else F

theorem specFracCount_le (V D F : Nat) (trim : Bool) :
    specFracCount V D F trim ≤ F := by
  unfold specFracCount
  split
  · exact Nat.findGreatest_le F
  · exact Nat.le_refl F

/-- Decimal digit count (1 for 0). -/
def numDigits10 (x : Nat) : Nat := if x = 0 then 1 else Nat.log 10 x + 1

theorem numDigits10_eq (x m : Nat) (h1 : 10 ^ m ≤ x) (h2 : x < 10 ^ (m + 1)) :
    numDigits10 x = m + 1 := by
  have hx : x ≠ 0 := by
    have := ten_pow_pos m; omega
  rw [numDigits10, if_neg hx, Nat.log_eq_of_pow_le_of_lt_pow h1 h2]

/-- Exact byte width of the render: integer digits (+ dot + fraction). -/
def specWidth (V D F : Nat) (trim : Bool) : Nat :=
  numDigits10 (roundedScaled V D F / 10 ^ F)
    + (if specFracCount V D F trim = 0 then 0
       else 1 + specFracCount V D F trim)

/-- The emitted integer width IS the decimal digit count of the integer
    part, given the digit-count discipline of the post-round buffer. -/
theorem intEmitN_eq_numDigits (W n td : Nat)
    (hn1 : 1 ≤ n)
    (hup : W < 10 ^ n)
    (hge : W ≠ 0 → 10 ^ (n - 1) ≤ W)
    (h0 : W = 0 → n = 1) :
    intEmitN n td = numDigits10 (W / 10 ^ td) := by
  by_cases hWz : W = 0
  · subst hWz
    have hn : n = 1 := h0 rfl
    subst hn
    rw [Nat.zero_div, show numDigits10 0 = 1 from rfl]
    simp only [intEmitN]
    split <;> omega
  · by_cases htd : n ≤ td
    · have hz : W / 10 ^ td = 0 :=
        Nat.div_eq_of_lt (lt_of_lt_of_le hup
          (Nat.pow_le_pow_right (by norm_num) htd))
      rw [hz, show numDigits10 0 = 1 from rfl]
      simp only [intEmitN, if_pos htd]
    · have hge' := hge hWz
      have hlow : 10 ^ (n - 1 - td) ≤ W / 10 ^ td := by
        rw [Nat.le_div_iff_mul_le (ten_pow_pos td), ← pow_add,
            show n - 1 - td + td = n - 1 from by omega]
        exact hge'
      have hhigh : W / 10 ^ td < 10 ^ (n - td) := by
        rw [Nat.div_lt_iff_lt_mul (ten_pow_pos td), ← pow_add,
            show n - td + td = n from by omega]
        exact hup
      rw [numDigits10_eq (W / 10 ^ td) (n - 1 - td) hlow
            (by rwa [show n - 1 - td + 1 = n - td from by omega])]
      simp only [intEmitN, if_neg htd]
      omega

/-- A nonzero-value buffer whose value reaches 10^(n-1) has a nonzero top
    digit (used to close the carryPost `n' = n` disjunct). -/
theorem top_digit_nonzero (l : List Std.U8) (n : Nat)
    (hlen : l.length = 80) (hn1 : 1 ≤ n) (hn : n ≤ 80)
    (hdig : ∀ i, i < 80 → (l[i]!).val ≤ 9)
    (hzero : ∀ i, n ≤ i → i < 80 → l[i]! = 0#u8)
    (hge : 10 ^ (n - 1) ≤ decValue l) :
    (l[n - 1]!).val ≠ 0 := by
  intro h0
  have hz' : ∀ i, n - 1 ≤ i → i < l.length → l[i]! = 0#u8 := by
    intro i hi1 hi2
    rcases Nat.eq_or_lt_of_le hi1 with heq | hlt
    · rw [← heq]
      exact UScalar.eq_of_val_eq (by simpa using h0)
    · exact hzero i (by omega) (by omega)
  have := decValue_lt_pow_of_zero_tail l (n - 1) (by omega)
      (fun i hi => hdig i (by omega)) hz'
  omega

/-! ### The end-to-end contract -/

/-- Well-formed decimal render with `FE` fractional digits: nonempty, every
    byte an ASCII digit or '.', the dot exactly at distance FE+1 from the
    end (present iff FE ≠ 0), a digit first, and a leading '0' only in the
    "0" / "0.xxx" shapes. -/
def wellFormedRender (s : List Std.U8) (FE : Nat) : Prop :=
  1 ≤ s.length ∧
  (FE ≠ 0 → FE + 2 ≤ s.length) ∧
  (∀ i, i < s.length →
     (48 ≤ (s[i]!).val ∧ (s[i]!).val ≤ 57) ∨ (s[i]!).val = 46) ∧
  (∀ i, i < s.length →
     ((s[i]!).val = 46 ↔ FE ≠ 0 ∧ i + (FE + 1) = s.length)) ∧
  (48 ≤ (s[0]!).val ∧ (s[0]!).val ≤ 57) ∧
  ((s[0]!).val = 48 → s.length = 1 ∨ (s[1]!).val = 46)

/-- The end-to-end contract: None (out untouched) iff the render does not
    fit; otherwise exactly `specWidth` bytes are written and they render
    the round-half-up value, well-formed, at `specFracCount` fractional
    digits, minimally when trimming. -/
def FormatPost (V D F : Nat) (trim : Bool) (out : Slice Std.U8)
    (p : (Option Std.Usize) × Slice Std.U8) : Prop :=
  (out.length < specWidth V D F trim → p = (none, out)) ∧
  (specWidth V D F trim ≤ out.length →
     ∃ w : Std.Usize, p.1 = some w ∧ w.val = specWidth V D F trim ∧
       p.2.length = out.length ∧
       p.2.val.drop w.val = out.val.drop w.val ∧
       wellFormedRender (p.2.val.take w.val) (specFracCount V D F trim) ∧
       parsedScaled (p.2.val.take w.val) * 10 ^ (F - specFracCount V D F trim)
         = roundedScaled V D F ∧
       (trim = true → specFracCount V D F trim ≠ 0 →
          parsedScaled (p.2.val.take w.val) % 10 ≠ 0))

/-- The None-iff form of the width contract. -/
theorem FormatPost.none_iff {V D F : Nat} {trim : Bool} {out : Slice Std.U8}
    {p : (Option Std.Usize) × Slice Std.U8}
    (h : FormatPost V D F trim out p) :
    p.1 = none ↔ out.length < specWidth V D F trim := by
  constructor
  · intro hn
    by_contra hnlt
    have hle : specWidth V D F trim ≤ out.length := by omega
    obtain ⟨w, hw, -⟩ := h.2 hle
    rw [hn] at hw
    exact absurd hw (by simp)
  · intro hlt
    rw [h.1 hlt]

/-- `emitBytes` is a well-formed render (given the no-leading-zero facts
    for the ≥2-integer-digit shape). -/
theorem wellFormedRender_emitBytes (l : List Std.U8) (n td fe : Nat)
    (htop : 2 ≤ intEmitN n td →
       td < n ∧ (l[n - 1]!).val ≤ 9 ∧ (l[n - 1]!).val ≠ 0) :
    wellFormedRender (emitBytes l n td fe) fe := by
  have hlen := emitBytes_length l n td fe
  have hie := intEmitN_pos n td
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [hlen]; exact needN_pos n td fe
  · intro hfe
    rw [hlen]
    simp only [needN, if_neg hfe]
    omega
  · intro i hi
    exact emitBytes_ascii l n td fe i hi
  · intro i hi
    rw [emitBytes_dot_iff l n td fe i hi, hlen]
    constructor
    · rintro ⟨hfe, rfl⟩
      refine ⟨hfe, ?_⟩
      simp only [needN, if_neg hfe]
      omega
    · rintro ⟨hfe, hsum⟩
      refine ⟨hfe, ?_⟩
      simp only [needN, if_neg hfe] at hsum
      omega
  · exact emitBytes_head_digit l n td fe
  · intro h48
    by_cases h2 : 2 ≤ intEmitN n td
    · obtain ⟨hgt, h9, hnz⟩ := htop h2
      exact absurd h48 (emitBytes_no_leading_zero l n td fe hgt h9 hnz)
    · have h1 : intEmitN n td = 1 := by omega
      by_cases hfe : fe = 0
      · left
        rw [hlen]
        simp only [needN, if_pos hfe]
        omega
      · right
        have hi1 : (1:Nat) < (emitBytes l n td fe).length := by
          rw [hlen]; simp only [needN, if_neg hfe]; omega
        exact (emitBytes_dot_iff l n td fe 1 hi1).mpr ⟨hfe, by omega⟩

/-! ### Emit-stage composition -/

set_option maxHeartbeats 4000000 in
/-- Under the (discharged) post-round facts and the per-branch trim facts,
    `fmt_emit` realises the full `FormatPost` contract. -/
theorem emit_stage (ds : Std.Array Std.U8 80#usize) (n td fe : Std.Usize)
    (out : Slice Std.U8) (V F : Nat) (trim : Bool)
    (hn1 : 1 ≤ n.val) (hn80 : n.val ≤ 80)
    (hdig : ∀ i, i < 80 → (ds.val[i]!).val ≤ 9)
    (hzero : ∀ i, n.val ≤ i → i < 80 → ds.val[i]! = 0#u8)
    (hfe255 : fe.val ≤ 255)
    (htopne : decValue ds.val ≠ 0 → (ds.val[n.val - 1]!).val ≠ 0)
    (h0n : decValue ds.val = 0 → n.val = 1)
    (hR : (if F ≤ td.val then decValue ds.val / 10 ^ (td.val - F)
           else decValue ds.val * 10 ^ (F - td.val))
          = roundedScaled V td.val F)
    (hFE : fe.val = specFracCount V td.val F trim)
    (hpres : (if fe.val ≤ td.val then decValue ds.val / 10 ^ (td.val - fe.val)
              else decValue ds.val * 10 ^ (fe.val - td.val))
               * 10 ^ (F - fe.val)
             = roundedScaled V td.val F)
    (hmin : trim = true → fe.val ≠ 0 →
       fe.val ≤ td.val ∧
       (decValue ds.val / 10 ^ (td.val - fe.val)) % 10 ≠ 0) :
    eip1559.fmt_emit ds n td fe out
      ⦃ p => FormatPost V td.val F trim out p ⦄ := by
  apply Aeneas.Std.WP.spec_mono (emit_spec ds n td fe out hn80 hdig hfe255)
  intro p hp
  have hlds : ds.val.length = 80 := by simp
  have hWup : decValue ds.val < 10 ^ n.val :=
    decValue_lt_pow_of_zero_tail ds.val n.val (by omega)
      (fun i hi => hdig i (by omega))
      (fun i hi1 hi2 => hzero i hi1 (by omega))
  have hge2 : decValue ds.val ≠ 0 → 10 ^ (n.val - 1) ≤ decValue ds.val := by
    intro hW
    have h1 : 1 ≤ (ds.val[n.val - 1]!).val := by
      have := htopne hW; omega
    calc 10 ^ (n.val - 1) = 1 * 10 ^ (n.val - 1) := by ring
      _ ≤ (ds.val[n.val - 1]!).val * 10 ^ (n.val - 1) :=
          Nat.mul_le_mul_right _ h1
      _ ≤ decValue ds.val :=
          le_decValue_of_getElem! ds.val (n.val - 1) (by omega)
  have hIW : intEmitN n.val td.val
      = numDigits10 (roundedScaled V td.val F / 10 ^ F) := by
    rw [← hR, scaled_div_pow]
    exact intEmitN_eq_numDigits (decValue ds.val) n.val td.val hn1 hWup
      hge2 h0n
  have hNW : needN n.val td.val fe.val = specWidth V td.val F trim := by
    simp only [needN, specWidth, ← hFE, hIW]
  obtain ⟨hnone, hsome⟩ := hp
  constructor
  · intro hlt
    exact hnone (by rw [hNW]; exact hlt)
  · intro hle
    obtain ⟨w, hw1, hw2, hplen, htake, hdrop⟩ := hsome (by rw [hNW]; exact hle)
    have hwv : w.val = specWidth V td.val F trim := by rw [hw2, hNW]
    have hs : p.2.val.take w.val = emitBytes ds.val n.val td.val fe.val := by
      rw [hw2]; exact htake
    have hparse : parsedScaled (p.2.val.take w.val)
        = (if fe.val ≤ td.val then decValue ds.val / 10 ^ (td.val - fe.val)
           else decValue ds.val * 10 ^ (fe.val - td.val)) := by
      rw [hs]
      exact parsedScaled_emitBytes ds.val n.val td.val fe.val hlds hn80
        hdig hzero
    refine ⟨w, hw1, hwv, hplen, ?_, ?_, ?_, ?_⟩
    · rw [hw2]
      exact hdrop
    · -- well-formedness
      rw [hs, ← hFE]
      apply wellFormedRender_emitBytes
      intro h2
      have hgt : td.val < n.val := by
        by_contra hle'
        have hle'' : n.val ≤ td.val := by omega
        simp only [intEmitN, if_pos hle''] at h2
        omega
      have hWne : decValue ds.val ≠ 0 := by
        intro hW0
        have hn1' := h0n hW0
        simp only [intEmitN, if_neg (show ¬ n.val ≤ td.val from by omega)]
          at h2
        omega
      exact ⟨hgt, hdig (n.val - 1) (by omega), htopne hWne⟩
    · -- the WYSIWYS headline
      rw [hparse, ← hFE]
      exact hpres
    · -- minimality under trim
      intro htr hFE0
      obtain ⟨hfetd, hd⟩ := hmin htr (by rw [hFE]; exact hFE0)
      rw [hparse, if_pos hfetd]
      exact hd

/-! ### The top-level composition -/

/-- Step spec for the `lift`ed u32→usize cast (no upstream step lemma). -/
theorem cast_u32_usize_spec (x : Std.U32) :
    (lift (UScalar.cast .Usize x) : Result Std.Usize)
      ⦃ z => z.val = x.val ⦄ := by
  simp only [lift, WP.spec_ok]
  exact Std.U32.cast_Usize_val_eq x

set_option maxHeartbeats 8000000 in
/-- **END-TO-END WYSIWYS**: `U256::format_decimal` renders exactly the
    round-half-up value of `beValue v / 10^decimals` at `frac_digits`
    fractional digits (trimmed value-preservingly when requested), or
    returns `(none, out)` untouched exactly when it does not fit — see
    `FormatPost` and the file header. -/
theorem format_decimal_spec (v : eip1559.U256)
    (decimals frac_digits : Std.U32) (trim : Bool) (out : Slice Std.U8)
    (hF255 : frac_digits.val ≤ 255) :
    eip1559.U256.format_decimal v decimals frac_digits trim out
      ⦃ p => FormatPost (beValue v.val) decimals.val frac_digits.val trim
               out p ⦄ := by
  unfold eip1559.U256.format_decimal
  have hrep : ∀ i, i < 80 →
      (Array.repeat 80#usize 0#u8 : Std.Array Std.U8 80#usize).val[i]!
        = 0#u8 := by
    intro i hi
    rw [Array.repeat_val, getElem!_pos _ _ (by simpa using hi)]
    exact List.eq_of_mem_replicate (List.getElem_mem _)
  let* ⟨n, ds1, hval1, hn1, hn78, hdig1, hzn1, htop1, hframe1⟩ ←
    ExtractDigitsSpec.extract_digits_spec
  let* ⟨td, htd⟩ ← cast_u32_usize_spec
  let* ⟨frac, hfrac⟩ ← cast_u32_usize_spec
  have hzero1 : ∀ i, n.val ≤ i → i < 80 → ds1.val[i]! = 0#u8 := by
    intro i h1 h2
    rw [hframe1 i h1 h2]
    exact hrep i h2
  have hlds1 : ds1.val.length = 80 := by simp
  have hdig80 : ∀ i, i < 80 → (ds1.val[i]!).val ≤ 9 := by
    intro i hi
    rcases Nat.lt_or_ge i n.val with h | h
    · exact hdig1 i h
    · rw [hzero1 i h hi]; simp
  have hV : decValue ds1.val = beValue v.val := by
    rw [decValue_take_of_zero_tail ds1.val n.val
          (fun i h1 h2 => hzero1 i h1 (hlds1 ▸ h2))]
    exact hval1
  have hVlt : decValue ds1.val < 10 ^ n.val :=
    decValue_lt_pow_of_zero_tail ds1.val n.val (by omega)
      (fun i hi => hdig80 i (hlds1 ▸ hi))
      (fun i h1 h2 => hzero1 i h1 (hlds1 ▸ h2))
  let* ⟨n2, ds2, hcarry, hid⟩ ← round_carry_spec ds1 n td frac hn1 hn78
    hdig1 hzero1
  -- unified post-round facts (round/no-round dichotomy resolved here)
  have hfacts :
      (∀ i, i < 80 → (ds2.val[i]!).val ≤ 9) ∧
      (∀ i, n2.val ≤ i → i < 80 → ds2.val[i]! = 0#u8) ∧
      1 ≤ n2.val ∧ n2.val ≤ 79 ∧
      (decValue ds2.val = 0 → n2.val = 1) ∧
      (decValue ds2.val ≠ 0 → (ds2.val[n2.val - 1]!).val ≠ 0) ∧
      ((if frac.val ≤ td.val
        then decValue ds2.val / 10 ^ (td.val - frac.val)
        else decValue ds2.val * 10 ^ (frac.val - td.val))
       = roundedScaled (beValue v.val) td.val frac.val) := by
    by_cases hcond : frac.val < td.val ∧
        5 ≤ dropDigitVal ds1.val n.val (td.val - frac.val)
    · -- rounding fired: carryPost
      obtain ⟨hW2, hpre2, hdig2, hn2lo, hn2hi, hzero2, hdisj⟩ :=
        hcarry hcond
      have hVne : beValue v.val ≠ 0 := by
        intro hV0
        have hn1' := hzn1 hV0
        have h00 := le_decValue_of_getElem! ds1.val 0 (by omega)
        rw [pow_zero, Nat.mul_one, hV, hV0] at h00
        have hdd0 : dropDigitVal ds1.val n.val (td.val - frac.val) = 0 := by
          unfold dropDigitVal
          split
          · rename_i hlt
            have hi0 : td.val - frac.val - 1 = 0 := by omega
            rw [hi0]
            omega
          · rfl
        omega
      have hge1 : 10 ^ (n.val - 1) ≤ beValue v.val := by
        have h1 : 1 ≤ (ds1.val[n.val - 1]!).val := by
          have := htop1 hVne; omega
        calc 10 ^ (n.val - 1) = 1 * 10 ^ (n.val - 1) := by ring
          _ ≤ (ds1.val[n.val - 1]!).val * 10 ^ (n.val - 1) :=
              Nat.mul_le_mul_right _ h1
          _ ≤ decValue ds1.val :=
              le_decValue_of_getElem! ds1.val (n.val - 1) (by omega)
          _ = beValue v.val := hV
      have hW : decValue ds2.val
          = beValue v.val + 10 ^ (td.val - frac.val) := by
        rw [hW2, hV]
      refine ⟨hdig2, hzero2, by omega, by omega, ?_, ?_, ?_⟩
      · intro h0
        rw [hW] at h0
        have := ten_pow_pos (td.val - frac.val)
        omega
      · intro hWne
        rcases hdisj with hnn | hne
        · apply top_digit_nonzero ds2.val n2.val (by simp) (by omega)
            (by omega) hdig2 hzero2
          rw [hW, hnn]
          -- 10^(n-1) ≤ V ≤ V + 10^(td-frac): omega mis-atomizes the two
          -- pow terms here; close by explicit transitivity instead.
          exact Nat.le_trans hge1 (Nat.le_add_right _ _)
        · exact hne
      · rw [if_pos (show frac.val ≤ td.val from by omega), hW,
            Nat.add_div_right _ (ten_pow_pos _)]
        simp only [roundedScaled, if_pos hcond.1]
        rw [round_half_up_div (beValue v.val) (td.val - frac.val)
              (by omega)]
        have hdd : dropDigitVal ds1.val n.val (td.val - frac.val)
            = (beValue v.val / 10 ^ (td.val - frac.val - 1)) % 10 := by
          rw [← hV]
          exact dropDigitVal_arith ds1.val n.val (td.val - frac.val) hlds1
            (by omega) hdig80 hVlt
        rw [if_pos (by rw [← hdd]; exact hcond.2)]
    · -- no rounding: bit-for-bit identity
      obtain ⟨hn2eq, hds2eq⟩ := hid hcond
      have hn2n : n2.val = n.val := by rw [hn2eq]
      have hWV : decValue ds2.val = beValue v.val := by
        rw [hds2eq, hV]
      refine ⟨?_, ?_, by omega, by omega, ?_, ?_, ?_⟩
      · intro i hi
        rw [hds2eq]
        exact hdig80 i hi
      · intro i h1 h2
        rw [hds2eq]
        exact hzero1 i (by omega) h2
      · intro h0
        rw [hWV] at h0
        rw [hn2n]
        exact hzn1 h0
      · intro hWne
        rw [hWV] at hWne
        rw [hds2eq, hn2n]
        exact htop1 hWne
      · rw [hWV]
        by_cases hFD : frac.val < td.val
        · have hdlt : dropDigitVal ds1.val n.val (td.val - frac.val) < 5 := by
            by_contra h5
            exact hcond ⟨hFD, by omega⟩
          have hdd : dropDigitVal ds1.val n.val (td.val - frac.val)
              = (beValue v.val / 10 ^ (td.val - frac.val - 1)) % 10 := by
            rw [← hV]
            exact dropDigitVal_arith ds1.val n.val (td.val - frac.val)
              hlds1 (by omega) hdig80 hVlt
          rw [if_pos (show frac.val ≤ td.val from by omega)]
          simp only [roundedScaled, if_pos hFD]
          rw [round_half_up_div (beValue v.val) (td.val - frac.val)
                (by omega),
              if_neg (by rw [← hdd]; omega)]
          omega
        · have hFD' : td.val ≤ frac.val := by omega
          simp only [roundedScaled, if_neg hFD]
          rcases Nat.eq_or_lt_of_le hFD' with heq | hlt
          · rw [if_pos (by omega), ← heq, Nat.sub_self, pow_zero,
                Nat.div_one, Nat.mul_one]
          · rw [if_neg (by omega)]
  obtain ⟨hdig2, hzero2, hn21, hn279, h0n2, htopne2, hR⟩ := hfacts
  have hlds2 : ds2.val.length = 80 := by simp
  have hW2lt : decValue ds2.val < 10 ^ n2.val :=
    decValue_lt_pow_of_zero_tail ds2.val n2.val (by omega)
      (fun i hi => hdig2 i (hlds2 ▸ hi))
      (fun i h1 h2 => hzero2 i h1 (hlds2 ▸ h2))
  have hfrac255 : frac.val ≤ 255 := by omega
  -- normalize the postcondition to the cast values
  simp only [← htd, ← hfrac]
  split
  · -- trim_trailing_zeros = true: value-preserving minimal trim
    rename_i htr
    simp only [htr]
    let* ⟨fe, hfe1, hfe2, hfe3⟩ ← trim_frac_spec ds2 n2 td frac (by omega)
    have hfd : ∀ pos,
        fracDigitVal ds2.val n2.val td.val pos
          = if pos ≤ td.val
            then (decValue ds2.val / 10 ^ (td.val - pos)) % 10 else 0 :=
      fun pos => fracDigitVal_arith ds2.val n2.val td.val pos hlds2
        (by omega) hdig2 hW2lt
    have hRd : ∀ pos, 1 ≤ pos → pos ≤ frac.val →
        (roundedScaled (beValue v.val) td.val frac.val
            / 10 ^ (frac.val - pos)) % 10
          = if pos ≤ td.val
            then (decValue ds2.val / 10 ^ (td.val - pos)) % 10 else 0 := by
      intro pos h1 h2
      rw [← hR]
      exact scaled_frac_digit (decValue ds2.val) td.val frac.val pos h1 h2
    have hFE : fe.val
        = specFracCount (beValue v.val) td.val frac.val true := by
      simp only [specFracCount, if_true]
      symm
      rw [Nat.findGreatest_eq_iff]
      refine ⟨hfe1, ?_, ?_⟩
      · intro hfe0
        rw [hRd fe.val (by omega) hfe1]
        have h2 := hfe2 hfe0
        rwa [hfd fe.val] at h2
      · intro m hm1 hm2
        simp only [ne_eq, not_not]
        rw [hRd m (by omega) hm2]
        have h3 := hfe3 m hm1 hm2
        rwa [hfd m] at h3
    have hpres : (if fe.val ≤ td.val
          then decValue ds2.val / 10 ^ (td.val - fe.val)
          else decValue ds2.val * 10 ^ (fe.val - td.val))
            * 10 ^ (frac.val - fe.val)
        = roundedScaled (beValue v.val) td.val frac.val := by
      rw [← hR]
      apply trim_value_preserving (decValue ds2.val) td.val frac.val
        fe.val hfe1
      intro pos hp1 hp2
      have h3 := hfe3 pos hp1 hp2
      rwa [hfd pos] at h3
    have hmin : true = true → fe.val ≠ 0 →
        fe.val ≤ td.val ∧
        (decValue ds2.val / 10 ^ (td.val - fe.val)) % 10 ≠ 0 := by
      intro _ hfe0
      have h2 := hfe2 hfe0
      rw [hfd fe.val] at h2
      by_cases hle : fe.val ≤ td.val
      · rw [if_pos hle] at h2
        exact ⟨hle, h2⟩
      · rw [if_neg hle] at h2
        exact absurd rfl h2
    exact emit_stage ds2 n2 td fe out (beValue v.val) frac.val true
      hn21 (by omega) hdig2 hzero2 (by omega) htopne2 h0n2 hR hFE hpres hmin
  · -- trim_trailing_zeros = false: exact F fractional digits
    rename_i htr
    have htrf : trim = false := by
      simp only [Bool.not_eq_true] at htr
      exact htr
    simp only [htrf]
    have hFE : frac.val
        = specFracCount (beValue v.val) td.val frac.val false := rfl
    have hpres : (if frac.val ≤ td.val
          then decValue ds2.val / 10 ^ (td.val - frac.val)
          else decValue ds2.val * 10 ^ (frac.val - td.val))
            * 10 ^ (frac.val - frac.val)
        = roundedScaled (beValue v.val) td.val frac.val := by
      rw [Nat.sub_self, pow_zero, Nat.mul_one]
      exact hR
    have hmin : false = true → frac.val ≠ 0 →
        frac.val ≤ td.val ∧
        (decValue ds2.val / 10 ^ (td.val - frac.val)) % 10 ≠ 0 :=
      fun h => absurd h (by simp)
    exact emit_stage ds2 n2 td frac out (beValue v.val) frac.val false
      hn21 (by omega) hdig2 hzero2 hfrac255 htopne2 h0n2 hR hFE hpres hmin

/-- Public wrapper over the extraction's free-function alias
    `u256_format_decimal` (definitionally the method call). -/
theorem u256_format_decimal_spec (v : eip1559.U256)
    (decimals frac_digits : Std.U32) (trim : Bool) (out : Slice Std.U8)
    (hF255 : frac_digits.val ≤ 255) :
    eip1559.u256_format_decimal v decimals frac_digits trim out
      ⦃ p => FormatPost (beValue v.val) decimals.val frac_digits.val trim
               out p ⦄ := by
  unfold eip1559.u256_format_decimal
  exact format_decimal_spec v decimals frac_digits trim out hF255

end FormatDecimalSpec
