/- §33 P2 — userOpHash theorems.

   `compute_user_op_hash` is a tooling/companion reconstruction of the
   EntryPoint v0.6 `userOpHash` (double-keccak). It is not the signed
   digest (that is compute_sphincs_digest_v06, SHA-256); it has no
   non-test signing caller. This file proves it TOTAL (never
   panics / diverges) for all inputs, and gives the step-specs for its
   two write helpers. keccak-256 is the single uninterpreted axiom
   (`keccak256_pure`, the FunsExternal model — mirrors AXIOM_STATUS
   A1). The full byte-layout equivalence (buffer = the abi.encode
   preimage) is in `UserOpEquivByteLayout.lean` (WIP — `step*` does the
   whole symbolic execution; only the 320-byte setSlice!-tower ↔
   concatenation list-arithmetic tail remains, the kind of obligation
   the §33 P1 AI-prover loop is meant to grind).

   v4.22→v4.30 import bridge to the wallet model is P1. -/
import Extracted.UserOp.Funs

set_option linter.unusedSimpArgs false

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_aa

/-! ## Step specs for the two write helpers -/

set_option maxHeartbeats 1000000 in
@[step]
theorem write_u64_in_word_be.step_spec (word : Slice U8) (v : U64)
    (h : word.val.length = 32) :
    userop.write_u64_in_word_be word v
      ⦃ out => out.val =
          word.val.setSlice! (32 - 8) ((v.bv.toBEBytes).map (@UScalar.mk .U8)) ⦄ := by
  unfold userop.write_u64_in_word_be
  step* <;> simp_all [userop.WORD] <;> scalar_tac

set_option maxHeartbeats 1000000 in
@[step]
theorem write_word_right_aligned.step_spec
    (buf : Array U8 320#usize) (i : Usize) (row : Slice U8)
    (h1 : row.val.length ≤ 32) (h2 : (i.val + 1) * 32 ≤ 320) :
    userop.write_word_right_aligned buf i row
      ⦃ out => out.val =
          buf.val.setSlice! ((i.val + 1) * 32 - row.val.length) row.val ⦄ := by
  unfold userop.write_word_right_aligned
  step* <;> simp_all [userop.WORD] <;> scalar_tac

/-! ## Panic-freedom (total correctness, no spec content)

The firmware never panics or diverges computing the userOpHash, for
ALL inputs — machine-checked DoS-hardening (work-todo §33 goal
theorem 3). `step*` discharges every bounds/arithmetic obligation. -/

set_option maxHeartbeats 2000000 in
set_option maxRecDepth 4096 in
theorem compute_user_op_hash_terminates
    (p : userop.AaUserOpParams) (cdh : Array U8 32#usize) :
    userop.compute_user_op_hash p cdh ⦃ _ => True ⦄ := by
  unfold userop.compute_user_op_hash
  step* <;>
    first
    | scalar_tac
    | (simp only [userop.WORD, Slice.length, Array.length_to_slice] at *; scalar_tac)
    | simp only [userop.WORD]

end Extracted.Equiv
