/- §33 P3 (KICKOFF) — FORS index-extraction equivalence (WIP).

   NOT in the default target / AxiomCheck (carries a sorry). The FORS
   index functions extract with ZERO external axioms (pure bit-
   manipulation over the digest — no hashing): `Extracted/Fors/Funs.lean`
   has `read_bits_le`, `extract_fors_indices`, `extract_ht_index`.

   `extract_ht_index` is security-critical: it is the `ht_idx` source of
   the CWE-347 FORS-position binding (mirrors the Yul
   `and(shr(143, digest), 0x3FFFF)` in SPHINCsC10Asm.sol).

   STATUS: `step*` discharges every panic obligation EXCEPT the
   `read_bits_le` loop. Unlike the loop-free ADRS/userOpHash proofs,
   this needs real loop reasoning — the documented "loop invariants are
   the human-reviewed residue" P3 work. Path (next session / AI-loop):

     1. Prove a step-spec for `fors.read_bits_le_loop` via
        `Aeneas.Std.loop.spec_decr_nat` with
          measure := fun (iter, _) => iter.end - iter.start
          inv    := fun _ => True            -- panic-freedom only
        The body obligation needs an `IteratorRange.next` decreasing
        lemma (Aeneas ships the `next` DEF but no step-spec — build one:
        `next` either yields & shrinks the range by 1, or returns none;
        `StepUsize.forward_checked _ 1 = ok (checked_add start 1)` never
        returns none for `start < end ≤ Usize.max`, so the `fail .panic`
        arm is dead).

        ⚠️ KEY FINDING (2026-06-10, verified by inspecting the body):
        `inv := True` is INSUFFICIENT even for panic-freedom. The loop
        body computes `b * 8` (then `digest[idx] <<< (b*8)`), where `b`
        is the yielded range element. With `inv = True` there is no
        bound on `b`, so the `b * 8` Usize-multiplication overflow check
        does NOT close. The invariant must bound the iteration variable,
        e.g. `inv := fun (iter, _) => iter.end.val ≤ 8` (bytes_needed ≤ 8
        for the C10 params), which gives `b < 8` and `b * 8 < 64`. So
        even panic-freedom here is a genuine (small) invariant, not a
        `True`-invariant rubber-stamp — the first real loop reasoning.
     2. With the loop spec, `extract_ht_index ⦃ _ => True ⦄` and
        `extract_fors_indices ⦃ _ => True ⦄` close (panic-freedom).
     3. FUNCTIONAL spec (extract_ht_index = (digest_le >> 143) & 0x3FFFF)
        then needs the loop INVARIANT relating `val` to the partial
        bit-read — the genuinely mathy part. The SetSliceLemmas method
        does not apply (bit-level, not byte-layout); expect a
        `read_bits_le`-accumulator invariant proof.
     4. Bridge: vendor `Spec/Fors.lean`'s htIdx extraction +
        `firmware_extract_ht_index_matches_vendored` (the SpecBridge
        pattern), closing the CWE-347 binding at the firmware level. -/
import Extracted.Fors.Funs

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open sphincs_c10

/-- Panic-freedom of `extract_ht_index` — BLOCKED on the
    `read_bits_le_loop` step-spec (see file header). -/
theorem extract_ht_index_terminates (digest : Array U8 32#usize) :
    fors.extract_ht_index digest ⦃ _ => True ⦄ := by
  sorry

end Extracted.Equiv
