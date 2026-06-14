/- §33 axiom-collapse — `hash.truncate` spec: the extracted body (fresh
   16-zero array, copy `digest[0..16)` over the whole of it) returns exactly
   `truncate16 digest`. Composed by every tweakable-hash spec in this
   directory. -/
import Extracted.Hash.Funs
import Extracted.HashPure
import Extracted.SetSliceLemmas

set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

open Aeneas Aeneas.Std Result
open Extracted.SetSlice

namespace sphincs_c10

@[step] theorem hash.truncate_spec (digest : Std.Array Std.U8 32#usize) :
    hash.truncate digest ⦃ r => r = truncate16 digest ⦄ := by
  unfold hash.truncate
  step* <;>
    first
    | scalar_tac
    | (simp only [params.N, Slice.length, Array.length_to_slice]; scalar_tac)
    | (simp_all [Slice.length, params.N])
    | skip
  apply Subtype.ext
  rw [truncate16_val]
  simp_all [Array.from_slice, List.slice, params.N]

end sphincs_c10
