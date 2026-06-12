/- Axiom-discipline check (extends the SphincsCVerify no-sorry/axiom-lint
   culture to the extracted-code project; CI wiring tracked in §33 P1).

   Both P0 theorems close over EXACTLY the Lean kernel built-ins
   [propext, Classical.choice, Quot.sound] — verified 2026-06-10.
   In particular NO `sorryAx`: the sorries inside the Aeneas support
   library (Aeneas/Std/Slice.lean etc.) are not on our proof paths. -/
import Extracted.AdrsEquiv
import Extracted.Bits
import Extracted.ForsExtract
import Extracted.UserOpEquiv
import Extracted.UserOpEquivByteLayout
import Extracted.SpecBridge
import Extracted.ForsLoop

#print axioms Extracted.Equiv.make_adrs_spec
#print axioms Extracted.Equiv.set_chain_index_spec
#print axioms Extracted.Equiv.compute_user_op_hash_terminates
#print axioms Extracted.Equiv.compute_user_op_hash_spec
#print axioms Extracted.Equiv.firmware_make_adrs_matches_vendored
#print axioms Extracted.Equiv.next_usize_spec
#print axioms Extracted.Equiv.read_bits_le_loop_terminates
#print axioms Extracted.Equiv.extract_ht_index_terminates
#print axioms Extracted.Equiv.extract_fors_indices_terminates
#print axioms Extracted.Equiv.extract_ht_index_in_range
#print axioms Extracted.Equiv.extract_fors_indices_in_range
#print axioms Extracted.Equiv.lor_eq_add_disjoint
#print axioms Extracted.Equiv.read_bits_le_spec
