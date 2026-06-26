/- Axiom-discipline check (extends the SphincsCVerify no-sorry/axiom-lint
   culture to the extracted-code project; CI wiring tracked in §33 P1).

   Both P0 theorems close over EXACTLY the Lean kernel built-ins
   [propext, Classical.choice, Quot.sound] — verified 2026-06-10.
   In particular NO `sorryAx`: the sorries inside the Aeneas support
   library (Aeneas/Std/Slice.lean etc.) are not on our proof paths. -/
import Extracted.AdrsEquiv
import Extracted.Bits
import Extracted.ForsExtract
import Extracted.Eip1271Equiv
import Extracted.WotsDigits
import Extracted.FwManifestSpec
import Extracted.Bip39RoundtripSpec
import Extracted.RlpIntSpec
import Extracted.U256MulSpec
import Extracted.MerkleVerifySpec
import Extracted.TxMerkleSpec
import Extracted.DecodeItemSpec
import Extracted.PkFromSigSpec
import Extracted.Sha256Pure
import Extracted.HashSpecs
import Extracted.UserOpEquiv
import Extracted.UserOpEquivByteLayout
import Extracted.SpecBridge
import Extracted.ForsLoop
import Extracted.PinState.PinStateSpec

#print axioms Extracted.Equiv.deserialize_pin_state_rejects_bad_len
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
#print axioms Extracted.Equiv.extract_ht_index_spec
#print axioms Extracted.Equiv.extract_fors_indices_spec
#print axioms Extracted.Equiv.domain_separator_spec
#print axioms Extracted.Equiv.replay_safe_hash_spec
#print axioms Extracted.Equiv.extract_digits_spec
#print axioms Extracted.Equiv.extract_digits_lt
#print axioms Extracted.Equiv.signed_preimage_spec
#print axioms Extracted.Equiv.roundtrip_11_id
#print axioms Extracted.Equiv.beValue_lt
#print axioms Extracted.Equiv.bytes_to_u64_spec
#print axioms Extracted.Equiv.bytes_to_u256_spec
#print axioms Extracted.Equiv.saturating_mul_u64_spec
#print axioms Extracted.Equiv.verify_auth_path_spec
#print axioms Extracted.Equiv.verify_proof_spec
#print axioms Extracted.Equiv.decode_length_be_spec
#print axioms Extracted.Equiv.decode_item_spec
#print axioms Extracted.Equiv.pk_from_sig_spec
#print axioms sha256_pure
#print axioms sphincs_c10.hash.truncate_spec
#print axioms sphincs_c10.hash.th_spec
#print axioms sphincs_c10.hash.th_pair_spec
#print axioms sphincs_c10.hash.wots_digest_spec
#print axioms sphincs_c10.hash.th_multi_spec
#print axioms sphincs_c10.hash.chain_hash_spec
