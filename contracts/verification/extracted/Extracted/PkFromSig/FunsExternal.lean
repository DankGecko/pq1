-- [sphincs_c10] external declarations for the pk_from_sig extraction.
-- THREE tweakable-hash boundaries, each in the keccak256_pure pattern
-- (uninterpreted pure axiom + total def wrapper + @[step] spec):
--   wots_digest_pure — the count-tweaked message digest (SHA-256 inside)
--   chain_hash_pure  — advance a WOTS chain `steps` times from `start`
--   th_multi_pure    — compress the L=43 chain ends into the leaf
-- Discharge artifact: the full sign/verify round-trip KATs
-- (contracts/smart-wallet/test/c10_test_vectors.json).
import Aeneas
import Extracted.PkFromSig.Types
open Aeneas Aeneas.Std Result

open sphincs_c10

axiom wots_digest_pure :
  Array Std.U8 32#usize → Array Std.U8 32#usize → Array Std.U8 32#usize →
    Std.U32 → Array Std.U8 32#usize

axiom chain_hash_pure :
  Array Std.U8 32#usize → Array Std.U8 32#usize → Array Std.U8 16#usize →
    Std.U32 → Std.U32 → Array Std.U8 16#usize

axiom th_multi_pure :
  Array Std.U8 32#usize → Array Std.U8 32#usize → Slice (Array Std.U8 16#usize) →
    Array Std.U8 16#usize

@[rust_fun "sphincs_c10::hash::wots_digest"]
noncomputable def hash.wots_digest
    (seed adrs padded : Array Std.U8 32#usize) (count : Std.U32) :
    Result (Array Std.U8 32#usize) :=
  ok (wots_digest_pure seed adrs padded count)

@[rust_fun "sphincs_c10::hash::chain_hash"]
noncomputable def hash.chain_hash
    (seed adrs : Array Std.U8 32#usize) (x : Array Std.U8 16#usize)
    (start steps : Std.U32) : Result (Array Std.U8 16#usize) :=
  ok (chain_hash_pure seed adrs x start steps)

@[rust_fun "sphincs_c10::hash::th_multi"]
noncomputable def hash.th_multi
    (seed adrs : Array Std.U8 32#usize) (elems : Slice (Array Std.U8 16#usize)) :
    Result (Array Std.U8 16#usize) :=
  ok (th_multi_pure seed adrs elems)

@[step] theorem hash.wots_digest_spec (seed adrs padded : Array Std.U8 32#usize) (count : Std.U32) :
    hash.wots_digest seed adrs padded count ⦃ r => r = wots_digest_pure seed adrs padded count ⦄ := by
  simp [hash.wots_digest, WP.spec_ok]

@[step] theorem hash.chain_hash_spec (seed adrs : Array Std.U8 32#usize)
    (x : Array Std.U8 16#usize) (start steps : Std.U32) :
    hash.chain_hash seed adrs x start steps ⦃ r => r = chain_hash_pure seed adrs x start steps ⦄ := by
  simp [hash.chain_hash, WP.spec_ok]

@[step] theorem hash.th_multi_spec (seed adrs : Array Std.U8 32#usize)
    (elems : Slice (Array Std.U8 16#usize)) :
    hash.th_multi seed adrs elems ⦃ r => r = th_multi_pure seed adrs elems ⦄ := by
  simp [hash.th_multi, WP.spec_ok]
