-- [pqsigner_tx] external declarations for the trust-bundle merkle extraction.
-- The two domain-separated SHA-256 constructors, keccak256_pure pattern:
--   leaf_hash_pure c        = sha256(0x00 || canonical)
--   node_hash_pure l r      = sha256(0x01 || l || r)
-- Discharge artifact: the dbgen-generated bundle KATs + tx/src/erc20 tests.
import Aeneas
import Extracted.TxMerkle.Types
open Aeneas Aeneas.Std Result

open pqsigner_tx

axiom leaf_hash_pure : Slice Std.U8 → Array Std.U8 32#usize

axiom node_hash_pure :
  Array Std.U8 32#usize → Array Std.U8 32#usize → Array Std.U8 32#usize

@[rust_fun "pqsigner_tx::erc20::merkle::leaf_hash"]
noncomputable def erc20.merkle.leaf_hash (canonical : Slice Std.U8) :
    Result (Array Std.U8 32#usize) :=
  ok (leaf_hash_pure canonical)

@[rust_fun "pqsigner_tx::erc20::merkle::node_hash"]
noncomputable def erc20.merkle.node_hash (l r : Array Std.U8 32#usize) :
    Result (Array Std.U8 32#usize) :=
  ok (node_hash_pure l r)

@[step] theorem erc20.merkle.leaf_hash_spec (canonical : Slice Std.U8) :
    erc20.merkle.leaf_hash canonical ⦃ r => r = leaf_hash_pure canonical ⦄ := by
  simp [erc20.merkle.leaf_hash, WP.spec_ok]

@[step] theorem erc20.merkle.node_hash_spec (l r : Array Std.U8 32#usize) :
    erc20.merkle.node_hash l r ⦃ x => x = node_hash_pure l r ⦄ := by
  simp [erc20.merkle.node_hash, WP.spec_ok]
