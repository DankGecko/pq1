-- [pqsigner_tx] external declarations for the trust-bundle merkle extraction.
--
-- §33 axiom-collapse: the two domain-separated SHA-256 constructors are DEFs
-- over the vendored FIPS 180-4 `sha256_pure` (`Extracted/HashPure.lean`):
--   leaf_hash_pure c   = sha256(0x00 ‖ canonical)
--   node_hash_pure l r = sha256(0x01 ‖ l ‖ r)
-- The `erc20.merkle.{leaf,node}_hash` wrappers below stay HANDWRITTEN (the
-- rank-11 extraction keeps them opaque): `leaf_hash`'s variable-length
-- `canonical` is not stack-bufferable in no_std, so the one-shot-boundary
-- extraction pattern doesn't apply; preimage fidelity rests on manual review
-- of the 6-line Rust bodies (tx/src/erc20/merkle.rs:72-92) + the dbgen
-- bundle KATs.
import Aeneas
import Extracted.TxMerkle.Types
import Extracted.HashPure
open Aeneas Aeneas.Std Result

open pqsigner_tx

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
