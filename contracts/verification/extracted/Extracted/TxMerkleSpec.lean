/- §33 rank 11 — tx::erc20::merkle::verify_proof: FUNCTIONAL spec (statement
   only). This ONE function underpins all four trust-bundle verifiers
   (erc20 / names / selectors / erc7730).

   Pinned content: (1) the exact-length gate `proof_bytes.len = depth * 32` —
   if the gate and the walk ever disagreed, a proof with trailing or missing
   siblings could be accepted; (2) the index walk (sibling order by idx&1,
   idx>>=1) — rank 6's walk restated for the sha256 domain-separated scheme;
   (3) acceptance ⟺ the fold collapses exactly to the expected root.

   Proof plan: rank-6 method. loop.spec_decr_nat, invariant
   (h_k, idx_k) = (merkleFold (chunks.take k) leafHash idx, idx >>> k);
   the try_from Ok branch is total under the length gate (slice index
   [l*32, l*32+32) in bounds, chunk pad empty); PartialEqArray.eq at the
   `none` exit gives the root comparison; the iff's ← direction needs the
   gate to force the Err branch unreachable. -/
import Extracted.TxMerkle.Funs

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_tx

/-- The 32-byte sibling at chunk `l` of the proof blob (zero-padded if short —
    the length gate makes the pad empty in every reachable case). -/
def chunk32 (bytes : List Std.U8) (l : Nat) : Std.Array Std.U8 32#usize :=
  ⟨((bytes.drop (l * 32)).take 32)
      ++ List.replicate (32 - ((bytes.drop (l * 32)).take 32).length) 0#u8, by
    simp [List.length_take, List.length_drop]⟩

/-- The pure index walk: fold the siblings upward, order by idx parity. -/
noncomputable def merkleFold :
    List (Std.Array Std.U8 32#usize) → Std.Array Std.U8 32#usize → Nat →
    Std.Array Std.U8 32#usize
  | [], h, _ => h
  | sib :: rest, h, idx =>
      merkleFold rest
        (if idx % 2 = 0 then node_hash_pure h sib else node_hash_pure sib h)
        (idx / 2)

/-- **Functional spec**: accepts ⟺ the blob is exactly `depth` siblings AND
    the domain-separated fold from `leaf_hash(canonical)` at `leaf_index`
    collapses to `expected_root`. -/
theorem verify_proof_spec (canonical : Slice Std.U8) (leaf_index : Std.Usize)
    (proof_bytes : Slice Std.U8) (proof_depth : Std.Usize)
    (expected_root : Std.Array Std.U8 32#usize) :
    erc20.merkle.verify_proof canonical leaf_index proof_bytes proof_depth
        expected_root
      ⦃ b => b = true ↔
        (proof_bytes.val.length = proof_depth.val * 32 ∧
         merkleFold ((List.range proof_depth.val).map (chunk32 proof_bytes.val))
             (leaf_hash_pure canonical) leaf_index.val
           = expected_root) ⦄ := by
  sorry

end Extracted.Equiv
