/- Honest signer-side Merkle / FORS trees (spec-level treehash).

   These are the HONEST tree constructions the reference signer emits and the
   verifier round-trip lemmas reconstruct against. They are pure spec (need only
   `th`/`thPair`/`Adrs`), but the verify_signs round-trip lemmas that consume them
   live in `Verifier/` files that import the whole interpreter — so the reference
   signer (`Spec/Signer.lean`) could not reach them there. They are hoisted here
   into `Spec` so BOTH `Signer.sign` (emits them) and the `Verifier/*Roundtrip`
   lemmas (`merkle_roundtrip`, `fors_roundtrip`, `hypertree_roundtrip`, …, which
   `open Spec`) reference the same definitions. Nothing imports `Spec.Signer`, so
   there is no cycle. -/
import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Adrs
import SphincsCVerify.Spec.Params

open SphincsCVerify

namespace SphincsCVerify.Spec

/-- Sibling index at climb level `h` for the leaf `leafIdx`: the index `p`'s
    sibling in the Merkle tree, where `p = leafIdx / 2^h` is the ancestor index
    at that level. -/
def sibIdx (leafIdx h : Nat) : Nat :=
  let p := leafIdx / 2 ^ h
  if p % 2 = 0 then p + 1 else p - 1

/-- The honest signer-side XMSS Merkle tree node at `(level, idx)` over leaves
    `lf`, using the exact `Adrs.treeNode` + `thPair` shape `htStep` reconstructs
    with. -/
def mtNode (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (lf : Nat → ByteVec 16) :
    Nat → Nat → ByteVec 16
  | 0, idx => lf idx
  | (ℓ + 1), idx =>
      Spec.thPair seed (Spec.Adrs.treeNode layer tree (UInt32.ofNat (ℓ + 1)) (UInt32.ofNat idx))
        (ByteVec.pad16 (mtNode seed layer tree lf ℓ (2 * idx)))
        (ByteVec.pad16 (mtNode seed layer tree lf ℓ (2 * idx + 1)))

/-- The honest XMSS auth path for `leafIdx`: the sibling node at each climb level. -/
def mtAuthPath (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (lf : Nat → ByteVec 16)
    (leafIdx : Nat) : Array (ByteVec 16) :=
  Array.ofFn (n := Spec.SubtreeH) fun h => mtNode seed layer tree lf h.val (sibIdx leafIdx h.val)

/-- The honest signer-side FORS Merkle tree node at `(level, idx)`: level-0 leaf
    is `th` of the secret `lf idx`; internal nodes are `thPair`, all under
    `Adrs.forsNode` — matching `forsStep`'s reconstruction shape exactly. -/
def forsMtNode (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32) (lf : Nat → ByteVec 16) :
    Nat → Nat → ByteVec 16
  | 0, idx =>
      Spec.th seed (Spec.Adrs.forsNode htIdx treeIdx 0 (UInt32.ofNat idx)) (ByteVec.pad16 (lf idx))
  | (ℓ + 1), idx =>
      Spec.thPair seed (Spec.Adrs.forsNode htIdx treeIdx (UInt32.ofNat (ℓ + 1)) (UInt32.ofNat idx))
        (ByteVec.pad16 (forsMtNode seed htIdx treeIdx lf ℓ (2 * idx)))
        (ByteVec.pad16 (forsMtNode seed htIdx treeIdx lf ℓ (2 * idx + 1)))

/-- The honest FORS auth path for `leafIdx`: the sibling node at each level. -/
def forsMtAuthPath (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32) (lf : Nat → ByteVec 16)
    (leafIdx : Nat) : Array (ByteVec 16) :=
  Array.ofFn (n := Spec.A) fun h => forsMtNode seed htIdx treeIdx lf h.val (sibIdx leafIdx h.val)

end SphincsCVerify.Spec
