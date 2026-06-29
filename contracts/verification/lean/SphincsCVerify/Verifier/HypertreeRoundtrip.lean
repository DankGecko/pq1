/- Group-V round-trip — hypertree composition (verify_signs sub-lemma 4, part 2/2).

   The D=2 hypertree walk `verifyHypertree` reconstructs the public-key root from
   honest layer signatures. Each layer is one `vhStep`, characterized by the
   existing `vhStep_some` (`HypertreePhase.lean`): given the WOTS public key is
   recovered (`pkFromSig = some wpk`) it climbs the subtree auth path. Composing
   `wots_pk_roundtrip` (recovers `wpk = keygenPk`, the honest leaf) with
   `merkle_roundtrip` (the honest subtree climb = the subtree root) gives the
   per-layer round-trip `vhLayer_roundtrip`; applying it across the two unrolled
   layers (`verifyHypertree_unroll`) gives the full `hypertree_roundtrip`. -/
import SphincsCVerify.Verifier.MerkleRoundtrip
import SphincsCVerify.Verifier.WotsRoundtrip
import SphincsCVerify.Interpreter.HypertreePhase

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify SphincsCVerify.Spec

/-- **One honest hypertree layer round-trips.** When the layer's WOTS+C
    signature recovers the honest leaf `wpk = lf idxLeaf` (the WOTS public key)
    and its auth path is the honest subtree path over `lf`, `vhStep` advances the
    accumulator to the honest subtree root `mtNode … SubtreeH 0` (and shifts the
    tree index). Combines `vhStep_some` + `merkle_roundtrip`; the WOTS recovery
    `hwots` is discharged by `wots_pk_roundtrip` at the call site. -/
theorem vhLayer_roundtrip (seed : ByteVec 32) (layers : Array Spec.Hypertree.LayerSig)
    (acc : MProd Bool (MProd (ByteVec 16) Nat)) (layer : Nat) (lf : Nat → ByteVec 16)
    (hbad : acc.fst = false)
    (hwots : Spec.Wots.pkFromSig seed (UInt32.ofNat layer)
        (UInt64.ofNat (acc.snd.snd >>> Spec.SubtreeH))
        (UInt32.ofNat (acc.snd.snd &&& (1 <<< Spec.SubtreeH - 1)))
        acc.snd.fst (layers.getD layer Spec.Hypertree.defaultLayerSig).wots
      = some (lf (acc.snd.snd &&& (1 <<< Spec.SubtreeH - 1))))
    (hpath : (layers.getD layer Spec.Hypertree.defaultLayerSig).authPath
      = mtAuthPath seed (UInt32.ofNat layer) (UInt64.ofNat (acc.snd.snd >>> Spec.SubtreeH)) lf
          (acc.snd.snd &&& (1 <<< Spec.SubtreeH - 1)))
    (hidxlt : (acc.snd.snd &&& (1 <<< Spec.SubtreeH - 1)) < 2 ^ Spec.SubtreeH) :
    vhStep seed layers acc layer
      = ⟨false, mtNode seed (UInt32.ofNat layer) (UInt64.ofNat (acc.snd.snd >>> Spec.SubtreeH)) lf
          Spec.SubtreeH 0, acc.snd.snd >>> Spec.SubtreeH⟩ := by
  rw [vhStep_some seed layers acc layer hbad
        (lf (acc.snd.snd &&& (1 <<< Spec.SubtreeH - 1))) hwots,
      hpath,
      merkle_roundtrip seed (UInt32.ofNat layer) (UInt64.ofNat (acc.snd.snd >>> Spec.SubtreeH)) lf
        (acc.snd.snd &&& (1 <<< Spec.SubtreeH - 1)) hidxlt]

/-- **`hypertree_roundtrip`** (sub-lemma 4, full D=2 composition). When both
    layers carry honest WOTS+C signatures (recovering `lf0`/`lf1` leaves) and
    honest subtree auth paths, `verifyHypertree` reconstructs the top root: layer
    0 climbs to its subtree root `root0`, which is layer 1's WOTS message, and
    layer 1 climbs to the final root. Two `vhLayer_roundtrip` applications over
    the unrolled D=2 loop (`verifyHypertree_unroll`). The honest-layer hypotheses
    are discharged at the call site by `wots_pk_roundtrip` (the `hwots*`) and the
    signer's honest auth-path construction (the `hpath*`). -/
theorem hypertree_roundtrip (seed : ByteVec 32) (forsPk : ByteVec 16) (htIdx : Nat)
    (layers : Array Spec.Hypertree.LayerSig) (lf0 lf1 : Nat → ByteVec 16)
    (hwots0 : Spec.Wots.pkFromSig seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> Spec.SubtreeH))
        (UInt32.ofNat (htIdx &&& (1 <<< Spec.SubtreeH - 1))) forsPk
        (layers.getD 0 Spec.Hypertree.defaultLayerSig).wots
      = some (lf0 (htIdx &&& (1 <<< Spec.SubtreeH - 1))))
    (hpath0 : (layers.getD 0 Spec.Hypertree.defaultLayerSig).authPath
      = mtAuthPath seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> Spec.SubtreeH)) lf0
          (htIdx &&& (1 <<< Spec.SubtreeH - 1)))
    (hidx0 : (htIdx &&& (1 <<< Spec.SubtreeH - 1)) < 2 ^ Spec.SubtreeH)
    (hwots1 : Spec.Wots.pkFromSig seed (UInt32.ofNat 1)
        (UInt64.ofNat ((htIdx >>> Spec.SubtreeH) >>> Spec.SubtreeH))
        (UInt32.ofNat ((htIdx >>> Spec.SubtreeH) &&& (1 <<< Spec.SubtreeH - 1)))
        (mtNode seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> Spec.SubtreeH)) lf0 Spec.SubtreeH 0)
        (layers.getD 1 Spec.Hypertree.defaultLayerSig).wots
      = some (lf1 ((htIdx >>> Spec.SubtreeH) &&& (1 <<< Spec.SubtreeH - 1))))
    (hpath1 : (layers.getD 1 Spec.Hypertree.defaultLayerSig).authPath
      = mtAuthPath seed (UInt32.ofNat 1) (UInt64.ofNat ((htIdx >>> Spec.SubtreeH) >>> Spec.SubtreeH)) lf1
          ((htIdx >>> Spec.SubtreeH) &&& (1 <<< Spec.SubtreeH - 1)))
    (hidx1 : ((htIdx >>> Spec.SubtreeH) &&& (1 <<< Spec.SubtreeH - 1)) < 2 ^ Spec.SubtreeH) :
    Spec.Hypertree.verifyHypertree seed forsPk htIdx layers
      = some (mtNode seed (UInt32.ofNat 1) (UInt64.ofNat ((htIdx >>> Spec.SubtreeH) >>> Spec.SubtreeH))
          lf1 Spec.SubtreeH 0) := by
  rw [verifyHypertree_unroll,
      vhLayer_roundtrip seed layers ⟨false, forsPk, htIdx⟩ 0 lf0 rfl hwots0 hpath0 hidx0,
      vhLayer_roundtrip seed layers
        ⟨false, mtNode seed (UInt32.ofNat 0) (UInt64.ofNat (htIdx >>> Spec.SubtreeH)) lf0 Spec.SubtreeH 0,
          htIdx >>> Spec.SubtreeH⟩ 1 lf1 rfl hwots1 hpath1 hidx1]
  rfl

end SphincsCVerify.Interpreter.C10
